//! swan-vault: the durable half of SwanTV.
//!
//! The Apple TV runs Swan; its SQLite files are a *cache*. Every committed
//! SQLite transaction is shipped here as a run of WAL frames before Swan
//! acknowledges the write to its client, and every blob / key envelope is
//! stored here as an immutable content-addressed object. This daemon owns the
//! USB disk and nothing else: no protocol logic, no schema knowledge.
//!
//! Consistency model (see docs/apple-tv-pds/TRANSACTION_MODEL.md):
//!   * One SQLite transaction == one or more WAL frames ending in a commit
//!     frame. A segment is a contiguous frame run ending on a commit frame.
//!   * Segments for a database are strictly sequential (`seq`), validated
//!     against the WAL header salt and the running WAL checksum chain, and
//!     fsynced before the manifest is advanced. A segment that fails any check
//!     is rejected whole; the manifest never references a partial segment.
//!   * A lease with a monotonically increasing generation fences writers. A
//!     mutation carrying a stale generation is refused with 409, so two Apple
//!     TVs pointed at one vault cannot interleave.
//!   * Objects are written to a temp file, fsynced, then renamed into place;
//!     the name is the SHA-256 of the content, verified on ingest.
//!
//! Layout under --root:
//!   vault.json                    identity + current generation
//!   db/<name>/manifest.json       page size, salt, next seq, snapshot info
//!   db/<name>/snapshot.db         base image (uploaded or compacted)
//!   db/<name>/wal/<seq>.seg       raw WAL frames, one segment per file
//!   objects/<aa>/<sha256>         immutable content-addressed objects
//!   tmp/                          in-flight writes (cleared at startup)
//!
//! ponytail: single process, one global mutex, blocking I/O, thread per
//! connection. A single-user PDS commits a few times a second at most; if that
//! ever matters, per-database locks are the upgrade path.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const FRAME_HEADER_LEN: usize = 24;
const MAX_SEGMENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Default)]
struct VaultMeta {
    vault_id: String,
    created_unix: u64,
    generation: u64,
    lease_holder: Option<String>,
    lease_issued_unix: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct DbManifest {
    page_size: u32,
    /// Salt of the WAL the next segment must belong to (hex, 8 bytes).
    salt: Option<String>,
    /// Running checksum after the last accepted frame (s0, s1).
    checksum: Option<(u32, u32)>,
    /// Frame index the next segment must start at (1-based within this WAL).
    next_frame: u32,
    /// Segment sequence the next POST must carry.
    next_seq: u64,
    snapshot_bytes: u64,
    snapshot_sha256: Option<String>,
    /// Segment metadata in order; restore replays these over the snapshot.
    segments: Vec<SegmentMeta>,
    updated_unix: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct SegmentMeta {
    seq: u64,
    first_frame: u32,
    frames: u32,
    bytes: u64,
    sha256: String,
    salt: String,
    /// Database size in pages after the last commit frame of this segment.
    db_pages: u32,
    /// True when this segment starts a fresh WAL (after a checkpoint/truncate).
    wal_reset: bool,
}

struct Vault {
    root: PathBuf,
    meta: VaultMeta,
    manifests: HashMap<String, DbManifest>,
    started_unix: u64,
}

struct App {
    token: Vec<u8>,
    vault: Mutex<Vault>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Durable replace: write temp, fsync file, rename, fsync directory.
fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no parent"))?;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> io::Result<T> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(value).unwrap())
}

/// Database names are opaque to the vault but must stay inside db/.
fn safe_name(name: &str) -> Option<String> {
    if name.is_empty() || name.len() > 200 {
        return None;
    }
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.starts_with('.')
    {
        Some(name.to_string())
    } else {
        None
    }
}

fn safe_sha(hexstr: &str) -> Option<String> {
    if hexstr.len() == 64 && hexstr.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hexstr.to_ascii_lowercase())
    } else {
        None
    }
}

impl Vault {
    fn open(root: PathBuf) -> io::Result<Vault> {
        fs::create_dir_all(root.join("db"))?;
        fs::create_dir_all(root.join("objects"))?;
        let tmp = root.join("tmp");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp)?;
        let meta_path = root.join("vault.json");
        let mut meta: VaultMeta = read_json(&meta_path)?;
        if meta.vault_id.is_empty() {
            let mut seed = [0u8; 16];
            File::open("/dev/urandom")?.read_exact(&mut seed)?;
            meta.vault_id = hex::encode(seed);
            meta.created_unix = now_unix();
            write_json(&meta_path, &meta)?;
        }
        let mut manifests = HashMap::new();
        for entry in fs::read_dir(root.join("db"))? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                let manifest: DbManifest = read_json(&entry.path().join("manifest.json"))?;
                manifests.insert(name, manifest);
            }
        }
        Ok(Vault {
            root,
            meta,
            manifests,
            started_unix: now_unix(),
        })
    }

    fn db_dir(&self, name: &str) -> PathBuf {
        self.root.join("db").join(name)
    }
    fn object_path(&self, sha: &str) -> PathBuf {
        self.root.join("objects").join(&sha[..2]).join(sha)
    }

    fn save_meta(&self) -> io::Result<()> {
        write_json(&self.root.join("vault.json"), &self.meta)
    }
    fn save_manifest(&self, name: &str, m: &DbManifest) -> io::Result<()> {
        write_json(&self.db_dir(name).join("manifest.json"), m)
    }

    fn disk_free_bytes(&self) -> u64 {
        // Use the platform ABI: Darwin and Linux have different statvfs layouts.
        // A failed probe is reported as unavailable (zero).
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let c = std::ffi::CString::new(self.root.as_os_str().as_bytes()).unwrap();
            let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0 {
                return (st.f_bavail as u64).saturating_mul(st.f_frsize as u64);
            }
        }
        0
    }
}

// ---- SQLite WAL validation -------------------------------------------------

/// SQLite WAL checksum: native-endian pairs, seeded by the previous checksum.
fn wal_checksum(big_endian: bool, data: &[u8], seed: (u32, u32)) -> (u32, u32) {
    let (mut s0, mut s1) = seed;
    let mut i = 0;
    while i + 8 <= data.len() {
        let a = [data[i], data[i + 1], data[i + 2], data[i + 3]];
        let b = [data[i + 4], data[i + 5], data[i + 6], data[i + 7]];
        let (x, y) = if big_endian {
            (u32::from_be_bytes(a), u32::from_be_bytes(b))
        } else {
            (u32::from_le_bytes(a), u32::from_le_bytes(b))
        };
        s0 = s0.wrapping_add(x).wrapping_add(s1);
        s1 = s1.wrapping_add(y).wrapping_add(s0);
        i += 8;
    }
    (s0, s1)
}

struct SegmentHeader {
    page_size: u32,
    salt: [u8; 8],
    frame_count: u32,
    big_endian: bool,
}

/// Verify frame headers (salt, checksum chain) and return (chain, db_pages).
/// Every frame must carry the WAL salt; the last frame must be a commit frame.
fn validate_frames(
    h: &SegmentHeader,
    body: &[u8],
    seed: (u32, u32),
) -> Result<((u32, u32), u32), String> {
    let frame_len = FRAME_HEADER_LEN + h.page_size as usize;
    if body.len() != frame_len * h.frame_count as usize {
        return Err(format!(
            "body is {} bytes, expected {} frames x {}",
            body.len(),
            h.frame_count,
            frame_len
        ));
    }
    let mut chain = seed;
    let mut db_pages = 0u32;
    for i in 0..h.frame_count as usize {
        let f = &body[i * frame_len..(i + 1) * frame_len];
        if f[8..16] != h.salt {
            return Err(format!("frame {} salt mismatch", i));
        }
        let page_no = u32::from_be_bytes([f[0], f[1], f[2], f[3]]);
        if page_no == 0 {
            return Err(format!("frame {} page 0", i));
        }
        let commit = u32::from_be_bytes([f[4], f[5], f[6], f[7]]);
        let mut c = wal_checksum(h.big_endian, &f[0..8], chain);
        c = wal_checksum(h.big_endian, &f[FRAME_HEADER_LEN..], c);
        let stored = (
            u32::from_be_bytes([f[16], f[17], f[18], f[19]]),
            u32::from_be_bytes([f[20], f[21], f[22], f[23]]),
        );
        if c != stored {
            return Err(format!("frame {} checksum mismatch", i));
        }
        chain = c;
        if commit != 0 {
            db_pages = commit;
        }
        if i + 1 == h.frame_count as usize && commit == 0 {
            return Err("segment does not end on a commit frame".into());
        }
    }
    Ok((chain, db_pages))
}

// ---- HTTP -------------------------------------------------------------------

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

fn json_response<T: Serialize>(status: u16, value: &T) -> Response<io::Cursor<Vec<u8>>> {
    Response::from_data(serde_json::to_vec(value).unwrap())
        .with_status_code(StatusCode(status))
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
}

fn error(status: u16, msg: &str) -> Response<io::Cursor<Vec<u8>>> {
    json_response(status, &serde_json::json!({ "error": msg }))
}

fn read_body(req: &mut Request, limit: usize) -> Result<Vec<u8>, String> {
    let declared = req.body_length().unwrap_or(0);
    if declared > limit {
        return Err(format!("body {} exceeds limit {}", declared, limit));
    }
    let mut buf = Vec::with_capacity(declared.min(limit));
    let mut reader = req.as_reader().take(limit as u64 + 1);
    reader.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    if buf.len() > limit {
        return Err("body exceeds limit".into());
    }
    if let Some(d) = req.body_length() {
        if d != buf.len() {
            return Err("truncated body".into());
        }
    }
    Ok(buf)
}

fn query(req: &Request) -> HashMap<String, String> {
    req.url()
        .splitn(2, '?')
        .nth(1)
        .unwrap_or("")
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            (
                it.next().unwrap_or("").to_string(),
                it.next().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn handle(app: &App, mut req: Request) {
    let path = req.url().split('?').next().unwrap_or("/").to_string();
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    // Health is unauthenticated on purpose: it leaks nothing but liveness and
    // is what a watchdog polls.
    if segments == ["v1", "health"] {
        let v = app.vault.lock();
        let body = serde_json::json!({
            "vault_id": v.meta.vault_id, "generation": v.meta.generation,
            "lease_holder": v.meta.lease_holder, "uptime_seconds": now_unix() - v.started_unix,
            "disk_free_bytes": v.disk_free_bytes(), "databases": v.manifests.keys().collect::<Vec<_>>(),
        });
        let _ = req.respond(json_response(200, &body));
        return;
    }

    let presented = header(&req, "Authorization")
        .and_then(|h| h.strip_prefix("Bearer ").map(|s| s.as_bytes().to_vec()));
    let authorized = presented
        .map(|p| p.len() == app.token.len() && p.ct_eq(&app.token).into())
        .unwrap_or(false);
    if !authorized {
        let _ = req.respond(error(401, "unauthorized"));
        return;
    }

    let q = query(&req);
    let method = req.method().clone();
    let response = match (method, segments.as_slice()) {
        (Method::Post, ["v1", "lease"]) => {
            let body = match read_body(&mut req, 4096) {
                Ok(b) => b,
                Err(e) => {
                    let _ = req.respond(error(400, &e));
                    return;
                }
            };
            let holder = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("holder").and_then(|h| h.as_str()).map(str::to_string))
                .unwrap_or_else(|| "anonymous".into());
            let mut v = app.vault.lock();
            v.meta.generation += 1;
            v.meta.lease_holder = Some(holder.clone());
            v.meta.lease_issued_unix = Some(now_unix());
            match v.save_meta() {
                Ok(()) => json_response(
                    200,
                    &serde_json::json!({ "generation": v.meta.generation, "vault_id": v.meta.vault_id, "holder": holder }),
                ),
                Err(e) => error(500, &e.to_string()),
            }
        }
        (Method::Get, ["v1", "db"]) => {
            let v = app.vault.lock();
            json_response(200, &v.manifests)
        }
        (Method::Get, ["v1", "db", name, "manifest"]) => {
            let Some(name) = safe_name(name) else {
                let _ = req.respond(error(400, "bad name"));
                return;
            };
            let v = app.vault.lock();
            match v.manifests.get(&name) {
                Some(m) => json_response(200, m),
                None => error(404, "unknown database"),
            }
        }
        (Method::Put, ["v1", "db", name, "snapshot"]) => {
            let Some(name) = safe_name(name) else {
                let _ = req.respond(error(400, "bad name"));
                return;
            };
            let body = match read_body(&mut req, MAX_OBJECT_BYTES) {
                Ok(b) => b,
                Err(e) => {
                    let _ = req.respond(error(413, &e));
                    return;
                }
            };
            let mut v = app.vault.lock();
            if let Err(r) = check_generation(&v, &q) {
                let _ = req.respond(r);
                return;
            }
            if body.len() < 100 || &body[..16] != b"SQLite format 3\0" {
                let _ = req.respond(error(400, "not a SQLite database image"));
                return;
            }
            let page_size = match u16::from_be_bytes([body[16], body[17]]) {
                1 => 65536u32,
                n => n as u32,
            };
            let dir = v.db_dir(&name);
            let _ = fs::remove_dir_all(dir.join("wal"));
            if let Err(e) = fs::create_dir_all(dir.join("wal")) {
                let _ = req.respond(error(500, &e.to_string()));
                return;
            }
            if let Err(e) = atomic_write(&dir.join("snapshot.db"), &body) {
                let _ = req.respond(error(500, &e.to_string()));
                return;
            }
            let m = DbManifest {
                page_size,
                salt: None,
                checksum: None,
                next_frame: 1,
                next_seq: 1,
                snapshot_bytes: body.len() as u64,
                snapshot_sha256: Some(sha256_hex(&body)),
                segments: Vec::new(),
                updated_unix: now_unix(),
            };
            match v.save_manifest(&name, &m) {
                Ok(()) => {
                    v.manifests.insert(name, m.clone());
                    json_response(200, &m)
                }
                Err(e) => error(500, &e.to_string()),
            }
        }
        (Method::Post, ["v1", "db", name, "wal"]) => {
            let Some(name) = safe_name(name) else {
                let _ = req.respond(error(400, "bad name"));
                return;
            };
            let parse = |k: &str| header(&req, k).and_then(|s| s.parse::<u64>().ok());
            let (Some(seq), Some(page_size), Some(first_frame), Some(frame_count), Some(salt_hex)) = (
                parse("X-Wal-Seq"),
                parse("X-Wal-Page-Size"),
                parse("X-Wal-First-Frame"),
                parse("X-Wal-Frame-Count"),
                header(&req, "X-Wal-Salt"),
            ) else {
                let _ = req.respond(error(400, "missing X-Wal-* headers"));
                return;
            };
            let wal_reset = header(&req, "X-Wal-Reset").as_deref() == Some("1");
            let big_endian = header(&req, "X-Wal-Big-Endian").as_deref() == Some("1");
            let header_checksum = header(&req, "X-Wal-Header-Checksum").and_then(|s| {
                let mut it = s.split(',');
                Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
            });
            let salt_bytes = match hex::decode(&salt_hex) {
                Ok(b) if b.len() == 8 => {
                    let mut s = [0u8; 8];
                    s.copy_from_slice(&b);
                    s
                }
                _ => {
                    let _ = req.respond(error(400, "bad salt"));
                    return;
                }
            };
            let body = match read_body(&mut req, MAX_SEGMENT_BYTES) {
                Ok(b) => b,
                Err(e) => {
                    let _ = req.respond(error(413, &e));
                    return;
                }
            };
            let mut v = app.vault.lock();
            if let Err(r) = check_generation(&v, &q) {
                let _ = req.respond(r);
                return;
            }
            let Some(mut m) = v.manifests.get(&name).cloned() else {
                let _ = req.respond(error(404, "upload a snapshot first"));
                return;
            };
            let sha = sha256_hex(&body);
            // Idempotent replay of the segment we already hold.
            if seq + 1 == m.next_seq {
                if let Some(last) = m.segments.last() {
                    if last.sha256 == sha {
                        let _ = req.respond(json_response(200, last));
                        return;
                    }
                }
            }
            if seq != m.next_seq {
                let _ = req.respond(error(409, &format!("expected seq {}", m.next_seq)));
                return;
            }
            if page_size as u32 != m.page_size {
                let _ = req.respond(error(400, "page size mismatch"));
                return;
            }
            let seed = if wal_reset {
                if first_frame != 1 {
                    let _ = req.respond(error(400, "wal reset must start at frame 1"));
                    return;
                }
                let Some(hc) = header_checksum else {
                    let _ = req.respond(error(400, "wal reset needs X-Wal-Header-Checksum"));
                    return;
                };
                hc
            } else {
                if m.salt.as_deref() != Some(salt_hex.as_str()) {
                    let _ = req.respond(error(
                        409,
                        "salt does not match current WAL; send X-Wal-Reset",
                    ));
                    return;
                }
                if first_frame as u32 != m.next_frame {
                    let _ = req.respond(error(
                        409,
                        &format!("expected first frame {}", m.next_frame),
                    ));
                    return;
                }
                match m.checksum {
                    Some(c) => c,
                    None => {
                        let _ = req.respond(error(409, "no checksum chain"));
                        return;
                    }
                }
            };
            let sh = SegmentHeader {
                page_size: page_size as u32,
                salt: salt_bytes,
                frame_count: frame_count as u32,
                big_endian,
            };
            let (chain, db_pages) = match validate_frames(&sh, &body, seed) {
                Ok(r) => r,
                Err(e) => {
                    let _ = req.respond(error(422, &e));
                    return;
                }
            };
            let seg_path = v.db_dir(&name).join("wal").join(format!("{:012}.seg", seq));
            if let Err(e) = atomic_write(&seg_path, &body) {
                let _ = req.respond(error(500, &e.to_string()));
                return;
            }
            let meta = SegmentMeta {
                seq,
                first_frame: first_frame as u32,
                frames: frame_count as u32,
                bytes: body.len() as u64,
                sha256: sha,
                salt: salt_hex.clone(),
                db_pages,
                wal_reset,
            };
            m.salt = Some(salt_hex);
            m.checksum = Some(chain);
            m.next_frame = first_frame as u32 + frame_count as u32;
            m.next_seq = seq + 1;
            m.updated_unix = now_unix();
            m.segments.push(meta.clone());
            match v.save_manifest(&name, &m) {
                Ok(()) => {
                    v.manifests.insert(name, m);
                    json_response(200, &meta)
                }
                Err(e) => error(500, &e.to_string()),
            }
        }
        (Method::Get, ["v1", "db", name, "snapshot"]) => {
            let Some(name) = safe_name(name) else {
                let _ = req.respond(error(400, "bad name"));
                return;
            };
            let v = app.vault.lock();
            match File::open(v.db_dir(&name).join("snapshot.db")) {
                Ok(f) => {
                    let len = f.metadata().ok().map(|m| m.len() as usize);
                    drop(v);
                    let _ = req.respond(Response::new(StatusCode(200), vec![], f, len, None));
                    return;
                }
                Err(_) => error(404, "no snapshot"),
            }
        }
        (Method::Get, ["v1", "db", name, "wal", seq]) => {
            let Some(name) = safe_name(name) else {
                let _ = req.respond(error(400, "bad name"));
                return;
            };
            let Ok(seq) = seq.parse::<u64>() else {
                let _ = req.respond(error(400, "bad seq"));
                return;
            };
            let v = app.vault.lock();
            match File::open(v.db_dir(&name).join("wal").join(format!("{:012}.seg", seq))) {
                Ok(f) => {
                    let len = f.metadata().ok().map(|m| m.len() as usize);
                    drop(v);
                    let _ = req.respond(Response::new(StatusCode(200), vec![], f, len, None));
                    return;
                }
                Err(_) => error(404, "no such segment"),
            }
        }
        (Method::Post, ["v1", "db", name, "compact"]) => {
            let Some(name) = safe_name(name) else {
                let _ = req.respond(error(400, "bad name"));
                return;
            };
            let mut v = app.vault.lock();
            if let Err(r) = check_generation(&v, &q) {
                let _ = req.respond(r);
                return;
            }
            match compact(&mut v, &name) {
                Ok(m) => json_response(200, &m),
                Err(e) => error(500, &e),
            }
        }
        (Method::Put, ["v1", "objects", sha]) => {
            let Some(sha) = safe_sha(sha) else {
                let _ = req.respond(error(400, "bad digest"));
                return;
            };
            let body = match read_body(&mut req, MAX_OBJECT_BYTES) {
                Ok(b) => b,
                Err(e) => {
                    let _ = req.respond(error(413, &e));
                    return;
                }
            };
            if sha256_hex(&body) != sha {
                let _ = req.respond(error(422, "content does not match digest"));
                return;
            }
            let v = app.vault.lock();
            if let Err(r) = check_generation(&v, &q) {
                let _ = req.respond(r);
                return;
            }
            let path = v.object_path(&sha);
            if path.exists() {
                json_response(200, &serde_json::json!({ "sha256": sha, "existed": true }))
            } else {
                match atomic_write(&path, &body) {
                    Ok(()) => json_response(
                        201,
                        &serde_json::json!({ "sha256": sha, "bytes": body.len() }),
                    ),
                    Err(e) => error(500, &e.to_string()),
                }
            }
        }
        (Method::Get, ["v1", "objects", sha]) | (Method::Head, ["v1", "objects", sha]) => {
            let Some(sha) = safe_sha(sha) else {
                let _ = req.respond(error(400, "bad digest"));
                return;
            };
            let v = app.vault.lock();
            match File::open(v.object_path(&sha)) {
                Ok(f) => {
                    let len = f.metadata().ok().map(|m| m.len() as usize);
                    drop(v);
                    let _ = req.respond(Response::new(StatusCode(200), vec![], f, len, None));
                    return;
                }
                Err(_) => error(404, "no such object"),
            }
        }
        _ => error(404, "no such route"),
    };
    let _ = req.respond(response);
}

/// Mutations must carry the live generation: `?gen=N`.
fn check_generation(
    v: &Vault,
    q: &HashMap<String, String>,
) -> Result<(), Response<io::Cursor<Vec<u8>>>> {
    match q.get("gen").and_then(|g| g.parse::<u64>().ok()) {
        Some(g) if g == v.meta.generation && g > 0 => Ok(()),
        Some(g) => Err(error(
            409,
            &format!("stale generation {} (current {})", g, v.meta.generation),
        )),
        None => Err(error(400, "missing gen")),
    }
}

/// Fold every segment into the snapshot: apply each frame's page at
/// (page_no-1)*page_size, truncate to the final db size, fsync, swap, then
/// drop the segments. Crash-safe: the old snapshot + segments stay valid until
/// the manifest swap lands.
fn compact(v: &mut Vault, name: &str) -> Result<DbManifest, String> {
    let m = v.manifests.get(name).cloned().ok_or("unknown database")?;
    if m.segments.is_empty() {
        return Ok(m);
    }
    let dir = v.db_dir(name);
    let mut image = fs::read(dir.join("snapshot.db")).map_err(|e| e.to_string())?;
    let ps = m.page_size as usize;
    let frame_len = FRAME_HEADER_LEN + ps;
    let mut final_pages = image.len() / ps;
    for seg in &m.segments {
        let bytes = fs::read(dir.join("wal").join(format!("{:012}.seg", seg.seq)))
            .map_err(|e| e.to_string())?;
        if sha256_hex(&bytes) != seg.sha256 {
            return Err(format!("segment {} corrupt on disk", seg.seq));
        }
        for f in bytes.chunks_exact(frame_len) {
            let page_no = u32::from_be_bytes([f[0], f[1], f[2], f[3]]) as usize;
            let end = page_no * ps;
            if image.len() < end {
                image.resize(end, 0);
            }
            image[end - ps..end].copy_from_slice(&f[FRAME_HEADER_LEN..]);
        }
        final_pages = seg.db_pages as usize;
    }
    image.truncate(final_pages * ps);
    let new_path = dir.join("snapshot.db.next");
    atomic_write(&new_path, &image).map_err(|e| e.to_string())?;
    fs::rename(&new_path, dir.join("snapshot.db")).map_err(|e| e.to_string())?;
    File::open(&dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| e.to_string())?;
    let mut nm = m.clone();
    nm.snapshot_bytes = image.len() as u64;
    nm.snapshot_sha256 = Some(sha256_hex(&image));
    nm.segments.clear();
    nm.updated_unix = now_unix();
    v.save_manifest(name, &nm).map_err(|e| e.to_string())?;
    for seg in &m.segments {
        let _ = fs::remove_file(dir.join("wal").join(format!("{:012}.seg", seg.seq)));
    }
    v.manifests.insert(name.to_string(), nm.clone());
    Ok(nm)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut root = PathBuf::from("/srv/swan-vault");
    let mut listen = "0.0.0.0:7180".to_string();
    let mut token_file: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => root = PathBuf::from(args.next().expect("--root PATH")),
            "--listen" => listen = args.next().expect("--listen ADDR:PORT"),
            "--token-file" => {
                token_file = Some(PathBuf::from(args.next().expect("--token-file PATH")))
            }
            _ => {
                eprintln!("usage: swan-vault --root DIR --listen ADDR:PORT --token-file FILE");
                std::process::exit(64);
            }
        }
    }
    let token_file = token_file.unwrap_or_else(|| {
        eprintln!("--token-file is required");
        std::process::exit(64);
    });
    let token = fs::read(&token_file)
        .map(|t| {
            t.iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<u8>>()
        })
        .unwrap_or_else(|e| {
            eprintln!("cannot read token file: {e}");
            std::process::exit(66);
        });
    if token.len() < 32 {
        eprintln!("token must be at least 32 bytes");
        std::process::exit(65);
    }
    let vault = Vault::open(root.clone()).unwrap_or_else(|e| {
        eprintln!("cannot open vault at {}: {e}", root.display());
        std::process::exit(74);
    });
    eprintln!(
        "swan-vault {} generation {} at {} listening on {}",
        vault.meta.vault_id,
        vault.meta.generation,
        root.display(),
        listen
    );
    let app = Arc::new(App {
        token,
        vault: Mutex::new(vault),
    });
    let server = Server::http(&listen).unwrap_or_else(|e| {
        eprintln!("cannot listen on {listen}: {e}");
        std::process::exit(69);
    });
    for req in server.incoming_requests() {
        let app = app.clone();
        std::thread::spawn(move || handle(&app, req));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a WAL header + frames the way SQLite would, then check the
    /// validator accepts the chain and rejects a flipped byte.
    #[test]
    fn wal_chain_round_trip() {
        let page_size = 4096u32;
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0x377f0682u32.to_be_bytes()); // LE checksum magic
        hdr.extend_from_slice(&3007000u32.to_be_bytes());
        hdr.extend_from_slice(&page_size.to_be_bytes());
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&salt);
        let hc = wal_checksum(false, &hdr, (0, 0));
        let mut frames = Vec::new();
        let mut chain = hc;
        for (i, commit) in [(1u32, 0u32), (2, 2)] {
            let mut f = Vec::new();
            f.extend_from_slice(&i.to_be_bytes());
            f.extend_from_slice(&commit.to_be_bytes());
            f.extend_from_slice(&salt);
            let page = vec![i as u8; page_size as usize];
            let c = wal_checksum(false, &f[0..8], chain);
            let c = wal_checksum(false, &page, c);
            f.extend_from_slice(&c.0.to_be_bytes());
            f.extend_from_slice(&c.1.to_be_bytes());
            f.extend_from_slice(&page);
            chain = c;
            frames.extend_from_slice(&f);
        }
        let h = SegmentHeader {
            page_size,
            salt,
            frame_count: 2,
            big_endian: false,
        };
        let (end, db_pages) = validate_frames(&h, &frames, hc).expect("valid chain");
        assert_eq!(end, chain);
        assert_eq!(db_pages, 2);
        let mut bad = frames.clone();
        bad[FRAME_HEADER_LEN + 10] ^= 1;
        assert!(validate_frames(&h, &bad, hc).is_err());
        let mut no_commit = frames[..FRAME_HEADER_LEN + page_size as usize].to_vec();
        no_commit.truncate(FRAME_HEADER_LEN + page_size as usize);
        let h1 = SegmentHeader {
            frame_count: 1,
            ..h
        };
        assert!(validate_frames(&h1, &no_commit, hc).is_err());
    }
}
