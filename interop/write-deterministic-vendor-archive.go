// Command write-deterministic-vendor-archive packages a Go vendor tree using
// only the pinned container's standard library. Its output is intentionally
// independent of host tar, gzip, Python, filesystem ownership, and mtimes.
package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type entry struct {
	name string
	path string
	info fs.FileInfo
}

func main() {
	if len(os.Args) != 3 {
		fatalf("usage: write-deterministic-vendor-archive <vendor-directory> <archive>")
	}
	source, err := filepath.Abs(os.Args[1])
	if err != nil {
		fatalf("resolve vendor directory: %v", err)
	}
	info, err := os.Lstat(source)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		fatalf("vendor source must be a real directory")
	}

	entries := []entry{{name: "vendor", path: source, info: info}}
	err = filepath.WalkDir(source, func(path string, directoryEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return nil
		}
		entryInfo, infoErr := os.Lstat(path)
		if infoErr != nil {
			return infoErr
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("vendor tree contains a symlink: %s", path)
		}
		if !entryInfo.IsDir() && !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("vendor tree contains a non-regular entry: %s", path)
		}
		relative, relativeErr := filepath.Rel(source, path)
		if relativeErr != nil {
			return relativeErr
		}
		name := "vendor/" + filepath.ToSlash(relative)
		if strings.Contains(name, "../") || strings.HasPrefix(name, "/") {
			return fmt.Errorf("vendor tree has unsafe path: %s", name)
		}
		entries = append(entries, entry{name: name, path: path, info: entryInfo})
		return nil
	})
	if err != nil {
		fatalf("walk vendor tree: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	destination, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fatalf("create archive: %v", err)
	}
	failed := true
	defer func() {
		_ = destination.Close()
		if failed {
			_ = os.Remove(os.Args[2])
		}
	}()

	gzipWriter := gzip.NewWriter(destination)
	// Pin every exposed header field instead of inheriting source metadata.
	gzipWriter.Header = gzip.Header{OS: 255}
	// Default compression plus this header yields FLG=0, MTIME=0, XFL=0,
	// OS=255 in the digest-pinned Go 1.26.4 implementation.
	tarWriter := tar.NewWriter(gzipWriter)
	for _, candidate := range entries {
		header := &tar.Header{
			Name:     candidate.name,
			Mode:     0o644,
			Uid:      0,
			Gid:      0,
			Size:     candidate.info.Size(),
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if candidate.info.IsDir() {
			header.Mode = 0o755
			header.Size = 0
			header.Typeflag = tar.TypeDir
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			fatalf("write USTAR header for %s: %v", candidate.name, err)
		}
		if candidate.info.IsDir() {
			continue
		}
		file, openErr := os.Open(candidate.path)
		if openErr != nil {
			fatalf("open %s: %v", candidate.name, openErr)
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil {
			fatalf("write %s: %v", candidate.name, copyErr)
		}
		if closeErr != nil {
			fatalf("close %s: %v", candidate.name, closeErr)
		}
	}
	if err := tarWriter.Close(); err != nil {
		fatalf("finish USTAR archive: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		fatalf("finish gzip stream: %v", err)
	}
	if err := destination.Close(); err != nil {
		fatalf("close archive: %v", err)
	}
	failed = false
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
