<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { api } from '$lib/api';
  import { toasts } from '$lib/stores/toasts';
  import { portal } from '$lib/stores/portal';
  import type { DidWebReservationResponse } from '$lib/types';

  interface Props {
    isOpen?: boolean;
    initialMode?: 'new' | 'rotate' | 'remove';
    onClose?: () => void;
  }

  let { isOpen = true, initialMode = 'new', onClose }: Props = $props();

  let mode = $state<'new' | 'rotate' | 'remove'>('new');
  let stage = $state<'input' | 'verify' | 'success'>('input');
  let busy = $state(false);
  let domain = $state('');
  let reservation = $state<DidWebReservationResponse | null>(null);
  let verificationTab = $state<'dns' | 'https'>('dns');
  let error = $state<string | null>(null);

  $effect(() => {
    if (isOpen) {
      mode = initialMode;
      stage = 'input';
      busy = false;
      domain = '';
      reservation = null;
      error = null;
    }
  });

  function cleanDomain(raw: string): string {
    return raw.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
  }

  async function handleReserve(e: SubmitEvent) {
    e.preventDefault();
    const handle = cleanDomain(domain);
    if (!handle) {
      error = 'Please enter a valid domain name (e.g. alice.example.com).';
      return;
    }

    busy = true;
    error = null;

    try {
      const targetDID = `did:web:${handle}`;
      const requestID = `req_${Math.random().toString(36).substring(2, 11)}`;
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();

      const res = await api.reserveDidWeb({
        requestID,
        targetDID,
        handle,
        expiresAt
      });

      reservation = res;
      stage = 'verify';
      toasts.info('Domain reserved. Complete DNS or HTTPS verification.');
    } catch (err: any) {
      error = err.message || 'Failed to reserve custom domain.';
    } finally {
      busy = false;
    }
  }

  async function handleClaim() {
    if (!reservation) return;
    busy = true;
    error = null;

    try {
      await api.claimDidWeb({
        requestID: reservation.requestID
      });

      stage = 'success';
      toasts.success(`Custom domain @${reservation.handle || domain} bound successfully!`);

      try {
        const snapshot = await api.fetchSnapshot();
        portal.setSnapshot(snapshot);
      } catch {
        // Non-blocking snapshot refresh
      }
    } catch (err: any) {
      error = err.message || 'Verification failed. Please ensure DNS TXT or did.json is reachable.';
    } finally {
      busy = false;
    }
  }

  async function handleRotate(e: SubmitEvent) {
    e.preventDefault();
    const handle = cleanDomain(domain);
    if (!handle) {
      error = 'Please enter the new domain name.';
      return;
    }

    busy = true;
    error = null;

    try {
      const requestID = `req_rot_${Math.random().toString(36).substring(2, 11)}`;
      const targetDID = `did:web:${handle}`;
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();

      await api.rotateDidWeb({
        requestID,
        targetDID,
        handle,
        expiresAt
      });

      stage = 'success';
      toasts.success(`Identity rotated to @${handle}`);

      try {
        const snapshot = await api.fetchSnapshot();
        portal.setSnapshot(snapshot);
      } catch {
        // Non-blocking snapshot refresh
      }
    } catch (err: any) {
      error = err.message || 'Failed to rotate custom domain identity.';
    } finally {
      busy = false;
    }
  }

  async function handleRemove() {
    busy = true;
    error = null;

    try {
      await api.removeDidWeb({});

      stage = 'success';
      toasts.success('Custom domain removed. Reverted to PLC DID identity.');

      try {
        const snapshot = await api.fetchSnapshot();
        portal.setSnapshot(snapshot);
      } catch {
        // Non-blocking snapshot refresh
      }
    } catch (err: any) {
      error = err.message || 'Failed to remove custom domain identity.';
    } finally {
      busy = false;
    }
  }

  function getGeneratedDidJson(): string {
    const handle = reservation?.handle || domain || 'alice.example.com';
    const did = reservation?.targetDID || `did:web:${handle}`;
    return JSON.stringify(
      {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        alsoKnownAs: [`at://${handle}`],
        verificationMethod: [
          {
            id: `${did}#atproto`,
            type: 'Multikey',
            controller: did,
            publicKeyMultibase: reservation?.publicKey || 'zQ3sh...'
          }
        ],
        service: [
          {
            id: '#atproto_pds',
            type: 'AtprotoPersonalDataServer',
            serviceEndpoint: 'https://swan.place'
          }
        ]
      },
      null,
      2
    );
  }

  function getDnsTxtHost(): string {
    const handle = reservation?.handle || domain || 'alice.example.com';
    return `_atproto.${handle}`;
  }

  function getDnsTxtValue(): string {
    const did = reservation?.targetDID || `did:web:${cleanDomain(domain)}`;
    return `did=${did}`;
  }

  function handleFinish() {
    stage = 'input';
    busy = false;
    domain = '';
    reservation = null;
    error = null;
    if (onClose) onClose();
  }

  const modalTitle = $derived.by(() => {
    if (stage === 'success') return 'Domain Identity Updated';
    if (mode === 'remove') return 'Remove Custom did:web Domain';
    if (mode === 'rotate') return 'Rotate did:web Identity';
    if (stage === 'verify') return 'Verify Domain Ownership';
    return 'Bring Your Own Domain (did:web)';
  });

  const modalDesc = $derived.by(() => {
    if (stage === 'success') return 'Your decentralized identity changes have been committed to the ledger.';
    if (mode === 'remove') return 'Revert your account identity back to standard did:plc.';
    if (mode === 'rotate') return 'Update or re-key your custom domain decentralized identity binding.';
    if (stage === 'verify') return 'Publish either a DNS TXT record or HTTPS did.json file to prove domain control.';
    return 'Bind your own domain name (e.g. alice.example.com) to your Swan account using did:web.';
  });
</script>

<Modal
  {isOpen}
  title={modalTitle}
  description={modalDesc}
  size={stage === 'verify' ? 'lg' : 'md'}
  preventClose={busy}
  onClose={handleFinish}
>
  {#if stage === 'success'}
    <div class="success-view">
      <div class="success-circle">✓</div>
      <h3>Configuration Complete</h3>
      <p>Your account identity settings have been updated successfully.</p>
      <div class="action-footer">
        <button type="button" class="btn primary" onclick={handleFinish}>Done</button>
      </div>
    </div>
  {:else if mode === 'remove'}
    <div class="confirm-view">
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="warning-card">
        <span class="warning-glyph">⚠️</span>
        <div>
          <strong>Revert to PLC Decentralized Identifier</strong>
          <p>Removing your custom domain identity will revert your account to its original <code>did:plc:...</code> identifier. Existing references to your did:web DID may break.</p>
        </div>
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleFinish} disabled={busy}>
          Cancel
        </button>
        <button type="button" class="btn danger" onclick={handleRemove} disabled={busy}>
          {#if busy}
            <Spinner size={14} color="#ffffff" /> Removing domain…
          {:else}
            Remove did:web Identity <span>↗</span>
          {/if}
        </button>
      </div>
    </div>
  {:else if mode === 'rotate'}
    <form class="wizard-form" onsubmit={handleRotate}>
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="form-field">
        <label for="did-rotate-domain">New Domain Name</label>
        <input
          id="did-rotate-domain"
          type="text"
          bind:value={domain}
          placeholder="new-domain.example.com"
          required
          disabled={busy}
        />
        <small class="field-hint">Rotation requires an elevated step-up session to authorize key update.</small>
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleFinish} disabled={busy}>
          Cancel
        </button>
        <button type="submit" class="btn primary" disabled={busy || !domain.trim()}>
          {#if busy}
            <Spinner size={14} color="#ffffff" /> Rotating…
          {:else}
            Rotate Domain <span>↗</span>
          {/if}
        </button>
      </div>
    </form>
  {:else if stage === 'verify'}
    <div class="verify-view">
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="reservation-badge">
        <span class="eyebrow">RESERVED TARGET DID</span>
        <strong>{reservation?.targetDID || `did:web:${cleanDomain(domain)}`}</strong>
      </div>

      <div class="tabs" role="tablist">
        <button
          type="button"
          role="tab"
          class="tab-btn"
          class:active={verificationTab === 'dns'}
          aria-selected={verificationTab === 'dns'}
          onclick={() => (verificationTab = 'dns')}
        >
          Option 1: DNS TXT Record (Recommended)
        </button>
        <button
          type="button"
          role="tab"
          class="tab-btn"
          class:active={verificationTab === 'https'}
          aria-selected={verificationTab === 'https'}
          onclick={() => (verificationTab = 'https')}
        >
          Option 2: HTTPS did.json
        </button>
      </div>

      {#if verificationTab === 'dns'}
        <div class="instruction-box">
          <p>Add the following DNS <strong>TXT</strong> record to your domain's DNS provider:</p>
          <div class="dns-grid">
            <div class="dns-cell">
              <span class="cell-label">HOST / NAME</span>
              <code>{getDnsTxtHost()}</code>
              <CopyButton text={getDnsTxtHost()} size="sm" label="Copy Host" />
            </div>
            <div class="dns-cell">
              <span class="cell-label">TYPE</span>
              <code>TXT</code>
            </div>
            <div class="dns-cell full-width">
              <span class="cell-label">VALUE / CONTENT</span>
              <code>{getDnsTxtValue()}</code>
              <CopyButton text={getDnsTxtValue()} size="sm" label="Copy Value" />
            </div>
          </div>
        </div>
      {:else}
        <div class="instruction-box">
          <p>Host the following JSON document at <code>https://{cleanDomain(domain)}/.well-known/did.json</code>:</p>
          <div class="code-preview">
            <pre><code>{getGeneratedDidJson()}</code></pre>
            <div class="preview-actions">
              <CopyButton text={getGeneratedDidJson()} variant="primary" label="Copy did.json" />
            </div>
          </div>
        </div>
      {/if}

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleFinish} disabled={busy}>
          Cancel
        </button>
        <button type="button" class="btn primary" onclick={handleClaim} disabled={busy}>
          {#if busy}
            <Spinner size={14} color="#ffffff" /> Verifying…
          {:else}
            Verify & Claim Binding <span>✓</span>
          {/if}
        </button>
      </div>
    </div>
  {:else}
    <form class="wizard-form" onsubmit={handleReserve}>
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="form-field">
        <label for="did-domain-input">Your Custom Domain</label>
        <input
          id="did-domain-input"
          type="text"
          bind:value={domain}
          placeholder="e.g. alice.example.com"
          required
          disabled={busy}
        />
        <small class="field-hint">Enter your domain or subdomain. You must have DNS or web hosting control over it.</small>
      </div>

      <div class="info-card">
        <span class="card-glyph">◎</span>
        <div>
          <strong>Self-Sovereign Identity</strong>
          <p>With did:web, your domain hosts your public keys. Swan acts as your personal data server while you retain full identity ownership.</p>
        </div>
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleFinish} disabled={busy}>
          Cancel
        </button>
        <button type="submit" class="btn primary" disabled={busy || !domain.trim()}>
          {#if busy}
            <Spinner size={14} color="#ffffff" /> Reserving…
          {:else}
            Reserve Domain <span>↗</span>
          {/if}
        </button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  .wizard-form, .verify-view, .confirm-view, .success-view { display: flex; flex-direction: column; gap: 20px; }
  .form-field { display: flex; flex-direction: column; gap: 6px; }
  .form-field label { font: 600 11px var(--mono, monospace); color: var(--muted, #687270); letter-spacing: 0.08em; text-transform: uppercase; }
  .form-field input[type="text"] { padding: 10px 12px; font: 13px var(--sans, sans-serif); border: 1px solid var(--line, #d7d5ca); background: #ffffff; color: var(--ink, #1f2827); border-radius: 2px; }
  .form-field input:focus { outline: 2px solid var(--teal, #2b7169); border-color: var(--teal, #2b7169); }
  .field-hint { font-size: 11px; color: var(--muted, #687270); }
  .info-card { display: flex; gap: 12px; background: #faf8f1; border: 1px solid var(--line, #d7d5ca); padding: 14px; border-radius: 2px; }
  .card-glyph { font-size: 22px; color: var(--teal, #2b7169); }
  .info-card strong { display: block; font-size: 13px; color: var(--ink, #1f2827); font-family: var(--sans, sans-serif); }
  .info-card p { margin: 4px 0 0; font-size: 12px; color: var(--muted, #687270); line-height: 1.4; }
  .warning-card { display: flex; gap: 12px; background: #faf4e6; border: 1px solid #f1dfb8; padding: 14px; border-radius: 2px; color: #5c4714; }
  .warning-glyph { font-size: 20px; flex-shrink: 0; }
  .warning-card strong { display: block; font-size: 13px; font-family: var(--sans, sans-serif); }
  .warning-card p { margin: 4px 0 0; font-size: 12px; line-height: 1.4; }
  .warning-card code { font: 11px var(--mono, monospace); background: #e6ded0; padding: 2px 4px; border-radius: 2px; }
  .error-banner { background: #fbebe8; color: var(--coral, #ba5e47); border-left: 3px solid var(--coral, #ba5e47); padding: 10px 14px; font-size: 12px; border-radius: 2px; }
  .reservation-badge { background: #faf8f1; border: 1px solid var(--line, #d7d5ca); padding: 12px 16px; border-radius: 2px; display: flex; flex-direction: column; gap: 4px; }
  .eyebrow { font: 600 10px var(--mono, monospace); color: var(--teal, #2b7169); letter-spacing: 0.1em; }
  .reservation-badge strong { font: 600 14px var(--mono, monospace); color: var(--teal-deep, #173f3e); }
  .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--line, #d7d5ca); padding-bottom: 8px; }
  .tab-btn { border: 0; background: transparent; color: var(--muted, #687270); font: 600 12px var(--sans, sans-serif); padding: 8px 12px; border-radius: 2px; cursor: pointer; transition: all 0.15s; }
  .tab-btn.active { background: var(--teal-deep, #173f3e); color: #ffffff; }
  .instruction-box { background: #ffffff; border: 1px solid var(--line, #d7d5ca); padding: 16px; border-radius: 2px; display: flex; flex-direction: column; gap: 12px; }
  .instruction-box p { margin: 0; font-size: 13px; color: var(--ink, #1f2827); font-family: var(--sans, sans-serif); }
  .dns-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 10px; margin-top: 4px; }
  .dns-cell { background: #faf8f1; border: 1px solid var(--line, #d7d5ca); padding: 10px 12px; border-radius: 2px; display: flex; flex-direction: column; gap: 6px; }
  .dns-cell.full-width { grid-column: 1 / -1; }
  .cell-label { font: 600 10px var(--mono, monospace); color: var(--muted, #687270); }
  .dns-cell code { font: 600 12px var(--mono, monospace); color: var(--teal-deep, #173f3e); word-break: break-all; }
  .code-preview { position: relative; background: #faf8f1; border: 1px solid var(--line, #d7d5ca); border-radius: 2px; }
  .code-preview pre { margin: 0; padding: 14px; font: 12px var(--mono, monospace); color: var(--ink, #1f2827); overflow-x: auto; max-height: 220px; }
  .preview-actions { padding: 8px 12px; border-top: 1px solid var(--line, #d7d5ca); display: flex; justify-content: flex-end; background: #ffffff; }
  .success-view { text-align: center; align-items: center; padding: 20px 0; display: flex; flex-direction: column; gap: 12px; }
  .success-circle { width: 48px; height: 48px; border-radius: 50%; background: var(--teal, #2b7169); color: #ffffff; display: grid; place-items: center; font-size: 22px; font-weight: bold; }
  .success-view h3 { margin: 0; font: 400 24px var(--serif, serif); }
  .success-view p { color: var(--muted, #687270); font-size: 13px; margin: 0; }
  .action-footer { display: flex; justify-content: flex-end; gap: 10px; width: 100%; }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; font-size: 12px; font-weight: 600; cursor: pointer; border-radius: 2px; border: 1px solid transparent; font-family: var(--sans, sans-serif); }
  .btn.primary { background: var(--teal, #2b7169); color: #ffffff; }
  .btn.primary:hover { background: var(--teal-deep, #173f3e); }
  .btn.danger { background: var(--coral, #ba5e47); color: #ffffff; }
  .btn.danger:hover { background: #963d28; }
  .btn.ghost { background: transparent; color: var(--muted, #687270); border-color: var(--line, #d7d5ca); }
  .btn.ghost:hover { background: #e6e3d9; color: var(--ink, #1f2827); }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
</style>
