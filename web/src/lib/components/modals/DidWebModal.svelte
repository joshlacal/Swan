<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
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
      toasts.success(`Custom domain @${reservation.handle || domain} bound successfully.`);

      try {
        const snapshot = await api.fetchSnapshot();
        portal.setSnapshot(snapshot);
      } catch {
        // Non-blocking snapshot refresh
      }
    } catch (err: any) {
      error = err.message || 'Verification failed. Ensure DNS TXT or did.json is reachable.';
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
    if (stage === 'success') return 'Custom domain updated';
    if (mode === 'remove') return 'Remove did:web domain';
    if (mode === 'rotate') return 'Rotate did:web identity';
    if (stage === 'verify') return 'Verify domain ownership';
    return 'Custom domain (did:web)';
  });

  const modalDesc = $derived.by(() => {
    if (stage === 'success') return 'Your custom domain identity configuration is complete.';
    if (mode === 'remove') return 'Revert your account identity back to standard did:plc.';
    if (mode === 'rotate') return 'Update your custom domain decentralized identity binding.';
    if (stage === 'verify') return 'Publish a DNS TXT record or HTTPS did.json file to prove domain control.';
    return 'Bind your own domain name (e.g. alice.example.com) to your account using did:web.';
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
    <div class="flex flex-col items-center text-center gap-4 py-4">
      <div class="w-12 h-12 rounded-full bg-success text-success-content flex items-center justify-center text-xl font-bold">
        ✓
      </div>
      <div>
        <h3 class="text-lg font-semibold text-base-content">Domain configured</h3>
        <p class="text-sm text-base-content/70 mt-1">Your account identity settings have been updated.</p>
      </div>
      <div class="modal-action mt-2 w-full flex justify-end">
        <button type="button" class="btn btn-primary" onclick={handleFinish}>Done</button>
      </div>
    </div>
  {:else if mode === 'remove'}
    <div class="flex flex-col gap-5">
      {#if error}
        <div class="alert alert-error text-sm" role="alert">
          <span>{error}</span>
        </div>
      {/if}

      <div class="alert alert-warning text-sm" role="alert">
        <svg class="h-5 w-5 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <div class="font-semibold">Revert to PLC identifier</div>
          <p class="mt-0.5 text-xs">
            Removing your custom domain reverts your account to its original <code class="font-mono">did:plc:...</code> identifier. Existing references to your did:web identifier may break.
          </p>
        </div>
      </div>

      <div class="modal-action mt-2 flex justify-end gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleFinish} disabled={busy}>
          Cancel
        </button>
        <button type="button" class="btn btn-error" onclick={handleRemove} disabled={busy}>
          {#if busy}
            <span class="loading loading-spinner loading-xs"></span>
            <span>Removing domain…</span>
          {:else}
            Remove did:web identity
          {/if}
        </button>
      </div>
    </div>
  {:else if mode === 'rotate'}
    <form class="flex flex-col gap-5" onsubmit={handleRotate}>
      {#if error}
        <div class="alert alert-error text-sm" role="alert">
          <span>{error}</span>
        </div>
      {/if}

      <fieldset class="fieldset gap-1">
        <legend class="fieldset-legend text-xs font-semibold uppercase tracking-wider text-base-content/70">New domain name</legend>
        <input
          id="did-rotate-domain"
          type="text"
          class="input w-full font-mono"
          bind:value={domain}
          placeholder="new-domain.example.com"
          required
          disabled={busy}
        />
        <p class="fieldset-label text-xs text-base-content/60">Rotation requires authorization with your account credentials.</p>
      </fieldset>

      <div class="modal-action mt-2 flex justify-end gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleFinish} disabled={busy}>
          Cancel
        </button>
        <button type="submit" class="btn btn-primary" disabled={busy || !domain.trim()}>
          {#if busy}
            <span class="loading loading-spinner loading-xs"></span>
            <span>Rotating…</span>
          {:else}
            Rotate domain
          {/if}
        </button>
      </div>
    </form>
  {:else if stage === 'verify'}
    <div class="flex flex-col gap-5">
      {#if error}
        <div class="alert alert-error text-sm" role="alert">
          <span>{error}</span>
        </div>
      {/if}

      <div class="card card-border bg-base-200/60 p-3.5 flex flex-col gap-1">
        <span class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Reserved target DID</span>
        <strong class="font-mono text-sm break-all text-base-content">{reservation?.targetDID || `did:web:${cleanDomain(domain)}`}</strong>
      </div>

      <div class="tabs tabs-box" role="tablist">
        <button
          type="button"
          role="tab"
          class="tab {verificationTab === 'dns' ? 'tab-active' : ''}"
          aria-selected={verificationTab === 'dns'}
          onclick={() => (verificationTab = 'dns')}
        >
          Option 1: DNS TXT record (Recommended)
        </button>
        <button
          type="button"
          role="tab"
          class="tab {verificationTab === 'https' ? 'tab-active' : ''}"
          aria-selected={verificationTab === 'https'}
          onclick={() => (verificationTab = 'https')}
        >
          Option 2: HTTPS did.json
        </button>
      </div>

      {#if verificationTab === 'dns'}
        <div class="card card-border bg-base-100 p-4 flex flex-col gap-3">
          <p class="text-sm text-base-content">Add the following DNS <strong class="font-semibold">TXT</strong> record to your domain:</p>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            <div class="sm:col-span-2 bg-base-200/80 rounded-box p-3 flex flex-col gap-2 border border-base-300">
              <span class="text-xs font-mono font-semibold uppercase text-base-content/60">Host / Name</span>
              <div class="flex items-center justify-between gap-2">
                <code class="font-mono text-sm break-all">{getDnsTxtHost()}</code>
                <CopyButton text={getDnsTxtHost()} size="sm" label="Copy" />
              </div>
            </div>
            <div class="bg-base-200/80 rounded-box p-3 flex flex-col gap-2 border border-base-300">
              <span class="text-xs font-mono font-semibold uppercase text-base-content/60">Type</span>
              <code class="font-mono text-sm font-semibold">TXT</code>
            </div>
            <div class="sm:col-span-3 bg-base-200/80 rounded-box p-3 flex flex-col gap-2 border border-base-300">
              <span class="text-xs font-mono font-semibold uppercase text-base-content/60">Value / Content</span>
              <div class="flex items-center justify-between gap-2">
                <code class="font-mono text-sm break-all">{getDnsTxtValue()}</code>
                <CopyButton text={getDnsTxtValue()} size="sm" label="Copy" />
              </div>
            </div>
          </div>
        </div>
      {:else}
        <div class="card card-border bg-base-100 p-4 flex flex-col gap-3">
          <p class="text-sm text-base-content">Host this JSON document at <code class="font-mono text-xs bg-base-200 px-1.5 py-0.5 rounded border border-base-300">https://{cleanDomain(domain)}/.well-known/did.json</code>:</p>
          <div class="rounded-box border border-base-300 overflow-hidden bg-base-200">
            <pre class="p-3 text-xs font-mono overflow-x-auto max-h-56"><code>{getGeneratedDidJson()}</code></pre>
            <div class="p-2 border-t border-base-300 flex justify-end bg-base-100">
              <CopyButton text={getGeneratedDidJson()} variant="primary" size="sm" label="Copy did.json" />
            </div>
          </div>
        </div>
      {/if}

      <div class="modal-action mt-2 flex justify-end gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleFinish} disabled={busy}>
          Cancel
        </button>
        <button type="button" class="btn btn-primary" onclick={handleClaim} disabled={busy}>
          {#if busy}
            <span class="loading loading-spinner loading-xs"></span>
            <span>Verifying…</span>
          {:else}
            Verify and claim domain
          {/if}
        </button>
      </div>
    </div>
  {:else}
    <form class="flex flex-col gap-5" onsubmit={handleReserve}>
      {#if error}
        <div class="alert alert-error text-sm" role="alert">
          <span>{error}</span>
        </div>
      {/if}

      <fieldset class="fieldset gap-1">
        <legend class="fieldset-legend text-xs font-semibold uppercase tracking-wider text-base-content/70">Custom domain</legend>
        <input
          id="did-domain-input"
          type="text"
          class="input w-full font-mono"
          bind:value={domain}
          placeholder="e.g. alice.example.com"
          required
          disabled={busy}
        />
        <p class="fieldset-label text-xs text-base-content/60">Enter a domain or subdomain you control.</p>
      </fieldset>

      <div class="card card-border bg-base-200/50 p-4">
        <div class="text-sm font-semibold text-base-content">Domain identity</div>
        <p class="text-xs text-base-content/70 mt-1">
          With did:web, your domain hosts your public keys. Swan serves your repository data while you retain ownership of the domain.
        </p>
      </div>

      <div class="modal-action mt-2 flex justify-end gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleFinish} disabled={busy}>
          Cancel
        </button>
        <button type="submit" class="btn btn-primary" disabled={busy || !domain.trim()}>
          {#if busy}
            <span class="loading loading-spinner loading-xs"></span>
            <span>Reserving…</span>
          {:else}
            Reserve domain
          {/if}
        </button>
      </div>
    </form>
  {/if}
</Modal>
