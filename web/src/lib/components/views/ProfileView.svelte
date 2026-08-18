<script lang="ts">
  import { portal, currentAccount, currentIdentity } from '$lib/stores/portal';
  import { modals } from '$lib/stores/modals';
  import { toasts } from '$lib/stores/toasts';
  import { api } from '$lib/api';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let reverifying = $state(false);

  const isDidWeb = $derived($currentIdentity?.method === 'didWeb');
  const handle = $derived($currentAccount?.handle || '');
  const did = $derived($currentAccount?.did || '');
  const email = $derived($currentAccount?.email || null);
  const lifecycle = $derived($currentAccount?.lifecycle || 'active');

  async function reverifyDomain() {
    reverifying = true;
    try {
      await api.reverifyDidWeb();
      toasts.success('Domain verification claim validated successfully.');
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
    } catch (err: any) {
      toasts.error(err.message || 'Domain reverification check failed.');
    } finally {
      reverifying = false;
    }
  }
</script>

<div class="profile-view">
  <section class="panel">
    <div class="panel-head">
      <div>
        <span class="eyebrow">IDENTITY & CONTACT</span>
        <h2>Account details</h2>
      </div>
      <span class="status-badge" class:active={lifecycle === 'active'}>
        {lifecycle.toUpperCase()}
      </span>
    </div>
    <p class="panel-copy">
      Your public decentralized identity and contact credentials stored on the Swan ledger.
    </p>

    <div class="details-list">
      <div class="detail-row">
        <div class="detail-meta">
          <span class="detail-label">HANDLE</span>
          <span class="detail-value mono">@{handle || '—'}</span>
        </div>
        {#if handle}
          <div class="detail-action">
            <CopyButton text={handle} label="Copy handle" />
          </div>
        {/if}
      </div>

      <div class="detail-row">
        <div class="detail-meta">
          <span class="detail-label">DECENTRALIZED IDENTIFIER (DID)</span>
          <span class="detail-value mono truncate">{did || '—'}</span>
        </div>
        {#if did}
          <div class="detail-action">
            <CopyButton text={did} label="Copy DID" />
          </div>
        {/if}
      </div>

      <div class="detail-row">
        <div class="detail-meta">
          <span class="detail-label">REGISTERED EMAIL</span>
          <span class="detail-value">{email || 'No email registered'}</span>
        </div>
      </div>

      <div class="detail-row">
        <div class="detail-meta">
          <span class="detail-label">IDENTITY METHOD</span>
          <span class="detail-value">{isDidWeb ? 'Custom Domain (did:web)' : 'PLC Directory (did:plc)'}</span>
        </div>
        <span class="pill success">
          {$currentIdentity?.state === 'active' ? 'Active' : ($currentIdentity?.state ?? 'Verified')}
        </span>
      </div>
    </div>
  </section>

  <!-- did:web Custom Domain Management Panel -->
  <section class="panel warm">
    <div class="panel-head">
      <div>
        <span class="eyebrow">CUSTOM DOMAIN IDENTIFIER</span>
        <h2>did:web Management</h2>
      </div>
    </div>

    {#if isDidWeb}
      <p class="panel-copy">
        Your account is bound to custom domain <strong>{handle}</strong> via <code>did:web</code>. DNS records and HTTPS documents are periodically reverified.
      </p>

      <div class="domain-card">
        <div class="domain-status">
          <span class="status-dot"></span>
          <div>
            <strong>did:web:{handle}</strong>
            <small>Method: did:web · State: {$currentIdentity?.state || 'Active'}</small>
          </div>
        </div>
      </div>

      <div class="action-stack">
        <button
          type="button"
          class="button primary"
          onclick={reverifyDomain}
          disabled={reverifying}
        >
          {#if reverifying}
            <Spinner size={14} color="#ffffff" /> Reverifying…
          {:else}
            Reverify Domain ↻
          {/if}
        </button>

        <button
          type="button"
          class="button dark"
          onclick={() => modals.open('did-web', { initialMode: 'rotate', mode: 'rotate' })}
        >
          Rotate Signing Key ↗
        </button>

        <button
          type="button"
          class="button danger-outline"
          onclick={() => modals.open('did-web', { initialMode: 'remove', mode: 'remove' })}
        >
          Remove did:web (Revert to PLC)
        </button>
      </div>
    {:else}
      <p class="panel-copy">
        Bring your own domain and establish self-sovereign control over your DID document using the W3C <code>did:web</code> method.
      </p>

      <div class="benefits-grid">
        <div class="benefit-item">
          <strong>Direct Resolution</strong>
          <small>Resolves via standard HTTPS .well-known/did.json or DNS TXT records.</small>
        </div>
        <div class="benefit-item">
          <strong>Key Rotation</strong>
          <small>Generate and rotate separate account signing keys on your own domain.</small>
        </div>
      </div>

      <button
        type="button"
        class="button primary"
        onclick={() => modals.open('did-web', { initialMode: 'new', mode: 'new' })}
      >
        Bring Your Own Domain (did:web) ↗
      </button>
    {/if}

    <div class="capability-note">
      <span>✦</span>
      <div>
        <strong>Cryptographic Verification</strong>
        <small>Decentralized identity claims are cryptographically signed and independently verifiable across the network.</small>
      </div>
    </div>
  </section>
</div>

<style>
  .profile-view {
    display: flex;
    flex-direction: column;
    gap: 28px;
  }

  .eyebrow {
    display: block;
    font: 600 10px/1.3 var(--mono);
    color: var(--muted);
    letter-spacing: 0.14em;
  }

  .panel {
    background: #faf8f1;
    border: 1px solid var(--line);
    padding: 28px;
    border-radius: 2px;
  }

  .panel.warm {
    background: #e6ded0;
    border-color: #e6ded0;
  }

  .panel-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
  }

  .panel h2 {
    font: 400 26px/1.05 var(--serif);
    margin: 9px 0 0;
    letter-spacing: -0.02em;
    color: var(--ink);
  }

  .panel-copy {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.6;
    max-width: 650px;
    margin: 14px 0 0;
  }

  .status-badge {
    border-radius: 20px;
    padding: 5px 10px;
    font: 10px var(--mono);
    background: #e6e3d9;
    color: var(--muted);
  }

  .status-badge.active {
    background: #dceee1;
    color: #39755b;
  }

  .details-list {
    margin-top: 24px;
    border-top: 1px solid var(--line);
  }

  .detail-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 0;
    border-bottom: 1px solid var(--line);
    gap: 16px;
  }

  .detail-meta {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .detail-label {
    font: 10px var(--mono);
    color: var(--muted);
    letter-spacing: 0.1em;
  }

  .detail-value {
    font-size: 14px;
    color: var(--ink);
  }

  .detail-value.mono {
    font-family: var(--mono);
    font-size: 13px;
  }

  .detail-value.truncate {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 460px;
  }

  .detail-action {
    flex-shrink: 0;
  }

  .pill {
    border-radius: 20px;
    padding: 4px 8px;
    font: 10px var(--mono);
  }

  .pill.success {
    color: #39755b;
    background: #dceee1;
  }

  .domain-card {
    background: #faf8f1;
    border: 1px solid var(--line);
    padding: 16px;
    margin: 18px 0;
    border-radius: 2px;
  }

  .domain-status {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .domain-status strong {
    display: block;
    font-size: 14px;
    color: var(--ink);
  }

  .domain-status small {
    display: block;
    color: var(--muted);
    font: 11px var(--mono);
    margin-top: 2px;
  }

  .status-dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    background: #4a9b78;
    border-radius: 50%;
    box-shadow: 0 0 0 4px rgba(74, 155, 120, 0.14);
    flex-shrink: 0;
  }

  .benefits-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin: 20px 0;
  }

  .benefit-item {
    background: #faf8f1;
    padding: 14px;
    border: 1px solid var(--line);
    border-radius: 2px;
  }

  .benefit-item strong {
    display: block;
    font-size: 13px;
    color: var(--ink);
    margin-bottom: 4px;
  }

  .benefit-item small {
    display: block;
    color: var(--muted);
    font-size: 11px;
    line-height: 1.4;
  }

  .action-stack {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 20px;
  }

  .button {
    border: 1px solid transparent;
    padding: 11px 15px;
    font-size: 12px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 10px;
    text-decoration: none;
    cursor: pointer;
    border-radius: 2px;
    transition: opacity 0.15s ease;
  }

  .button:hover {
    opacity: 0.9;
  }

  .button.primary {
    background: var(--teal);
    color: white;
  }

  .button.dark {
    background: var(--ink);
    color: #f7f2e7;
  }

  .button.danger-outline {
    border-color: #d9b8ad;
    background: transparent;
    color: var(--coral);
  }

  .button.danger-outline:hover {
    background: #faeae6;
  }

  .capability-note {
    display: flex;
    gap: 12px;
    margin-top: 28px;
    padding: 15px;
    background: #eee9dc;
    border-radius: 2px;
  }

  .capability-note > span {
    color: var(--ochre);
    font-size: 22px;
    line-height: 1;
  }

  .capability-note strong {
    display: block;
    font-size: 12px;
    color: var(--ink);
  }

  .capability-note small {
    display: block;
    color: var(--muted);
    font-size: 11px;
    margin-top: 4px;
    line-height: 1.4;
  }

  @media (max-width: 640px) {
    .detail-value.truncate {
      max-width: 200px;
    }
    .benefits-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
