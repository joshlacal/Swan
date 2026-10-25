<script lang="ts">
  import { portal, currentAccount, currentIdentity } from '#lib/stores/portal.ts';
  import { modals } from '#lib/stores/modals.ts';
  import { toasts } from '#lib/stores/toasts.ts';
  import { api } from '#lib/api.ts';
  import CopyButton from '#lib/components/ui/CopyButton.svelte';

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

<div class="flex flex-col gap-6">
  <!-- Account details section -->
  <section class="card bg-base-100 shadow-sm border border-base-200">
    <div class="card-body gap-4">
      <div class="flex items-start justify-between gap-4">
        <div>
          <span class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Identity & contact</span>
          <h2 class="card-title text-lg mt-1">Account details</h2>
        </div>
        <span class="badge {lifecycle === 'active' ? 'badge-success' : lifecycle === 'pending' ? 'badge-warning' : 'badge-neutral'}">
          {lifecycle.toUpperCase()}
        </span>
      </div>
      <p class="text-sm text-base-content/70">
        Public identity and contact information for this account.
      </p>

      <div class="flex flex-col divide-y divide-base-200 border-t border-b border-base-200 mt-2">
        <div class="flex items-center justify-between py-3 gap-4">
          <div class="min-w-0">
            <div class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Handle</div>
            <div class="font-mono text-sm break-all mt-0.5">@{handle || '—'}</div>
          </div>
          {#if handle}
            <div class="shrink-0">
              <CopyButton text={handle} label="Copy handle" />
            </div>
          {/if}
        </div>

        <div class="flex items-center justify-between py-3 gap-4">
          <div class="min-w-0">
            <div class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Decentralized identifier (DID)</div>
            <div class="font-mono text-sm break-all mt-0.5">{did || '—'}</div>
          </div>
          {#if did}
            <div class="shrink-0">
              <CopyButton text={did} label="Copy DID" />
            </div>
          {/if}
        </div>

        <div class="flex items-center justify-between py-3 gap-4">
          <div class="min-w-0">
            <div class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Registered email</div>
            <div class="text-sm mt-0.5">{email || 'No email registered'}</div>
          </div>
        </div>

        <div class="flex items-center justify-between py-3 gap-4">
          <div class="min-w-0">
            <div class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Identity method</div>
            <div class="text-sm mt-0.5">{isDidWeb ? 'Custom domain (did:web)' : 'PLC directory (did:plc)'}</div>
          </div>
          <span class="badge badge-success shrink-0">
            {$currentIdentity?.state === 'active' ? 'Active' : ($currentIdentity?.state ?? 'Verified')}
          </span>
        </div>
      </div>
    </div>
  </section>

  <!-- did:web Custom Domain Management Panel -->
  <section class="card bg-base-100 shadow-sm border border-base-200">
    <div class="card-body gap-4">
      <div>
        <span class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Custom domain identifier</span>
        <h2 class="card-title text-lg mt-1">did:web management</h2>
      </div>

      {#if isDidWeb}
        <p class="text-sm text-base-content/70">
          Account bound to custom domain <strong class="text-base-content">{handle}</strong> via <code class="font-mono text-xs">did:web</code>.
        </p>

        <div class="card card-border bg-base-200/60 p-4 flex flex-col gap-1">
          <div class="font-mono font-semibold text-sm break-all">did:web:{handle}</div>
          <div class="text-xs text-base-content/60">Method: did:web · State: {$currentIdentity?.state || 'Active'}</div>
        </div>

        <div class="flex flex-wrap gap-3 pt-2">
          <button
            type="button"
            class="btn btn-primary btn-sm"
            onclick={reverifyDomain}
            disabled={reverifying}
          >
            {#if reverifying}
              <span class="loading loading-spinner loading-xs"></span> Reverifying…
            {:else}
              Reverify domain
            {/if}
          </button>

          <button
            type="button"
            class="btn btn-outline btn-sm"
            onclick={() => modals.open('did-web', { initialMode: 'rotate', mode: 'rotate' })}
          >
            Rotate signing key
          </button>

          <button
            type="button"
            class="btn btn-error btn-outline btn-sm"
            onclick={() => modals.open('did-web', { initialMode: 'remove', mode: 'remove' })}
          >
            Remove did:web (Revert to PLC)
          </button>
        </div>
      {:else}
        <p class="text-sm text-base-content/70">
          Bind a custom domain to this account using the W3C <code class="font-mono text-xs">did:web</code> method.
        </p>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div class="card card-border bg-base-200/60 p-3 flex flex-col gap-1">
            <div class="font-semibold text-sm">Direct resolution</div>
            <div class="text-xs text-base-content/60">Resolves via HTTPS .well-known/did.json or DNS TXT records.</div>
          </div>
          <div class="card card-border bg-base-200/60 p-3 flex flex-col gap-1">
            <div class="font-semibold text-sm">Key rotation</div>
            <div class="text-xs text-base-content/60">Manage separate signing keys directly on your domain.</div>
          </div>
        </div>

        <div class="pt-2">
          <button
            type="button"
            class="btn btn-primary btn-sm"
            onclick={() => modals.open('did-web', { initialMode: 'new', mode: 'new' })}
          >
            Configure custom domain (did:web)
          </button>
        </div>
      {/if}

      <div class="text-xs text-base-content/60 pt-2 border-t border-base-200">
        Identity claims are cryptographically signed and independently verifiable.
      </div>
    </div>
  </section>
</div>
