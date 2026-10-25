<script lang="ts">
  import { modals } from '#lib/stores/modals.ts';
  import { currentAccount } from '#lib/stores/portal.ts';
</script>

<div class="flex flex-col gap-6">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body gap-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 class="card-title text-lg">Export & migrate</h2>
          <p class="text-sm text-base-content/70">
            Download a portable copy of your account data, repository records, and identity proofs.
          </p>
        </div>
        <button
          type="button"
          class="btn btn-primary self-start sm:self-auto"
          onclick={() => modals.open('export')}
        >
          Request data export
        </button>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div class="card card-border bg-base-200/30 p-4">
          <span class="badge badge-sm badge-neutral">CAR v2</span>
          <h3 class="font-medium text-sm mt-2">Repository archive</h3>
          <p class="text-xs text-base-content/70 mt-1">
            Complete Merkle Search Tree (MST) history with all commits, posts, records, and blob references.
          </p>
        </div>

        <div class="card card-border bg-base-200/30 p-4">
          <span class="badge badge-sm badge-neutral">JSON-LD</span>
          <h3 class="font-medium text-sm mt-2">Identity manifest</h3>
          <p class="text-xs text-base-content/70 mt-1">
            Cryptographic DID proofs, public signing keys, and did:web / PLC verification history.
          </p>
        </div>

        <div class="card card-border bg-base-200/30 p-4">
          <span class="badge badge-sm badge-neutral">Envelope</span>
          <h3 class="font-medium text-sm mt-2">Factor envelopes</h3>
          <p class="text-xs text-base-content/70 mt-1">
            Public factor registrations, WebAuthn credential IDs, and session metadata. No private keys.
          </p>
        </div>
      </div>

      <div class="card card-border bg-base-200/50 p-4">
        <h3 class="font-medium text-sm mb-2">Export package contents</h3>
        <ul class="list-disc list-inside space-y-1 text-xs text-base-content/80">
          <li>Full AT Protocol repository checkout (<span class="font-mono">com.atproto.repo.getRepo</span>)</li>
          <li>Account profile metadata for <span class="font-mono">@{$currentAccount?.handle || 'swan-user'}</span></li>
          <li>Signing key metadata and DID document representation</li>
          <li>Active factor public configurations (passkeys, TOTP registrations)</li>
          <li>Portable to any standard AT Protocol Personal Data Server (PDS)</li>
        </ul>
      </div>

      <div class="alert alert-info bg-info/10 text-info-content text-xs border border-info/20">
        <span>Export generation runs asynchronously. When processing completes, a direct download link is provided.</span>
      </div>
    </div>
  </section>
</div>
