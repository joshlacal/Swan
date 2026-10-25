<script lang="ts">
  import { modals } from '#lib/stores/modals.ts';
  import { currentAccount } from '#lib/stores/portal.ts';

  const isActive = $derived($currentAccount?.lifecycle === 'active');
  const lifecycleStatus = $derived($currentAccount?.lifecycle?.toUpperCase() || 'ACTIVE');
</script>

<div class="flex flex-col gap-6">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body gap-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 class="card-title text-lg">Account lifecycle</h2>
          <p class="text-sm text-base-content/70">
            Manage account status, deactivation, and permanent deletion.
          </p>
        </div>
        <span class="badge {isActive ? 'badge-success' : 'badge-neutral'} badge-sm self-start sm:self-auto">
          {lifecycleStatus}
        </span>
      </div>

      <div class="flex flex-col gap-4">
        <!-- Deactivate Card -->
        <div class="card card-border bg-base-200/40 p-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div class="space-y-1">
              <div class="flex items-center gap-2">
                <span class="badge badge-sm badge-neutral">Temporary</span>
                <h3 class="font-medium text-sm">Deactivate account</h3>
              </div>
              <p class="text-xs text-base-content/70">
                Hide your profile, posts, and repository records. You can reactivate by signing in again.
              </p>
            </div>
            <button
              type="button"
              class="btn btn-outline btn-sm self-start sm:self-auto"
              onclick={() => modals.open('lifecycle-deactivate', { mode: 'deactivate' })}
            >
              Deactivate account
            </button>
          </div>
        </div>

        <!-- Delete Card -->
        <div class="card card-border border-error/40 bg-error/5 p-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div class="space-y-1">
              <div class="flex items-center gap-2">
                <span class="badge badge-sm badge-error">Irreversible</span>
                <h3 class="font-medium text-sm text-error">Delete account</h3>
              </div>
              <p class="text-xs text-base-content/70">
                Deleting this account is permanent. Its repository, blobs and handle are released and cannot be restored.
              </p>
            </div>
            <button
              type="button"
              class="btn btn-error btn-sm self-start sm:self-auto"
              onclick={() => modals.open('lifecycle-delete', { mode: 'delete' })}
            >
              Delete account
            </button>
          </div>
        </div>
      </div>

      <div class="alert alert-info bg-info/10 text-info-content text-xs border border-info/20">
        <span>Account deactivation and deletion require re-authentication and explicit confirmation.</span>
      </div>
    </div>
  </section>
</div>
