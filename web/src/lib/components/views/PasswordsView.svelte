<script lang="ts">
  import { portal, activePasswords } from '#lib/stores/portal.ts';
  import { modals } from '#lib/stores/modals.ts';
  import { toasts } from '#lib/stores/toasts.ts';
  import { api } from '#lib/api.ts';

  let revokingName = $state<string | null>(null);

  async function handleRevokePassword(name: string) {
    revokingName = name;
    try {
      await api.revokeAppPassword(name);
      toasts.success(`App password "${name}" revoked.`);
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
    } catch (err: any) {
      toasts.error(err.message || 'Failed to revoke app password.');
    } finally {
      revokingName = null;
    }
  }
</script>

<div class="flex flex-col gap-6">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body gap-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <span class="text-xs font-semibold uppercase tracking-wider text-base-content/60">Scoped Access</span>
          <h2 class="card-title text-lg">App passwords</h2>
        </div>
        <button
          type="button"
          class="btn btn-primary btn-sm"
          onclick={() => modals.open('app-password')}
        >
          Create password
        </button>
      </div>

      <p class="text-sm text-base-content/70">
        Passwords for clients and bots that do not support OAuth. Each password can be scoped and revoked independently.
      </p>

      <div class="overflow-x-auto">
        {#if $activePasswords.length === 0}
          <div class="py-8 text-center text-sm text-base-content/60">No app passwords configured.</div>
        {:else}
          <table class="table table-sm">
            <thead>
              <tr>
                <th>Name</th>
                <th>Scopes</th>
                <th>Created</th>
                <th>Last used</th>
                <th class="text-end">Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each $activePasswords as password (password.name)}
                <tr>
                  <td>
                    <span class="font-medium text-base-content">{password.name}</span>
                  </td>
                  <td>
                    {#if password.scopes && password.scopes.length > 0}
                      <div class="flex flex-wrap gap-1">
                        {#each password.scopes as scope}
                          <span class="badge badge-neutral badge-xs">{scope}</span>
                        {/each}
                      </div>
                    {:else}
                      <span class="text-xs text-base-content/50">—</span>
                    {/if}
                  </td>
                  <td>
                    <span class="text-xs text-base-content/70">{password.createdAt || 'recently'}</span>
                  </td>
                  <td>
                    <span class="text-xs text-base-content/70">{password.lastUsedAt || 'Never'}</span>
                  </td>
                  <td class="text-end">
                    <button
                      type="button"
                      class="btn btn-error btn-xs"
                      disabled={revokingName === password.name}
                      onclick={() => handleRevokePassword(password.name)}
                      aria-label={`Revoke app password ${password.name}`}
                    >
                      {#if revokingName === password.name}
                        <span class="loading loading-spinner loading-xs" aria-hidden="true"></span>
                      {:else}
                        Revoke
                      {/if}
                    </button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>

      <div class="alert alert-warning/10 text-xs text-base-content/80 mt-2">
        <span>App passwords are hashed with Argon2id and cannot be viewed again after creation.</span>
      </div>
    </div>
  </section>
</div>
