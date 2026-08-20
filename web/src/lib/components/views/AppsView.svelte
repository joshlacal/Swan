<script lang="ts">
  import { portal, activeApps } from '$lib/stores/portal';
  import { toasts } from '$lib/stores/toasts';
  import { api } from '$lib/api';

  let revokingId = $state<string | null>(null);

  async function handleRevokeApp(appId: string, appName: string) {
    revokingId = appId;
    try {
      await api.revokeConnectedApp(appId);
      toasts.success(`OAuth access for "${appName}" revoked.`);
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
    } catch (err: any) {
      toasts.error(err.message || 'Failed to revoke connected app.');
    } finally {
      revokingId = null;
    }
  }
</script>

<div class="flex flex-col gap-6">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body gap-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <span class="text-xs font-semibold uppercase tracking-wider text-base-content/60">OAuth Grants</span>
          <h2 class="card-title text-lg">Connected apps</h2>
        </div>
        <span class="badge badge-neutral badge-sm">
          {$activeApps.length} {$activeApps.length === 1 ? 'grant' : 'grants'}
        </span>
      </div>

      <p class="text-sm text-base-content/70">
        Third-party applications authorized to act on your behalf. Revocation takes effect immediately.
      </p>

      {#if $activeApps.length === 0}
        <div class="py-8 text-center text-sm text-base-content/60">No connected apps found.</div>
      {:else}
        <div class="flex flex-col gap-3">
          {#each $activeApps as app (app.id)}
            <div class="card card-border bg-base-200/60 p-4">
              <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div class="flex flex-col gap-2 min-w-0">
                  <div class="flex items-baseline gap-2 flex-wrap">
                    {#if app.name}
                      <span class="font-medium text-base-content text-sm">{app.name}</span>
                    {/if}
                    <span class="font-mono break-all text-sm text-base-content/70">{app.id}</span>
                  </div>

                  {#if app.scopes && app.scopes.length > 0}
                    <div class="flex flex-wrap gap-1.5">
                      {#each app.scopes as scope}
                        <span class="badge badge-neutral badge-sm">{scope}</span>
                      {/each}
                    </div>
                  {/if}

                  <span class="text-xs text-base-content/60">
                    Granted on {app.createdAt || 'recently'}
                  </span>
                </div>

                <div class="shrink-0">
                  <button
                    type="button"
                    class="btn btn-error btn-sm"
                    disabled={revokingId === app.id}
                    onclick={() => handleRevokeApp(app.id, app.name)}
                    aria-label={`Revoke access for ${app.name}`}
                  >
                    {#if revokingId === app.id}
                      <span class="loading loading-spinner loading-xs" aria-hidden="true"></span>
                    {:else}
                      Revoke
                    {/if}
                  </button>
                </div>
              </div>
            </div>
          {/each}
        </div>
      {/if}

      <div class="alert alert-warning/10 text-xs text-base-content/80 mt-2">
        <span>Revoking an app invalidates its DPoP-bound tokens and rejects further requests immediately.</span>
      </div>
    </div>
  </section>
</div>
