<script lang="ts">
  import { portal, activeSessions } from '$lib/stores/portal';
  import { toasts } from '$lib/stores/toasts';
  import { api } from '$lib/api';

  let revokingId = $state<string | null>(null);
  let revokingOthers = $state(false);

  const canRevokeOthers = $derived(
    $activeSessions.filter((s) => !s.current).length > 0 && !revokingOthers
  );

  async function handleRevokeSession(sessionId: string, sessionLabel: string) {
    revokingId = sessionId;
    try {
      await api.revokeSession(sessionId);
      toasts.success(`Session "${sessionLabel}" revoked.`);
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
    } catch (err: any) {
      toasts.error(err.message || 'Failed to revoke session.');
    } finally {
      revokingId = null;
    }
  }

  async function handleRevokeOthers() {
    if (!canRevokeOthers) return;
    revokingOthers = true;
    try {
      await api.revokeOtherSessions();
      toasts.success('All other sessions were signed out.');
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
    } catch (err: any) {
      toasts.error(err.message || 'Failed to sign out other sessions.');
    } finally {
      revokingOthers = false;
    }
  }
</script>

<div class="flex flex-col gap-6">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body gap-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <span class="text-xs font-semibold uppercase tracking-wider text-base-content/60">Devices & Access</span>
          <h2 class="card-title text-lg">Active sessions</h2>
        </div>
        <button
          type="button"
          class="btn btn-outline btn-error btn-sm"
          disabled={!canRevokeOthers}
          onclick={handleRevokeOthers}
        >
          {#if revokingOthers}
            <span class="loading loading-spinner loading-xs" aria-hidden="true"></span>
            Signing out others…
          {:else}
            Sign out others
          {/if}
        </button>
      </div>

      <p class="text-sm text-base-content/70">
        Active management sessions and clients signed into this account. Revoking a session deletes its authentication tokens immediately.
      </p>

      <div class="overflow-x-auto">
        {#if $activeSessions.length === 0}
          <div class="py-8 text-center text-sm text-base-content/60">No active sessions found.</div>
        {:else}
          <table class="table table-sm">
            <thead>
              <tr>
                <th>Client</th>
                <th>Kind</th>
                <th>Last seen</th>
                <th class="text-end">Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each $activeSessions as session (session.id)}
                <tr>
                  <td>
                    <div class="flex items-center gap-2">
                      <span class="font-medium text-base-content">{session.label}</span>
                      {#if session.current}
                        <span class="badge badge-neutral badge-sm">Current</span>
                      {/if}
                    </div>
                  </td>
                  <td>
                    <span class="capitalize text-base-content/70">{session.kind}</span>
                  </td>
                  <td>
                    <span class="text-xs text-base-content/70">{session.lastSeen}</span>
                  </td>
                  <td class="text-end">
                    {#if session.current}
                      <span class="text-xs text-base-content/60">(This device)</span>
                    {:else}
                      <button
                        type="button"
                        class="btn btn-error btn-xs"
                        disabled={revokingId === session.id}
                        onclick={() => handleRevokeSession(session.id, session.label)}
                        aria-label={`Revoke session ${session.label}`}
                      >
                        {#if revokingId === session.id}
                          <span class="loading loading-spinner loading-xs" aria-hidden="true"></span>
                        {:else}
                          Revoke
                        {/if}
                      </button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>

      <div class="alert alert-warning/10 text-xs text-base-content/80 mt-2">
        <span>Revoking a session invalidates its refresh token and disconnects open subscriptions immediately.</span>
      </div>
    </div>
  </section>
</div>
