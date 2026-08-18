<script lang="ts">
  import { portal, activeSessions } from '$lib/stores/portal';
  import { toasts } from '$lib/stores/toasts';
  import { api } from '$lib/api';
  import Spinner from '$lib/components/ui/Spinner.svelte';

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

<div class="sessions-view">
  <section class="panel">
    <div class="panel-head">
      <div>
        <span class="eyebrow">DEVICES & ACCESS</span>
        <h2>Where you're signed in</h2>
      </div>
      <button
        type="button"
        class="button danger-outline"
        disabled={!canRevokeOthers}
        onclick={handleRevokeOthers}
      >
        {#if revokingOthers}
          <Spinner size={12} color="var(--coral)" /> Signing out others…
        {:else}
          Sign out others
        {/if}
      </button>
    </div>
    <p class="panel-copy">
      Review active management sessions and legacy clients signed into this account. Revoking a session immediately deletes its authentication tokens.
    </p>

    <div class="table">
      {#if $activeSessions.length === 0}
        <div class="empty-row">No active sessions found.</div>
      {:else}
        {#each $activeSessions as session (session.id)}
          <div class="table-row">
            <div class="device-icon">
              {session.kind === 'management' ? '⌂' : '◌'}
            </div>
            <div class="session-meta">
              <div class="session-title">
                <strong>{session.label}</strong>
                {#if session.current}
                  <span class="current-badge">CURRENT</span>
                {/if}
              </div>
              <small>
                <span class="kind-tag">{session.kind}</span> · Last seen {session.lastSeen}
              </small>
            </div>

            <div class="session-action">
              {#if session.current}
                <span class="this-device">(This device)</span>
              {:else}
                <button
                  type="button"
                  class="row-action"
                  disabled={revokingId === session.id}
                  onclick={() => handleRevokeSession(session.id, session.label)}
                  aria-label={`Revoke session ${session.label}`}
                >
                  {#if revokingId === session.id}
                    <Spinner size={12} color="var(--coral)" />
                  {:else}
                    Revoke
                  {/if}
                </button>
              {/if}
            </div>
          </div>
        {/each}
      {/if}
    </div>

    <div class="capability-note">
      <span>✦</span>
      <div>
        <strong>Session Isolation</strong>
        <small>Revoking a session invalidates its refresh token and disconnects open WebSocket subscriptions immediately.</small>
      </div>
    </div>
  </section>
</div>

<style>
  .sessions-view {
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

  .table {
    margin-top: 25px;
    border-top: 1px solid var(--line);
  }

  .table-row {
    display: flex;
    align-items: center;
    gap: 14px;
    min-height: 74px;
    border-bottom: 1px solid var(--line);
  }

  .device-icon {
    width: 37px;
    height: 37px;
    background: #e6e3d9;
    display: grid;
    place-items: center;
    color: var(--teal);
    font-size: 20px;
    border-radius: 2px;
    flex-shrink: 0;
  }

  .session-meta {
    min-width: 0;
    flex-grow: 1;
  }

  .session-title {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .session-title strong {
    font-size: 13px;
    color: var(--ink);
  }

  .current-badge {
    border-radius: 20px;
    padding: 2px 7px;
    font: 10px var(--mono);
    color: var(--teal);
    background: #dceee1;
  }

  .session-meta small {
    color: var(--muted);
    display: block;
    font: 10px var(--mono);
    margin-top: 4px;
  }

  .kind-tag {
    text-transform: capitalize;
  }

  .session-action {
    margin-left: auto;
    flex-shrink: 0;
  }

  .this-device {
    color: var(--muted);
    font: 11px var(--mono);
  }

  .row-action {
    border: 0;
    background: none;
    color: var(--coral);
    font: 11px var(--mono);
    cursor: pointer;
    padding: 6px 10px;
    border-radius: 2px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .row-action:hover:not(:disabled) {
    background: #faeae6;
  }

  .row-action:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .empty-row {
    color: var(--muted);
    font-size: 13px;
    padding: 24px 0;
  }

  .button {
    border: 1px solid transparent;
    padding: 9px 14px;
    font-size: 12px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    text-decoration: none;
    cursor: pointer;
    border-radius: 2px;
    transition: opacity 0.15s ease;
  }

  .button:hover:not(:disabled) {
    opacity: 0.9;
  }

  .button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .button.danger-outline {
    border-color: #d9b8ad;
    background: transparent;
    color: var(--coral);
  }

  .button.danger-outline:hover:not(:disabled) {
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
</style>
