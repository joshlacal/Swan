<script lang="ts">
  import { portal, activeApps } from '$lib/stores/portal';
  import { toasts } from '$lib/stores/toasts';
  import { api } from '$lib/api';
  import Spinner from '$lib/components/ui/Spinner.svelte';

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

<div class="apps-view">
  <section class="panel">
    <div class="panel-head">
      <div>
        <span class="eyebrow">OAUTH GRANTS</span>
        <h2>Connected apps</h2>
      </div>
      <span class="pill" class:success={$activeApps.length > 0}>
        {$activeApps.length} grant{$activeApps.length === 1 ? '' : 's'}
      </span>
    </div>
    <p class="panel-copy">
      These third-party applications can act on your behalf through narrowly scoped, DPoP-bound OAuth grants. Revocation takes effect immediately.
    </p>

    <div class="table">
      {#if $activeApps.length === 0}
        <div class="empty-row">No connected apps. Your account is quiet.</div>
      {:else}
        {#each $activeApps as app (app.id)}
          <div class="table-row">
            <div class="app-badge">
              {app.name ? app.name.slice(0, 1).toUpperCase() : 'A'}
            </div>
            <div class="app-meta">
              <strong>{app.name}</strong>
              <div class="scope-tags">
                {#each app.scopes as scope}
                  <span class="scope-pill">{scope}</span>
                {/each}
              </div>
              <small>Granted on {app.createdAt || 'recent'}</small>
            </div>

            <div class="app-action">
              <button
                type="button"
                class="row-action"
                disabled={revokingId === app.id}
                onclick={() => handleRevokeApp(app.id, app.name)}
                aria-label={`Revoke access for ${app.name}`}
              >
                {#if revokingId === app.id}
                  <Spinner size={12} color="var(--coral)" />
                {:else}
                  Revoke
                {/if}
              </button>
            </div>
          </div>
        {/each}
      {/if}
    </div>

    <div class="capability-note">
      <span>✦</span>
      <div>
        <strong>Cryptographic DPoP Binding</strong>
        <small>Connected OAuth apps use Demonstrating Proof-of-Possession (DPoP) tokens. Revoking a client immediately rejects further API requests.</small>
      </div>
    </div>
  </section>
</div>

<style>
  .apps-view {
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

  .pill {
    border-radius: 20px;
    padding: 4px 8px;
    font: 10px var(--mono);
    background: #e6e3d9;
    color: var(--muted);
  }

  .pill.success {
    color: #39755b;
    background: #dceee1;
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

  .app-badge {
    width: 37px;
    height: 37px;
    display: grid;
    place-items: center;
    color: white;
    background: var(--ochre);
    font: 700 17px var(--serif);
    border-radius: 2px;
    flex-shrink: 0;
  }

  .app-meta {
    min-width: 0;
    flex-grow: 1;
  }

  .app-meta strong {
    font-size: 13px;
    display: block;
    color: var(--ink);
  }

  .scope-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 4px;
  }

  .scope-pill {
    background: #e6e3d9;
    color: var(--muted);
    font: 9px var(--mono);
    padding: 2px 6px;
    border-radius: 2px;
  }

  .app-meta small {
    color: var(--muted);
    display: block;
    font: 10px var(--mono);
    margin-top: 4px;
  }

  .app-action {
    margin-left: auto;
    flex-shrink: 0;
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
