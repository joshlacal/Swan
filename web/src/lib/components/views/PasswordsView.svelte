<script lang="ts">
  import { portal, activePasswords } from '$lib/stores/portal';
  import { modals } from '$lib/stores/modals';
  import { toasts } from '$lib/stores/toasts';
  import { api } from '$lib/api';
  import Spinner from '$lib/components/ui/Spinner.svelte';

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

<div class="passwords-view">
  <section class="panel">
    <div class="panel-head">
      <div>
        <span class="eyebrow">SCOPED LEGACY ACCESS</span>
        <h2>App passwords</h2>
      </div>
      <button
        type="button"
        class="button primary"
        onclick={() => modals.open('app-password')}
      >
        Create password <span>＋</span>
      </button>
    </div>
    <p class="panel-copy">
      Use these only for legacy clients and bots that cannot use OAuth. Each secret is shown once, never stored in plaintext by the browser, and can be scoped to minimal access.
    </p>

    <div class="table">
      {#if $activePasswords.length === 0}
        <div class="empty-row">No app passwords yet. That's a good default.</div>
      {:else}
        {#each $activePasswords as password (password.name)}
          <div class="table-row">
            <div class="device-icon">⌁</div>
            <div class="password-meta">
              <strong>{password.name}</strong>
              <div class="scope-tags">
                {#each password.scopes as scope}
                  <span class="scope-pill">{scope}</span>
                {/each}
              </div>
              <small>
                Created {password.createdAt || 'recently'}
                {#if password.lastUsedAt}
                  · Last used {password.lastUsedAt}
                {/if}
              </small>
            </div>

            <div class="password-action">
              <button
                type="button"
                class="row-action"
                disabled={revokingName === password.name}
                onclick={() => handleRevokePassword(password.name)}
                aria-label={`Revoke app password ${password.name}`}
              >
                {#if revokingName === password.name}
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
        <strong>Cryptographic Hashing</strong>
        <small>App passwords are salted and hashed using Argon2id. Once created, secrets cannot be recovered or displayed again.</small>
      </div>
    </div>
  </section>
</div>

<style>
  .passwords-view {
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

  .password-meta {
    min-width: 0;
    flex-grow: 1;
  }

  .password-meta strong {
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

  .password-meta small {
    color: var(--muted);
    display: block;
    font: 10px var(--mono);
    margin-top: 4px;
  }

  .password-action {
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

  .button {
    border: 1px solid transparent;
    padding: 10px 16px;
    font-size: 12px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    text-decoration: none;
    cursor: pointer;
    border-radius: 2px;
    transition: opacity 0.15s ease;
    flex-shrink: 0;
  }

  .button:hover {
    opacity: 0.9;
  }

  .button.primary {
    background: var(--teal);
    color: white;
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
