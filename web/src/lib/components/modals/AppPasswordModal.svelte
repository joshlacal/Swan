<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { api } from '$lib/api';
  import { toasts } from '$lib/stores/toasts';
  import { portal } from '$lib/stores/portal';
  import { APP_PASSWORD_SCOPES, type AppPasswordScope } from '$lib/types';

  interface Props {
    isOpen?: boolean;
    onClose?: () => void;
  }

  let { isOpen = true, onClose }: Props = $props();

  let name = $state('');
  let selectedScopes = $state<Set<string>>(new Set(['atproto']));
  let submitting = $state(false);
  let error = $state<string | null>(null);
  let createdPassword = $state<string | null>(null);

  const scopeLabels: Record<AppPasswordScope, { label: string; desc: string }> = {
    'atproto': {
      label: 'Base AT Protocol access',
      desc: 'Allows reading and creating repository records (required).'
    },
    'transition:chat.bsky': {
      label: 'Direct Messages (chat.bsky)',
      desc: 'Allows accessing Bluesky direct messages.'
    },
    'transition:email': {
      label: 'Email Notifications',
      desc: 'Allows managing email communication preferences.'
    },
    'transition:generic': {
      label: 'Generic Account Transition',
      desc: 'Allows general transition operations across services.'
    }
  };

  function toggleScope(scope: string) {
    if (scope === 'atproto') return; // Base scope is required
    const next = new Set(selectedScopes);
    if (next.has(scope)) {
      next.delete(scope);
    } else {
      next.add(scope);
    }
    selectedScopes = next;
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (!name.trim()) {
      error = 'Please enter a name for this app password.';
      return;
    }

    submitting = true;
    error = null;

    try {
      const result = await api.createAppPassword({
        name: name.trim(),
        scopes: Array.from(selectedScopes)
      });

      if (result.password) {
        createdPassword = result.password;
        toasts.success('App password created successfully');
        try {
          const snapshot = await api.fetchSnapshot();
          portal.setSnapshot(snapshot);
        } catch {
          // Non-blocking snapshot refresh
        }
      } else {
        error = 'Server did not return a generated password.';
      }
    } catch (err: any) {
      error = err.message || 'Failed to create app password.';
    } finally {
      submitting = false;
    }
  }

  function handleFinish() {
    name = '';
    selectedScopes = new Set(['atproto']);
    createdPassword = null;
    error = null;
    if (onClose) onClose();
  }
</script>

<Modal
  {isOpen}
  title={createdPassword ? 'App Password Created' : 'Create App Password'}
  description={createdPassword ? undefined : 'Generate a scoped password for legacy clients that do not support OAuth.'}
  size="md"
  preventClose={submitting}
  onClose={handleFinish}
>
  {#if createdPassword}
    <div class="created-state">
      <div class="success-banner">
        <span class="banner-icon">✓</span>
        <div>
          <strong>Generated for {name}</strong>
          <p>Scopes: {Array.from(selectedScopes).join(' · ')}</p>
        </div>
      </div>

      <div class="password-box">
        <span class="eyebrow">YOUR ONE-TIME PASSWORD</span>
        <div class="password-row">
          <code class="password-code">{createdPassword}</code>
          <CopyButton text={createdPassword} variant="primary" label="Copy Password" copiedLabel="Copied!" />
        </div>
      </div>

      <div class="warning-box" role="alert">
        <span class="warning-icon">⚠️</span>
        <p>
          <strong>Save this password now.</strong> For security, Swan will never display this secret again. Anyone with this password can act on your behalf with the selected scopes.
        </p>
      </div>

      <div class="action-footer">
        <button type="button" class="btn primary" onclick={handleFinish}>
          Done
        </button>
      </div>
    </div>
  {:else}
    <form class="create-form" onsubmit={handleSubmit}>
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="form-field">
        <label for="app-name">App Name or Device</label>
        <input
          id="app-name"
          type="text"
          bind:value={name}
          placeholder="e.g. Grayscale iOS, Feed Bot"
          maxlength="255"
          required
          disabled={submitting}
        />
      </div>

      <div class="scopes-field">
        <span class="field-label">Access Permissions</span>
        <div class="scopes-list">
          {#each APP_PASSWORD_SCOPES as scope}
            <label class="scope-item" class:disabled={scope === 'atproto'}>
              <input
                type="checkbox"
                checked={selectedScopes.has(scope)}
                disabled={scope === 'atproto' || submitting}
                onchange={() => toggleScope(scope)}
              />
              <div class="scope-text">
                <span class="scope-name">{scopeLabels[scope]?.label ?? scope}</span>
                <span class="scope-desc">{scopeLabels[scope]?.desc ?? ''}</span>
              </div>
            </label>
          {/each}
        </div>
      </div>

      <div class="form-actions">
        <button type="button" class="btn ghost" onclick={handleFinish} disabled={submitting}>
          Cancel
        </button>
        <button type="submit" class="btn primary" disabled={submitting || !name.trim()}>
          {#if submitting}
            <Spinner size={14} color="#ffffff" /> Creating…
          {:else}
            Create Password <span>＋</span>
          {/if}
        </button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  .create-form { display: flex; flex-direction: column; gap: 20px; }
  .form-field { display: flex; flex-direction: column; gap: 6px; }
  .form-field label, .field-label { font: 600 11px var(--mono, monospace); color: var(--muted, #687270); letter-spacing: 0.08em; text-transform: uppercase; }
  .form-field input[type="text"] { padding: 10px 12px; font: 13px var(--sans, sans-serif); border: 1px solid var(--line, #d7d5ca); background: #ffffff; color: var(--ink, #1f2827); border-radius: 2px; }
  .form-field input:focus { outline: 2px solid var(--teal, #2b7169); border-color: var(--teal, #2b7169); }
  .scopes-field { display: flex; flex-direction: column; gap: 6px; }
  .scopes-list { display: flex; flex-direction: column; gap: 8px; margin-top: 4px; }
  .scope-item { display: flex; align-items: flex-start; gap: 10px; padding: 10px 12px; background: #ffffff; border: 1px solid var(--line, #d7d5ca); border-radius: 2px; cursor: pointer; }
  .scope-item.disabled { background: #faf8f1; cursor: default; }
  .scope-item input[type="checkbox"] { margin-top: 3px; accent-color: var(--teal, #2b7169); }
  .scope-text { display: flex; flex-direction: column; gap: 2px; }
  .scope-name { font-weight: 600; font-size: 13px; color: var(--ink, #1f2827); }
  .scope-desc { font-size: 11px; color: var(--muted, #687270); }
  .error-banner { background: #fbebe8; color: var(--coral, #ba5e47); border-left: 3px solid var(--coral, #ba5e47); padding: 10px 14px; font-size: 12px; border-radius: 2px; }
  .form-actions, .action-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px; }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; font-size: 12px; font-weight: 600; cursor: pointer; border-radius: 2px; border: 1px solid transparent; font-family: var(--sans, sans-serif); }
  .btn.primary { background: var(--teal, #2b7169); color: #ffffff; }
  .btn.primary:hover { background: var(--teal-deep, #173f3e); }
  .btn.ghost { background: transparent; color: var(--muted, #687270); border-color: var(--line, #d7d5ca); }
  .btn.ghost:hover { background: #e6e3d9; color: var(--ink, #1f2827); }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
  .created-state { display: flex; flex-direction: column; gap: 18px; }
  .success-banner { display: flex; align-items: center; gap: 12px; background: #dceee1; padding: 12px 16px; border-radius: 2px; color: var(--teal-deep, #173f3e); font-size: 13px; }
  .success-banner strong { display: block; }
  .success-banner p { margin: 2px 0 0; font-size: 11px; opacity: 0.85; }
  .banner-icon { width: 24px; height: 24px; border-radius: 50%; background: var(--teal, #2b7169); color: #ffffff; display: grid; place-items: center; font-weight: bold; flex-shrink: 0; }
  .password-box { background: #ffffff; border: 1px solid var(--line, #d7d5ca); padding: 16px; border-radius: 2px; display: flex; flex-direction: column; gap: 8px; }
  .eyebrow { font: 600 10px var(--mono, monospace); color: var(--muted, #687270); letter-spacing: 0.1em; }
  .password-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .password-code { font: 600 16px var(--mono, monospace); color: var(--teal-deep, #173f3e); background: #faf8f1; padding: 6px 10px; border-radius: 2px; word-break: break-all; }
  .warning-box { display: flex; gap: 10px; background: #faf4e6; border: 1px solid #f1dfb8; padding: 12px 14px; border-radius: 2px; color: #5c4714; font-size: 12px; line-height: 1.5; }
  .warning-icon { font-size: 16px; flex-shrink: 0; }
  .warning-box p { margin: 0; }
</style>
