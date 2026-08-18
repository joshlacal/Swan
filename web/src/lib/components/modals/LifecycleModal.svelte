<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { api } from '$lib/api';
  import { toasts } from '$lib/stores/toasts';
  import { portal, currentAccount } from '$lib/stores/portal';

  interface Props {
    isOpen?: boolean;
    mode?: 'deactivate' | 'delete';
    onClose?: () => void;
  }

  let { isOpen = true, mode = 'deactivate', onClose }: Props = $props();

  let confirmInput = $state('');
  let submitting = $state(false);
  let error = $state<string | null>(null);

  const accountHandle = $derived($currentAccount?.handle || 'alice.swan.place');

  const expectedPhrase = $derived.by(() => {
    if (mode === 'delete') {
      return 'DELETE';
    }
    return accountHandle;
  });

  const isConfirmed = $derived.by(() => {
    const input = confirmInput.trim();
    if (mode === 'delete') {
      return input === 'DELETE' || input === accountHandle || input === `@${accountHandle}`;
    }
    return input === accountHandle || input === `@${accountHandle}`;
  });

  $effect(() => {
    if (isOpen) {
      confirmInput = '';
      submitting = false;
      error = null;
    }
  });

  async function handleDeactivate(e: SubmitEvent) {
    e.preventDefault();
    if (!isConfirmed || submitting) return;

    submitting = true;
    error = null;

    try {
      await api.deactivateAccount();
      toasts.warning('Account deactivated. Sign in anytime to reactivate.');
      try {
        await api.logout();
      } catch {
        // Non-blocking logout
      }
      portal.reset();
      if (typeof window !== 'undefined') {
        window.location.href = '/account';
      }
    } catch (err: any) {
      error = err.message || 'Failed to deactivate account.';
      submitting = false;
    }
  }

  async function handleDelete(e: SubmitEvent) {
    e.preventDefault();
    if (!isConfirmed || submitting) return;

    submitting = true;
    error = null;

    try {
      // api.deleteAccount triggers Step-Up Interceptor if elevation needed
      await api.deleteAccount();
      toasts.error('Account permanently deleted.');
      portal.reset();
      if (typeof window !== 'undefined') {
        window.location.href = '/account';
      }
    } catch (err: any) {
      error = err.message || 'Failed to delete account.';
      submitting = false;
    }
  }

  function handleClose() {
    confirmInput = '';
    error = null;
    if (onClose) onClose();
  }

  const modalTitle = $derived(
    mode === 'delete' ? 'Delete Account Permanently' : 'Deactivate Account'
  );

  const modalDesc = $derived(
    mode === 'delete'
      ? 'Permanent, irreversible action: all repository commits, signing keys, and factor envelopes will be destroyed.'
      : 'Temporary deactivation: your profile will be hidden and write operations suspended until your next login.'
  );
</script>

<Modal
  {isOpen}
  title={modalTitle}
  description={modalDesc}
  size="md"
  preventClose={submitting}
  onClose={handleClose}
>
  {#if mode === 'delete'}
    <form class="lifecycle-form" onsubmit={handleDelete}>
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="danger-box">
        <span class="danger-glyph">⚠️</span>
        <div>
          <strong>IRREVERSIBLE ACCOUNT DESTRUCTION</strong>
          <p>
            Deleting your account writes a permanent tombstone to the PLC directory. Your handle, repository records, and cryptographic credentials cannot be recovered by anyone.
          </p>
        </div>
      </div>

      <div class="form-field">
        <label for="delete-confirm-input">
          To confirm deletion, type <strong class="confirm-target">DELETE</strong> or <strong class="confirm-target">@{accountHandle}</strong>:
        </label>
        <input
          id="delete-confirm-input"
          type="text"
          bind:value={confirmInput}
          placeholder="DELETE"
          disabled={submitting}
          required
        />
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleClose} disabled={submitting}>
          Cancel
        </button>
        <button type="submit" class="btn danger" disabled={!isConfirmed || submitting}>
          {#if submitting}
            <Spinner size={14} color="#ffffff" /> Deleting Account…
          {:else}
            Permanently Delete Account <span>✕</span>
          {/if}
        </button>
      </div>
    </form>
  {:else}
    <form class="lifecycle-form" onsubmit={handleDeactivate}>
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="warning-box">
        <span class="warning-glyph">✦</span>
        <div>
          <strong>Account Deactivation</strong>
          <p>
            Your profile and public repositories will be hidden from view. Your sessions will be signed out. You can reactivate your account at any time simply by signing in again.
          </p>
        </div>
      </div>

      <div class="form-field">
        <label for="deactivate-confirm-input">
          To confirm deactivation, type your handle <strong class="confirm-target">@{accountHandle}</strong>:
        </label>
        <input
          id="deactivate-confirm-input"
          type="text"
          bind:value={confirmInput}
          placeholder={accountHandle}
          disabled={submitting}
          required
        />
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleClose} disabled={submitting}>
          Cancel
        </button>
        <button type="submit" class="btn warning-btn" disabled={!isConfirmed || submitting}>
          {#if submitting}
            <Spinner size={14} color="#ffffff" /> Deactivating…
          {:else}
            Deactivate Account <span>↗</span>
          {/if}
        </button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  .lifecycle-form { display: flex; flex-direction: column; gap: 20px; }
  .danger-box { display: flex; gap: 12px; background: #fbebe8; border: 1px solid #f3cdc6; padding: 16px; border-radius: 2px; color: #662214; }
  .danger-glyph { font-size: 22px; flex-shrink: 0; }
  .danger-box strong { display: block; font-size: 13px; font-family: var(--mono, monospace); letter-spacing: 0.05em; }
  .danger-box p { margin: 6px 0 0; font-size: 12px; line-height: 1.5; color: #7a2d1d; }
  .warning-box { display: flex; gap: 12px; background: #faf4e6; border: 1px solid #f1dfb8; padding: 16px; border-radius: 2px; color: #5c4714; }
  .warning-glyph { font-size: 22px; flex-shrink: 0; color: var(--ochre, #d1a85b); }
  .warning-box strong { display: block; font-size: 13px; font-family: var(--sans, sans-serif); }
  .warning-box p { margin: 6px 0 0; font-size: 12px; line-height: 1.5; }
  .form-field { display: flex; flex-direction: column; gap: 8px; }
  .form-field label { font-size: 13px; color: var(--ink, #1f2827); font-family: var(--sans, sans-serif); }
  .confirm-target { font-family: var(--mono, monospace); color: var(--coral, #ba5e47); background: #faf8f1; padding: 2px 6px; border-radius: 2px; }
  .form-field input[type="text"] { padding: 10px 12px; font: 14px var(--mono, monospace); border: 1px solid var(--line, #d7d5ca); background: #ffffff; color: var(--ink, #1f2827); border-radius: 2px; }
  .form-field input:focus { outline: 2px solid var(--coral, #ba5e47); border-color: var(--coral, #ba5e47); }
  .error-banner { background: #fbebe8; color: var(--coral, #ba5e47); border-left: 3px solid var(--coral, #ba5e47); padding: 10px 14px; font-size: 12px; border-radius: 2px; }
  .action-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 4px; }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; font-size: 12px; font-weight: 600; cursor: pointer; border-radius: 2px; border: 1px solid transparent; font-family: var(--sans, sans-serif); }
  .btn.danger { background: var(--coral, #ba5e47); color: #ffffff; }
  .btn.danger:hover { background: #963d28; }
  .btn.warning-btn { background: var(--ochre, #d1a85b); color: #1f2827; }
  .btn.warning-btn:hover { background: #b89146; }
  .btn.ghost { background: transparent; color: var(--muted, #687270); border-color: var(--line, #d7d5ca); }
  .btn.ghost:hover { background: #e6e3d9; color: var(--ink, #1f2827); }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
