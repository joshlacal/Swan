<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
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
    mode === 'delete' ? 'Delete account permanently' : 'Deactivate account'
  );

  const modalDesc = $derived(
    mode === 'delete'
      ? 'Permanent action: all repository commits, signing keys, and factor envelopes will be deleted.'
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
    <form class="flex flex-col gap-5" onsubmit={handleDelete}>
      {#if error}
        <div class="alert alert-error text-sm" role="alert">
          <span>{error}</span>
        </div>
      {/if}

      <div class="alert alert-error text-sm" role="alert">
        <svg class="h-5 w-5 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <div class="font-semibold uppercase tracking-wider text-xs">Irreversible action</div>
          <p class="mt-0.5 text-xs">
            Deleting your account writes a permanent tombstone to the PLC directory. Your handle, repository records, and cryptographic credentials cannot be recovered.
          </p>
        </div>
      </div>

      <fieldset class="fieldset gap-1.5">
        <legend class="fieldset-legend text-xs">
          To confirm, type <strong class="font-mono text-error font-bold">DELETE</strong> or <strong class="font-mono text-error font-bold">@{accountHandle}</strong>:
        </legend>
        <input
          id="delete-confirm-input"
          type="text"
          class="input w-full font-mono"
          bind:value={confirmInput}
          placeholder="DELETE"
          disabled={submitting}
          required
        />
      </fieldset>

      <div class="modal-action mt-2 flex justify-end gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleClose} disabled={submitting}>
          Cancel
        </button>
        <button type="submit" class="btn btn-error" disabled={!isConfirmed || submitting}>
          {#if submitting}
            <span class="loading loading-spinner loading-xs"></span>
            <span>Deleting account…</span>
          {:else}
            Permanently delete account
          {/if}
        </button>
      </div>
    </form>
  {:else}
    <form class="flex flex-col gap-5" onsubmit={handleDeactivate}>
      {#if error}
        <div class="alert alert-error text-sm" role="alert">
          <span>{error}</span>
        </div>
      {/if}

      <div class="alert alert-warning text-sm" role="alert">
        <svg class="h-5 w-5 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <div class="font-semibold">Account deactivation</div>
          <p class="mt-0.5 text-xs">
            Your profile and public repositories will be hidden from view. Your sessions will be signed out. You can reactivate your account at any time by signing in again.
          </p>
        </div>
      </div>

      <fieldset class="fieldset gap-1.5">
        <legend class="fieldset-legend text-xs">
          To confirm deactivation, type your handle <strong class="font-mono font-bold text-warning-content">@{accountHandle}</strong>:
        </legend>
        <input
          id="deactivate-confirm-input"
          type="text"
          class="input w-full font-mono"
          bind:value={confirmInput}
          placeholder={accountHandle}
          disabled={submitting}
          required
        />
      </fieldset>

      <div class="modal-action mt-2 flex justify-end gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleClose} disabled={submitting}>
          Cancel
        </button>
        <button type="submit" class="btn btn-warning" disabled={!isConfirmed || submitting}>
          {#if submitting}
            <span class="loading loading-spinner loading-xs"></span>
            <span>Deactivating…</span>
          {:else}
            Deactivate account
          {/if}
        </button>
      </div>
    </form>
  {/if}
</Modal>
