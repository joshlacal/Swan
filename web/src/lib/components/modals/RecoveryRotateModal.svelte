<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
  import { api } from '$lib/api';
  import { toasts } from '$lib/stores/toasts';
  import { portal, currentAccount } from '$lib/stores/portal';

  interface Props {
    isOpen?: boolean;
    onClose?: () => void;
  }

  let { isOpen = true, onClose }: Props = $props();

  let stage = $state<'confirm' | 'rotating' | 'displayed'>('confirm');
  let codes = $state<string[]>([]);
  let acknowledged = $state(false);
  let error = $state<string | null>(null);

  async function handleRotate() {
    stage = 'rotating';
    error = null;

    try {
      const response = await api.rotateRecoveryCodes();
      if (response.recoveryCodes && response.recoveryCodes.length > 0) {
        codes = response.recoveryCodes;
        stage = 'displayed';
        toasts.success('Recovery codes rotated successfully');

        try {
          const snapshot = await api.fetchSnapshot();
          portal.setSnapshot(snapshot);
        } catch {
          // Non-blocking snapshot refresh
        }
      } else {
        error = 'No recovery codes returned.';
        stage = 'confirm';
      }
    } catch (err: any) {
      stage = 'confirm';
      error = err.message || 'Failed to rotate recovery codes.';
    }
  }

  function getFormattedCodes(): string {
    const handle = $currentAccount?.handle || 'swan-user';
    const date = new Date().toISOString();
    return (
      `SWAN ACCOUNT RECOVERY CODES\n` +
      `============================\n` +
      `Account: @${handle}\n` +
      `Generated: ${date}\n\n` +
      `Each code can only be used once for emergency account access.\n` +
      `Store these codes in a secure, offline location.\n\n` +
      codes.map((c, i) => `${String(i + 1).padStart(2, '0')}. ${c}`).join('\n') +
      `\n`
    );
  }

  function handleDownload() {
    const content = getFormattedCodes();
    const handle = $currentAccount?.handle || 'account';
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `swan-recovery-codes-${handle}-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toasts.info('Recovery codes downloaded');
  }

  function handleFinish() {
    stage = 'confirm';
    codes = [];
    acknowledged = false;
    error = null;
    if (onClose) onClose();
  }
</script>

<Modal
  {isOpen}
  title={stage === 'displayed' ? 'New recovery codes' : 'Rotate recovery codes'}
  description={stage === 'displayed' ? 'Save these single-use codes offline.' : 'Generate a new set of emergency recovery codes.'}
  size={stage === 'displayed' ? 'lg' : 'md'}
  preventClose={stage === 'rotating'}
  onClose={handleFinish}
>
  {#if stage === 'displayed'}
    <div class="flex flex-col gap-4">
      <div class="alert alert-warning text-sm" role="alert">
        <span>Previous recovery codes are invalidated. Each code below can be used once for emergency access.</span>
      </div>

      <div class="grid grid-cols-2 gap-2 font-mono text-sm p-3 bg-base-200/50 border border-base-300 rounded" role="region" aria-label="Recovery codes list">
        {#each codes as code, i}
          <div class="flex items-center gap-2 p-1.5 bg-base-100 rounded">
            <span class="text-xs text-base-content/50">{String(i + 1).padStart(2, '0')}.</span>
            <code class="font-semibold">{code}</code>
          </div>
        {/each}
      </div>

      <div class="flex gap-2 flex-wrap">
        <CopyButton
          text={getFormattedCodes()}
          variant="ghost"
          size="sm"
          class="btn btn-outline btn-sm"
          label="Copy all codes"
          copiedLabel="Copied"
        />
        <button type="button" class="btn btn-outline btn-sm" onclick={handleDownload}>
          Download .txt file
        </button>
      </div>

      <div class="card card-border bg-base-200/40 p-3">
        <label class="flex items-center gap-3 cursor-pointer text-sm">
          <input type="checkbox" class="checkbox checkbox-primary checkbox-sm" bind:checked={acknowledged} />
          <span>I have saved these recovery codes in a safe place.</span>
        </label>
      </div>

      <div class="modal-action">
        <button
          type="button"
          class="btn btn-primary"
          disabled={!acknowledged}
          onclick={handleFinish}
        >
          Done
        </button>
      </div>
    </div>
  {:else}
    <div class="flex flex-col gap-4">
      {#if error}
        <div class="alert alert-error text-sm" role="alert">{error}</div>
      {/if}

      <div class="alert alert-warning text-sm">
        <span>Rotating recovery codes generates 10 new emergency codes and invalidates any existing codes.</span>
      </div>

      <div class="modal-action">
        <button type="button" class="btn btn-ghost" onclick={handleFinish} disabled={stage === 'rotating'}>
          Cancel
        </button>
        <button type="button" class="btn btn-error" onclick={handleRotate} disabled={stage === 'rotating'}>
          {#if stage === 'rotating'}
            <span class="loading loading-spinner loading-xs"></span> Rotating…
          {:else}
            Rotate recovery codes
          {/if}
        </button>
      </div>
    </div>
  {/if}
</Modal>
