<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import { accountFetch, api } from '$lib/api';
  import { toasts } from '$lib/stores/toasts';

  interface Props {
    isOpen?: boolean;
    onClose?: () => void;
  }

  interface ExportStatusData {
    id?: string;
    status?: 'none' | 'pending' | 'ready' | 'completed' | 'failed' | string;
    requestedAt?: string;
    downloadUrl?: string;
  }

  let { isOpen = true, onClose }: Props = $props();

  let stage = $state<'idle' | 'requesting' | 'polling' | 'ready' | 'error'>('idle');
  let exportData = $state<ExportStatusData | null>(null);
  let errorMessage = $state('');
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  async function checkInitialStatus() {
    try {
      const res = await accountFetch<{ export: ExportStatusData }>('export');
      if (res && res.export && res.export.status && res.export.status !== 'none') {
        exportData = res.export;
        if (res.export.status === 'ready' || res.export.status === 'completed') {
          stage = 'ready';
          stopPolling();
        } else if (res.export.status === 'pending') {
          stage = 'polling';
          startPolling();
        }
      }
    } catch {
      // Non-blocking initial check
    }
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(async () => {
      try {
        const res = await accountFetch<{ export: ExportStatusData }>('export');
        if (res && res.export) {
          exportData = res.export;
          if (res.export.status === 'ready' || res.export.status === 'completed') {
            stage = 'ready';
            stopPolling();
            toasts.success('Account data export archive is ready for download.');
          } else if (res.export.status === 'failed') {
            stage = 'error';
            errorMessage = 'Data export generation failed. Please try again.';
            stopPolling();
          }
        }
      } catch (err: any) {
        stage = 'error';
        errorMessage = err.message || 'Failed to check export status.';
        stopPolling();
      }
    }, 2500);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  async function handleRequestExport() {
    stage = 'requesting';
    errorMessage = '';

    try {
      const res = await api.requestExport();
      toasts.info('Data export requested. Generating portable archive…');
      if (res && res.exportID) {
        exportData = { id: res.exportID, status: 'pending', requestedAt: new Date().toISOString() };
      }
      stage = 'polling';
      startPolling();
    } catch (err: any) {
      stage = 'error';
      errorMessage = err.message || 'Failed to request account data export.';
    }
  }

  $effect(() => {
    if (isOpen) {
      checkInitialStatus();
    } else {
      stopPolling();
    }
  });

  onDestroy(() => {
    stopPolling();
  });

  function handleClose() {
    stopPolling();
    if (onClose) onClose();
  }
</script>

<Modal
  {isOpen}
  title="Account data export"
  description="Generate a portable archive containing your AT Protocol repository, commit records, and identity proofs."
  size="md"
  preventClose={stage === 'requesting'}
  onClose={handleClose}
>
  {#if stage === 'ready' && exportData}
    <div class="flex flex-col gap-4">
      <div class="alert alert-success text-sm">
        <svg class="h-5 w-5 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
        <div>
          <div class="font-semibold">Export archive ready</div>
          <div class="text-xs opacity-80">Format: swan-account-export-v2 (CAR + identity manifest)</div>
        </div>
      </div>

      <div class="card card-border bg-base-100 p-4 flex flex-col gap-2.5">
        <div class="flex justify-between items-center text-sm">
          <span class="text-xs font-mono font-semibold uppercase text-base-content/60">Export ID</span>
          <code class="font-mono text-xs bg-base-200 px-2 py-0.5 rounded border border-base-300">{exportData.id || 'exp_current'}</code>
        </div>
        {#if exportData.requestedAt}
          <div class="flex justify-between items-center text-sm">
            <span class="text-xs font-mono font-semibold uppercase text-base-content/60">Generated at</span>
            <span class="text-xs text-base-content/80">{new Date(exportData.requestedAt).toLocaleString()}</span>
          </div>
        {/if}
        <div class="flex justify-between items-center text-sm">
          <span class="text-xs font-mono font-semibold uppercase text-base-content/60">Format</span>
          <span class="text-xs text-base-content/80">Content Addressable Archive (.car)</span>
        </div>
      </div>

      <div class="alert alert-warning text-sm" role="alert">
        <svg class="h-5 w-5 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <span>Store this archive in a secure location. It contains your complete repository records and credentials.</span>
      </div>

      <div class="modal-action mt-2 flex justify-between items-center gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleRequestExport}>
          Request fresh export
        </button>
        <a
          class="btn btn-primary"
          href={exportData.downloadUrl || '/account/api/export/download'}
          download={`swan-export-${exportData.id || 'account'}.car`}
        >
          Download archive
        </a>
      </div>
    </div>
  {:else if stage === 'polling' || stage === 'requesting'}
    <div class="flex flex-col items-center text-center gap-4 py-6">
      <span class="loading loading-spinner loading-lg text-primary"></span>
      <div>
        <h3 class="text-lg font-semibold text-base-content">Packaging repository…</h3>
        <p class="text-sm text-base-content/70 mt-1 max-w-sm">Compiling your data tree, cryptographic signing keys, and identity bindings. This usually takes 5 to 30 seconds.</p>
      </div>

      <div class="badge badge-neutral gap-2 py-3 px-4 text-xs font-mono">
        <span class="inline-block w-2 h-2 rounded-full bg-primary animate-pulse"></span>
        Polling status every 2.5s
      </div>

      <div class="modal-action mt-2 w-full flex justify-end">
        <button type="button" class="btn btn-ghost" onclick={handleClose}>
          Close
        </button>
      </div>
    </div>
  {:else}
    <div class="flex flex-col gap-5">
      {#if stage === 'error'}
        <div class="alert alert-error text-sm" role="alert">
          <span>{errorMessage}</span>
        </div>
      {/if}

      <div class="card card-border bg-base-200/50 p-4">
        <div class="text-sm font-semibold text-base-content">Portable account archive</div>
        <p class="text-xs text-base-content/70 mt-1">
          Your export includes all AT Protocol repository commits, signed blocks, account metadata, and factor records. It can be inspected or imported into any compatible PDS.
        </p>
      </div>

      <div class="card card-border bg-base-100 p-4 flex flex-col gap-2">
        <div class="flex items-center gap-2 text-sm text-base-content">
          <span class="text-success font-bold">✓</span>
          <span>Complete CAR repository history</span>
        </div>
        <div class="flex items-center gap-2 text-sm text-base-content">
          <span class="text-success font-bold">✓</span>
          <span>Decentralized identity claims and keys</span>
        </div>
        <div class="flex items-center gap-2 text-sm text-base-content">
          <span class="text-success font-bold">✓</span>
          <span>Account configuration and factor records</span>
        </div>
      </div>

      <div class="modal-action mt-2 flex justify-end gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleClose}>
          Cancel
        </button>
        <button type="button" class="btn btn-primary" onclick={handleRequestExport}>
          Generate data export
        </button>
      </div>
    </div>
  {/if}
</Modal>
