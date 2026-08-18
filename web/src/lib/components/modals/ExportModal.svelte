<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
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
  title="Account Data Export"
  description="Generate a portable cryptographic archive containing your AT Protocol repository, commit records, and identity proofs."
  size="md"
  preventClose={stage === 'requesting'}
  onClose={handleClose}
>
  {#if stage === 'ready' && exportData}
    <div class="ready-view">
      <div class="success-banner">
        <span class="banner-icon">✓</span>
        <div>
          <strong>Export Archive Ready</strong>
          <p>Format: swan-account-export-v2 (CAR + identity manifest)</p>
        </div>
      </div>

      <div class="export-meta-card">
        <div class="meta-row">
          <span class="meta-label">EXPORT ID</span>
          <code>{exportData.id || 'exp_current'}</code>
        </div>
        {#if exportData.requestedAt}
          <div class="meta-row">
            <span class="meta-label">GENERATED AT</span>
            <span>{new Date(exportData.requestedAt).toLocaleString()}</span>
          </div>
        {/if}
        <div class="meta-row">
          <span class="meta-label">FORMAT</span>
          <span>Content Addressable Archive (.car)</span>
        </div>
      </div>

      <div class="security-box">
        <span class="sec-icon">🔒</span>
        <p>
          <strong>Security Notice:</strong> Store this archive in an encrypted, offline location. This file contains your complete public and private repository records.
        </p>
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleRequestExport}>
          Request Fresh Export ↺
        </button>
        <a
          class="btn primary"
          href={exportData.downloadUrl || '/account/api/export/download'}
          download={`swan-export-${exportData.id || 'account'}.car`}
        >
          Download Data Archive <span>↓</span>
        </a>
      </div>
    </div>
  {:else if stage === 'polling' || stage === 'requesting'}
    <div class="polling-view">
      <div class="spinner-box">
        <Spinner size={32} />
        <h3>Packaging Your Repository…</h3>
        <p>Compiling your data tree, cryptographic signing keys, and identity bindings. This usually takes 5 to 30 seconds.</p>
      </div>

      <div class="pulse-indicator">
        <span class="pulse-dot"></span>
        <span class="pulse-text">Polling status every 2.5s</span>
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleClose}>
          Close & Notify Me
        </button>
      </div>
    </div>
  {:else}
    <div class="intro-view">
      {#if stage === 'error'}
        <div class="error-banner" role="alert">{errorMessage}</div>
      {/if}

      <div class="info-card">
        <span class="card-glyph">📦</span>
        <div>
          <strong>Self-Contained Portable Archive</strong>
          <p>
            Your export includes all AT Protocol repository commits, signed blocks, account metadata, and factor envelopes. It can be inspected or imported into any compatible PDS.
          </p>
        </div>
      </div>

      <div class="checklist">
        <div class="check-item">
          <span class="check-glyph">✓</span>
          <span>Complete CAR repository history</span>
        </div>
        <div class="check-item">
          <span class="check-glyph">✓</span>
          <span>Decentralized identity claims & keys</span>
        </div>
        <div class="check-item">
          <span class="check-glyph">✓</span>
          <span>Account configuration and factor records</span>
        </div>
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleClose}>
          Cancel
        </button>
        <button type="button" class="btn primary" onclick={handleRequestExport}>
          Generate Data Export <span>↗</span>
        </button>
      </div>
    </div>
  {/if}
</Modal>

<style>
  .intro-view, .polling-view, .ready-view { display: flex; flex-direction: column; gap: 20px; }
  .info-card { display: flex; gap: 12px; background: #faf8f1; border: 1px solid var(--line, #d7d5ca); padding: 16px; border-radius: 2px; }
  .card-glyph { font-size: 24px; }
  .info-card strong { display: block; font-size: 13px; color: var(--ink, #1f2827); font-family: var(--sans, sans-serif); }
  .info-card p { margin: 6px 0 0; font-size: 12px; color: var(--muted, #687270); line-height: 1.5; }
  .checklist { display: flex; flex-direction: column; gap: 8px; background: #ffffff; border: 1px solid var(--line, #d7d5ca); padding: 14px 16px; border-radius: 2px; }
  .check-item { display: flex; align-items: center; gap: 10px; font-size: 13px; color: var(--ink, #1f2827); }
  .check-glyph { color: var(--teal, #2b7169); font-weight: bold; }
  .error-banner { background: #fbebe8; color: var(--coral, #ba5e47); border-left: 3px solid var(--coral, #ba5e47); padding: 10px 14px; font-size: 12px; border-radius: 2px; }
  .polling-view { text-align: center; align-items: center; padding: 20px 0; }
  .spinner-box { display: flex; flex-direction: column; align-items: center; gap: 12px; }
  .spinner-box h3 { margin: 0; font: 400 24px var(--serif, serif); }
  .spinner-box p { color: var(--muted, #687270); font-size: 13px; max-width: 380px; margin: 0; line-height: 1.5; }
  .pulse-indicator { display: flex; align-items: center; gap: 8px; font: 600 11px var(--mono, monospace); color: var(--teal, #2b7169); background: #faf8f1; padding: 6px 12px; border-radius: 12px; }
  .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--teal, #2b7169); animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
  .success-banner { display: flex; align-items: center; gap: 12px; background: #dceee1; padding: 14px 16px; border-radius: 2px; color: var(--teal-deep, #173f3e); font-size: 13px; }
  .banner-icon { width: 24px; height: 24px; border-radius: 50%; background: var(--teal, #2b7169); color: #ffffff; display: grid; place-items: center; font-weight: bold; flex-shrink: 0; }
  .export-meta-card { background: #ffffff; border: 1px solid var(--line, #d7d5ca); padding: 16px; border-radius: 2px; display: flex; flex-direction: column; gap: 10px; }
  .meta-row { display: flex; justify-content: space-between; align-items: center; font-size: 13px; }
  .meta-label { font: 600 10px var(--mono, monospace); color: var(--muted, #687270); letter-spacing: 0.08em; }
  .meta-row code { font: 600 12px var(--mono, monospace); color: var(--teal-deep, #173f3e); background: #faf8f1; padding: 2px 6px; border-radius: 2px; }
  .security-box { display: flex; gap: 10px; background: #faf4e6; border: 1px solid #f1dfb8; padding: 12px 14px; border-radius: 2px; color: #5c4714; font-size: 12px; line-height: 1.5; }
  .sec-icon { font-size: 16px; flex-shrink: 0; }
  .action-footer { display: flex; justify-content: flex-end; gap: 10px; width: 100%; }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; font-size: 12px; font-weight: 600; cursor: pointer; border-radius: 2px; border: 1px solid transparent; text-decoration: none; font-family: var(--sans, sans-serif); }
  .btn.primary { background: var(--teal, #2b7169); color: #ffffff; }
  .btn.primary:hover { background: var(--teal-deep, #173f3e); }
  .btn.ghost { background: transparent; color: var(--muted, #687270); border-color: var(--line, #d7d5ca); }
  .btn.ghost:hover { background: #e6e3d9; color: var(--ink, #1f2827); }
</style>
