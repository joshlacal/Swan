<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
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
      // Calling api.rotateRecoveryCodes() triggers Step-Up Interceptor automatically if required
      const response = await api.rotateRecoveryCodes();
      if (response.recoveryCodes && response.recoveryCodes.length > 0) {
        codes = response.recoveryCodes;
        stage = 'displayed';
        toasts.success('Recovery codes rotated successfully');

        // Refresh snapshot
        try {
          const snapshot = await api.fetchSnapshot();
          portal.setSnapshot(snapshot);
        } catch {
          // Non-blocking snapshot refresh
        }
      } else {
        error = 'No recovery codes were returned by the server.';
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
  title={stage === 'displayed' ? 'New Recovery Codes' : 'Rotate Recovery Codes'}
  description={stage === 'displayed' ? 'Save these single-use codes offline in a safe location.' : 'Generate a fresh set of emergency recovery codes.'}
  size={stage === 'displayed' ? 'lg' : 'md'}
  preventClose={stage === 'rotating'}
  onClose={handleFinish}
>
  {#if stage === 'displayed'}
    <div class="codes-display">
      <div class="warning-banner" role="alert">
        <span class="warning-glyph">⚠️</span>
        <div>
          <strong>Previous recovery codes are now invalidated</strong>
          <p>Each code below can be used exactly once to log in if you lose access to your primary authentication factors.</p>
        </div>
      </div>

      <div class="codes-grid" role="region" aria-label="Recovery codes list">
        {#each codes as code, i}
          <div class="code-pill">
            <span class="code-idx">{String(i + 1).padStart(2, '0')}.</span>
            <code class="code-val">{code}</code>
          </div>
        {/each}
      </div>

      <div class="export-actions">
        <CopyButton
          text={getFormattedCodes()}
          variant="primary"
          label="Copy All Codes"
          copiedLabel="All Codes Copied!"
        />
        <button type="button" class="btn dark" onclick={handleDownload}>
          Download .txt File <span>↓</span>
        </button>
      </div>

      <div class="ack-field">
        <label class="ack-label">
          <input type="checkbox" bind:checked={acknowledged} />
          <span>I have safely recorded or downloaded these recovery codes offline.</span>
        </label>
      </div>

      <div class="action-footer">
        <button
          type="button"
          class="btn primary"
          disabled={!acknowledged}
          onclick={handleFinish}
        >
          Done & Close
        </button>
      </div>
    </div>
  {:else}
    <div class="confirm-view">
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="notice-card">
        <span class="notice-glyph">✦</span>
        <div>
          <strong>Important security consideration</strong>
          <p>Rotating your recovery codes generates a new set of 10 single-use emergency codes. Any existing codes you previously saved will stop working immediately.</p>
        </div>
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleFinish} disabled={stage === 'rotating'}>
          Cancel
        </button>
        <button type="button" class="btn danger" onclick={handleRotate} disabled={stage === 'rotating'}>
          {#if stage === 'rotating'}
            <Spinner size={14} color="#ffffff" /> Rotating codes…
          {:else}
            Rotate Recovery Codes <span>↗</span>
          {/if}
        </button>
      </div>
    </div>
  {/if}
</Modal>

<style>
  .confirm-view, .codes-display { display: flex; flex-direction: column; gap: 20px; }
  .notice-card { display: flex; gap: 12px; background: #faf8f1; border: 1px solid var(--line, #d7d5ca); padding: 16px; border-radius: 2px; }
  .notice-glyph { color: var(--ochre, #d1a85b); font-size: 20px; }
  .notice-card strong { display: block; font-size: 13px; color: var(--ink, #1f2827); font-family: var(--sans, sans-serif); }
  .notice-card p { margin: 6px 0 0; font-size: 12px; color: var(--muted, #687270); line-height: 1.5; }
  .warning-banner { display: flex; gap: 12px; background: #faf4e6; border: 1px solid #f1dfb8; padding: 14px; border-radius: 2px; color: #5c4714; }
  .warning-glyph { font-size: 20px; flex-shrink: 0; }
  .warning-banner strong { display: block; font-size: 13px; font-family: var(--sans, sans-serif); }
  .warning-banner p { margin: 4px 0 0; font-size: 12px; }
  .codes-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; background: #ffffff; border: 1px solid var(--line, #d7d5ca); padding: 16px; border-radius: 2px; }
  .code-pill { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: #faf8f1; border-radius: 2px; }
  .code-idx { font: 600 11px var(--mono, monospace); color: var(--muted, #687270); }
  .code-val { font: 600 13px var(--mono, monospace); color: var(--teal-deep, #173f3e); letter-spacing: 0.05em; }
  .export-actions { display: flex; gap: 10px; flex-wrap: wrap; }
  .ack-field { background: #faf8f1; border: 1px solid var(--line, #d7d5ca); padding: 14px; border-radius: 2px; }
  .ack-label { display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 13px; font-weight: 500; color: var(--ink, #1f2827); font-family: var(--sans, sans-serif); }
  .ack-label input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--teal, #2b7169); }
  .error-banner { background: #fbebe8; color: var(--coral, #ba5e47); border-left: 3px solid var(--coral, #ba5e47); padding: 10px 14px; font-size: 12px; border-radius: 2px; }
  .action-footer { display: flex; justify-content: flex-end; gap: 10px; width: 100%; }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; font-size: 12px; font-weight: 600; cursor: pointer; border-radius: 2px; border: 1px solid transparent; font-family: var(--sans, sans-serif); }
  .btn.primary { background: var(--teal, #2b7169); color: #ffffff; }
  .btn.primary:hover { background: var(--teal-deep, #173f3e); }
  .btn.dark { background: var(--ink, #1f2827); color: #f7f2e7; }
  .btn.dark:hover { background: #000000; }
  .btn.danger { background: var(--coral, #ba5e47); color: #ffffff; }
  .btn.danger:hover { background: #963d28; }
  .btn.ghost { background: transparent; color: var(--muted, #687270); border-color: var(--line, #d7d5ca); }
  .btn.ghost:hover { background: #e6e3d9; color: var(--ink, #1f2827); }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
  @media (max-width: 560px) {
    .codes-grid { grid-template-columns: 1fr; }
  }
</style>
