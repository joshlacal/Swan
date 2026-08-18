<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
  import QrCode from '$lib/components/ui/QrCode.svelte';
  import CopyButton from '$lib/components/ui/CopyButton.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { api } from '$lib/api';
  import { toasts } from '$lib/stores/toasts';
  import { portal, currentAccount } from '$lib/stores/portal';
  import { generateOtpauthUri, generateBase32Secret } from '$lib/qrcode';

  interface Props {
    isOpen?: boolean;
    onClose?: () => void;
  }

  let { isOpen = true, onClose }: Props = $props();

  let stage = $state<'init' | 'ready' | 'verifying' | 'success'>('init');
  let secret = $state('');
  let factorID = $state('');
  let otpauthUri = $state('');
  let verificationCode = $state('');
  let showManualKey = $state(false);
  let error = $state<string | null>(null);

  $effect(() => {
    if (isOpen && stage === 'init') {
      setupTotp();
    }
  });

  async function setupTotp() {
    stage = 'init';
    error = null;

    try {
      // 1. Generate client Base32 secret seed (20 bytes = 160 bits)
      secret = generateBase32Secret(20);
      const handle = $currentAccount?.handle || 'swan-user';

      // 2. Call backend to initiate pending TOTP factor envelope
      const response = await api.enrollTotp({
        secret,
        label: 'Authenticator App'
      });

      if (!response.factorID) {
        throw new Error('Server did not return a factor ID.');
      }

      factorID = response.factorID;

      // 3. Build otpauth:// URI for QR generation
      otpauthUri = generateOtpauthUri({
        account: handle,
        secret,
        issuer: 'Swan',
        digits: 6,
        period: 30
      });

      stage = 'ready';
    } catch (err: any) {
      error = err.message || 'Failed to initialize TOTP enrollment.';
    }
  }

  async function handleVerify(e: SubmitEvent) {
    e.preventDefault();
    const cleanCode = verificationCode.replace(/\D/g, '');
    if (cleanCode.length !== 6) {
      error = 'Please enter a valid 6-digit confirmation code.';
      return;
    }

    stage = 'verifying';
    error = null;

    try {
      await api.verifyTotpEnrollment(factorID, cleanCode);
      stage = 'success';
      toasts.success('Authenticator app enrolled successfully');

      // Refresh snapshot
      try {
        const snapshot = await api.fetchSnapshot();
        portal.setSnapshot(snapshot);
      } catch {
        // Non-blocking snapshot refresh
      }
    } catch (err: any) {
      stage = 'ready';
      error = err.message || 'Invalid confirmation code. Please check your authenticator clock and try again.';
      verificationCode = '';
    }
  }

  function formatSecret(raw: string): string {
    return raw.match(/.{1,4}/g)?.join(' ') ?? raw;
  }

  function handleDone() {
    stage = 'init';
    secret = '';
    factorID = '';
    verificationCode = '';
    error = null;
    if (onClose) onClose();
  }
</script>

<Modal
  {isOpen}
  title="Set Up Authenticator (TOTP)"
  description="Connect an authenticator app (Google Authenticator, Apple Passwords, 1Password) for 6-digit security codes."
  size="md"
  preventClose={stage === 'verifying'}
  onClose={handleDone}
>
  {#if stage === 'init'}
    <div class="loading-box">
      <Spinner size={24} />
      <p>Generating cryptographic seed…</p>
    </div>
  {:else if stage === 'success'}
    <div class="success-view">
      <div class="success-circle">✓</div>
      <h3>Authenticator Enrolled</h3>
      <p>Your authenticator app is now registered. You can use it whenever a 6-digit verification code is required.</p>
      <div class="action-footer">
        <button type="button" class="btn primary" onclick={handleDone}>Done</button>
      </div>
    </div>
  {:else}
    <div class="totp-container">
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="step-card">
        <span class="step-badge">1</span>
        <div class="step-content">
          <strong>Scan this QR code with your authenticator</strong>
          <div class="qr-presentation">
            <QrCode value={otpauthUri} size={180} title="TOTP Setup QR Code" />
          </div>

          <div class="manual-toggle">
            <button
              type="button"
              class="text-btn"
              onclick={() => (showManualKey = !showManualKey)}
            >
              {showManualKey ? 'Hide manual key' : 'Can’t scan? View setup key ↗'}
            </button>
          </div>

          {#if showManualKey}
            <div class="manual-box">
              <span class="eyebrow">MANUAL SETUP SECRET</span>
              <div class="manual-row">
                <code class="secret-code">{formatSecret(secret)}</code>
                <CopyButton text={secret} size="sm" label="Copy Secret" />
              </div>
            </div>
          {/if}
        </div>
      </div>

      <div class="step-card">
        <span class="step-badge">2</span>
        <form class="verify-form" onsubmit={handleVerify}>
          <div class="form-field">
            <label for="totp-code">Enter the 6-digit code shown in your app</label>
            <div class="code-input-row">
              <input
                id="totp-code"
                type="text"
                inputmode="numeric"
                pattern="[0-9]*"
                maxlength="6"
                placeholder="000000"
                bind:value={verificationCode}
                disabled={stage === 'verifying'}
                autocomplete="one-time-code"
                required
              />
              <button
                type="submit"
                class="btn primary"
                disabled={stage === 'verifying' || verificationCode.replace(/\D/g, '').length !== 6}
              >
                {#if stage === 'verifying'}
                  <Spinner size={14} color="#ffffff" /> Verifying…
                {:else}
                  Verify & Activate <span>✓</span>
                {/if}
              </button>
            </div>
          </div>
        </form>
      </div>

      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleDone} disabled={stage === 'verifying'}>
          Cancel
        </button>
      </div>
    </div>
  {/if}
</Modal>

<style>
  .totp-container { display: flex; flex-direction: column; gap: 20px; }
  .loading-box { display: grid; place-items: center; padding: 40px 0; color: var(--muted, #687270); gap: 12px; font-size: 13px; font-family: var(--mono, monospace); }
  .step-card { display: flex; gap: 14px; background: #ffffff; border: 1px solid var(--line, #d7d5ca); padding: 18px; border-radius: 2px; }
  .step-badge { width: 24px; height: 24px; border-radius: 50%; background: var(--teal-deep, #173f3e); color: #ffffff; display: grid; place-items: center; font: 700 12px var(--mono, monospace); flex-shrink: 0; }
  .step-content { flex: 1; display: flex; flex-direction: column; gap: 12px; }
  .step-content strong { font-size: 13px; color: var(--ink, #1f2827); }
  .qr-presentation { display: grid; place-items: center; padding: 10px 0; }
  .manual-toggle { text-align: center; }
  .text-btn { border: 0; background: transparent; color: var(--teal, #2b7169); font-size: 12px; font-weight: 600; cursor: pointer; padding: 4px; font-family: var(--sans, sans-serif); }
  .manual-box { background: #faf8f1; border: 1px solid var(--line, #d7d5ca); padding: 12px; border-radius: 2px; display: flex; flex-direction: column; gap: 6px; }
  .eyebrow { font: 600 10px var(--mono, monospace); color: var(--muted, #687270); letter-spacing: 0.1em; }
  .manual-row { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
  .secret-code { font: 600 13px var(--mono, monospace); color: var(--teal-deep, #173f3e); }
  .verify-form { flex: 1; }
  .form-field { display: flex; flex-direction: column; gap: 8px; }
  .form-field label { font-size: 13px; font-weight: 600; color: var(--ink, #1f2827); font-family: var(--sans, sans-serif); }
  .code-input-row { display: flex; gap: 10px; }
  .code-input-row input { flex: 1; padding: 10px 14px; font: 700 18px var(--mono, monospace); letter-spacing: 0.25em; text-align: center; border: 1px solid var(--line, #d7d5ca); border-radius: 2px; }
  .code-input-row input:focus { outline: 2px solid var(--teal, #2b7169); }
  .error-banner { background: #fbebe8; color: var(--coral, #ba5e47); border-left: 3px solid var(--coral, #ba5e47); padding: 10px 14px; font-size: 12px; border-radius: 2px; }
  .success-view { text-align: center; align-items: center; padding: 20px 0; display: flex; flex-direction: column; gap: 12px; }
  .success-circle { width: 48px; height: 48px; border-radius: 50%; background: var(--teal, #2b7169); color: #ffffff; display: grid; place-items: center; font-size: 22px; font-weight: bold; }
  .success-view h3 { margin: 0; font: 400 24px var(--serif, serif); }
  .success-view p { color: var(--muted, #687270); font-size: 13px; max-width: 360px; margin: 0; }
  .action-footer { display: flex; justify-content: flex-end; gap: 10px; width: 100%; }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; font-size: 12px; font-weight: 600; cursor: pointer; border-radius: 2px; border: 1px solid transparent; font-family: var(--sans, sans-serif); }
  .btn.primary { background: var(--teal, #2b7169); color: #ffffff; }
  .btn.primary:hover { background: var(--teal-deep, #173f3e); }
  .btn.ghost { background: transparent; color: var(--muted, #687270); border-color: var(--line, #d7d5ca); }
  .btn.ghost:hover { background: #e6e3d9; color: var(--ink, #1f2827); }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
</style>
