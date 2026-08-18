<script lang="ts">
  import Modal from '$lib/components/ui/Modal.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { api } from '$lib/api';
  import { toasts } from '$lib/stores/toasts';
  import { portal, currentAccount } from '$lib/stores/portal';
  import { isWebAuthnSupported, formatWebAuthnError, performPasskeyRegistration } from '$lib/webauthn';

  interface Props {
    isOpen?: boolean;
    onClose?: () => void;
  }

  let { isOpen = true, onClose }: Props = $props();

  let label = $state('Touch ID / Security Key');
  let stage = $state<'input' | 'enrolling' | 'success' | 'unsupported'>('input');
  let error = $state<string | null>(null);

  $effect(() => {
    if (isOpen) {
      if (!isWebAuthnSupported()) {
        stage = 'unsupported';
      } else {
        stage = 'input';
      }
      error = null;
    }
  });

  async function handleEnroll(e: SubmitEvent) {
    e.preventDefault();
    stage = 'enrolling';
    error = null;

    try {
      const passkeyLabel = label.trim() || 'Passkey';
      const userHandle = $currentAccount?.handle || 'Swan User';

      // 1. Fetch challenge from backend
      const challengeResponse = await api.requestPasskeyChallenge(passkeyLabel);
      if (!challengeResponse.challenge || !challengeResponse.factorID) {
        throw new Error('Server did not return a valid challenge.');
      }

      // 2. Perform WebAuthn ceremony via browser API
      const attestation = await performPasskeyRegistration(
        {
          challenge: challengeResponse.challenge,
          factorID: challengeResponse.factorID,
          accountDID: challengeResponse.accountDID
        },
        passkeyLabel,
        userHandle
      );

      // 3. Submit attestation to backend
      await api.registerPasskey(attestation, challengeResponse.factorID);

      // 4. Success state
      stage = 'success';
      toasts.success('Passkey registered successfully');

      // Refresh snapshot
      try {
        const snapshot = await api.fetchSnapshot();
        portal.setSnapshot(snapshot);
      } catch {
        // Non-blocking snapshot refresh
      }
    } catch (err: any) {
      stage = 'input';
      error = formatWebAuthnError(err);
    }
  }

  function handleDone() {
    stage = 'input';
    error = null;
    if (onClose) onClose();
  }
</script>

<Modal
  {isOpen}
  title="Add Passkey Factor"
  description="Register biometric authentication (Touch ID, Face ID, Windows Hello) or a hardware security key."
  size="md"
  preventClose={stage === 'enrolling'}
  onClose={handleDone}
>
  {#if stage === 'unsupported'}
    <div class="unsupported-view">
      <div class="error-banner">
        <strong>WebAuthn Not Supported</strong>
        <p>Your current browser does not support WebAuthn passkey registration. Please use a modern browser such as Safari, Chrome, Edge, or Firefox.</p>
      </div>
      <div class="action-footer">
        <button type="button" class="btn ghost" onclick={handleDone}>Close</button>
      </div>
    </div>
  {:else if stage === 'success'}
    <div class="success-view">
      <div class="success-circle">✓</div>
      <h3>Passkey Activated</h3>
      <p>Your passkey <strong>"{label}"</strong> is now registered as a strong authentication factor on your account.</p>
      <div class="action-footer">
        <button type="button" class="btn primary" onclick={handleDone}>Done</button>
      </div>
    </div>
  {:else}
    <form class="enroll-form" onsubmit={handleEnroll}>
      {#if error}
        <div class="error-banner" role="alert">{error}</div>
      {/if}

      <div class="form-field">
        <label for="passkey-label">Passkey Label</label>
        <input
          id="passkey-label"
          type="text"
          bind:value={label}
          placeholder="e.g. MacBook Touch ID, YubiKey 5C"
          maxlength="100"
          required
          disabled={stage === 'enrolling'}
        />
        <small class="field-hint">Give this device a recognizable name so you can identify it in your security settings.</small>
      </div>

      <div class="info-card">
        <span class="card-glyph">🔑</span>
        <div>
          <strong>How this works</strong>
          <p>When you click continue, your device will prompt you to use your fingerprint, facial recognition, or insert your security key.</p>
        </div>
      </div>

      <div class="form-actions">
        <button type="button" class="btn ghost" onclick={handleDone} disabled={stage === 'enrolling'}>
          Cancel
        </button>
        <button type="submit" class="btn primary" disabled={stage === 'enrolling' || !label.trim()}>
          {#if stage === 'enrolling'}
            <Spinner size={14} color="#ffffff" /> Waiting for device…
          {:else}
            Continue with Passkey <span>↗</span>
          {/if}
        </button>
      </div>
    </form>
  {/if}
</Modal>

<style>
  .enroll-form, .unsupported-view, .success-view { display: flex; flex-direction: column; gap: 20px; }
  .form-field { display: flex; flex-direction: column; gap: 6px; }
  .form-field label { font: 600 11px var(--mono, monospace); color: var(--muted, #687270); letter-spacing: 0.08em; text-transform: uppercase; }
  .form-field input[type="text"] { padding: 10px 12px; font: 13px var(--sans, sans-serif); border: 1px solid var(--line, #d7d5ca); background: #ffffff; color: var(--ink, #1f2827); border-radius: 2px; }
  .form-field input:focus { outline: 2px solid var(--teal, #2b7169); border-color: var(--teal, #2b7169); }
  .field-hint { font-size: 11px; color: var(--muted, #687270); }
  .info-card { display: flex; gap: 12px; background: #faf8f1; border: 1px solid var(--line, #d7d5ca); padding: 14px; border-radius: 2px; }
  .card-glyph { font-size: 20px; }
  .info-card strong { display: block; font-size: 13px; color: var(--ink, #1f2827); }
  .info-card p { margin: 4px 0 0; font-size: 12px; color: var(--muted, #687270); line-height: 1.4; }
  .error-banner { background: #fbebe8; color: var(--coral, #ba5e47); border-left: 3px solid var(--coral, #ba5e47); padding: 10px 14px; font-size: 12px; line-height: 1.4; border-radius: 2px; }
  .error-banner p { margin: 4px 0 0; }
  .success-view { text-align: center; align-items: center; padding: 10px 0; }
  .success-circle { width: 48px; height: 48px; border-radius: 50%; background: var(--teal, #2b7169); color: #ffffff; display: grid; place-items: center; font-size: 22px; font-weight: bold; margin-bottom: 8px; }
  .success-view h3 { margin: 0; font: 400 24px var(--serif, serif); }
  .success-view p { color: var(--muted, #687270); font-size: 13px; max-width: 360px; margin: 8px auto 0; }
  .form-actions, .action-footer { display: flex; justify-content: flex-end; gap: 10px; width: 100%; }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; font-size: 12px; font-weight: 600; cursor: pointer; border-radius: 2px; border: 1px solid transparent; font-family: var(--sans, sans-serif); }
  .btn.primary { background: var(--teal, #2b7169); color: #ffffff; }
  .btn.primary:hover { background: var(--teal-deep, #173f3e); }
  .btn.ghost { background: transparent; color: var(--muted, #687270); border-color: var(--line, #d7d5ca); }
  .btn.ghost:hover { background: #e6e3d9; color: var(--ink, #1f2827); }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
</style>
