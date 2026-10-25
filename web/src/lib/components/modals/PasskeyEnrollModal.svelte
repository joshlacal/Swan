<script lang="ts">
  import Modal from '#lib/components/ui/Modal.svelte';
  import { api } from '#lib/api.ts';
  import { toasts } from '#lib/stores/toasts.ts';
  import { portal, currentAccount } from '#lib/stores/portal.ts';
  import { isWebAuthnSupported, formatWebAuthnError, performPasskeyRegistration } from '#lib/webauthn.ts';

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
  title="Add passkey"
  description="Register biometric authentication or a hardware security key."
  size="md"
  preventClose={stage === 'enrolling'}
  onClose={handleDone}
>
  {#if stage === 'unsupported'}
    <div class="flex flex-col gap-4">
      <div class="alert alert-error text-sm" role="alert">
        <div>
          <div class="font-bold">WebAuthn not supported</div>
          <div class="text-xs mt-1">This browser does not support WebAuthn passkey registration.</div>
        </div>
      </div>
      <div class="modal-action">
        <button type="button" class="btn btn-ghost" onclick={handleDone}>Close</button>
      </div>
    </div>
  {:else if stage === 'success'}
    <div class="flex flex-col items-center text-center gap-4 py-4">
      <div class="badge badge-success badge-xl p-4">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 stroke-current shrink-0" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
      </div>
      <div>
        <h3 class="text-lg font-semibold">Passkey registered</h3>
        <p class="text-sm text-base-content/70 mt-1">Passkey "{label}" is now registered to your account.</p>
      </div>
      <div class="modal-action w-full justify-end">
        <button type="button" class="btn btn-primary" onclick={handleDone}>Done</button>
      </div>
    </div>
  {:else}
    <form class="flex flex-col gap-4" onsubmit={handleEnroll}>
      {#if error}
        <div class="alert alert-error text-sm" role="alert">{error}</div>
      {/if}

      <fieldset class="fieldset gap-1">
        <legend class="fieldset-legend">Passkey label</legend>
        <input
          id="passkey-label"
          type="text"
          class="input w-full"
          bind:value={label}
          placeholder="e.g. MacBook Touch ID, YubiKey"
          maxlength="100"
          required
          disabled={stage === 'enrolling'}
        />
        <p class="text-xs text-base-content/60">A label to identify this device.</p>
      </fieldset>

      <div class="alert alert-info bg-base-200 text-base-content border-base-300 text-sm">
        <span>Your device will prompt for biometric verification or a security key.</span>
      </div>

      <div class="modal-action">
        <button type="button" class="btn btn-ghost" onclick={handleDone} disabled={stage === 'enrolling'}>
          Cancel
        </button>
        <button type="submit" class="btn btn-primary" disabled={stage === 'enrolling' || !label.trim()}>
          {#if stage === 'enrolling'}
            <span class="loading loading-spinner loading-xs"></span> Waiting for device…
          {:else}
            Continue
          {/if}
        </button>
      </div>
    </form>
  {/if}
</Modal>
