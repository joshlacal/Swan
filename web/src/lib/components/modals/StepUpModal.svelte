<script lang="ts">
  import { tick } from 'svelte';
  import { api } from '$lib/api';
  import { stepup, type StepUpFactorKind } from '$lib/stores/stepup';
  import { activeFactors } from '$lib/stores/portal';
  import { performPasskeyAssertion, formatWebAuthnError } from '$lib/webauthn';
  import Modal from '$lib/components/ui/Modal.svelte';

  let password = $state('');
  let totpCode = $state('');
  let recoveryCode = $state('');
  let passwordInput = $state<HTMLInputElement | null>(null);
  let totpInput = $state<HTMLInputElement | null>(null);
  let recoveryInput = $state<HTMLInputElement | null>(null);

  const isOpen = $derived($stepup.isOpen);
  const loading = $derived($stepup.loading);
  const errorMessage = $derived($stepup.error);
  const selectedFactor = $derived($stepup.selectedFactor);
  const allowedFactors = $derived($stepup.allowedFactors);
  const context = $derived($stepup.context);

  async function focusActiveInput() {
    await tick();
    if (selectedFactor === 'password') passwordInput?.focus();
    else if (selectedFactor === 'totp') totpInput?.focus();
    else if (selectedFactor === 'recoveryCode') recoveryInput?.focus();
  }

  $effect(() => {
    if (isOpen) {
      focusActiveInput();
    } else {
      password = '';
      totpCode = '';
      recoveryCode = '';
    }
  });

  async function submitPassword(e?: SubmitEvent) {
    if (e) e.preventDefault();
    if (!password || loading) return;

    stepup.setLoading(true);
    stepup.setError(null);

    try {
      const res = await api.stepUpPassword(password);
      stepup.resolveStepUp(res.factorToken || true);
    } catch (err: any) {
      stepup.setError(err.message || 'Password incorrect.');
    }
  }

  async function submitTotp(e?: SubmitEvent) {
    if (e) e.preventDefault();
    const cleanCode = totpCode.replace(/\D/g, '');
    if (cleanCode.length !== 6 || loading) return;

    stepup.setLoading(true);
    stepup.setError(null);

    try {
      const factor = $activeFactors.find((f) => f.kind === 'totp') || { id: 'totp_1' };
      const res = await api.stepUpTotp(factor.id, cleanCode);
      stepup.resolveStepUp(res.factorToken || true);
    } catch (err: any) {
      stepup.setError(err.message || 'Invalid verification code.');
    }
  }

  async function submitPasskey() {
    if (loading) return;

    stepup.setLoading(true);
    stepup.setError(null);

    try {
      const factor = $activeFactors.find((f) => f.kind === 'passkey');
      const factorID = factor?.id;
      const challengeRes = await api.requestPasskeyStepUpChallenge(factorID);

      const assertion = await performPasskeyAssertion({
        challenge: challengeRes.challenge!,
        factorID: challengeRes.factorID || factorID || 'passkey'
      });

      const res = await api.submitPasskeyAssertion(assertion);
      stepup.resolveStepUp(res.factorToken || true);
    } catch (err: any) {
      stepup.setError(formatWebAuthnError(err));
    }
  }

  async function submitRecovery(e?: SubmitEvent) {
    if (e) e.preventDefault();
    if (!recoveryCode.trim() || loading) return;

    stepup.setLoading(true);
    stepup.setError(null);

    try {
      const res = await api.stepUpRecoveryCode(recoveryCode.trim().toUpperCase());
      stepup.resolveStepUp(res.factorToken || true);
    } catch (err: any) {
      stepup.setError(err.message || 'Invalid or consumed recovery code.');
    }
  }

  function handleTotpInput(e: Event) {
    const target = e.target as HTMLInputElement;
    totpCode = target.value.replace(/\D/g, '').slice(0, 6);
    if (totpCode.length === 6) {
      submitTotp();
    }
  }
</script>

<Modal
  {isOpen}
  title="Confirm identity"
  description={context?.operation ? `Authorizing ${context.operation} requires verification.` : 'This action requires verification.'}
  size="md"
  preventClose={loading}
  onClose={() => stepup.cancelStepUp()}
>
  {#if allowedFactors.length > 1}
    <div class="join w-full mb-4" role="tablist" aria-label="Verification method">
      {#each allowedFactors as factor}
        <button
          type="button"
          role="tab"
          class="btn join-item flex-1 btn-sm {selectedFactor === factor ? 'btn-active btn-neutral' : 'btn-ghost'}"
          aria-selected={selectedFactor === factor}
          disabled={loading}
          onclick={() => stepup.selectFactor(factor)}
        >
          {#if factor === 'password'}Password
          {:else if factor === 'passkey'}Passkey
          {:else if factor === 'totp'}Authenticator
          {:else if factor === 'recoveryCode'}Recovery code
          {/if}
        </button>
      {/each}
    </div>
  {/if}

  {#if errorMessage}
    <div class="alert alert-error text-sm py-2 mb-4" role="alert">
      <span>{errorMessage}</span>
    </div>
  {/if}

  <div>
    {#if selectedFactor === 'password'}
      <form onsubmit={submitPassword} class="flex flex-col gap-4">
        <fieldset class="fieldset gap-1">
          <legend class="fieldset-legend">Account password</legend>
          <input
            bind:this={passwordInput}
            type="password"
            class="input w-full"
            bind:value={password}
            autocomplete="current-password"
            placeholder="Enter your password"
            disabled={loading}
            required
          />
        </fieldset>
        <div class="modal-action mt-2">
          <button type="button" class="btn btn-ghost" disabled={loading} onclick={() => stepup.cancelStepUp()}>
            Cancel
          </button>
          <button type="submit" class="btn btn-primary" disabled={loading || !password}>
            {#if loading}
              <span class="loading loading-spinner loading-xs"></span> Verifying…
            {:else}
              Verify password
            {/if}
          </button>
        </div>
      </form>
    {:else if selectedFactor === 'passkey'}
      <div class="flex flex-col gap-4">
        <p class="text-sm text-base-content/70">Use device biometrics or a security key to verify.</p>
        <div class="modal-action mt-2">
          <button type="button" class="btn btn-ghost" disabled={loading} onclick={() => stepup.cancelStepUp()}>
            Cancel
          </button>
          <button type="button" class="btn btn-primary" disabled={loading} onclick={submitPasskey}>
            {#if loading}
              <span class="loading loading-spinner loading-xs"></span> Waiting for passkey…
            {:else}
              Verify with passkey
            {/if}
          </button>
        </div>
      </div>
    {:else if selectedFactor === 'totp'}
      <form onsubmit={submitTotp} class="flex flex-col gap-4">
        <fieldset class="fieldset gap-1">
          <legend class="fieldset-legend">6-digit authenticator code</legend>
          <input
            bind:this={totpInput}
            type="text"
            inputmode="numeric"
            pattern="[0-9]{6}"
            maxlength="6"
            placeholder="123456"
            class="input w-full font-mono text-center text-lg tracking-widest"
            value={totpCode}
            oninput={handleTotpInput}
            autocomplete="one-time-code"
            disabled={loading}
            required
          />
        </fieldset>
        <div class="modal-action mt-2">
          <button type="button" class="btn btn-ghost" disabled={loading} onclick={() => stepup.cancelStepUp()}>
            Cancel
          </button>
          <button type="submit" class="btn btn-primary" disabled={loading || totpCode.length !== 6}>
            {#if loading}
              <span class="loading loading-spinner loading-xs"></span> Verifying…
            {:else}
              Verify code
            {/if}
          </button>
        </div>
      </form>
    {:else if selectedFactor === 'recoveryCode'}
      <form onsubmit={submitRecovery} class="flex flex-col gap-4">
        <fieldset class="fieldset gap-1">
          <legend class="fieldset-legend">Single-use recovery code</legend>
          <input
            bind:this={recoveryInput}
            type="text"
            class="input w-full font-mono uppercase"
            bind:value={recoveryCode}
            placeholder="RCV-XXXX-XXXX"
            autocomplete="one-time-code"
            inputmode="numeric"
            spellcheck="false"
            disabled={loading}
            required
          />
          <p class="text-xs text-base-content/60">Using a recovery code consumes it permanently.</p>
        </fieldset>
        <div class="modal-action mt-2">
          <button type="button" class="btn btn-ghost" disabled={loading} onclick={() => stepup.cancelStepUp()}>
            Cancel
          </button>
          <button type="submit" class="btn btn-primary" disabled={loading || !recoveryCode.trim()}>
            {#if loading}
              <span class="loading loading-spinner loading-xs"></span> Consuming code…
            {:else}
              Use recovery code
            {/if}
          </button>
        </div>
      </form>
    {/if}
  </div>
</Modal>
