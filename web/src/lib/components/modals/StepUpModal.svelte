<script lang="ts">
  import { tick } from 'svelte';
  import { api } from '$lib/api';
  import { stepup, type StepUpFactorKind } from '$lib/stores/stepup';
  import { activeFactors } from '$lib/stores/portal';
  import { performPasskeyAssertion, formatWebAuthnError } from '$lib/webauthn';
  import Spinner from '$lib/components/ui/Spinner.svelte';
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
      stepup.setError(err.message || 'Password incorrect. Please try again.');
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
      stepup.setError(err.message || 'Invalid TOTP verification code.');
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
  size="md"
  preventClose={loading}
  onClose={() => stepup.cancelStepUp()}
>
  {#snippet header()}
    <header class="dialog-header">
      <span class="eyebrow">SECURITY RE-AUTHENTICATION</span>
      <h2 id="step-up-title">Confirm it's you</h2>
      <p id="step-up-desc">
        {#if context?.operation}
          Authorizing <code>{context.operation}</code> requires step-up verification.
        {:else}
          This protected action requires elevated security clearance.
        {/if}
      </p>
    </header>
  {/snippet}

  {#if allowedFactors.length > 1}
    <div class="factor-tabs" role="tablist" aria-label="Verification method">
      {#each allowedFactors as factor}
        <button
          type="button"
          role="tab"
          class="tab-button"
          class:active={selectedFactor === factor}
          aria-selected={selectedFactor === factor}
          disabled={loading}
          onclick={() => stepup.selectFactor(factor)}
        >
          {#if factor === 'password'}🔑 Password
          {:else if factor === 'passkey'}🛡️ Passkey
          {:else if factor === 'totp'}📱 Authenticator
          {:else if factor === 'recoveryCode'}🗝️ Recovery
          {/if}
        </button>
      {/each}
    </div>
  {/if}

  {#if errorMessage}
    <div class="error-banner" role="alert">
      <span class="error-glyph">⚠</span>
      <span>{errorMessage}</span>
    </div>
  {/if}

  <div class="factor-body">
    {#if selectedFactor === 'password'}
      <form onsubmit={submitPassword} class="form-stack">
        <label>
          <span class="label-text">Account Password</span>
          <input
            bind:this={passwordInput}
            type="password"
            bind:value={password}
            autocomplete="current-password"
            placeholder="Enter your account password"
            disabled={loading}
            required
          />
        </label>
        <div class="form-actions">
          <button type="button" class="button dark" disabled={loading} onclick={() => stepup.cancelStepUp()}>
            Cancel
          </button>
          <button type="submit" class="button primary" disabled={loading || !password}>
            {#if loading}<Spinner size={14} color="#ffffff" /> Verifying…{:else}Verify Password ↗{/if}
          </button>
        </div>
      </form>
    {:else if selectedFactor === 'passkey'}
      <div class="passkey-pane">
        <p class="pane-copy">Use your device biometrics (Touch ID, Face ID, Windows Hello) or a hardware security key.</p>
        <div class="form-actions">
          <button type="button" class="button dark" disabled={loading} onclick={() => stepup.cancelStepUp()}>
            Cancel
          </button>
          <button type="button" class="button primary" disabled={loading} onclick={submitPasskey}>
            {#if loading}<Spinner size={14} color="#ffffff" /> Awaiting Passkey…{:else}Verify with Passkey ↗{/if}
          </button>
        </div>
      </div>
    {:else if selectedFactor === 'totp'}
      <form onsubmit={submitTotp} class="form-stack">
        <label>
          <span class="label-text">6-Digit Authenticator Code</span>
          <input
            bind:this={totpInput}
            type="text"
            inputmode="numeric"
            pattern="[0-9]{6}"
            maxlength="6"
            placeholder="123456"
            value={totpCode}
            oninput={handleTotpInput}
            autocomplete="one-time-code"
            disabled={loading}
            required
          />
        </label>
        <div class="form-actions">
          <button type="button" class="button dark" disabled={loading} onclick={() => stepup.cancelStepUp()}>
            Cancel
          </button>
          <button type="submit" class="button primary" disabled={loading || totpCode.length !== 6}>
            {#if loading}<Spinner size={14} color="#ffffff" /> Verifying…{:else}Verify Code ↗{/if}
          </button>
        </div>
      </form>
    {:else if selectedFactor === 'recoveryCode'}
      <form onsubmit={submitRecovery} class="form-stack">
        <label>
          <span class="label-text">Single-Use Recovery Code</span>
          <input
            bind:this={recoveryInput}
            type="text"
            bind:value={recoveryCode}
            placeholder="RCV-XXXX-XXXX"
            autocomplete="off"
            spellcheck="false"
            disabled={loading}
            required
          />
        </label>
        <p class="hint-text">Using a recovery code consumes it permanently.</p>
        <div class="form-actions">
          <button type="button" class="button dark" disabled={loading} onclick={() => stepup.cancelStepUp()}>
            Cancel
          </button>
          <button type="submit" class="button primary" disabled={loading || !recoveryCode.trim()}>
            {#if loading}<Spinner size={14} color="#ffffff" /> Consuming Code…{:else}Use Recovery Code ↗{/if}
          </button>
        </div>
      </form>
    {/if}
  </div>
</Modal>

<style>
  .dialog-header h2 {
    font: 400 28px/1.1 var(--serif, 'Iowan Old Style', serif);
    margin: 8px 0 10px;
    letter-spacing: -0.02em;
  }
  .dialog-header p {
    color: var(--muted, #687270);
    font-size: 13px;
    line-height: 1.5;
    margin: 0 0 16px;
  }
  .dialog-header code {
    font: 11px var(--mono, monospace);
    background: #e6e3d9;
    padding: 2px 6px;
    border-radius: 2px;
  }
  .eyebrow {
    display: block;
    font: 600 10px/1.3 var(--mono, monospace);
    color: var(--teal, #2b7169);
    letter-spacing: 0.14em;
  }
  .factor-tabs {
    display: flex;
    gap: 6px;
    border-bottom: 1px solid var(--line, #d7d5ca);
    margin-bottom: 20px;
    padding-bottom: 8px;
    overflow-x: auto;
  }
  .tab-button {
    border: 0;
    background: transparent;
    color: var(--muted, #687270);
    font: 600 11px var(--sans, sans-serif);
    padding: 8px 12px;
    border-radius: 2px;
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.2s;
  }
  .tab-button.active {
    background: var(--teal-deep, #173f3e);
    color: #f7f2e7;
  }
  .error-banner {
    display: flex;
    gap: 8px;
    align-items: center;
    background: #fcf1ef;
    border: 1px solid #eecbc4;
    color: var(--coral, #ba5e47);
    padding: 10px 14px;
    font-size: 12px;
    margin-bottom: 16px;
    border-radius: 2px;
  }
  .error-glyph {
    font-weight: bold;
  }
  .form-stack {
    display: grid;
    gap: 16px;
  }
  .label-text {
    display: block;
    font: 600 11px var(--mono, monospace);
    color: var(--muted, #687270);
    margin-bottom: 6px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  input {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--line, #d7d5ca);
    background: #ffffff;
    font-size: 14px;
    color: var(--ink, #1f2827);
    box-sizing: border-box;
    border-radius: 2px;
  }
  input:focus {
    outline: 2px solid var(--teal, #2b7169);
    border-color: transparent;
  }
  .hint-text {
    font-size: 11px;
    color: var(--muted, #687270);
    margin: -8px 0 0;
  }
  .pane-copy {
    font-size: 13px;
    color: var(--muted, #687270);
    line-height: 1.5;
    margin: 0 0 24px;
  }
  .form-actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 8px;
  }
  .button {
    border: 1px solid transparent;
    padding: 10px 16px;
    font-size: 12px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    border-radius: 2px;
    font-family: var(--sans, sans-serif);
  }
  .button.primary {
    background: var(--teal, #2b7169);
    color: white;
  }
  .button.primary:hover {
    background: var(--teal-deep, #173f3e);
  }
  .button.dark {
    background: #e6e3d9;
    color: var(--ink, #1f2827);
  }
  .button.dark:hover {
    background: #d7d5ca;
  }
  .button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
