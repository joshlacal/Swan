<script lang="ts">
  import Modal from '#lib/components/ui/Modal.svelte';
  import QrCode from '#lib/components/ui/QrCode.svelte';
  import CopyButton from '#lib/components/ui/CopyButton.svelte';
  import { api } from '#lib/api.ts';
  import { toasts } from '#lib/stores/toasts.ts';
  import { portal, currentAccount } from '#lib/stores/portal.ts';
  import { generateOtpauthUri, generateBase32Secret } from '#lib/qrcode.ts';

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
      error = 'Enter a valid 6-digit confirmation code.';
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
      error = err.message || 'Invalid confirmation code. Check your authenticator time and try again.';
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
  title="Set up authenticator"
  description="Connect an authenticator app for 6-digit verification codes."
  size="md"
  preventClose={stage === 'verifying'}
  onClose={handleDone}
>
  {#if error && stage === 'init'}
    <div class="flex flex-col gap-4 py-2">
      <div class="alert alert-error text-sm" role="alert">{error}</div>
      <div class="modal-action">
        <button type="button" class="btn btn-primary" onclick={setupTotp}>Retry</button>
        <button type="button" class="btn btn-ghost" onclick={handleDone}>Cancel</button>
      </div>
    </div>
  {:else if stage === 'init'}
    <div class="flex flex-col items-center justify-center py-8 gap-3 text-base-content/60">
      <span class="loading loading-spinner loading-md"></span>
      <span class="text-xs font-mono">Generating key…</span>
    </div>
  {:else if stage === 'success'}
    <div class="flex flex-col items-center text-center gap-4 py-4">
      <div class="badge badge-success badge-xl p-4">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 stroke-current shrink-0" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
      </div>
      <div>
        <h3 class="text-lg font-semibold">Authenticator added</h3>
        <p class="text-sm text-base-content/70 mt-1">Your authenticator app is now registered for verification codes.</p>
      </div>
      <div class="modal-action w-full justify-end">
        <button type="button" class="btn btn-primary" onclick={handleDone}>Done</button>
      </div>
    </div>
  {:else}
    <div class="flex flex-col gap-4">
      {#if error}
        <div class="alert alert-error text-sm" role="alert">{error}</div>
      {/if}

      <div class="card card-border bg-base-200/50">
        <div class="card-body p-4 gap-3">
          <h3 class="font-medium text-sm">1. Scan QR code</h3>
          <div class="flex justify-center p-2 bg-white rounded">
            <QrCode value={otpauthUri} size={180} title="TOTP Setup QR Code" />
          </div>

          <div class="text-center">
            <button
              type="button"
              class="btn btn-link btn-xs text-base-content/70 no-underline hover:underline"
              onclick={() => (showManualKey = !showManualKey)}
            >
              {showManualKey ? 'Hide manual key' : 'Enter key manually'}
            </button>
          </div>

          {#if showManualKey}
            <div class="bg-base-100 border border-base-300 p-3 rounded flex flex-col gap-1">
              <span class="text-xs text-base-content/60 font-mono">SECRET KEY</span>
              <div class="flex items-center justify-between gap-2">
                <code class="font-mono break-all text-sm font-semibold">{formatSecret(secret)}</code>
                <CopyButton text={secret} size="sm" label="Copy" />
              </div>
            </div>
          {/if}
        </div>
      </div>

      <div class="card card-border bg-base-200/50">
        <div class="card-body p-4">
          <h3 class="font-medium text-sm mb-2">2. Enter verification code</h3>
          <form onsubmit={handleVerify} class="flex flex-col gap-3">
            <fieldset class="fieldset gap-1">
              <legend class="fieldset-legend">6-digit code</legend>
              <div class="flex gap-2">
                <input
                  id="totp-code"
                  type="text"
                  inputmode="numeric"
                  pattern="[0-9]*"
                  maxlength="6"
                  placeholder="000000"
                  class="input w-full font-mono text-center text-lg tracking-widest"
                  bind:value={verificationCode}
                  disabled={stage === 'verifying'}
                  autocomplete="one-time-code"
                  required
                />
                <button
                  type="submit"
                  class="btn btn-primary shrink-0"
                  disabled={stage === 'verifying' || verificationCode.replace(/\D/g, '').length !== 6}
                >
                  {#if stage === 'verifying'}
                    <span class="loading loading-spinner loading-xs"></span> Verifying…
                  {:else}
                    Verify
                  {/if}
                </button>
              </div>
            </fieldset>
          </form>
        </div>
      </div>

      <div class="modal-action">
        <button type="button" class="btn btn-ghost" onclick={handleDone} disabled={stage === 'verifying'}>
          Cancel
        </button>
      </div>
    </div>
  {/if}
</Modal>
