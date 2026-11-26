<script lang="ts">
  import { portal, activeFactors } from '$lib/stores/portal';
  import { modals } from '$lib/stores/modals';
  import { toasts } from '$lib/stores/toasts';
  import { api } from '$lib/api';

  let revokingId = $state<string | null>(null);

  const passkeys = $derived($activeFactors.filter((f) => f.kind === 'passkey'));
  const totpFactors = $derived($activeFactors.filter((f) => f.kind === 'totp'));
  const hasTotp = $derived(totpFactors.length > 0);

  async function handleRevokePasskey(factorId: string) {
    if (!factorId) return;
    revokingId = factorId;
    try {
      await api.revokePasskey(factorId);
      toasts.success('Passkey factor revoked.');
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
    } catch (err: any) {
      toasts.error(err.message || 'Failed to revoke passkey.');
    } finally {
      revokingId = null;
    }
  }

  async function handleRevokeTotp(factorId?: string) {
    revokingId = factorId || 'totp';
    try {
      await api.revokeTotp(factorId);
      toasts.success('Authenticator app factor revoked.');
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
    } catch (err: any) {
      toasts.error(err.message || 'Failed to revoke TOTP factor.');
    } finally {
      revokingId = null;
    }
  }

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let changingPassword = $state(false);
  const newPasswordBytes = $derived(new TextEncoder().encode(newPassword).length);
  const passwordFormValid = $derived(
    currentPassword.length > 0 &&
      newPasswordBytes >= 8 &&
      newPasswordBytes <= 256 &&
      newPassword === confirmPassword
  );

  async function handleChangePassword(event: SubmitEvent) {
    event.preventDefault();
    if (!passwordFormValid) return;
    changingPassword = true;
    try {
      const result = await api.changePassword(currentPassword, newPassword);
      currentPassword = newPassword = confirmPassword = '';
      if (result.message === 'Password changed') {
        toasts.success('Password changed. Other account sessions were signed out.');
      } else {
        toasts.warning(result.message);
      }
    } catch (err: any) {
      toasts.error(err.message || 'Failed to change password.');
    } finally {
      changingPassword = false;
    }
  }
</script>

<div class="flex flex-col gap-6">
  <!-- Page Header / Summary Card -->
  <section class="card bg-base-100 shadow-sm border border-base-200">
    <form class="card-body gap-4" onsubmit={handleChangePassword}>
      <h2 class="card-title text-lg">Change password</h2>
      <label class="form-control w-full">
        <span class="label-text mb-1">Current password</span>
        <input class="input input-bordered w-full" type="password" autocomplete="current-password" bind:value={currentPassword} required />
      </label>
      <label class="form-control w-full">
        <span class="label-text mb-1">New password (8–256 characters)</span>
        <input class="input input-bordered w-full" type="password" autocomplete="new-password" bind:value={newPassword} required />
      </label>
      <label class="form-control w-full">
        <span class="label-text mb-1">Confirm new password</span>
        <input class="input input-bordered w-full" type="password" autocomplete="new-password" bind:value={confirmPassword} required />
      </label>
      {#if confirmPassword && newPassword !== confirmPassword}
        <p class="text-error text-sm">Passwords do not match.</p>
      {/if}
      <div class="card-actions justify-end">
        <button class="btn btn-primary" type="submit" disabled={!passwordFormValid || changingPassword}>
          {changingPassword ? 'Changing…' : 'Change password'}
        </button>
      </div>
    </form>
  </section>

  <section class="card bg-base-100 shadow-sm border border-base-200">
    <div class="card-body gap-4">
      <div class="flex items-start justify-between gap-4">
        <div>
          <span class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Factors & sign-in</span>
          <h2 class="card-title text-lg mt-1">Multi-factor authentication</h2>
        </div>
        <span class="badge {$activeFactors.length > 0 ? 'badge-success' : 'badge-neutral'}">
          {$activeFactors.length > 0 ? `${$activeFactors.length} active factor${$activeFactors.length === 1 ? '' : 's'}` : 'Password only'}
        </span>
      </div>
      <p class="text-sm text-base-content/70">
        Protect your account with passkeys, authenticator apps, and single-use recovery codes.
      </p>
    </div>
  </section>

  <!-- Passkeys Card -->
  <section class="card bg-base-100 shadow-sm border border-base-200">
    <div class="card-body gap-4">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h3 class="font-semibold text-base">WebAuthn passkeys</h3>
          <p class="text-xs text-base-content/60 mt-0.5">Hardware security keys and platform authenticators</p>
        </div>
        <button
          type="button"
          class="btn btn-primary btn-sm"
          onclick={() => modals.open('passkey-enroll')}
        >
          Add passkey
        </button>
      </div>

      <div class="flex flex-col gap-2 pt-1">
        {#if passkeys.length === 0}
          <div class="text-sm text-base-content/60 py-2">No passkeys registered.</div>
        {:else}
          {#each passkeys as passkey (passkey.id)}
            <div class="card card-border bg-base-200/60 p-4 flex flex-row items-center justify-between gap-4">
              <div class="min-w-0">
                <div class="font-semibold text-sm">{passkey.label || 'Passkey'}</div>
                <div class="font-mono text-xs text-base-content/60 mt-0.5 break-all">ID: {passkey.id}</div>
              </div>
              <div class="flex items-center gap-3 shrink-0">
                <span class="badge badge-success badge-sm">Active</span>
                <button
                  type="button"
                  class="btn btn-error btn-outline btn-sm"
                  disabled={revokingId === passkey.id}
                  onclick={() => handleRevokePasskey(passkey.id)}
                  aria-label={`Revoke passkey ${passkey.label}`}
                >
                  {#if revokingId === passkey.id}
                    <span class="loading loading-spinner loading-xs"></span>
                  {:else}
                    Revoke
                  {/if}
                </button>
              </div>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </section>

  <!-- Authenticator Apps (TOTP) Card -->
  <section class="card bg-base-100 shadow-sm border border-base-200">
    <div class="card-body gap-4">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h3 class="font-semibold text-base">Authenticator apps (TOTP)</h3>
          <p class="text-xs text-base-content/60 mt-0.5">Time-based verification codes generated by an authenticator app</p>
        </div>
        {#if !hasTotp}
          <button
            type="button"
            class="btn btn-outline btn-sm"
            onclick={() => modals.open('totp-enroll')}
          >
            Set up TOTP
          </button>
        {/if}
      </div>

      <div class="flex flex-col gap-2 pt-1">
        {#if !hasTotp}
          <div class="text-sm text-base-content/60 py-2">No authenticator app enrolled.</div>
        {:else}
          {#each totpFactors as totp (totp.id)}
            <div class="card card-border bg-base-200/60 p-4 flex flex-row items-center justify-between gap-4">
              <div class="min-w-0">
                <div class="font-semibold text-sm">{totp.label || 'Authenticator App'}</div>
                <div class="text-xs text-base-content/60 mt-0.5">Time-based one-time password (RFC 6238)</div>
              </div>
              <div class="flex items-center gap-3 shrink-0">
                <span class="badge badge-success badge-sm">Active</span>
                <button
                  type="button"
                  class="btn btn-error btn-outline btn-sm"
                  disabled={revokingId === (totp.id || 'totp')}
                  onclick={() => handleRevokeTotp(totp.id)}
                  aria-label="Revoke TOTP authenticator"
                >
                  {#if revokingId === (totp.id || 'totp')}
                    <span class="loading loading-spinner loading-xs"></span>
                  {:else}
                    Revoke
                  {/if}
                </button>
              </div>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </section>

  <!-- Emergency Recovery Codes Card -->
  <section class="card bg-base-100 shadow-sm border border-base-200">
    <div class="card-body gap-4">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h3 class="font-semibold text-base">Emergency recovery codes</h3>
          <p class="text-xs text-base-content/60 mt-0.5">Single-use backup keys for account recovery if primary factors are unavailable</p>
        </div>
        <button
          type="button"
          class="btn btn-outline btn-sm"
          onclick={() => modals.open('recovery-rotate')}
        >
          Rotate recovery codes
        </button>
      </div>
    </div>
  </section>

  <!-- Step-Up Notice -->
  <div class="text-xs text-base-content/60 px-1">
    Enrolling or revoking authentication factors requires step-up re-authentication.
  </div>
</div>
