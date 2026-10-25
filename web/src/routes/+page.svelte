<script lang="ts">
  import { onMount } from 'svelte';
  import { fade } from 'svelte/transition';

  // API Client & Stores
  import { api, bootstrap } from '#lib/api.ts';
  import {
    portal,
    SECTIONS,
    currentAccount,
    type NavigationSection
  } from '#lib/stores/portal.ts';
  import { modals, activeModal } from '#lib/stores/modals.ts';
  import { toasts } from '#lib/stores/toasts.ts';
  import { stepup } from '#lib/stores/stepup.ts';

  // Section Views
  import OverviewView from '#lib/components/views/OverviewView.svelte';
  import ProfileView from '#lib/components/views/ProfileView.svelte';
  import SecurityView from '#lib/components/views/SecurityView.svelte';
  import RecoveryView from '#lib/components/views/RecoveryView.svelte';
  import SessionsView from '#lib/components/views/SessionsView.svelte';
  import AppsView from '#lib/components/views/AppsView.svelte';
  import PasswordsView from '#lib/components/views/PasswordsView.svelte';
  import ExportView from '#lib/components/views/ExportView.svelte';
  import LifecycleView from '#lib/components/views/LifecycleView.svelte';

  // Modal Dialogs
  import StepUpModal from '#lib/components/modals/StepUpModal.svelte';
  import AppPasswordModal from '#lib/components/modals/AppPasswordModal.svelte';
  import PasskeyEnrollModal from '#lib/components/modals/PasskeyEnrollModal.svelte';
  import TotpEnrollModal from '#lib/components/modals/TotpEnrollModal.svelte';
  import RecoveryRotateModal from '#lib/components/modals/RecoveryRotateModal.svelte';
  import DidWebModal from '#lib/components/modals/DidWebModal.svelte';
  import ExportModal from '#lib/components/modals/ExportModal.svelte';
  import LifecycleModal from '#lib/components/modals/LifecycleModal.svelte';

  // UI Primitives
  import ToastContainer from '#lib/components/ui/ToastContainer.svelte';
  import Spinner from '#lib/components/ui/Spinner.svelte';

  // Component Reactive State
  let handle = $state('');
  let password = $state('');
  let signingIn = $state(false);
  let loginError = $state('');

  const currentSection = $derived(
    SECTIONS.find((s) => s.id === $portal.activeTab) ?? SECTIONS[0]
  );

  async function loadPortal() {
    portal.setLoading(true);
    portal.setError(null);
    try {
      await bootstrap();
      const snapshot = await api.fetchSnapshot();
      portal.setSnapshot(snapshot);
    } catch (caught) {
      const msg = caught instanceof Error ? caught.message : 'Please sign in to manage this account.';
      portal.setError(msg);
    } finally {
      portal.setLoading(false);
    }
  }

  onMount(async () => {
    await loadPortal();
  });

  async function signIn(e: SubmitEvent) {
    e.preventDefault();
    if (!handle.trim() || !password) return;

    signingIn = true;
    loginError = '';
    try {
      const result = await api.login({ handle: handle.trim(), password });
      portal.setSnapshot(result.snapshot);
      toasts.success('Signed in successfully.');
      password = '';
    } catch (caught) {
      loginError = caught instanceof Error ? caught.message : 'Sign-in was not accepted.';
    } finally {
      signingIn = false;
    }
  }

  async function signOut() {
    try {
      await api.logout();
      toasts.info('Signed out of management session.');
    } catch {
      // Non-blocking logout error
    } finally {
      portal.reset();
    }
  }

  function handleSelectSection(sectionId: NavigationSection) {
    portal.selectTab(sectionId);
  }
</script>

<svelte:head>
  <title>Swan / Account</title>
  <meta name="description" content="Account management for Swan." />
</svelte:head>

{#if $portal.loading}
  <main class="min-h-screen flex flex-col items-center justify-center gap-3 p-4" aria-live="polite">
    <span class="loading loading-spinner loading-lg text-primary"></span>
    <p class="text-sm text-base-content/60">Loading account…</p>
  </main>
{:else if $portal.error || !$portal.snapshot}
  <main class="min-h-screen flex items-center justify-center p-4" aria-labelledby="sign-in-title">
    <div class="card bg-base-100 w-full max-w-sm shadow-sm">
      <div class="card-body gap-4">
        <h1 class="card-title text-xl" id="sign-in-title">Sign in</h1>

        {#if $portal.error && $portal.error !== 'Authentication required. Please sign in.'}
          <div class="alert alert-error text-sm" role="alert">
            <span>{$portal.error}</span>
            <button type="button" class="btn btn-xs btn-outline" onclick={loadPortal}>Retry</button>
          </div>
        {/if}

        {#if loginError}
          <div class="alert alert-error text-sm" role="alert">
            <span>{loginError}</span>
          </div>
        {/if}

        <form class="flex flex-col gap-3" onsubmit={signIn}>
          <fieldset class="fieldset gap-1">
            <legend class="fieldset-legend">Handle or DID</legend>
            <input
              class="input w-full"
              bind:value={handle}
              autocomplete="username"
              placeholder="alice.swan.place"
              required
              maxlength="2048"
              disabled={signingIn}
            />
          </fieldset>

          <fieldset class="fieldset gap-1">
            <legend class="fieldset-legend">Password</legend>
            <input
              class="input w-full"
              type="password"
              bind:value={password}
              autocomplete="current-password"
              placeholder="••••••••••••"
              required
              maxlength="4096"
              disabled={signingIn}
            />
          </fieldset>

          <button
            type="submit"
            class="btn btn-primary w-full mt-2"
            disabled={signingIn || !handle || !password}
          >
            {#if signingIn}
              <span class="loading loading-spinner loading-sm"></span> Signing in…
            {:else}
              Sign in
            {/if}
          </button>
        </form>

        <div class="text-center">
          <a class="link text-sm text-base-content/70 hover:text-base-content" href="/oauth/authorize">
            Use OAuth
          </a>
        </div>
      </div>
    </div>
  </main>
{:else}
  <div class="mx-auto w-full max-w-5xl p-4 sm:p-6 flex flex-col gap-4">
    <header class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-base-300">
      <div class="flex items-center gap-3">
        <span class="font-bold text-lg">Swan</span>
        <span class="text-base-content/30">/</span>
        <div class="flex flex-col">
          <span class="font-semibold leading-tight">@{$currentAccount?.handle || 'swan-user'}</span>
          {#if $currentAccount?.did}
            <span class="font-mono break-all text-xs text-base-content/60">{$currentAccount.did}</span>
          {/if}
        </div>
      </div>
      <div class="flex items-center gap-2">
        {#if $portal.lastUpdated}
          <span class="text-xs text-base-content/60">
            Updated {new Date($portal.lastUpdated).toLocaleTimeString()}
          </span>
        {/if}
        <button
          type="button"
          class="btn btn-ghost btn-xs"
          onclick={loadPortal}
          title="Refresh snapshot"
          aria-label="Refresh data"
        >
          ↻
        </button>
        <button type="button" class="btn btn-outline btn-sm" onclick={signOut}>
          Sign out
        </button>
      </div>
    </header>

    <nav class="overflow-x-auto" aria-label="Portal navigation">
      <div class="tabs tabs-box min-w-max" role="tablist">
        {#each SECTIONS as section}
          <button
            type="button"
            role="tab"
            class="tab"
            class:tab-active={$portal.activeTab === section.id}
            aria-selected={$portal.activeTab === section.id}
            onclick={() => handleSelectSection(section.id)}
          >
            {section.label}
          </button>
        {/each}
      </div>
    </nav>

    <main class="flex flex-col gap-4" aria-live="polite">
      <div class="view-viewport" in:fade={{ duration: 120 }}>
        {#if $portal.activeTab === 'overview'}
          <OverviewView />
        {:else if $portal.activeTab === 'profile'}
          <ProfileView />
        {:else if $portal.activeTab === 'security'}
          <SecurityView />
        {:else if $portal.activeTab === 'recovery'}
          <RecoveryView />
        {:else if $portal.activeTab === 'sessions'}
          <SessionsView />
        {:else if $portal.activeTab === 'apps'}
          <AppsView />
        {:else if $portal.activeTab === 'passwords'}
          <PasswordsView />
        {:else if $portal.activeTab === 'export'}
          <ExportView />
        {:else if $portal.activeTab === 'lifecycle'}
          <LifecycleView />
        {/if}
      </div>
    </main>
  </div>
{/if}

<!-- Modal Dialog Controller Mounts -->
<StepUpModal />

<AppPasswordModal
  isOpen={$modals.active?.type === 'app-password' || $modals.active?.type === 'app-password-create' || modals.isOpen('app-password')}
  onClose={() => modals.close('app-password')}
/>

<PasskeyEnrollModal
  isOpen={$modals.active?.type === 'passkey-enroll' || modals.isOpen('passkey-enroll')}
  onClose={() => modals.close('passkey-enroll')}
/>

<TotpEnrollModal
  isOpen={$modals.active?.type === 'totp-enroll' || modals.isOpen('totp-enroll')}
  onClose={() => modals.close('totp-enroll')}
/>

<RecoveryRotateModal
  isOpen={$modals.active?.type === 'recovery-rotate' || modals.isOpen('recovery-rotate')}
  onClose={() => modals.close('recovery-rotate')}
/>

<DidWebModal
  isOpen={$modals.active?.type === 'did-web' || modals.isOpen('did-web')}
  initialMode={$modals.active?.payload?.mode ?? $modals.active?.payload?.initialMode ?? 'new'}
  onClose={() => modals.close('did-web')}
/>

<ExportModal
  isOpen={$modals.active?.type === 'export' || modals.isOpen('export')}
  onClose={() => modals.close('export')}
/>

<LifecycleModal
  isOpen={$modals.active?.type === 'lifecycle-deactivate' || $modals.active?.type === 'lifecycle-delete' || $modals.active?.type === 'lifecycle' || modals.isOpen('lifecycle-deactivate') || modals.isOpen('lifecycle-delete')}
  mode={$modals.active?.type === 'lifecycle-delete' || $modals.active?.payload?.mode === 'delete' ? 'delete' : 'deactivate'}
  onClose={() => modals.close()}
/>

<!-- Toast Notifications Mount -->
<ToastContainer position="bottom-right" />
