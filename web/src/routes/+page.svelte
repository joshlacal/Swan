<script lang="ts">
  import { onMount } from 'svelte';
  import { fade } from 'svelte/transition';

  // API Client & Stores
  import { api, bootstrap } from '$lib/api';
  import {
    portal,
    SECTIONS,
    currentAccount,
    type NavigationSection
  } from '$lib/stores/portal';
  import { modals, activeModal } from '$lib/stores/modals';
  import { toasts } from '$lib/stores/toasts';
  import { stepup } from '$lib/stores/stepup';

  // Section Views
  import OverviewView from '$lib/components/views/OverviewView.svelte';
  import ProfileView from '$lib/components/views/ProfileView.svelte';
  import SecurityView from '$lib/components/views/SecurityView.svelte';
  import RecoveryView from '$lib/components/views/RecoveryView.svelte';
  import SessionsView from '$lib/components/views/SessionsView.svelte';
  import AppsView from '$lib/components/views/AppsView.svelte';
  import PasswordsView from '$lib/components/views/PasswordsView.svelte';
  import ExportView from '$lib/components/views/ExportView.svelte';
  import LifecycleView from '$lib/components/views/LifecycleView.svelte';

  // Modal Dialogs
  import StepUpModal from '$lib/components/modals/StepUpModal.svelte';
  import AppPasswordModal from '$lib/components/modals/AppPasswordModal.svelte';
  import PasskeyEnrollModal from '$lib/components/modals/PasskeyEnrollModal.svelte';
  import TotpEnrollModal from '$lib/components/modals/TotpEnrollModal.svelte';
  import RecoveryRotateModal from '$lib/components/modals/RecoveryRotateModal.svelte';
  import DidWebModal from '$lib/components/modals/DidWebModal.svelte';
  import ExportModal from '$lib/components/modals/ExportModal.svelte';
  import LifecycleModal from '$lib/components/modals/LifecycleModal.svelte';

  // UI Primitives
  import ToastContainer from '$lib/components/ui/ToastContainer.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

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
  <title>Swan / Account Atlas</title>
  <meta name="description" content="Private account controls and security ceremonies for your Swan data server." />
</svelte:head>

<div class="shell">
  <header class="masthead">
    <a class="wordmark" href="/account" aria-label="Swan account home">
      <span class="mark">✳</span> SWAN <span class="slash">/</span> ACCOUNT ATLAS
    </a>
    <div class="mast-meta">
      <span class="eyebrow">PRIVATE CONTROL PLANE</span>
      <span class="rule" aria-hidden="true"></span>
      <span class="status-dot" aria-label="Encrypted connection"></span>
      {#if $portal.snapshot}
        <button type="button" class="signout-link" onclick={signOut}>Sign out</button>
      {/if}
    </div>
  </header>

  {#if $portal.loading}
    <main class="loading-state" aria-live="polite">
      <Spinner size={32} />
      <p>Reading your private ledger…</p>
    </main>
  {:else if $portal.error || !$portal.snapshot}
    <main class="empty-state" aria-labelledby="sign-in-title">
      <p class="eyebrow">ACCOUNT ATLAS</p>
      <h1 id="sign-in-title">A quiet place for your data.</h1>

      {#if $portal.error && $portal.error !== 'Authentication required. Please sign in.'}
        <div class="error-banner" role="alert">
          <span>{$portal.error}</span>
          <button type="button" class="retry-btn" onclick={loadPortal}>Retry connection</button>
        </div>
      {/if}

      {#if loginError}
        <div class="error-banner" role="alert">{loginError}</div>
      {/if}

      <form class="login-form" onsubmit={signIn}>
        <label>
          <span>Handle or DID</span>
          <input
            bind:value={handle}
            autocomplete="username"
            placeholder="alice.swan.place"
            required
            maxlength="2048"
            disabled={signingIn}
          />
        </label>
        <label>
          <span>Password</span>
          <input
            type="password"
            bind:value={password}
            autocomplete="current-password"
            placeholder="••••••••••••"
            required
            maxlength="4096"
            disabled={signingIn}
          />
        </label>
        <button type="submit" class="button primary" disabled={signingIn || !handle || !password}>
          {#if signingIn}
            <Spinner size={14} color="#ffffff" /> Signing in…
          {:else}
            Sign in securely <span>↗</span>
          {/if}
        </button>
      </form>
      <a class="text-button" href="/oauth/authorize">Use OAuth instead ↗</a>
    </main>
  {:else}
    <div class="layout">
      <aside class="sidebar" aria-label="Account sections">
        <div class="account-chip">
          <div class="avatar">
            {$currentAccount?.handle ? $currentAccount.handle.slice(0, 1).toUpperCase() : 'S'}
          </div>
          <div class="account-meta">
            <strong>@{$currentAccount?.handle || 'swan-user'}</strong>
            <small title={$currentAccount?.did || ''}>{$currentAccount?.did || ''}</small>
          </div>
        </div>

        <nav aria-label="Portal navigation">
          {#each SECTIONS as section}
            <button
              type="button"
              role="tab"
              class:active={$portal.activeTab === section.id}
              aria-selected={$portal.activeTab === section.id}
              onclick={() => handleSelectSection(section.id)}
            >
              <span class="nav-index">{section.number}</span>
              <span class="nav-label">{section.label}</span>
              <small>{section.note}</small>
            </button>
          {/each}
        </nav>

        <div class="sidebar-foot">
          <span class="status-dot"></span>
          <span>Encrypted at rest</span>
          <span class="version">v1.0</span>
        </div>
      </aside>

      <main class="content" aria-live="polite">
        <div class="content-head">
          <div>
            <p class="eyebrow">
              {$portal.activeTab === 'overview' ? 'WELCOME BACK' : currentSection.note.toUpperCase()}
            </p>
            <h1>{currentSection.label}</h1>
          </div>
          <div class="head-actions">
            <span class="last-seen">
              {$portal.lastUpdated ? `Updated ${new Date($portal.lastUpdated).toLocaleTimeString()}` : 'Connected'}
            </span>
            <button type="button" class="refresh-btn" onclick={loadPortal} title="Refresh snapshot" aria-label="Refresh data">
              ↻
            </button>
          </div>
        </div>

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

  <footer class="footer">
    <span>SWAN ACCOUNT ATLAS</span>
    <span>Local-first. Open protocol. Quietly yours.</span>
    <span>Privacy ↗</span>
  </footer>
</div>

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

<style>
  :global(*) {
    box-sizing: border-box;
  }
  :global(body) {
    margin: 0;
    background: var(--paper);
    color: var(--ink);
    font-family: var(--sans);
  }
  :global(:root) {
    --paper: #f3f0e9;
    --ink: #1f2827;
    --muted: #687270;
    --line: #d7d5ca;
    --teal: #2b7169;
    --teal-deep: #173f3e;
    --ochre: #d1a85b;
    --coral: #ba5e47;
    --sans: "Avenir Next", "Helvetica Neue", sans-serif;
    --serif: "Iowan Old Style", "Palatino Linotype", Palatino, serif;
    --mono: "SFMono-Regular", Consolas, monospace;
  }
  :global(button),
  :global(a) {
    font: inherit;
  }
  :global(button) {
    cursor: pointer;
  }

  .shell {
    min-height: 100vh;
    max-width: 1600px;
    margin: auto;
    padding: 0 4vw;
  }

  .masthead {
    height: 92px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--line);
  }

  .wordmark {
    color: var(--ink);
    text-decoration: none;
    letter-spacing: 0.16em;
    font-size: 12px;
    font-weight: 700;
  }
  .mark {
    color: var(--teal);
    font-size: 22px;
    margin-right: 9px;
  }
  .slash {
    color: var(--ochre);
    margin: 0 8px;
  }

  .mast-meta,
  .sidebar-foot {
    display: flex;
    align-items: center;
    gap: 12px;
    color: var(--muted);
  }

  .eyebrow {
    display: block;
    font: 600 10px/1.3 var(--mono);
    color: var(--muted);
    letter-spacing: 0.14em;
  }

  .rule {
    width: 55px;
    height: 1px;
    background: var(--line);
  }

  .status-dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    background: #4a9b78;
    border-radius: 50%;
    box-shadow: 0 0 0 4px rgba(74, 155, 120, 0.14);
  }

  .signout-link {
    border: 0;
    background: none;
    color: var(--muted);
    font: 11px var(--mono);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 2px;
  }
  .signout-link:hover {
    color: var(--ink);
    text-decoration: underline;
  }

  .layout {
    display: grid;
    grid-template-columns: 260px 1fr;
    min-height: calc(100vh - 152px);
  }

  .sidebar {
    border-right: 1px solid var(--line);
    padding: 34px 28px 28px 0;
    display: flex;
    flex-direction: column;
  }

  .account-chip {
    display: flex;
    gap: 12px;
    align-items: center;
    padding-bottom: 30px;
    border-bottom: 1px solid var(--line);
  }

  .avatar {
    width: 38px;
    height: 38px;
    border-radius: 50%;
    background: var(--teal-deep);
    color: #e9e5d8;
    display: grid;
    place-items: center;
    font: 700 14px var(--serif);
    flex-shrink: 0;
  }

  .account-meta {
    min-width: 0;
  }

  .account-chip strong {
    font-size: 13px;
    display: block;
    color: var(--ink);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .account-chip small {
    display: block;
    color: var(--muted);
    font: 10px var(--mono);
    margin-top: 5px;
    max-width: 170px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .sidebar nav {
    display: grid;
    gap: 3px;
    padding-top: 23px;
  }

  .sidebar nav button {
    position: relative;
    border: 0;
    background: transparent;
    text-align: left;
    color: var(--muted);
    display: grid;
    grid-template-columns: 28px 1fr;
    padding: 11px 12px;
    border-radius: 2px;
    transition: color 0.2s, background 0.2s;
    cursor: pointer;
  }

  .sidebar nav button:hover,
  .sidebar nav button.active {
    color: var(--ink);
    background: #e6e3d9;
  }

  .sidebar nav button.active:before {
    content: '';
    position: absolute;
    left: -28px;
    top: 0;
    bottom: 0;
    width: 3px;
    background: var(--teal);
  }

  .nav-index {
    font: 10px var(--mono);
    opacity: 0.6;
  }

  .nav-label {
    font-weight: 500;
    font-size: 13px;
  }

  .sidebar nav small {
    grid-column: 2;
    font-size: 10px;
    margin-top: 3px;
    color: var(--muted);
  }

  .sidebar-foot {
    margin-top: auto;
    padding-top: 22px;
    border-top: 1px solid var(--line);
    font: 10px var(--mono);
  }

  .version {
    margin-left: auto;
    opacity: 0.6;
  }

  .content {
    padding: 54px 0 60px 6vw;
    max-width: 1150px;
    width: 100%;
  }

  .content-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    margin-bottom: 35px;
  }

  .content-head h1 {
    font: 400 clamp(38px, 5vw, 66px) / 0.95 var(--serif);
    margin: 10px 0 0;
    letter-spacing: -0.04em;
    color: var(--ink);
  }

  .head-actions {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .last-seen {
    font: 10px var(--mono);
    color: var(--muted);
  }

  .refresh-btn {
    border: 1px solid var(--line);
    background: transparent;
    color: var(--muted);
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    font-size: 14px;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }

  .refresh-btn:hover {
    background: #e6e3d9;
    color: var(--ink);
  }

  .loading-state,
  .empty-state {
    min-height: calc(100vh - 180px);
    display: grid;
    place-content: center;
    text-align: center;
  }

  .loading-state p {
    color: var(--muted);
    font: 12px var(--mono);
    margin-top: 16px;
  }

  .empty-state h1 {
    font: 400 52px var(--serif);
    margin: 16px 0 24px;
    color: var(--ink);
  }

  .error-banner {
    background: #faeae6;
    border: 1px solid #e2c0b6;
    color: var(--coral);
    padding: 12px 18px;
    border-radius: 2px;
    font-size: 13px;
    max-width: 420px;
    margin: 0 auto 20px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    align-items: center;
  }

  .retry-btn {
    border: 1px solid var(--coral);
    background: transparent;
    color: var(--coral);
    font: 11px var(--mono);
    padding: 4px 10px;
    border-radius: 2px;
    cursor: pointer;
  }

  .login-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
    width: 100%;
    max-width: 380px;
    margin: 0 auto 24px;
    text-align: left;
  }

  .login-form label {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .login-form label span {
    font: 10px var(--mono);
    color: var(--muted);
    letter-spacing: 0.1em;
  }

  .login-form input {
    background: #faf8f1;
    border: 1px solid var(--line);
    padding: 10px 12px;
    font-size: 14px;
    border-radius: 2px;
    font-family: inherit;
    color: var(--ink);
  }

  .login-form input:focus {
    outline: 2px solid var(--teal);
    border-color: var(--teal);
  }

  .button {
    border: 1px solid transparent;
    padding: 11px 16px;
    font-size: 13px;
    font-weight: 600;
    display: inline-flex;
    justify-content: center;
    align-items: center;
    gap: 10px;
    text-decoration: none;
    cursor: pointer;
    border-radius: 2px;
    transition: opacity 0.15s;
  }

  .button:hover:not(:disabled) {
    opacity: 0.9;
  }

  .button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .button.primary {
    background: var(--teal);
    color: white;
  }

  .text-button {
    border: 0;
    background: none;
    color: var(--teal);
    font-size: 13px;
    font-weight: 600;
    text-decoration: none;
    margin-top: 8px;
    display: inline-block;
  }

  .text-button:hover {
    text-decoration: underline;
  }

  .footer {
    border-top: 1px solid var(--line);
    height: 60px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--muted);
    font: 10px var(--mono);
    letter-spacing: 0.04em;
  }

  .footer span:nth-child(2) {
    font-family: var(--serif);
    font-size: 12px;
    font-style: italic;
  }

  .footer span:last-child {
    color: var(--teal);
  }

  @media (prefers-reduced-motion: reduce) {
    :global(*) {
      scroll-behavior: auto !important;
      animation-duration: 0.01ms !important;
      transition-duration: 0.01ms !important;
    }
  }

  @media (max-width: 900px) {
    .layout {
      grid-template-columns: 1fr;
    }
    .sidebar {
      border-right: 0;
      padding: 22px 0;
      border-bottom: 1px solid var(--line);
    }
    .sidebar nav {
      display: flex;
      overflow-x: auto;
      padding: 15px 0 0;
      gap: 6px;
    }
    .sidebar nav button {
      min-width: 130px;
      padding: 10px;
    }
    .sidebar nav button.active:before {
      left: 0;
      right: 0;
      bottom: -1px;
      top: auto;
      width: auto;
      height: 3px;
    }
    .sidebar nav small,
    .nav-index {
      display: none;
    }
    .sidebar-foot {
      display: none;
    }
    .content {
      padding: 38px 0;
    }
    .footer {
      height: auto;
      padding: 18px 0;
      gap: 12px;
      flex-wrap: wrap;
    }
    .footer span:nth-child(2) {
      order: 3;
      width: 100%;
    }
  }

  @media (max-width: 560px) {
    .masthead {
      height: 72px;
    }
    .mast-meta {
      display: none;
    }
    .wordmark {
      font-size: 10px;
    }
    .content-head {
      align-items: flex-start;
    }
    .head-actions {
      display: none;
    }
    .content-head h1 {
      font-size: 47px;
    }
    .footer span:first-child,
    .footer span:last-child {
      font-size: 9px;
    }
  }
</style>
