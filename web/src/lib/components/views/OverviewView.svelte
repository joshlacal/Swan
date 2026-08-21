<script lang="ts">
  import {
    portal,
    currentAccount,
    currentIdentity,
    activeSessions,
    activeApps,
    activeFactors
  } from '$lib/stores/portal';
  import { modals } from '$lib/stores/modals';
</script>

<div class="flex flex-col gap-6">
  <!-- Account Stats Grid -->
  <section aria-label="Account overview statistics" class="stats stats-vertical sm:stats-horizontal bg-base-100 shadow-sm border border-base-200 w-full">
    <div class="stat">
      <div class="stat-title text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Identity</div>
      <div class="stat-value text-2xl font-semibold">{$currentIdentity?.method === 'didWeb' ? 'did:web' : 'PLC'}</div>
      <div class="stat-desc mt-1">
        <span class="badge badge-sm badge-success">{$currentIdentity?.state ?? 'Active'}</span>
      </div>
    </div>
    <div class="stat">
      <div class="stat-title text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Active sessions</div>
      <div class="stat-value text-2xl font-semibold">{$activeSessions.length}</div>
      <div class="stat-desc mt-1">Connected devices</div>
    </div>
    <div class="stat">
      <div class="stat-title text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Connected apps</div>
      <div class="stat-value text-2xl font-semibold">{$activeApps.length}</div>
      <div class="stat-desc mt-1">Authorized OAuth clients</div>
    </div>
    <div class="stat">
      <div class="stat-title text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Auth factors</div>
      <div class="stat-value text-2xl font-semibold">{$activeFactors.length}</div>
      <div class="stat-desc mt-1">Enrolled credentials</div>
    </div>
  </section>

  <!-- Identity & Sessions Panels -->
  <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <section class="card bg-base-100 shadow-sm border border-base-200">
      <div class="card-body gap-4">
        <div class="flex items-start justify-between gap-4">
          <div>
            <span class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Identity</span>
            <h2 class="card-title text-lg mt-1">Account identifier</h2>
          </div>
          <button type="button" class="btn btn-ghost btn-sm" onclick={() => portal.selectTab('profile')}>
            Manage
          </button>
        </div>

        <div class="flex items-center justify-between gap-4 p-4 rounded-lg bg-base-200/60 border border-base-200">
          <div class="min-w-0">
            <div class="font-semibold text-base">@{$currentAccount?.handle || 'swan-user'}</div>
            <div class="font-mono break-all text-xs text-base-content/60 mt-1">{$currentAccount?.did || 'did:plc:...'}</div>
          </div>
          <span class="badge badge-success shrink-0">Verified</span>
        </div>
      </div>
    </section>

    <section class="card bg-base-100 shadow-sm border border-base-200">
      <div class="card-body gap-4">
        <div>
          <span class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Sessions</span>
          <h2 class="card-title text-lg mt-1">Device access</h2>
        </div>
        <p class="text-sm text-base-content/70">
          Review active devices with access to your account.
        </p>
        <div class="card-actions mt-auto pt-2">
          <button type="button" class="btn btn-outline btn-sm" onclick={() => portal.selectTab('sessions')}>
            Review sessions
          </button>
        </div>
      </div>
    </section>
  </div>

  <!-- Quick Actions -->
  <section class="card bg-base-100 shadow-sm border border-base-200">
    <div class="card-body gap-4">
      <div>
        <span class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">Shortcuts</span>
        <h2 class="card-title text-lg mt-1">Quick actions</h2>
      </div>
      <div class="flex flex-wrap gap-3 pt-1">
        <button type="button" class="btn btn-primary btn-sm" onclick={() => modals.open('passkey-enroll')}>
          Add passkey
        </button>
        <button type="button" class="btn btn-outline btn-sm" onclick={() => modals.open('app-password')}>
          Add app password
        </button>
        <button type="button" class="btn btn-outline btn-sm" onclick={() => modals.open('export')}>
          Export data
        </button>
      </div>
    </div>
  </section>
</div>
