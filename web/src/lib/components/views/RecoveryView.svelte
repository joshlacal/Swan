<script lang="ts">
  import { modals } from '$lib/stores/modals';
  import { activeFactors, currentAccount } from '$lib/stores/portal';

  const hasRecoveryFactor = $derived(
    $activeFactors.some((f) => f.kind === 'recoveryCode')
  );
  const email = $derived($currentAccount?.email || null);
</script>

<div class="flex flex-col gap-6">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body gap-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 class="card-title text-lg">Emergency recovery codes</h2>
          <p class="text-sm text-base-content/70">Single-use backup codes for emergency sign-in when primary authentication factors are unavailable.</p>
        </div>
        {#if hasRecoveryFactor}
          <span class="badge badge-success badge-sm self-start sm:self-auto">Configured</span>
        {:else}
          <span class="badge badge-neutral badge-sm self-start sm:self-auto">Not configured</span>
        {/if}
      </div>

      {#if email}
        <div class="card card-border bg-base-200/50 p-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <div class="text-xs font-semibold uppercase tracking-wider text-base-content/60">Recovery email</div>
              <div class="font-mono text-sm break-all mt-0.5">{email}</div>
            </div>
            <span class="badge badge-sm badge-neutral self-start sm:self-auto">Registered</span>
          </div>
        </div>
      {/if}

      <div class="card card-border bg-base-200/50 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div class="flex items-center gap-3">
          <span class="inline-block w-2.5 h-2.5 rounded-full {hasRecoveryFactor ? 'bg-success' : 'bg-neutral'}"></span>
          <div>
            <div class="font-medium text-sm">
              {hasRecoveryFactor ? '10 single-use recovery codes active' : 'No recovery codes generated'}
            </div>
            <div class="text-xs text-base-content/60">
              {hasRecoveryFactor ? 'Ready for emergency sign-in and step-up authorization' : 'Generate codes to use for emergency account recovery'}
            </div>
          </div>
        </div>
        <button
          type="button"
          class="btn btn-outline btn-sm self-start sm:self-auto"
          onclick={() => modals.open('recovery-rotate')}
        >
          Rotate recovery codes
        </button>
      </div>

      {#if hasRecoveryFactor}
        <div class="grid grid-cols-2 gap-2" aria-label="Active recovery codes">
          {#each Array(10) as _, i}
            <div class="flex items-center justify-between p-2 rounded bg-base-200/60 font-mono text-xs text-base-content/70 border border-base-300">
              <span>{String(i + 1).padStart(2, '0')}.</span>
              <span>••••-••••</span>
            </div>
          {/each}
        </div>
      {/if}

      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div class="card card-border bg-base-200/30 p-3.5">
          <span class="text-xs font-mono text-primary font-semibold">01</span>
          <h3 class="font-medium text-sm mt-1">Single-use</h3>
          <p class="text-xs text-base-content/70 mt-0.5">Each code is invalidated immediately upon verification.</p>
        </div>
        <div class="card card-border bg-base-200/30 p-3.5">
          <span class="text-xs font-mono text-primary font-semibold">02</span>
          <h3 class="font-medium text-sm mt-1">Store offline</h3>
          <p class="text-xs text-base-content/70 mt-0.5">Store codes in an encrypted password manager or safe physical location.</p>
        </div>
        <div class="card card-border bg-base-200/30 p-3.5">
          <span class="text-xs font-mono text-primary font-semibold">03</span>
          <h3 class="font-medium text-sm mt-1">Rotation</h3>
          <p class="text-xs text-base-content/70 mt-0.5">Generating a new set replaces and invalidates all previous codes.</p>
        </div>
      </div>

      <div class="alert alert-info bg-info/10 text-info-content text-xs border border-info/20">
        <span>Viewing or rotating recovery codes requires password confirmation or multi-factor authentication.</span>
      </div>
    </div>
  </section>
</div>
