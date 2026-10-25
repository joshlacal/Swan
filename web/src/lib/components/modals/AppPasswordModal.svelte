<script lang="ts">
  import Modal from '#lib/components/ui/Modal.svelte';
  import CopyButton from '#lib/components/ui/CopyButton.svelte';
  import { api } from '#lib/api.ts';
  import { toasts } from '#lib/stores/toasts.ts';
  import { portal } from '#lib/stores/portal.ts';
  import { APP_PASSWORD_SCOPES, type AppPasswordScope } from '#lib/types.ts';

  interface Props {
    isOpen?: boolean;
    onClose?: () => void;
  }

  let { isOpen = true, onClose }: Props = $props();

  let name = $state('');
  let selectedScopes = $state<Set<string>>(new Set(['atproto']));
  let submitting = $state(false);
  let error = $state<string | null>(null);
  let createdPassword = $state<string | null>(null);

  const scopeLabels: Record<AppPasswordScope, { label: string; desc: string }> = {
    'atproto': {
      label: 'Base AT Protocol access',
      desc: 'Read and create repository records (required).'
    },
    'transition:chat.bsky': {
      label: 'Direct messages (chat.bsky)',
      desc: 'Access Bluesky direct messages.'
    },
    'transition:email': {
      label: 'Email notifications',
      desc: 'Manage email preferences.'
    },
    'transition:generic': {
      label: 'Generic account transition',
      desc: 'Transition operations across services.'
    }
  };

  function toggleScope(scope: string) {
    if (scope === 'atproto') return; // Base scope is required
    const next = new Set(selectedScopes);
    if (next.has(scope)) {
      next.delete(scope);
    } else {
      next.add(scope);
    }
    selectedScopes = next;
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (!name.trim()) {
      error = 'Please enter a name for this app password.';
      return;
    }

    submitting = true;
    error = null;

    try {
      const result = await api.createAppPassword({
        name: name.trim(),
        scopes: Array.from(selectedScopes)
      });

      if (result.password) {
        createdPassword = result.password;
        toasts.success('App password created');
        try {
          const snapshot = await api.fetchSnapshot();
          portal.setSnapshot(snapshot);
        } catch {
          // Non-blocking snapshot refresh
        }
      } else {
        error = 'Server did not return a generated password.';
      }
    } catch (err: any) {
      error = err.message || 'Failed to create app password.';
    } finally {
      submitting = false;
    }
  }

  function handleFinish() {
    name = '';
    selectedScopes = new Set(['atproto']);
    createdPassword = null;
    error = null;
    if (onClose) onClose();
  }
</script>

<Modal
  {isOpen}
  title={createdPassword ? 'App password created' : 'Create app password'}
  description={createdPassword ? undefined : 'Generate a scoped password for clients that do not support OAuth.'}
  size="md"
  preventClose={submitting}
  onClose={handleFinish}
>
  {#if createdPassword}
    <div class="flex flex-col gap-4">
      <div class="alert alert-success text-sm">
        <svg class="h-5 w-5 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
        <div>
          <div class="font-semibold">Generated for {name}</div>
          <div class="text-xs opacity-80">Scopes: {Array.from(selectedScopes).join(' · ')}</div>
        </div>
      </div>

      <div class="card card-border bg-base-200/60 p-4 flex flex-col gap-2">
        <span class="text-xs font-mono font-semibold uppercase tracking-wider text-base-content/60">One-time password</span>
        <div class="flex items-center justify-between gap-3 flex-wrap">
          <code class="font-mono font-semibold text-base break-all bg-base-100 px-3 py-1.5 rounded-box border border-base-300">{createdPassword}</code>
          <CopyButton text={createdPassword} variant="primary" label="Copy password" copiedLabel="Copied" />
        </div>
      </div>

      <div class="alert alert-warning text-sm" role="alert">
        <svg class="h-5 w-5 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <span>Save this password now. It will not be shown again. Anyone with this password can access your account with the selected scopes.</span>
      </div>

      <div class="modal-action mt-2 flex justify-end">
        <button type="button" class="btn btn-primary" onclick={handleFinish}>
          Done
        </button>
      </div>
    </div>
  {:else}
    <form class="flex flex-col gap-5" onsubmit={handleSubmit}>
      {#if error}
        <div class="alert alert-error text-sm" role="alert">
          <span>{error}</span>
        </div>
      {/if}

      <fieldset class="fieldset gap-1">
        <legend class="fieldset-legend text-xs font-semibold uppercase tracking-wider text-base-content/70">App name or device</legend>
        <input
          id="app-name"
          type="text"
          class="input w-full"
          bind:value={name}
          placeholder="e.g. Grayscale iOS, Feed bot"
          maxlength="255"
          required
          disabled={submitting}
        />
      </fieldset>

      <fieldset class="fieldset gap-2">
        <legend class="fieldset-legend text-xs font-semibold uppercase tracking-wider text-base-content/70">Access permissions</legend>
        <div class="flex flex-col gap-2">
          {#each APP_PASSWORD_SCOPES as scope}
            <label
              class="flex items-start gap-3 p-3 rounded-box border border-base-300 bg-base-100 cursor-pointer hover:bg-base-200/50 transition-colors {scope === 'atproto' ? 'opacity-70 cursor-not-allowed bg-base-200/40' : ''}"
            >
              <input
                type="checkbox"
                class="checkbox checkbox-primary checkbox-sm mt-0.5"
                checked={selectedScopes.has(scope)}
                disabled={scope === 'atproto' || submitting}
                onchange={() => toggleScope(scope)}
              />
              <div class="flex flex-col gap-0.5">
                <span class="text-sm font-semibold text-base-content">{scopeLabels[scope]?.label ?? scope}</span>
                {#if scopeLabels[scope]?.desc}
                  <span class="text-xs text-base-content/60">{scopeLabels[scope]?.desc}</span>
                {/if}
              </div>
            </label>
          {/each}
        </div>
      </fieldset>

      <div class="modal-action mt-2 flex justify-end gap-2">
        <button type="button" class="btn btn-ghost" onclick={handleFinish} disabled={submitting}>
          Cancel
        </button>
        <button type="submit" class="btn btn-primary" disabled={submitting || !name.trim()}>
          {#if submitting}
            <span class="loading loading-spinner loading-xs"></span>
            <span>Creating…</span>
          {:else}
            Create password
          {/if}
        </button>
      </div>
    </form>
  {/if}
</Modal>
