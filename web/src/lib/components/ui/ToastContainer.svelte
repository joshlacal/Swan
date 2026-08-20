<script lang="ts">
  import { toasts } from '$lib/stores/toasts';

  interface Props {
    position?: 'top-right' | 'top-center' | 'bottom-right' | 'bottom-center';
  }

  let { position = 'bottom-right' }: Props = $props();

  const positionClass = $derived(
    position === 'bottom-center'
      ? 'toast toast-center toast-bottom'
      : position === 'top-right'
        ? 'toast toast-end toast-top'
        : position === 'top-center'
          ? 'toast toast-center toast-top'
          : 'toast toast-end toast-bottom'
  );

  function alertClass(type: string): string {
    switch (type) {
      case 'success':
        return 'alert alert-success';
      case 'error':
        return 'alert alert-error';
      case 'warning':
        return 'alert alert-warning';
      default:
        return 'alert alert-info';
    }
  }
</script>

<aside
  class="{positionClass} z-50 p-4 max-w-md w-full pointer-events-none"
  role="region"
  aria-label="Notifications"
  aria-live="polite"
  aria-atomic="false"
>
  {#each $toasts as toast (toast.id)}
    <div
      class="{alertClass(toast.type)} shadow-lg pointer-events-auto flex items-start justify-between gap-3 text-sm"
      role={toast.type === 'error' ? 'alert' : 'status'}
    >
      <div class="flex items-start gap-2 min-w-0 flex-1">
        <span class="font-bold shrink-0 mt-0.5" aria-hidden="true">
          {#if toast.type === 'success'}
            ✓
          {:else if toast.type === 'error'}
            ✕
          {:else if toast.type === 'warning'}
            !
          {:else}
            ℹ
          {/if}
        </span>

        <div class="min-w-0 flex-1 break-words">
          {#if toast.title}
            <div class="font-semibold text-xs mb-0.5">{toast.title}</div>
          {/if}
          <div>{toast.message}</div>
        </div>
      </div>

      {#if toast.dismissible}
        <button
          type="button"
          class="btn btn-ghost btn-xs btn-circle shrink-0"
          aria-label="Dismiss notification"
          onclick={() => toasts.dismiss(toast.id)}
        >
          ✕
        </button>
      {/if}
    </div>
  {/each}
</aside>
