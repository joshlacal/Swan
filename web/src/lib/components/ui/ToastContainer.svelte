<script lang="ts">
  import { fade, fly } from 'svelte/transition';
  import { toasts } from '$lib/stores/toasts';

  interface Props {
    position?: 'top-right' | 'top-center' | 'bottom-right' | 'bottom-center';
  }

  let { position = 'bottom-right' }: Props = $props();
</script>

<aside
  class="toast-viewport {position}"
  role="region"
  aria-label="Notifications"
  aria-live="polite"
  aria-atomic="false"
>
  {#each $toasts as toast (toast.id)}
    <div
      class="toast-card {toast.type}"
      role={toast.type === 'error' ? 'alert' : 'status'}
      in:fly={{ y: 16, duration: 220 }}
      out:fade={{ duration: 150 }}
    >
      <div class="toast-indicator" aria-hidden="true">
        {#if toast.type === 'success'}
          ✓
        {:else if toast.type === 'error'}
          ✕
        {:else if toast.type === 'warning'}
          !
        {:else}
          ℹ
        {/if}
      </div>

      <div class="toast-body">
        {#if toast.title}
          <div class="toast-title">{toast.title}</div>
        {/if}
        <div class="toast-message">{toast.message}</div>
      </div>

      {#if toast.dismissible}
        <button
          type="button"
          class="toast-dismiss"
          aria-label="Dismiss notification"
          onclick={() => toasts.dismiss(toast.id)}
        >
          &times;
        </button>
      {/if}
    </div>
  {/each}
</aside>

<style>
  .toast-viewport {
    position: fixed;
    z-index: 10000;
    display: flex;
    flex-direction: column;
    gap: 10px;
    max-width: 420px;
    width: calc(100vw - 32px);
    pointer-events: none;
  }

  .toast-viewport.bottom-right {
    bottom: 24px;
    right: 24px;
  }
  .toast-viewport.bottom-center {
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
  }
  .toast-viewport.top-right {
    top: 24px;
    right: 24px;
  }
  .toast-viewport.top-center {
    top: 24px;
    left: 50%;
    transform: translateX(-50%);
  }

  .toast-card {
    pointer-events: auto;
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px 16px;
    background: var(--paper, #f3f0e9);
    color: var(--ink, #1f2827);
    border: 1px solid var(--line, #d7d5ca);
    border-radius: 2px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
    font-family: var(--sans, 'Avenir Next', sans-serif);
    font-size: 13px;
    line-height: 1.45;
  }

  .toast-card.success {
    background: #dceee1;
    border-color: #badcc3;
    color: var(--teal-deep, #173f3e);
    border-left: 4px solid var(--teal, #2b7169);
  }

  .toast-card.error {
    background: #fbebe8;
    border-color: #f3cdc6;
    color: #662214;
    border-left: 4px solid var(--coral, #ba5e47);
  }

  .toast-card.warning {
    background: #faf4e6;
    border-color: #f1dfb8;
    color: #5c4714;
    border-left: 4px solid var(--ochre, #d1a85b);
  }

  .toast-card.info {
    background: #faf8f1;
    border-color: var(--line, #d7d5ca);
    color: var(--ink, #1f2827);
    border-left: 4px solid var(--teal, #2b7169);
  }

  .toast-indicator {
    font-family: var(--mono, monospace);
    font-weight: 700;
    font-size: 14px;
    line-height: 1.2;
    flex-shrink: 0;
    padding-top: 1px;
  }

  .toast-body {
    flex: 1;
    min-width: 0;
    overflow-wrap: break-word;
  }

  .toast-title {
    font-weight: 600;
    font-size: 12px;
    margin-bottom: 2px;
    letter-spacing: -0.01em;
  }

  .toast-dismiss {
    border: 0;
    background: transparent;
    color: currentColor;
    opacity: 0.6;
    font-size: 18px;
    line-height: 1;
    padding: 0 4px;
    cursor: pointer;
    transition: opacity 0.15s;
  }

  .toast-dismiss:hover {
    opacity: 1;
  }

  @media (prefers-reduced-motion: reduce) {
    .toast-card {
      transition: none !important;
      animation: none !important;
    }
  }

  @media (max-width: 560px) {
    .toast-viewport.bottom-right,
    .toast-viewport.bottom-center {
      bottom: 16px;
      right: 16px;
      left: 16px;
      transform: none;
      width: auto;
    }
  }
</style>
