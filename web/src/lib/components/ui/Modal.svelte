<script lang="ts">
  import { onDestroy, type Snippet } from 'svelte';
  import { fade, fly } from 'svelte/transition';

  interface Props {
    isOpen?: boolean;
    title?: string;
    description?: string;
    size?: 'sm' | 'md' | 'lg' | 'xl';
    closeOnEscape?: boolean;
    closeOnBackdrop?: boolean;
    preventClose?: boolean;
    showCloseButton?: boolean;
    ariaLabel?: string;
    ariaDescribedBy?: string;
    class?: string;
    onClose?: () => void;
    children?: Snippet;
    header?: Snippet;
    footer?: Snippet;
    titleSnippet?: Snippet;
  }

  let {
    isOpen = true,
    title,
    description,
    size = 'md',
    closeOnEscape = true,
    closeOnBackdrop = true,
    preventClose = false,
    showCloseButton = true,
    ariaLabel,
    ariaDescribedBy,
    class: className = '',
    onClose,
    children,
    header,
    footer,
    titleSnippet
  }: Props = $props();

  const id = `modal-${Math.random().toString(36).substring(2, 9)}`;
  const titleId = `modal-title-${id}`;
  const descId = `modal-desc-${id}`;

  let dialogElement = $state<HTMLElement | null>(null);
  let previousActiveElement: HTMLElement | null = null;

  function handleClose() {
    if (!preventClose && onClose) {
      onClose();
    }
  }

  function handleBackdropClick(e: MouseEvent) {
    if (closeOnBackdrop && !preventClose && e.target === e.currentTarget) {
      handleClose();
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (!isOpen) return;

    if (e.key === 'Escape' && closeOnEscape && !preventClose) {
      e.preventDefault();
      e.stopPropagation();
      handleClose();
      return;
    }

    if (e.key === 'Tab' && dialogElement) {
      const focusables = dialogElement.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])'
      );
      if (focusables.length === 0) return;

      const first = focusables[0];
      const last = focusables[focusables.length - 1];

      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  $effect(() => {
    if (isOpen) {
      if (typeof document !== 'undefined') {
        previousActiveElement = document.activeElement as HTMLElement | null;
        const originalOverflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden';

        const timer = setTimeout(() => {
          if (dialogElement) {
            const auto = dialogElement.querySelector<HTMLElement>('[autofocus]');
            if (auto) {
              auto.focus();
            } else {
              const first = dialogElement.querySelector<HTMLElement>(
                'input:not([disabled]), button:not([disabled]):not(.modal-close), [href], select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])'
              );
              if (first) first.focus();
              else dialogElement.focus();
            }
          }
        }, 50);

        return () => {
          clearTimeout(timer);
          document.body.style.overflow = originalOverflow;
          if (previousActiveElement && typeof previousActiveElement.focus === 'function') {
            previousActiveElement.focus();
          }
        };
      }
    }
  });

  onDestroy(() => {
    if (typeof document !== 'undefined') {
      document.body.style.overflow = '';
    }
  });
</script>

<svelte:window onkeydown={handleKeydown} />

{#if isOpen}
  <div
    class="modal-backdrop"
    in:fade={{ duration: 150 }}
    out:fade={{ duration: 120 }}
    onclick={handleBackdropClick}
    role="presentation"
  >
    <div
      bind:this={dialogElement}
      class="modal-card {size} {className}"
      role="dialog"
      aria-modal="true"
      aria-labelledby={title ? titleId : ariaLabel ? undefined : undefined}
      aria-label={ariaLabel}
      aria-describedby={description ? descId : ariaDescribedBy}
      tabindex="-1"
      in:fly={{ y: 12, duration: 200 }}
      out:fade={{ duration: 120 }}
    >
      <div class="modal-header">
        {#if header}
          {@render header()}
        {:else}
          <div class="title-group">
            {#if titleSnippet}
              {@render titleSnippet()}
            {:else if title}
              <h2 id={titleId} class="modal-title">{title}</h2>
            {/if}
            {#if description}
              <p id={descId} class="modal-desc">{description}</p>
            {/if}
          </div>
        {/if}

        {#if showCloseButton && !preventClose}
          <button
            type="button"
            class="modal-close"
            aria-label="Close dialog"
            onclick={handleClose}
          >
            &times;
          </button>
        {/if}
      </div>

      <div class="modal-body">
        {@render children?.()}
      </div>

      {#if footer}
        <div class="modal-footer">
          {@render footer()}
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    z-index: 9999;
    background: rgba(23, 63, 62, 0.45);
    backdrop-filter: blur(4px);
    display: grid;
    place-items: center;
    padding: 16px;
    overflow-y: auto;
  }

  .modal-card {
    background: var(--paper, #f3f0e9);
    color: var(--ink, #1f2827);
    border: 1px solid var(--line, #d7d5ca);
    border-radius: 2px;
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.16);
    width: 100%;
    max-height: calc(100vh - 32px);
    display: flex;
    flex-direction: column;
    outline: none;
    margin: auto;
  }

  .modal-card.sm { max-width: 400px; }
  .modal-card.md { max-width: 540px; }
  .modal-card.lg { max-width: 720px; }
  .modal-card.xl { max-width: 900px; }

  .modal-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    padding: 24px 28px 16px;
    border-bottom: 1px solid var(--line, #d7d5ca);
    gap: 16px;
  }

  .title-group {
    flex: 1;
    min-width: 0;
  }

  .modal-title {
    margin: 0;
    font-family: var(--serif, 'Iowan Old Style', serif);
    font-weight: 400;
    font-size: 24px;
    line-height: 1.15;
    letter-spacing: -0.02em;
    color: var(--ink, #1f2827);
  }

  .modal-desc {
    margin: 6px 0 0;
    font-family: var(--sans, sans-serif);
    font-size: 13px;
    color: var(--muted, #687270);
    line-height: 1.45;
  }

  .modal-close {
    border: 0;
    background: transparent;
    color: var(--muted, #687270);
    font-size: 24px;
    line-height: 1;
    cursor: pointer;
    padding: 2px 6px;
    margin: -4px -6px 0 0;
    transition: color 0.15s;
  }

  .modal-close:hover {
    color: var(--ink, #1f2827);
  }

  .modal-body {
    padding: 24px 28px;
    overflow-y: auto;
    flex: 1;
  }

  .modal-footer {
    padding: 16px 28px 24px;
    border-top: 1px solid var(--line, #d7d5ca);
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    background: rgba(0, 0, 0, 0.02);
  }

  @media (prefers-reduced-motion: reduce) {
    .modal-backdrop, .modal-card {
      transition: none !important;
      animation: none !important;
    }
  }

  @media (max-width: 560px) {
    .modal-header, .modal-body, .modal-footer {
      padding-left: 20px;
      padding-right: 20px;
    }
    .modal-card {
      max-height: calc(100vh - 16px);
    }
  }
</style>
