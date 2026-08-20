<script lang="ts">
  import { onDestroy, type Snippet } from 'svelte';

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

  const sizeClass = $derived(
    size === 'sm'
      ? 'max-w-sm'
      : size === 'lg'
        ? 'max-w-3xl'
        : size === 'xl'
          ? 'max-w-5xl'
          : 'max-w-lg'
  );

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
    class="modal modal-open"
    role="presentation"
    onclick={handleBackdropClick}
  >
    <div
      bind:this={dialogElement}
      class="modal-box relative {sizeClass} {className}"
      role="dialog"
      aria-modal="true"
      aria-labelledby={title ? titleId : ariaLabel ? undefined : undefined}
      aria-label={ariaLabel}
      aria-describedby={description ? descId : ariaDescribedBy}
      tabindex="-1"
    >
      {#if showCloseButton && !preventClose}
        <button
          type="button"
          class="btn btn-sm btn-circle btn-ghost absolute right-3 top-3 modal-close"
          aria-label="Close dialog"
          onclick={handleClose}
        >
          ✕
        </button>
      {/if}

      {#if header}
        <div class="mb-4">
          {@render header()}
        </div>
      {:else if titleSnippet || title || description}
        <div class="mb-4 pr-8">
          {#if titleSnippet}
            {@render titleSnippet()}
          {:else if title}
            <h3 id={titleId} class="text-lg font-semibold">{title}</h3>
          {/if}
          {#if description}
            <p id={descId} class="text-sm text-base-content/70 mt-1">{description}</p>
          {/if}
        </div>
      {/if}

      <div>
        {@render children?.()}
      </div>

      {#if footer}
        <div class="modal-action mt-6">
          {@render footer()}
        </div>
      {/if}
    </div>

    {#if closeOnBackdrop && !preventClose}
      <div class="modal-backdrop">
        <button type="button" class="cursor-default" aria-label="Close" onclick={handleClose}>
          close
        </button>
      </div>
    {/if}
  </div>
{/if}
