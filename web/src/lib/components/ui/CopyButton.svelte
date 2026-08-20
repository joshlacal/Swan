<script lang="ts">
  import { onDestroy } from 'svelte';

  interface Props {
    text: string;
    label?: string;
    copiedLabel?: string;
    title?: string;
    variant?: 'primary' | 'dark' | 'ghost' | 'icon';
    size?: 'sm' | 'md' | 'lg';
    timeout?: number;
    class?: string;
    onCopy?: (text: string) => void;
  }

  let {
    text,
    label = 'Copy',
    copiedLabel = 'Copied',
    title = 'Copy to clipboard',
    variant = 'ghost',
    size = 'md',
    timeout = 2000,
    class: className = '',
    onCopy
  }: Props = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  const sizeClass = $derived(
    size === 'sm' ? 'btn-xs' : size === 'lg' ? 'btn-md' : 'btn-sm'
  );

  const variantClass = $derived.by(() => {
    if (copied) return 'btn-success';
    if (variant === 'primary') return 'btn-primary';
    if (variant === 'dark') return 'btn-neutral';
    return 'btn-ghost';
  });

  async function performCopy() {
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }

      copied = true;
      if (onCopy) onCopy(text);

      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        copied = false;
      }, timeout);
    } catch {
      copied = false;
    }
  }

  onDestroy(() => {
    if (timer) clearTimeout(timer);
  });
</script>

<button
  type="button"
  class="btn {variantClass} {sizeClass} font-mono {variant === 'icon' ? 'btn-square' : ''} {className}"
  title={copied ? copiedLabel : title}
  aria-label={copied ? copiedLabel : title}
  onclick={performCopy}
>
  <span class="inline-flex items-center justify-center shrink-0" aria-hidden="true">
    {#if copied}
      <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
    {:else}
      <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
      </svg>
    {/if}
  </span>

  {#if variant !== 'icon'}
    <span class="leading-none" aria-live="polite">
      {copied ? copiedLabel : label}
    </span>
  {/if}
</button>
