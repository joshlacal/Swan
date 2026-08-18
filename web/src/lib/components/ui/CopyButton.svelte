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
    copiedLabel = 'Copied!',
    title = 'Copy to clipboard',
    variant = 'ghost',
    size = 'md',
    timeout = 2000,
    class: className = '',
    onCopy
  }: Props = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

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
  class="copy-button {variant} {size} {className}"
  class:copied
  title={copied ? copiedLabel : title}
  aria-label={copied ? copiedLabel : title}
  onclick={performCopy}
>
  <span class="icon" aria-hidden="true">
    {#if copied}
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
    {:else}
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
      </svg>
    {/if}
  </span>

  {#if variant !== 'icon'}
    <span class="label" aria-live="polite">
      {copied ? copiedLabel : label}
    </span>
  {/if}
</button>

<style>
  .copy-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    border: 1px solid transparent;
    cursor: pointer;
    font-family: var(--mono, monospace);
    font-weight: 600;
    transition: background 0.15s, color 0.15s, border-color 0.15s;
    user-select: none;
    border-radius: 2px;
  }

  .copy-button.sm {
    padding: 4px 8px;
    font-size: 10px;
  }

  .copy-button.md {
    padding: 6px 12px;
    font-size: 11px;
  }

  .copy-button.lg {
    padding: 10px 16px;
    font-size: 13px;
  }

  .copy-button.ghost {
    background: transparent;
    color: var(--muted, #687270);
    border-color: var(--line, #d7d5ca);
  }

  .copy-button.ghost:hover {
    color: var(--ink, #1f2827);
    background: #e6e3d9;
  }

  .copy-button.primary {
    background: var(--teal, #2b7169);
    color: #ffffff;
  }

  .copy-button.primary:hover {
    background: var(--teal-deep, #173f3e);
  }

  .copy-button.dark {
    background: var(--ink, #1f2827);
    color: #f7f2e7;
  }

  .copy-button.dark:hover {
    background: #000000;
  }

  .copy-button.icon {
    padding: 6px;
    background: transparent;
    color: var(--muted, #687270);
  }

  .copy-button.icon:hover {
    color: var(--ink, #1f2827);
  }

  .copy-button.copied {
    color: var(--teal, #2b7169);
    border-color: var(--teal, #2b7169);
    background: #dceee1;
  }

  .icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .label {
    line-height: 1;
  }
</style>
