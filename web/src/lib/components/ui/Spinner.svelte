<script lang="ts">
  interface Props {
    size?: number | string;
    color?: string;
    trackColor?: string;
    borderWidth?: number | string;
    label?: string;
    class?: string;
  }

  let {
    size = 20,
    color = 'var(--teal, #2b7169)',
    trackColor = 'var(--line, #d7d5ca)',
    borderWidth = 2,
    label = 'Loading…',
    class: className = ''
  }: Props = $props();

  const computedSize = $derived(typeof size === 'number' ? `${size}px` : size);
  const computedBorder = $derived(typeof borderWidth === 'number' ? `${borderWidth}px` : borderWidth);
</script>

<div
  class="spinner-container {className}"
  role="status"
  style="--spinner-size: {computedSize}; --spinner-color: {color}; --spinner-track: {trackColor}; --spinner-width: {computedBorder};"
>
  <div class="spinner-disc" aria-hidden="true"></div>
  <span class="sr-only">{label}</span>
</div>

<style>
  .spinner-container {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    vertical-align: middle;
  }

  .spinner-disc {
    width: var(--spinner-size, 20px);
    height: var(--spinner-size, 20px);
    border: var(--spinner-width, 2px) solid var(--spinner-track, #d7d5ca);
    border-top-color: var(--spinner-color, #2b7169);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    box-sizing: border-box;
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .spinner-disc {
      animation-duration: 2s;
    }
  }
</style>
