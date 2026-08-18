<script lang="ts">
  import { generateQrSvgPath } from '$lib/qrcode';

  interface Props {
    value: string;
    size?: number | string;
    fgColor?: string;
    bgColor?: string;
    margin?: number;
    title?: string;
    class?: string;
  }

  let {
    value,
    size = 200,
    fgColor = 'var(--ink, #1f2827)',
    bgColor = '#ffffff',
    margin = 2,
    title = 'QR Code',
    class: className = ''
  }: Props = $props();

  const computedSize = $derived(typeof size === 'number' ? `${size}px` : size);

  const qrData = $derived.by(() => {
    if (!value) return null;
    try {
      return generateQrSvgPath(value, { margin });
    } catch {
      return null;
    }
  });
</script>

<div
  class="qr-code-wrapper {className}"
  style="--qr-size: {computedSize}; --qr-bg: {bgColor};"
  role="img"
  aria-label={title}
>
  {#if qrData}
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={qrData.viewBox}
      width="100%"
      height="100%"
      shape-rendering="crispEdges"
      aria-hidden="true"
    >
      <rect width="100%" height="100%" fill="var(--qr-bg)" />
      <path d={qrData.path} fill={fgColor} />
    </svg>
  {:else}
    <div class="qr-placeholder" aria-hidden="true">
      <span>No QR code data</span>
    </div>
  {/if}
</div>

<style>
  .qr-code-wrapper {
    display: inline-block;
    width: var(--qr-size, 200px);
    height: var(--qr-size, 200px);
    background: var(--qr-bg, #ffffff);
    padding: 8px;
    box-sizing: border-box;
    border: 1px solid var(--line, #d7d5ca);
    border-radius: 2px;
  }

  .qr-placeholder {
    width: 100%;
    height: 100%;
    display: grid;
    place-items: center;
    background: #faf8f1;
    color: var(--muted, #687270);
    font-family: var(--mono, monospace);
    font-size: 11px;
  }

  svg {
    display: block;
  }
</style>
