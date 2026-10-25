<script lang="ts">
  import { generateQrSvgPath } from '#lib/qrcode.ts';

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
    fgColor = '#000000',
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
  class="bg-base-100 border-base-300 rounded-box border p-3 inline-block {className}"
  role="img"
  aria-label={title}
>
  {#if qrData}
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={qrData.viewBox}
      style="width: {computedSize}; height: {computedSize};"
      shape-rendering="crispEdges"
      aria-hidden="true"
      class="block bg-white rounded"
    >
      <rect width="100%" height="100%" fill={bgColor} />
      <path d={qrData.path} fill={fgColor} />
    </svg>
  {:else}
    <div
      class="grid place-items-center bg-base-200 text-base-content/60 font-mono text-xs rounded"
      style="width: {computedSize}; height: {computedSize};"
      aria-hidden="true"
    >
      <span>No QR code</span>
    </div>
  {/if}
</div>
