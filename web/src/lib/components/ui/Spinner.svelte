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
    color,
    trackColor,
    borderWidth,
    label = 'Loading…',
    class: className = ''
  }: Props = $props();

  const sizeClass = $derived.by(() => {
    if (typeof size === 'number') {
      if (size <= 14) return 'loading-xs';
      if (size <= 20) return 'loading-sm';
      if (size <= 28) return 'loading-md';
      return 'loading-lg';
    }
    return '';
  });
</script>

<span
  class="loading loading-spinner {sizeClass} {className}"
  role="status"
  style={color ? `color: ${color};` : undefined}
>
  <span class="sr-only">{label}</span>
</span>
