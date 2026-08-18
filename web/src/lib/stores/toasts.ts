import { writable } from 'svelte/store';
import type { ToastItem, ToastType } from '../types';

export type { ToastItem, ToastType } from '../types';

export interface ToastOptions {
  /** Duration in ms before auto-dismissal. Set to 0 or Infinity for persistent toasts. */
  duration?: number;
  /** Optional title for the notification. */
  title?: string;
  /** Whether the user can manually dismiss the toast. Default: true. */
  dismissible?: boolean;
}

export interface Toast extends ToastOptions {
  id: string;
  type: ToastType;
  message: string;
  createdAt: number;
}

const DEFAULT_DURATIONS: Record<ToastType, number> = {
  info: 5000,
  success: 5000,
  warning: 6000,
  error: 8000
};

const timers = new Map<string, ReturnType<typeof setTimeout>>();

function createToastStore() {
  const { subscribe, update, set } = writable<Toast[]>([]);

  function generateId(): string {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    return `toast-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  }

  function dismiss(id: string): void {
    const timer = timers.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.delete(id);
    }
    update((items) => items.filter((t) => t.id !== id));
  }

  function clear(): void {
    timers.forEach((timer) => clearTimeout(timer));
    timers.clear();
    set([]);
  }

  function add(type: ToastType, message: string, options?: ToastOptions): string {
    const id = generateId();
    const duration = options?.duration !== undefined ? options.duration : DEFAULT_DURATIONS[type];
    const dismissible = options?.dismissible !== false;

    const toast: Toast = {
      id,
      type,
      message,
      title: options?.title,
      duration,
      dismissible,
      createdAt: Date.now()
    };

    update((items) => [...items, toast]);

    if (duration > 0 && duration !== Infinity) {
      const timer = setTimeout(() => {
        dismiss(id);
      }, duration);
      timers.set(id, timer);
    }

    return id;
  }

  return {
    subscribe,
    add,
    info: (message: string, options?: ToastOptions) => add('info', message, options),
    success: (message: string, options?: ToastOptions) => add('success', message, options),
    error: (message: string, options?: ToastOptions) => add('error', message, options),
    warning: (message: string, options?: ToastOptions) => add('warning', message, options),
    dismiss,
    clear
  };
}

export const toasts = createToastStore();
