import { writable, derived } from 'svelte/store';
import type { ModalType } from '../types';

export type { ModalType } from '../types';

export interface ModalInstance<T = any> {
  id: string;
  type: ModalType;
  payload?: T;
  title?: string;
  createdAt: number;
}

export interface ModalsState {
  active: ModalInstance | null;
  stack: ModalInstance[];
}

function createModalsStore() {
  const { subscribe, update, set } = writable<ModalsState>({
    active: null,
    stack: []
  });

  function generateId(): string {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    return `modal-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  }

  function open<T = any>(type: ModalType, payload?: T, options?: { title?: string }): string {
    const id = generateId();
    const instance: ModalInstance<T> = {
      id,
      type,
      payload,
      title: options?.title,
      createdAt: Date.now()
    };

    update(() => {
      return {
        active: instance,
        stack: [instance]
      };
    });

    return id;
  }

  function push<T = any>(type: ModalType, payload?: T, options?: { title?: string }): string {
    const id = generateId();
    const instance: ModalInstance<T> = {
      id,
      type,
      payload,
      title: options?.title,
      createdAt: Date.now()
    };

    update((state) => {
      const stack = [...state.stack, instance];
      return {
        active: instance,
        stack
      };
    });

    return id;
  }

  function pop(): ModalInstance | undefined {
    let popped: ModalInstance | undefined;
    update((state) => {
      if (state.stack.length === 0) return state;
      const stack = [...state.stack];
      popped = stack.pop();
      const active = stack.length > 0 ? stack[stack.length - 1] : null;
      return { active, stack };
    });
    return popped;
  }

  function close(idOrType?: string): void {
    update((state) => {
      if (!idOrType) {
        if (state.stack.length <= 1) {
          return { active: null, stack: [] };
        }
        const stack = state.stack.slice(0, -1);
        return { active: stack[stack.length - 1], stack };
      }

      const stack = state.stack.filter((m) => m.id !== idOrType && m.type !== idOrType);
      const active = stack.length > 0 ? stack[stack.length - 1] : null;
      return { active, stack };
    });
  }

  function closeAll(): void {
    set({ active: null, stack: [] });
  }

  function isOpen(type: ModalType): boolean {
    let open = false;
    const unsubscribe = subscribe((state) => {
      open = state.stack.some((m) => m.type === type);
    });
    unsubscribe();
    return open;
  }

  return {
    subscribe,
    open,
    push,
    pop,
    close,
    closeAll,
    isOpen
  };
}

export const modals = createModalsStore();
export const activeModal = derived(modals, ($m) => $m.active);
