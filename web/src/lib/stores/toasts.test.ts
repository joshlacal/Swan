import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';
import { toasts } from './toasts';

describe('toasts store', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    toasts.clear();
  });

  afterEach(() => {
    toasts.clear();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('initializes with an empty list', () => {
    expect(get(toasts)).toEqual([]);
  });

  it('adds info, success, error, and warning toasts with proper types', () => {
    const id1 = toasts.info('Info message');
    const id2 = toasts.success('Success message', { title: 'Good job' });
    const id3 = toasts.error('Error message');
    const id4 = toasts.warning('Warning message');

    const items = get(toasts);
    expect(items.length).toBe(4);

    expect(items[0]).toMatchObject({ id: id1, type: 'info', message: 'Info message' });
    expect(items[1]).toMatchObject({ id: id2, type: 'success', message: 'Success message', title: 'Good job' });
    expect(items[2]).toMatchObject({ id: id3, type: 'error', message: 'Error message' });
    expect(items[3]).toMatchObject({ id: id4, type: 'warning', message: 'Warning message' });
  });

  it('dismisses a single toast by ID', () => {
    const id1 = toasts.info('First');
    const id2 = toasts.info('Second');

    expect(get(toasts).length).toBe(2);
    toasts.dismiss(id1);

    const items = get(toasts);
    expect(items.length).toBe(1);
    expect(items[0].id).toBe(id2);
  });

  it('clears all toasts', () => {
    toasts.info('1');
    toasts.info('2');
    toasts.info('3');
    expect(get(toasts).length).toBe(3);

    toasts.clear();
    expect(get(toasts)).toEqual([]);
  });

  it('auto-dismisses toasts after duration', () => {
    toasts.info('Expiring soon', { duration: 3000 });
    expect(get(toasts).length).toBe(1);

    vi.advanceTimersByTime(2999);
    expect(get(toasts).length).toBe(1);

    vi.advanceTimersByTime(2);
    expect(get(toasts).length).toBe(0);
  });

  it('retains persistent toasts with duration 0 or Infinity', () => {
    toasts.info('Persistent', { duration: 0 });
    toasts.error('Also persistent', { duration: Infinity });

    vi.advanceTimersByTime(100000);
    expect(get(toasts).length).toBe(2);
  });
});
