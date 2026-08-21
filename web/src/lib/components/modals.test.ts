import { describe, expect, it } from 'vitest';
import Modal from './ui/Modal.svelte';
import StepUpModal from './modals/StepUpModal.svelte';
import AppPasswordModal from './modals/AppPasswordModal.svelte';
import PasskeyEnrollModal from './modals/PasskeyEnrollModal.svelte';
import TotpEnrollModal from './modals/TotpEnrollModal.svelte';
import RecoveryRotateModal from './modals/RecoveryRotateModal.svelte';
import DidWebModal from './modals/DidWebModal.svelte';
import ExportModal from './modals/ExportModal.svelte';
import LifecycleModal from './modals/LifecycleModal.svelte';

describe('Modal Component Suite Definitions & Contracts', () => {
  it('exports valid Svelte components for all required modals', () => {
    expect(Modal).toBeDefined();
    expect(StepUpModal).toBeDefined();
    expect(AppPasswordModal).toBeDefined();
    expect(PasskeyEnrollModal).toBeDefined();
    expect(TotpEnrollModal).toBeDefined();
    expect(RecoveryRotateModal).toBeDefined();
    expect(DidWebModal).toBeDefined();
    expect(ExportModal).toBeDefined();
    expect(LifecycleModal).toBeDefined();
  });
});
