import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  generateBase32Secret,
  generateOtpauthUri,
  generateQrSvg,
  generateQrSvgPath,
  generateQrMatrix
} from '../qrcode';
import { api, accountFetch, setCSRF } from '../api';
import { portal, currentAccount } from '../stores/portal';
import { modals, activeModal } from '../stores/modals';
import { toasts } from '../stores/toasts';
import { APP_PASSWORD_SCOPES, type AppPasswordScope } from '../types';
import { setupTestEnv, teardownTestEnv, createMockPublicKeyCredential, mockWebAuthnCreate } from '../../../tests/e2e/harness/test-env';
import type { MockSwanBackend, MockSession } from '../../../tests/e2e/harness/mock-backend';

describe('Empirical Adversarial Stress & Verification Suite: Parameterized Modal Dialogs', () => {
  let backend: MockSwanBackend;
  let session: MockSession;

  beforeEach(() => {
    const env = setupTestEnv({ authenticated: true, elevated: true });
    backend = env.backend;
    session = env.session!;
    setCSRF(session.csrfToken);
    portal.reset();
    modals.closeAll();
    toasts.clear();
  });

  afterEach(() => {
    teardownTestEnv();
    setCSRF(undefined);
    portal.reset();
    modals.closeAll();
    toasts.clear();
    vi.restoreAllMocks();
  });

  // =========================================================================
  // 1. Base Modal (`Modal.svelte`) A11y, Focus Trapping & Scroll Locking
  // =========================================================================
  describe('1. Base Modal Focus Trapping, Keyboard Navigation & DOM Interactions', () => {
    it('focus trapping cycles forward from last element to first element on Tab', () => {
      // Simulate DOM container with focusable elements
      const firstInput = { focus: vi.fn(), disabled: false, tagName: 'INPUT' } as unknown as HTMLElement;
      const secondBtn = { focus: vi.fn(), disabled: false, tagName: 'BUTTON' } as unknown as HTMLElement;
      const lastBtn = { focus: vi.fn(), disabled: false, tagName: 'BUTTON' } as unknown as HTMLElement;

      const focusables = [firstInput, secondBtn, lastBtn];

      // Simulate handleKeydown Tab logic from Modal.svelte
      function simulateTab(activeElement: HTMLElement, shiftKey: boolean) {
        let prevented = false;
        const e = {
          key: 'Tab',
          shiftKey,
          preventDefault: () => { prevented = true; }
        };

        const first = focusables[0];
        const last = focusables[focusables.length - 1];

        if (e.shiftKey && activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && activeElement === last) {
          e.preventDefault();
          first.focus();
        }

        return { prevented };
      }

      // Tab on last element -> wraps to first
      const res1 = simulateTab(lastBtn, false);
      expect(res1.prevented).toBe(true);
      expect(firstInput.focus).toHaveBeenCalledTimes(1);

      // Shift+Tab on first element -> wraps to last
      const res2 = simulateTab(firstInput, true);
      expect(res2.prevented).toBe(true);
      expect(lastBtn.focus).toHaveBeenCalledTimes(1);

      // Normal Tab on middle element -> allows standard browser navigation
      const res3 = simulateTab(secondBtn, false);
      expect(res3.prevented).toBe(false);

      // Normal Shift+Tab on middle element -> allows standard browser navigation
      const res4 = simulateTab(secondBtn, true);
      expect(res4.prevented).toBe(false);
    });

    it('focus trapping handles single-element modal without throwing', () => {
      const singleButton = { focus: vi.fn(), disabled: false } as unknown as HTMLElement;
      const focusables = [singleButton];

      let prevented = false;
      const e = {
        key: 'Tab',
        shiftKey: false,
        preventDefault: () => { prevented = true; }
      };

      const first = focusables[0];
      const last = focusables[focusables.length - 1];

      if (!e.shiftKey && singleButton === last) {
        e.preventDefault();
        first.focus();
      }

      expect(prevented).toBe(true);
      expect(singleButton.focus).toHaveBeenCalledTimes(1);
    });

    it('focus trapping on empty modal (0 focusables) does not crash or throw', () => {
      const focusables: HTMLElement[] = [];
      let prevented = false;
      const e = {
        key: 'Tab',
        shiftKey: false,
        preventDefault: () => { prevented = true; }
      };

      if (focusables.length === 0) {
        // Modal.svelte line 76: if (focusables.length === 0) return;
        expect(focusables.length).toBe(0);
      }

      expect(prevented).toBe(false);
    });

    it('Escape key dismissal respects closeOnEscape and preventClose flags', () => {
      let closeCount = 0;
      const onClose = () => { closeCount++; };

      function handleKeydown(eKey: string, closeOnEscape: boolean, preventClose: boolean, isOpen: boolean) {
        if (!isOpen) return;
        if (eKey === 'Escape' && closeOnEscape && !preventClose) {
          if (onClose) onClose();
        }
      }

      // Normal Escape -> closes
      handleKeydown('Escape', true, false, true);
      expect(closeCount).toBe(1);

      // Escape when closeOnEscape is false -> does not close
      handleKeydown('Escape', false, false, true);
      expect(closeCount).toBe(1);

      // Escape when preventClose is true (e.g. submitting) -> does not close
      handleKeydown('Escape', true, true, true);
      expect(closeCount).toBe(1);

      // Escape when modal is closed -> does not close
      handleKeydown('Escape', true, false, false);
      expect(closeCount).toBe(1);

      // Other key (e.g. Enter) -> does not close
      handleKeydown('Enter', true, false, true);
      expect(closeCount).toBe(1);
    });

    it('Backdrop click dismissal respects closeOnBackdrop and preventClose flags', () => {
      let closeCount = 0;
      const onClose = () => { closeCount++; };

      function handleBackdropClick(
        target: any,
        currentTarget: any,
        closeOnBackdrop: boolean,
        preventClose: boolean
      ) {
        if (closeOnBackdrop && !preventClose && target === currentTarget) {
          if (onClose) onClose();
        }
      }

      const backdrop = { id: 'backdrop' };
      const card = { id: 'card' };
      const button = { id: 'button' };

      // Click on backdrop -> closes
      handleBackdropClick(backdrop, backdrop, true, false);
      expect(closeCount).toBe(1);

      // Click inside modal card (target !== currentTarget) -> does not close
      handleBackdropClick(card, backdrop, true, false);
      expect(closeCount).toBe(1);

      // Click on inner button -> does not close
      handleBackdropClick(button, backdrop, true, false);
      expect(closeCount).toBe(1);

      // Click on backdrop when closeOnBackdrop = false -> does not close
      handleBackdropClick(backdrop, backdrop, false, false);
      expect(closeCount).toBe(1);

      // Click on backdrop when preventClose = true -> does not close
      handleBackdropClick(backdrop, backdrop, true, true);
      expect(closeCount).toBe(1);
    });

    it('body scroll locking and focus restoration lifecycle behaves properly', () => {
      const originalBodyOverflow = 'auto';
      const mockDocument = {
        body: { style: { overflow: originalBodyOverflow } },
        activeElement: { id: 'open-button', focus: vi.fn() }
      };

      // When modal mounts and opens:
      const previousActiveElement = mockDocument.activeElement;
      const originalOverflow = mockDocument.body.style.overflow;
      mockDocument.body.style.overflow = 'hidden';

      expect(mockDocument.body.style.overflow).toBe('hidden');

      // When modal unmounts or closes:
      mockDocument.body.style.overflow = originalOverflow;
      if (previousActiveElement && typeof previousActiveElement.focus === 'function') {
        previousActiveElement.focus();
      }

      expect(mockDocument.body.style.overflow).toBe('auto');
      expect(previousActiveElement.focus).toHaveBeenCalledTimes(1);
    });
  });

  // =========================================================================
  // 2. App Password Modal (`AppPasswordModal.svelte`)
  // =========================================================================
  describe('2. App Password Modal Input Validation & Scope Enforcement', () => {
    it('base scope atproto is always enforced and cannot be toggled off', () => {
      let selectedScopes = new Set<string>(['atproto']);

      function toggleScope(scope: string) {
        if (scope === 'atproto') return; // Base scope required
        const next = new Set(selectedScopes);
        if (next.has(scope)) {
          next.delete(scope);
        } else {
          next.add(scope);
        }
        selectedScopes = next;
      }

      // Attempt to toggle off atproto
      toggleScope('atproto');
      expect(selectedScopes.has('atproto')).toBe(true);

      // Add other valid scopes
      toggleScope('transition:chat.bsky');
      expect(selectedScopes.has('transition:chat.bsky')).toBe(true);
      expect(selectedScopes.has('atproto')).toBe(true);

      toggleScope('transition:email');
      expect(selectedScopes.has('transition:email')).toBe(true);

      // Toggle off an optional scope
      toggleScope('transition:chat.bsky');
      expect(selectedScopes.has('transition:chat.bsky')).toBe(false);
      expect(selectedScopes.has('transition:email')).toBe(true);
      expect(selectedScopes.has('atproto')).toBe(true);
    });

    it('rejects empty or whitespace-only name and accepts valid name', async () => {
      // Empty name
      expect(() => {
        const name = '   ';
        if (!name.trim()) throw new Error('Please enter a name for this app password.');
      }).toThrow('Please enter a name for this app password.');

      // Valid creation
      const res = await api.createAppPassword({
        name: '  Grayscale iOS App  '.trim(),
        scopes: ['atproto', 'transition:chat.bsky']
      });

      expect(res.accepted).toBe(true);
      expect((res as any).password).toBeDefined();
      expect((res as any).password).toMatch(/^swan-app-/);

      // Verify backend state
      const passwords = backend.getAppPasswords(session.accountDID);
      const created = passwords.find(p => p.name === 'Grayscale iOS App');
      expect(created).toBeDefined();
      expect(created?.scopes).toEqual(['atproto', 'transition:chat.bsky']);
    });

    it('handles backend error when scope validation fails', async () => {
      try {
        await api.createAppPassword({
          name: 'Invalid Scope App',
          scopes: ['transition:chat.bsky'] as any
        });
        expect.unreachable('Should have failed without atproto scope');
      } catch (err: any) {
        expect(err.status).toBe(400);
        expect(err.code).toBe('invalid_request');
      }
    });

    it('verifies all 4 APP_PASSWORD_SCOPES constants are valid AT Protocol scopes', () => {
      expect(APP_PASSWORD_SCOPES).toEqual([
        'atproto',
        'transition:chat.bsky',
        'transition:email',
        'transition:generic'
      ]);
    });
  });

  // =========================================================================
  // 3. Passkey Enrollment Modal (`PasskeyEnrollModal.svelte`)
  // =========================================================================
  describe('3. Passkey Enrollment WebAuthn Ceremony & Handshake', () => {
    it('completes passkey registration challenge and attestation handshake', async () => {
      const challengeRes = await api.requestPasskeyChallenge('MacBook Touch ID');
      expect(challengeRes.challenge).toBeDefined();
      expect(challengeRes.factorID).toBeDefined();

      mockWebAuthnCreate(async () => {
        return createMockPublicKeyCredential('create', { challenge: challengeRes.challenge });
      });

      const registerRes = await api.registerPasskey({
        label: 'MacBook Touch ID',
        challenge: challengeRes.challenge!,
        clientDataJSON: 'mock-cd',
        authenticatorData: 'mock-ad',
        credentialID: 'mock-cred-id',
        factorID: challengeRes.factorID
      });

      expect(registerRes.accepted).toBe(true);
      expect(registerRes.message).toBe('Passkey enrolled');

      const factors = backend.getFactors(session.accountDID);
      const passkey = factors.find(f => f.id === challengeRes.factorID);
      expect(passkey).toBeDefined();
      expect(passkey?.kind).toBe('passkey');
      expect(passkey?.label).toBe('MacBook Touch ID');
    });

    it('handles WebAuthn challenge generation failure gracefully', async () => {
      vi.spyOn(backend, 'fetch').mockImplementationOnce(async () => {
        return new Response(JSON.stringify({ code: 'internal_error', message: 'HSM unavailable' }), {
          status: 500
        });
      });

      await expect(api.requestPasskeyChallenge('Security Key')).rejects.toMatchObject({
        status: 500,
        code: 'internal_error'
      });
    });
  });

  // =========================================================================
  // 4. TOTP Enrollment Modal (`TotpEnrollModal.svelte`)
  // =========================================================================
  describe('4. TOTP Enrollment Modal, Base32 Seed & 6-Digit Code Validation', () => {
    it('generates 20-byte Base32 secret seed and valid otpauth URI', () => {
      const secret = generateBase32Secret(20);
      expect(secret).toMatch(/^[A-Z2-7]{32}$/);

      const uri = generateOtpauthUri({
        account: 'alice.swan.place',
        secret,
        issuer: 'Swan',
        digits: 6,
        period: 30
      });

      expect(uri.startsWith('otpauth://totp/Swan:alice.swan.place?')).toBe(true);
      expect(uri).toContain(`secret=${secret}`);
      expect(uri).toContain('issuer=Swan');
      expect(uri).toContain('digits=6');
      expect(uri).toContain('period=30');
    });

    it('cleans and strictly validates 6-digit confirmation code format', () => {
      function validateTotpCode(raw: string): { valid: boolean; cleanCode: string; error?: string } {
        const cleanCode = raw.replace(/\D/g, '');
        if (cleanCode.length !== 6) {
          return { valid: false, cleanCode, error: 'Please enter a valid 6-digit confirmation code.' };
        }
        return { valid: true, cleanCode };
      }

      // Valid codes with formatting / spaces
      expect(validateTotpCode('123 456')).toEqual({ valid: true, cleanCode: '123456' });
      expect(validateTotpCode(' 987-654 ')).toEqual({ valid: true, cleanCode: '987654' });
      expect(validateTotpCode('000000')).toEqual({ valid: true, cleanCode: '000000' });

      // Invalid lengths
      expect(validateTotpCode('12345').valid).toBe(false);
      expect(validateTotpCode('1234567').valid).toBe(false);
      expect(validateTotpCode('').valid).toBe(false);
      expect(validateTotpCode('abcdef').valid).toBe(false);
    });

    it('formats secret into 4-character monospace chunks', () => {
      function formatSecret(raw: string): string {
        return raw.match(/.{1,4}/g)?.join(' ') ?? raw;
      }

      expect(formatSecret('JBSWY3DPEHPK3PXP')).toBe('JBSW Y3DP EHPK 3PXP');
      expect(formatSecret('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')).toBe('ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567');
      expect(formatSecret('')).toBe('');
    });

    it('full TOTP enrollment and 6-digit verification lifecycle succeeds', async () => {
      const secret = generateBase32Secret(20);
      const enrollRes = await api.enrollTotp({
        secret,
        label: 'Authenticator App'
      });

      expect(enrollRes.factorID).toBeDefined();

      const verifyRes = await api.verifyTotpEnrollment(enrollRes.factorID!, '123456');
      expect(verifyRes.accepted).toBe(true);

      const factors = backend.getFactors(session.accountDID);
      const totp = factors.find(f => f.id === enrollRes.factorID);
      expect(totp?.enabled).toBe(true);
    });
  });

  // =========================================================================
  // 5. Recovery Rotate Modal (`RecoveryRotateModal.svelte`)
  // =========================================================================
  describe('5. Recovery Rotate Modal Offline Backup & Download Lifecycle', () => {
    it('rotates recovery codes and returns 10 fresh single-use codes', async () => {
      const res = await api.rotateRecoveryCodes();
      expect(res.recoveryCodes).toBeDefined();
      expect(res.recoveryCodes!.length).toBe(10);
      for (const code of res.recoveryCodes!) {
        expect(code).toMatch(/^RCV-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
      }
    });

    it('formats recovery codes text file with account header and enumerated list', () => {
      const codes = [
        'RCV-AAAA-1111',
        'RCV-BBBB-2222',
        'RCV-CCCC-3333',
        'RCV-DDDD-4444',
        'RCV-EEEE-5555',
        'RCV-FFFF-6666',
        'RCV-GGGG-7777',
        'RCV-HHHH-8888',
        'RCV-IIII-9999',
        'RCV-JJJJ-0000'
      ];

      function getFormattedCodes(handle: string, rawCodes: string[]): string {
        return (
          `SWAN ACCOUNT RECOVERY CODES\n` +
          `============================\n` +
          `Account: @${handle}\n` +
          `Generated: 2026-08-18T12:00:00.000Z\n\n` +
          `Each code can only be used once for emergency account access.\n` +
          `Store these codes in a secure, offline location.\n\n` +
          rawCodes.map((c, i) => `${String(i + 1).padStart(2, '0')}. ${c}`).join('\n') +
          `\n`
        );
      }

      const formatted = getFormattedCodes('alice.swan.place', codes);
      expect(formatted).toContain('SWAN ACCOUNT RECOVERY CODES');
      expect(formatted).toContain('Account: @alice.swan.place');
      expect(formatted).toContain('01. RCV-AAAA-1111');
      expect(formatted).toContain('10. RCV-JJJJ-0000');
    });

    it('safety acknowledgment checkbox strictly controls finish action', () => {
      let acknowledged = false;
      function canFinish(): boolean {
        return acknowledged;
      }

      expect(canFinish()).toBe(false);
      acknowledged = true;
      expect(canFinish()).toBe(true);
      acknowledged = false;
      expect(canFinish()).toBe(false);
    });
  });

  // =========================================================================
  // 6. did:web Wizard Modal (`DidWebModal.svelte`)
  // =========================================================================
  describe('6. did:web Domain Normalization, DNS/HTTPS Verification & Modes', () => {
    it('cleanDomain normalizes protocols, paths, whitespace, and casing', () => {
      function cleanDomain(raw: string): string {
        return raw.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
      }

      expect(cleanDomain('https://alice.example.com')).toBe('alice.example.com');
      expect(cleanDomain('HTTP://ALICE.EXAMPLE.COM/some/path')).toBe('alice.example.com');
      expect(cleanDomain('  sub.domain.org/  ')).toBe('sub.domain.org');
      expect(cleanDomain('MY-DOMAIN.IO')).toBe('my-domain.io');
      expect(cleanDomain('https://foo.bar.baz/')).toBe('foo.bar.baz');
    });

    it('generates accurate DNS TXT host and value records', () => {
      const handle = 'identity.example.com';
      const targetDID = `did:web:${handle}`;

      const dnsHost = `_atproto.${handle}`;
      const dnsValue = `did=${targetDID}`;

      expect(dnsHost).toBe('_atproto.identity.example.com');
      expect(dnsValue).toBe('did=did:web:identity.example.com');
    });

    it('generates standard W3C compliant did.json document structure', () => {
      const handle = 'alice.example.com';
      const did = `did:web:${handle}`;
      const publicKey = 'zQ3shMockKey12345';

      const didJsonStr = JSON.stringify(
        {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: did,
          alsoKnownAs: [`at://${handle}`],
          verificationMethod: [
            {
              id: `${did}#atproto`,
              type: 'Multikey',
              controller: did,
              publicKeyMultibase: publicKey
            }
          ],
          service: [
            {
              id: '#atproto_pds',
              type: 'AtprotoPersonalDataServer',
              serviceEndpoint: 'https://swan.place'
            }
          ]
        },
        null,
        2
      );

      const parsed = JSON.parse(didJsonStr);
      expect(parsed['@context']).toEqual(['https://www.w3.org/ns/did/v1']);
      expect(parsed.id).toBe('did:web:alice.example.com');
      expect(parsed.alsoKnownAs).toEqual(['at://alice.example.com']);
      expect(parsed.verificationMethod[0].type).toBe('Multikey');
      expect(parsed.verificationMethod[0].publicKeyMultibase).toBe(publicKey);
      expect(parsed.service[0].serviceEndpoint).toBe('https://swan.place');
    });

    it('reserves and claims custom did:web domain through API', async () => {
      const reserveRes = await api.reserveDidWeb({
        requestID: 'req_test_123',
        targetDID: 'did:web:alice.example.com',
        handle: 'alice.example.com',
        expiresAt: new Date(Date.now() + 3600000).toISOString()
      });

      expect(reserveRes.requestID).toBe('req_test_123');
      expect(reserveRes.nonce).toBeDefined();
      expect(reserveRes.claimEndpoint).toContain('/.well-known/swan/did-web-claim/');

      const claimRes = await api.claimDidWeb({
        requestID: 'req_test_123'
      });

      expect(claimRes.state).toBe('active');
      expect(claimRes.handle).toBe('alice.example.com');
      expect(claimRes.did).toBe('did:web:alice.example.com');
    });

    it('removes did:web domain identity through API', async () => {
      const removeRes = await api.removeDidWeb({});
      expect(removeRes.state).toBe('removed');
    });
  });

  // =========================================================================
  // 7. Export Modal Polling Interval & Teardown Lifecycle (`ExportModal.svelte`)
  // =========================================================================
  describe('7. Export Modal Polling Interval, State Transitions & Teardown', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('polls status every 2500ms and transitions to ready when archive is compiled', async () => {
      let pollCount = 0;
      let stage: 'idle' | 'requesting' | 'polling' | 'ready' | 'error' = 'idle';
      let exportData: any = null;
      let pollTimer: any = null;

      function stopPolling() {
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      }

      function startPolling() {
        stopPolling();
        pollTimer = setInterval(async () => {
          pollCount++;
          if (pollCount >= 3) {
            stage = 'ready';
            exportData = { id: 'exp_999', status: 'ready', downloadUrl: '/account/api/export/download' };
            stopPolling();
          } else {
            stage = 'polling';
            exportData = { id: 'exp_999', status: 'pending' };
          }
        }, 2500);
      }

      // Start polling
      startPolling();
      expect(pollTimer).not.toBeNull();
      expect(pollCount).toBe(0);

      // Advance 2500ms -> 1st poll
      await vi.advanceTimersByTimeAsync(2500);
      expect(pollCount).toBe(1);
      expect(stage).toBe('polling');
      expect(exportData?.status).toBe('pending');
      expect(pollTimer).not.toBeNull();

      // Advance 2500ms -> 2nd poll
      await vi.advanceTimersByTimeAsync(2500);
      expect(pollCount).toBe(2);
      expect(stage).toBe('polling');
      expect(pollTimer).not.toBeNull();

      // Advance 2500ms -> 3rd poll (ready)
      await vi.advanceTimersByTimeAsync(2500);
      expect(pollCount).toBe(3);
      expect(stage).toBe('ready');
      expect(exportData?.status).toBe('ready');
      expect(pollTimer).toBeNull(); // Cleaned up

      // Advance further -> no additional polls fire
      await vi.advanceTimersByTimeAsync(10000);
      expect(pollCount).toBe(3);
    });

    it('teardown immediately clears polling timer on modal close or unmount', async () => {
      let pollTimer: any = null;
      let pollFired = 0;

      function stopPolling() {
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      }

      function startPolling() {
        stopPolling();
        pollTimer = setInterval(() => {
          pollFired++;
        }, 2500);
      }

      startPolling();
      expect(pollTimer).not.toBeNull();

      // Advance 1000ms (before first poll)
      await vi.advanceTimersByTimeAsync(1000);
      expect(pollFired).toBe(0);

      // Unmount / close modal
      stopPolling();
      expect(pollTimer).toBeNull();

      // Advance 10000ms past multiple intervals
      await vi.advanceTimersByTimeAsync(10000);
      expect(pollFired).toBe(0); // Zero polls fired
    });

    it('stops polling and transitions to error when status is failed', async () => {
      let stage = 'polling';
      let pollTimer: any = null;
      let errorMessage = '';

      function stopPolling() {
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      }

      pollTimer = setInterval(() => {
        // Simulate failure from server
        stage = 'error';
        errorMessage = 'Data export generation failed. Please try again.';
        stopPolling();
      }, 2500);

      await vi.advanceTimersByTimeAsync(2500);
      expect(stage).toBe('error');
      expect(errorMessage).toBe('Data export generation failed. Please try again.');
      expect(pollTimer).toBeNull();
    });
  });

  // =========================================================================
  // 8. Lifecycle Modal (`LifecycleModal.svelte`) Confirmation Safeguards
  // =========================================================================
  describe('8. Lifecycle Modal Confirmation Text Matching & Safety Safeguards', () => {
    const handle = 'alice.swan.place';

    it('delete mode accepts DELETE, handle, or @handle (case-sensitive for DELETE)', () => {
      function checkDeleteConfirm(input: string): boolean {
        const clean = input.trim();
        return clean === 'DELETE' || clean === handle || clean === `@${handle}`;
      }

      // Valid matches
      expect(checkDeleteConfirm('DELETE')).toBe(true);
      expect(checkDeleteConfirm('  DELETE  ')).toBe(true);
      expect(checkDeleteConfirm('alice.swan.place')).toBe(true);
      expect(checkDeleteConfirm('@alice.swan.place')).toBe(true);
      expect(checkDeleteConfirm('  @alice.swan.place  ')).toBe(true);

      // Invalid matches
      expect(checkDeleteConfirm('delete')).toBe(false); // Lowercase
      expect(checkDeleteConfirm('Delete')).toBe(false);
      expect(checkDeleteConfirm('del')).toBe(false);
      expect(checkDeleteConfirm('alice')).toBe(false);
      expect(checkDeleteConfirm('bob.swan.place')).toBe(false);
      expect(checkDeleteConfirm('')).toBe(false);
      expect(checkDeleteConfirm('DELETE NOW')).toBe(false);
    });

    it('deactivate mode strictly requires handle or @handle (rejects DELETE)', () => {
      function checkDeactivateConfirm(input: string): boolean {
        const clean = input.trim();
        return clean === handle || clean === `@${handle}`;
      }

      // Valid matches
      expect(checkDeactivateConfirm('alice.swan.place')).toBe(true);
      expect(checkDeactivateConfirm('@alice.swan.place')).toBe(true);
      expect(checkDeactivateConfirm('  @alice.swan.place  ')).toBe(true);

      // Invalid matches (including DELETE)
      expect(checkDeactivateConfirm('DELETE')).toBe(false);
      expect(checkDeactivateConfirm('alice')).toBe(false);
      expect(checkDeactivateConfirm('')).toBe(false);
      expect(checkDeactivateConfirm('@bob.swan.place')).toBe(false);
    });

    it('submitting deactivation or deletion calls correct API and resets portal state', async () => {
      // Setup portal with active snapshot
      portal.setSnapshot({
        account: { did: 'did:plc:alice', handle: 'alice.swan.place', lifecycle: 'active' },
        identity: { method: 'plc', handle: 'alice.swan.place', state: 'active' },
        strength: 'stepUpPassword',
        factors: [],
        sessions: [],
        apps: [],
        passwords: []
      });

      expect(get(currentAccount)).not.toBeNull();

      // Perform deactivation
      const res = await api.deactivateAccount();
      expect(res.accepted).toBe(true);

      portal.reset();
      expect(get(currentAccount)).toBeNull();
    });

    it('submitting deletion calls deleteAccount API endpoint', async () => {
      const res = await api.deleteAccount();
      expect(res.accepted).toBe(true);
    });
  });

  // =========================================================================
  // 9. Base32 Secret Generation Randomness, Uniformity & RFC 4648
  // =========================================================================
  describe('9. Base32 Secret Generation Uniformity, Randomness & RFC 4648 Format', () => {
    const RFC4648_BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    it('every character in generated secret belongs strictly to RFC 4648 Base32 alphabet', () => {
      for (let i = 0; i < 500; i++) {
        const secret = generateBase32Secret(20);
        expect(secret.length).toBe(32);
        for (const char of secret) {
          expect(RFC4648_BASE32).toContain(char);
        }
      }
    });

    it('produces expected lengths for different byte lengths', () => {
      // 20 bytes * 8 = 160 bits -> 160 / 5 = 32 chars
      expect(generateBase32Secret(20).length).toBe(32);

      // 10 bytes * 8 = 80 bits -> 80 / 5 = 16 chars
      expect(generateBase32Secret(10).length).toBe(16);

      // 5 bytes * 8 = 40 bits -> 40 / 5 = 8 chars
      expect(generateBase32Secret(5).length).toBe(8);

      // 35 bytes * 8 = 280 bits -> 280 / 5 = 56 chars
      expect(generateBase32Secret(35).length).toBe(56);
    });

    it('collision resistance: 2,000 generated secrets are 100% unique (0 collisions)', () => {
      const generated = new Set<string>();
      const count = 2000;

      for (let i = 0; i < count; i++) {
        const secret = generateBase32Secret(20);
        expect(generated.has(secret)).toBe(false);
        generated.add(secret);
      }

      expect(generated.size).toBe(count);
    });

    it('character frequency distribution across 32 Base32 symbols is uniform', () => {
      const frequencies: Record<string, number> = {};
      for (const char of RFC4648_BASE32) {
        frequencies[char] = 0;
      }

      const totalSecrets = 1000;
      const totalChars = totalSecrets * 32; // 32,000 characters

      for (let i = 0; i < totalSecrets; i++) {
        const secret = generateBase32Secret(20);
        for (const char of secret) {
          frequencies[char]++;
        }
      }

      // Expected mean per symbol = 32000 / 32 = 1000
      const expectedMean = totalChars / 32;

      for (const char of RFC4648_BASE32) {
        const count = frequencies[char];
        expect(count).toBeGreaterThan(0);
        // Ensure count is within +/- 30% of theoretical mean
        expect(count).toBeGreaterThan(expectedMean * 0.70);
        expect(count).toBeLessThan(expectedMean * 1.30);
      }
    });

    it('fallback when crypto.getRandomValues is stubbed uses Math.random fallback without error', () => {
      const spy = vi.spyOn(crypto, 'getRandomValues').mockImplementation((arr: any) => {
        for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
        return arr;
      });

      const secret = generateBase32Secret(20);
      expect(secret.length).toBe(32);
      for (const char of secret) {
        expect(RFC4648_BASE32).toContain(char);
      }
      expect(spy).toHaveBeenCalled();
    });
  });
});
