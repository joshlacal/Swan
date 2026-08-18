import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  createMockPublicKeyCredential,
  setupTestEnv,
  teardownTestEnv
} from '../harness/test-env';
import { MockSwanBackend } from '../harness/mock-backend';

describe('Tier 1 - F17: Test Infrastructure & Scripts', () => {
  it('T1-F17-01: package.json specifies required test, check, and build npm scripts', () => {
    const pkgPath = path.resolve(__dirname, '../../../package.json');
    expect(fs.existsSync(pkgPath)).toBe(true);

    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    expect(pkg.scripts).toBeDefined();
    expect(pkg.scripts['test:unit']).toBe('vitest run');
    expect(pkg.scripts['test']).toBe('vitest run');
    expect(pkg.scripts['check']).toContain('svelte-check');
    expect(pkg.scripts['build']).toContain('vite build');
    expect(pkg.scripts['lint']).toBeDefined();
  });

  it('T1-F17-02: vite.config.ts includes src and tests/e2e test patterns', () => {
    const configPath = path.resolve(__dirname, '../../../vite.config.ts');
    expect(fs.existsSync(configPath)).toBe(true);

    const content = fs.readFileSync(configPath, 'utf8');
    expect(content).toContain('src/**/*.{test,spec}.ts');
    expect(content).toContain('tests/e2e/**/*.{test,spec}.ts');
  });

  it('T1-F17-03: setupTestEnv and teardownTestEnv cleanly manage fetch redirection and restore', async () => {
    const original = globalThis.fetch;

    const env = setupTestEnv({ authenticated: false });
    expect(globalThis.fetch).not.toBe(original);

    const resp = await fetch('/account/api/signup/policy');
    expect(resp.status).toBe(200);

    teardownTestEnv();
    expect(globalThis.fetch).toBe(original);
  });

  it('T1-F17-04: Virtual WebAuthn mock generates standard P-256 / CBOR credential structures', () => {
    const createCred = createMockPublicKeyCredential('create', { challenge: 'test-challenge' });
    expect(createCred.id).toBeDefined();
    expect(createCred.type).toBe('public-key');
    expect(createCred.response.clientDataJSON).toBeInstanceOf(ArrayBuffer);
    expect(createCred.response.attestationObject).toBeInstanceOf(ArrayBuffer);
    expect(createCred.response.getPublicKeyAlgorithm()).toBe(-7);

    const getCred = createMockPublicKeyCredential('get', { challenge: 'test-challenge' });
    expect(getCred.response.signature).toBeInstanceOf(ArrayBuffer);
    expect(getCred.response.authenticatorData).toBeInstanceOf(ArrayBuffer);
  });

  it('T1-F17-05: MockSwanBackend reset restores state to clean deterministic seed', () => {
    const backend = new MockSwanBackend();
    const testDid = 'did:plc:swan-test-user-12345';

    // Add extra state
    backend.addAppPassword(testDid, 'Temp Key');
    backend.addFactor(testDid, { kind: 'passkey', label: 'Temp Passkey' });
    expect(backend.getAppPasswords(testDid).length).toBe(1);
    expect(backend.getFactors(testDid).length).toBe(1);

    // Reset
    backend.reset();
    expect(backend.getAppPasswords(testDid).length).toBe(0);
    expect(backend.getFactors(testDid).length).toBe(0);
    expect(backend.getAccount(testDid)).toBeDefined();
    expect(backend.getAccount(testDid)?.handle).toBe('alice.swan.place');
  });
});
