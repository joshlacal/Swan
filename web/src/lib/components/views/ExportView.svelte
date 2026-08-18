<script lang="ts">
  import { modals } from '$lib/stores/modals';
  import { currentAccount } from '$lib/stores/portal';
</script>

<div class="export-view">
  <section class="panel">
    <div class="panel-head">
      <div>
        <span class="eyebrow">MOVE YOUR DATA</span>
        <h2>Export & migrate</h2>
      </div>
      <button
        type="button"
        class="button primary"
        onclick={() => modals.open('export')}
      >
        Request Data Export ↗
      </button>
    </div>
    <p class="panel-copy">
      Take a complete, portable copy of your personal data server. The Swan engine packages your AT Protocol repository, signed record blocks, account metadata, and factor envelopes into a standard Content Addressable Archive (.car).
    </p>

    <div class="format-cards-grid">
      <div class="format-card">
        <span class="format-badge">CAR v2</span>
        <strong>Repository Archive</strong>
        <p>Complete Merkle Search Tree (MST) history with all commits, posts, profile records, and blob references.</p>
      </div>

      <div class="format-card">
        <span class="format-badge">JSON-LD</span>
        <strong>Identity Manifest</strong>
        <p>Cryptographic DID proofs, public signing keys, and did:web / PLC verification history.</p>
      </div>

      <div class="format-card">
        <span class="format-badge">ENVELOPE</span>
        <strong>Factor Envelopes</strong>
        <p>Public factor registrations, WebAuthn credential IDs, and session metadata (no private secrets).</p>
      </div>
    </div>

    <div class="export-highlights">
      <h3>What is included in your export package:</h3>
      <ul>
        <li>Full AT Protocol repository checkout (`com.atproto.repo.getRepo`)</li>
        <li>Account profile metadata for <code>@{$currentAccount?.handle || 'swan-user'}</code></li>
        <li>Signing key metadata and DID document representation</li>
        <li>Active factor public configurations (passkeys, TOTP registrations)</li>
        <li>Zero lock-in: Portable to any standard AT Protocol Personal Data Server (PDS)</li>
      </ul>
    </div>

    <div class="capability-note">
      <span>✦</span>
      <div>
        <strong>Asynchronous Packaging</strong>
        <small>Export generation runs asynchronously on the backend. When complete, a direct CAR archive download link is provided.</small>
      </div>
    </div>
  </section>
</div>

<style>
  .export-view {
    display: flex;
    flex-direction: column;
    gap: 28px;
  }

  .eyebrow {
    display: block;
    font: 600 10px/1.3 var(--mono);
    color: var(--muted);
    letter-spacing: 0.14em;
  }

  .panel {
    background: #faf8f1;
    border: 1px solid var(--line);
    padding: 28px;
    border-radius: 2px;
  }

  .panel-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
  }

  .panel h2 {
    font: 400 26px/1.05 var(--serif);
    margin: 9px 0 0;
    letter-spacing: -0.02em;
    color: var(--ink);
  }

  .panel-copy {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.6;
    max-width: 650px;
    margin: 14px 0 0;
  }

  .format-cards-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
    margin: 28px 0;
  }

  .format-card {
    background: #faf8f1;
    border: 1px solid var(--line);
    padding: 20px;
    border-radius: 2px;
  }

  .format-badge {
    display: inline-block;
    font: 600 9px var(--mono);
    color: var(--teal);
    background: #dceee1;
    padding: 2px 6px;
    border-radius: 2px;
    margin-bottom: 10px;
  }

  .format-card strong {
    display: block;
    font-size: 14px;
    color: var(--ink);
    margin-bottom: 6px;
  }

  .format-card p {
    color: var(--muted);
    font-size: 12px;
    line-height: 1.5;
    margin: 0;
  }

  .export-highlights {
    background: #e6ded0;
    padding: 22px;
    border-radius: 2px;
    margin-top: 10px;
  }

  .export-highlights h3 {
    font: 600 14px var(--sans);
    color: var(--ink);
    margin: 0 0 12px 0;
  }

  .export-highlights ul {
    margin: 0;
    padding-left: 20px;
    color: var(--muted);
    font-size: 13px;
    line-height: 1.7;
  }

  .button {
    border: 1px solid transparent;
    padding: 10px 16px;
    font-size: 12px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    text-decoration: none;
    cursor: pointer;
    border-radius: 2px;
    transition: opacity 0.15s ease;
    flex-shrink: 0;
  }

  .button:hover {
    opacity: 0.9;
  }

  .button.primary {
    background: var(--teal);
    color: white;
  }

  .capability-note {
    display: flex;
    gap: 12px;
    margin-top: 28px;
    padding: 15px;
    background: #eee9dc;
    border-radius: 2px;
  }

  .capability-note > span {
    color: var(--ochre);
    font-size: 22px;
    line-height: 1;
  }

  .capability-note strong {
    display: block;
    font-size: 12px;
    color: var(--ink);
  }

  .capability-note small {
    display: block;
    color: var(--muted);
    font-size: 11px;
    margin-top: 4px;
    line-height: 1.4;
  }

  @media (max-width: 768px) {
    .format-cards-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
