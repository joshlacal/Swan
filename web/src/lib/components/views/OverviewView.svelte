<script lang="ts">
  import {
    portal,
    currentAccount,
    currentIdentity,
    activeSessions,
    activeApps,
    activeFactors
  } from '$lib/stores/portal';
  import { modals } from '$lib/stores/modals';
</script>

<div class="overview-view">
  <section class="hero-grid">
    <article class="hero-card">
      <div>
        <p class="eyebrow pale">YOUR DATA, YOUR RULES</p>
        <h2>Everything is<br /><em>in your hands.</em></h2>
        <p class="hero-copy">
          A calm view of the credentials, identities, and devices that touch your personal data server.
        </p>
      </div>
      <div class="hero-glyph" aria-hidden="true">✳</div>
    </article>

    <article class="signal-card">
      <span class="eyebrow">ACCOUNT SIGNAL</span>
      <div class="signal-value">
        <span class="status-dot"></span>Clear
      </div>
      <p>No unusual activity detected.</p>
      <div class="signal-line"><span></span></div>
      <small>Protected by your management session</small>
    </article>
  </section>

  <section class="metric-grid">
    <article>
      <span class="metric-label">IDENTITY</span>
      <strong>{$currentIdentity?.method === 'didWeb' ? 'did:web' : 'PLC'}</strong>
      <span class="metric-note">{$currentIdentity?.state ?? 'Active'}</span>
    </article>
    <article>
      <span class="metric-label">ACTIVE DEVICES</span>
      <strong>{$activeSessions.length}</strong>
      <span class="metric-note">Across your account</span>
    </article>
    <article>
      <span class="metric-label">CONNECTED APPS</span>
      <strong>{$activeApps.length}</strong>
      <span class="metric-note">OAuth access grants</span>
    </article>
    <article>
      <span class="metric-label">AUTH FACTORS</span>
      <strong>{$activeFactors.length}</strong>
      <span class="metric-note">Protected credentials</span>
    </article>
  </section>

  <section class="split">
    <article class="panel">
      <div class="panel-head">
        <div>
          <span class="eyebrow">IDENTITY</span>
          <h2>How the world finds you</h2>
        </div>
        <button type="button" class="text-button" onclick={() => portal.selectTab('profile')}>
          Manage ↗
        </button>
      </div>
      <div class="identity-row">
        <div class="identity-symbol">
          {$currentIdentity?.method === 'didWeb' ? '◎' : '◇'}
        </div>
        <div class="identity-info">
          <strong>@{$currentAccount?.handle || 'swan-user'}</strong>
          <p>{$currentAccount?.did || 'did:plc:...'}</p>
        </div>
        <span class="pill success">Verified</span>
      </div>
    </article>

    <article class="panel warm">
      <div class="panel-head">
        <div>
          <span class="eyebrow">NEXT BEST STEP</span>
          <h2>Review your sessions</h2>
        </div>
        <span class="arrow" aria-hidden="true">↗</span>
      </div>
      <p class="panel-copy">
        Keep only the devices you recognize. Revoking a session is immediate and reversible by signing in again.
      </p>
      <button type="button" class="button dark" onclick={() => portal.selectTab('sessions')}>
        Review devices
      </button>
    </article>
  </section>

  <section class="quick-actions-panel panel">
    <div class="panel-head">
      <div>
        <span class="eyebrow">SHORTCUTS</span>
        <h2>Quick actions</h2>
      </div>
    </div>
    <div class="quick-actions-buttons">
      <button type="button" class="button primary" onclick={() => modals.open('passkey-enroll')}>
        Add Passkey ↗
      </button>
      <button type="button" class="button dark" onclick={() => modals.open('app-password')}>
        New App Password ＋
      </button>
      <button type="button" class="button outline" onclick={() => modals.open('export')}>
        Export Archive ↗
      </button>
    </div>
  </section>
</div>

<style>
  .overview-view {
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

  .hero-grid {
    display: grid;
    grid-template-columns: 1.45fr 0.8fr;
    gap: 16px;
  }

  .hero-card {
    position: relative;
    overflow: hidden;
    min-height: 275px;
    padding: 36px;
    background: var(--teal-deep);
    color: #f1ebdb;
    display: flex;
    justify-content: space-between;
    border-radius: 2px;
  }

  .hero-card:after {
    content: '';
    position: absolute;
    width: 320px;
    height: 320px;
    right: -120px;
    bottom: -160px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 50%;
    box-shadow: 0 0 0 32px rgba(255, 255, 255, 0.04), 0 0 0 64px rgba(255, 255, 255, 0.025);
    pointer-events: none;
  }

  .hero-card h2 {
    font: 400 43px/1 var(--serif);
    margin: 18px 0 16px;
    letter-spacing: -0.04em;
  }

  .hero-card h2 em {
    color: #e6bd72;
    font-style: normal;
  }

  .pale {
    color: #a5c5b9;
  }

  .hero-copy {
    max-width: 300px;
    color: #bfd3c8;
    font-size: 13px;
    line-height: 1.6;
    margin: 0;
  }

  .hero-glyph {
    color: #e1b667;
    font-size: 70px;
    line-height: 1;
    z-index: 1;
  }

  .signal-card {
    padding: 29px;
    background: #e5dfd0;
    min-height: 275px;
    display: flex;
    flex-direction: column;
    border-radius: 2px;
  }

  .signal-value {
    margin-top: auto;
    font: 400 31px var(--serif);
    display: flex;
    gap: 13px;
    align-items: center;
  }

  .status-dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    background: #4a9b78;
    border-radius: 50%;
    box-shadow: 0 0 0 4px rgba(74, 155, 120, 0.14);
  }

  .signal-card p {
    margin: 8px 0 20px;
    color: var(--muted);
    font-size: 12px;
  }

  .signal-line {
    height: 3px;
    background: #cbc3ae;
    overflow: hidden;
  }

  .signal-line span {
    display: block;
    height: 100%;
    width: 82%;
    background: var(--teal);
  }

  .signal-card small {
    margin-top: 12px;
    font: 10px var(--mono);
    color: var(--muted);
  }

  .metric-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0;
    border-bottom: 1px solid var(--line);
    padding-bottom: 10px;
  }

  .metric-grid article {
    padding: 24px 18px 23px 0;
    border-right: 1px solid var(--line);
    margin-right: 18px;
  }

  .metric-grid article:last-child {
    border-right: 0;
    margin-right: 0;
  }

  .metric-label {
    display: block;
    font: 10px var(--mono);
    color: var(--muted);
    letter-spacing: 0.12em;
    margin-bottom: 12px;
  }

  .metric-grid strong {
    display: block;
    font: 400 28px var(--serif);
    color: var(--ink);
  }

  .metric-note {
    display: block;
    color: var(--muted);
    font-size: 11px;
    margin-top: 5px;
  }

  .split {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }

  .panel {
    background: #faf8f1;
    border: 1px solid var(--line);
    padding: 28px;
    border-radius: 2px;
  }

  .panel.warm {
    background: #e6ded0;
    border-color: #e6ded0;
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

  .text-button {
    border: 0;
    background: none;
    color: var(--teal);
    font-size: 12px;
    font-weight: 600;
    padding: 5px 0;
    cursor: pointer;
  }

  .text-button:hover {
    text-decoration: underline;
  }

  .identity-row {
    display: flex;
    align-items: center;
    gap: 13px;
    padding-top: 28px;
  }

  .identity-symbol {
    width: 37px;
    height: 37px;
    background: #e6e3d9;
    display: grid;
    place-items: center;
    color: var(--teal);
    font-size: 21px;
    border-radius: 2px;
    flex-shrink: 0;
  }

  .identity-info {
    min-width: 0;
    overflow: hidden;
  }

  .identity-info strong {
    font-size: 13px;
    display: block;
    color: var(--ink);
  }

  .identity-info p {
    color: var(--muted);
    font: 10px var(--mono);
    margin: 4px 0 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .pill {
    margin-left: auto;
    border-radius: 20px;
    padding: 5px 9px;
    font: 10px var(--mono);
    flex-shrink: 0;
  }

  .pill.success {
    color: #39755b;
    background: #dceee1;
  }

  .panel-copy {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.6;
    max-width: 570px;
    margin: 14px 0 0;
  }

  .arrow {
    color: var(--coral);
    font-size: 26px;
  }

  .button {
    border: 1px solid transparent;
    padding: 11px 15px;
    font-size: 12px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 12px;
    text-decoration: none;
    cursor: pointer;
    border-radius: 2px;
    transition: opacity 0.15s ease, background-color 0.15s ease;
  }

  .button:hover {
    opacity: 0.9;
  }

  .button.primary {
    background: var(--teal);
    color: white;
  }

  .button.dark {
    background: var(--ink);
    color: #f7f2e7;
    margin-top: 14px;
  }

  .button.outline {
    background: transparent;
    border-color: var(--line);
    color: var(--ink);
  }

  .button.outline:hover {
    background: #e6e3d9;
  }

  .quick-actions-panel {
    margin-top: 4px;
  }

  .quick-actions-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-top: 18px;
  }

  @media (max-width: 900px) {
    .hero-grid,
    .split {
      grid-template-columns: 1fr;
    }
    .metric-grid {
      grid-template-columns: repeat(2, 1fr);
    }
    .metric-grid article:nth-child(2) {
      border-right: 0;
    }
  }

  @media (max-width: 560px) {
    .hero-card {
      padding: 25px;
      min-height: 230px;
    }
    .hero-card h2 {
      font-size: 34px;
    }
    .hero-glyph {
      font-size: 45px;
    }
  }
</style>
