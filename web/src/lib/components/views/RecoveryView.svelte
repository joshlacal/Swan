<script lang="ts">
  import { modals } from '$lib/stores/modals';
  import { activeFactors } from '$lib/stores/portal';

  const hasRecoveryFactor = $derived(
    $activeFactors.some((f) => f.kind === 'recoveryCode')
  );
</script>

<div class="recovery-view">
  <section class="panel">
    <div class="panel-head">
      <div>
        <span class="eyebrow">YOUR WAY BACK IN</span>
        <h2>Emergency recovery codes</h2>
      </div>
      <span class="pill success">Configured</span>
    </div>
    <p class="panel-copy">
      Recovery codes are cryptographic single-use bypass tokens for emergencies when your primary device or authenticator is lost.
    </p>

    <div class="rules-grid">
      <div class="rule-card">
        <span class="rule-num">01</span>
        <strong>Single-Use Only</strong>
        <p>Each 10-character code is permanently invalidated the moment it is verified by the Swan server.</p>
      </div>

      <div class="rule-card">
        <span class="rule-num">02</span>
        <strong>Store Offline</strong>
        <p>Keep these codes in an encrypted password manager or printed in a physical safe, never in browser cache.</p>
      </div>

      <div class="rule-card">
        <span class="rule-num">03</span>
        <strong>Immediate Invalidation</strong>
        <p>Generating a new set of recovery codes destroys all existing codes immediately across all servers.</p>
      </div>
    </div>

    <div class="status-card">
      <div class="status-meta">
        <span class="status-dot"></span>
        <div>
          <strong>10 Single-Use Recovery Codes Active</strong>
          <small>Status: Ready for emergency sign-in and step-up authorization</small>
        </div>
      </div>
      <button
        type="button"
        class="button primary"
        onclick={() => modals.open('recovery-rotate')}
      >
        Rotate Recovery Codes ↗
      </button>
    </div>

    <div class="capability-note">
      <span>✦</span>
      <div>
        <strong>Protected Action</strong>
        <small>Viewing or rotating recovery codes requires password confirmation or multi-factor step-up verification.</small>
      </div>
    </div>
  </section>
</div>

<style>
  .recovery-view {
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

  .pill {
    border-radius: 20px;
    padding: 4px 8px;
    font: 10px var(--mono);
  }

  .pill.success {
    color: #39755b;
    background: #dceee1;
  }

  .rules-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
    margin: 28px 0;
  }

  .rule-card {
    background: #faf8f1;
    border: 1px solid var(--line);
    padding: 20px;
    border-radius: 2px;
  }

  .rule-num {
    display: block;
    font: 600 11px var(--mono);
    color: var(--teal);
    margin-bottom: 8px;
  }

  .rule-card strong {
    display: block;
    font-size: 14px;
    color: var(--ink);
    margin-bottom: 6px;
  }

  .rule-card p {
    color: var(--muted);
    font-size: 12px;
    line-height: 1.5;
    margin: 0;
  }

  .status-card {
    background: #e6ded0;
    border: 1px solid #d7d5ca;
    padding: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    border-radius: 2px;
  }

  .status-meta {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .status-dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    background: #4a9b78;
    border-radius: 50%;
    box-shadow: 0 0 0 4px rgba(74, 155, 120, 0.14);
    flex-shrink: 0;
  }

  .status-meta strong {
    display: block;
    font-size: 14px;
    color: var(--ink);
  }

  .status-meta small {
    display: block;
    color: var(--muted);
    font: 11px var(--mono);
    margin-top: 3px;
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
    .rules-grid {
      grid-template-columns: 1fr;
    }
    .status-card {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
