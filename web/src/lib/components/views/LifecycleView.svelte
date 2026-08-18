<script lang="ts">
  import { modals } from '$lib/stores/modals';
  import { currentAccount } from '$lib/stores/portal';
</script>

<div class="lifecycle-view">
  <section class="panel">
    <div class="panel-head">
      <div>
        <span class="eyebrow">PAUSE OR LEAVE</span>
        <h2>Account lifecycle</h2>
      </div>
      <span class="pill status" class:active={$currentAccount?.lifecycle === 'active'}>
        {$currentAccount?.lifecycle?.toUpperCase() || 'ACTIVE'}
      </span>
    </div>
    <p class="panel-copy">
      Lifecycle actions alter the accessibility and existence of your account across the federated network. These operations are guarded by step-up authorization.
    </p>

    <div class="lifecycle-cards">
      <!-- Temporary Deactivation -->
      <article class="lifecycle-card">
        <div class="card-content">
          <span class="card-tag">TEMPORARY</span>
          <h3>Deactivate account</h3>
          <p>
            Temporarily pause your account. Your profile, public posts, and repository records will be hidden from view. You can reactivate anytime simply by signing back into Swan.
          </p>
        </div>
        <div class="card-action">
          <button
            type="button"
            class="button warning-outline"
            onclick={() => modals.open('lifecycle-deactivate', { mode: 'deactivate' })}
          >
            Deactivate account
          </button>
        </div>
      </article>

      <!-- Permanent Deletion -->
      <article class="lifecycle-card danger">
        <div class="card-content">
          <span class="card-tag danger">IRREVERSIBLE</span>
          <h3>Permanently delete account</h3>
          <p>
            Permanent, irreversible destruction: all repository commits, signing keys, and factor envelopes will be permanently wiped from the Swan server. A tombstone will be written to the PLC directory.
          </p>
        </div>
        <div class="card-action">
          <button
            type="button"
            class="button danger"
            onclick={() => modals.open('lifecycle-delete', { mode: 'delete' })}
          >
            Request account deletion
          </button>
        </div>
      </article>
    </div>

    <div class="capability-note">
      <span>✦</span>
      <div>
        <strong>Protected Lifecycle Ceremony</strong>
        <small>Deactivation and deletion require explicit handle or phrase confirmation and step-up re-authentication.</small>
      </div>
    </div>
  </section>
</div>

<style>
  .lifecycle-view {
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
    background: #e6e3d9;
    color: var(--muted);
  }

  .pill.active {
    color: #39755b;
    background: #dceee1;
  }

  .lifecycle-cards {
    display: flex;
    flex-direction: column;
    gap: 16px;
    margin: 28px 0;
  }

  .lifecycle-card {
    background: #faf8f1;
    border: 1px solid var(--line);
    padding: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 24px;
    border-radius: 2px;
  }

  .lifecycle-card.danger {
    border-color: #e2c0b6;
    background: #fcf6f4;
  }

  .card-content {
    min-width: 0;
    flex-grow: 1;
  }

  .card-tag {
    display: inline-block;
    font: 600 9px var(--mono);
    color: var(--muted);
    background: #e6e3d9;
    padding: 2px 6px;
    border-radius: 2px;
    margin-bottom: 8px;
  }

  .card-tag.danger {
    color: var(--coral);
    background: #faeae6;
  }

  .card-content h3 {
    font: 600 16px var(--sans);
    color: var(--ink);
    margin: 0 0 6px 0;
  }

  .card-content p {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.5;
    margin: 0;
    max-width: 580px;
  }

  .card-action {
    flex-shrink: 0;
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
    transition: opacity 0.15s ease, background-color 0.15s ease;
  }

  .button:hover {
    opacity: 0.9;
  }

  .button.warning-outline {
    border-color: var(--line);
    background: transparent;
    color: var(--ink);
  }

  .button.warning-outline:hover {
    background: #e6e3d9;
  }

  .button.danger {
    background: var(--coral);
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
    .lifecycle-card {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
