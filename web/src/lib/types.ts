/**
 * Swan Account Management Portal — Exhaustive Data Types
 * Aligned with Swift backend routes and DTOs in SwanHTTP, SwanAccounts, and SwanCore.
 */

// ============================================================================
// 1. Account & Portal Snapshot Entities
// ============================================================================

export interface AccountDetails {
  did: string;
  handle: string;
  email?: string | null;
  lifecycle: 'active' | 'deactivated' | 'tombstoned' | string;
}

export interface IdentityDetails {
  method: 'plc' | 'didWeb' | string;
  handle: string;
  state: 'active' | 'pending' | 'grace' | string;
}

export interface Factor {
  id: string; // Unique factor identifier (UUID)
  kind: 'passkey' | 'totp' | 'recoveryCode' | string;
  label: string;
  enabled: boolean | string;
}

export interface Session {
  id: string;
  label: string;
  kind: 'management' | 'legacy' | string;
  lastSeen: string;
  current: boolean;
}

export interface ConnectedApp {
  id: string;
  name: string;
  scopes: string[];
  createdAt: string;
}

export interface AppPassword {
  name: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt?: string | null;
}

export interface PortalSnapshot {
  account: AccountDetails;
  identity?: IdentityDetails | null;
  strength: 'password' | 'stepUpPassword' | string;
  factors: Factor[];
  sessions: Session[];
  apps: ConnectedApp[];
  passwords: AppPassword[];
}

// ============================================================================
// 2. Authentication & Bootstrap DTOs
// ============================================================================

export interface BootstrapResponse {
  csrf: string;
}

export interface SignupPolicy {
  policy: string;
  inviteCodeRequired: boolean;
  turnstileRequired: boolean;
  emailVerificationRequired: boolean;
}

export interface LoginRequest {
  handle: string;
  password: string;
  authFactorToken?: string;
}

export interface LoginResponse {
  snapshot: PortalSnapshot;
  csrf: string;
}

export interface PasswordReauthRequest {
  password: string;
}

// ============================================================================
// 3. Generic Mutation Response
// ============================================================================

export interface MutationResponse {
  accepted?: boolean;
  message: string;
  accountDID?: string;
  password?: string; // One-time plaintext app password (creation only)
  factorToken?: string; // One-time MFA receipt token for X-Swan-Step-Up
  recoveryCodes?: string[]; // Plaintext recovery codes on rotation
  challenge?: string; // Base64URL encoded WebAuthn challenge
  factorID?: string;
  factorKind?: 'passkey' | 'totp' | 'recoveryCode' | string;
  exportID?: string;
}

// ============================================================================
// 4. WebAuthn, TOTP & Recovery Factor DTOs
// ============================================================================

export interface WebAuthnChallenge {
  challenge: string; // Base64URL encoded challenge
  factorID: string;
  relyingPartyId?: string;
  userHandle?: string;
  accountDID?: string;
  message?: string;
}

export type WebAuthnStepUpChallenge = WebAuthnChallenge;

export interface WebAuthnAttestationPayload {
  kind?: 'passkey';
  factorID?: string;
  label: string;
  challenge: string; // Base64URL encoded
  clientDataJSON: string; // Base64URL encoded
  authenticatorData: string; // Base64URL encoded
  credentialID: string; // Base64URL encoded
  transports?: string[];
}

export interface WebAuthnAssertionPayload {
  kind: 'passkey';
  factorID: string;
  challenge: string; // Base64URL encoded
  clientDataJSON: string; // Base64URL encoded
  authenticatorData: string; // Base64URL encoded
  credentialID: string; // Base64URL encoded
  signature: string; // Base64URL encoded
  userHandle?: string; // Base64URL encoded
}

export interface TotpEnrollRequest {
  kind?: 'totp';
  factorID?: string;
  label?: string;
  secret: string; // Base32 encoded secret seed
}

export interface TotpEnrollResponse {
  factorID: string;
  secret: string;
  uri: string;
  period?: number;
  digits?: number;
  algorithm?: 'sha1' | 'sha256' | 'sha512' | string;
}

export interface TotpVerifyRequest {
  factorID: string;
  code: string; // 6-digit verification code
}

export interface StepUpRequest {
  kind: 'totp' | 'passkey' | 'recoveryCode';
  factorID: string;
  code?: string;
  challenge?: string;
  clientDataJSON?: string;
  authenticatorData?: string;
  credentialID?: string;
  signature?: string;
}

// ============================================================================
// 5. App Passwords & Scopes
// ============================================================================

export interface AppPasswordCreateRequest {
  name: string;
  scopes: string[];
}

export const APP_PASSWORD_SCOPES = [
  'atproto',
  'transition:chat.bsky',
  'transition:email',
  'transition:generic'
] as const;

export type AppPasswordScope = (typeof APP_PASSWORD_SCOPES)[number];

// ============================================================================
// 6. did:web Identity Management DTOs
// ============================================================================

export interface DidWebReserveRequest {
  requestID?: string;
  targetDID?: string;
  handle: string;
  expiresAt?: string; // ISO 8601 Date
}

export interface DidWebReservationResponse {
  requestID: string;
  targetDID?: string;
  handle?: string;
  keyID?: string;
  keyType?: string;
  publicKey?: string; // Base64URL encoded
  nonce?: string; // Base64URL encoded
  expiresAt?: string; // ISO 8601 Date
  claimServiceEndpoint?: string;
  claimEndpoint?: string;
  claimPayload?: string;
}

export interface DidWebClaimRequest {
  requestID: string;
  stepUpReceipt?: string;
}

export interface DidWebRotateRequest {
  requestID?: string;
  targetDID?: string;
  handle: string;
  expiresAt?: string;
  stepUpReceipt?: string;
}

export interface DidWebRemoveRequest {
  did?: string;
  stepUpReceipt?: string;
}

export interface DidWebIdentityBindingResponse {
  accountDID?: string;
  identityDID?: string;
  did?: string;
  method?: string;
  handle?: string;
  state: string;
  lastValidatedAt?: string | null;
  graceExpiresAt?: string | null;
  verifiedAt?: string;
}

export interface DidWebAdmissionResponse {
  continuity?: string;
  allowsRead?: boolean;
  allowsWrite?: boolean;
  allowsTokenIssuance?: boolean;
  admitted?: boolean;
  method?: string;
  state?: string;
}

// ============================================================================
// 7. Error & Step-Up Handler Types
// ============================================================================

export interface ApiError {
  code: string;
  message: string;
  status?: number;
  retryAfter?: number;
}

export type StepUpFactorKind = 'password' | 'totp' | 'passkey' | 'recoveryCode';

export interface StepUpChallengeContext {
  operation?: string;
  error?: ApiError;
  factorID?: string;
  factorKind?: StepUpFactorKind;
  allowedFactors?: StepUpFactorKind[];
}

export interface StepUpStoreState {
  isOpen: boolean;
  context: StepUpChallengeContext | null;
  allowedFactors: StepUpFactorKind[];
  selectedFactor: StepUpFactorKind;
  loading: boolean;
  error: string | null;
}

export type StepUpHandler = (context: {
  operation?: string;
  error: ApiError;
}) => Promise<string | boolean>;

// ============================================================================
// 8. Navigation & UI Store Types
// ============================================================================

export type SectionId =
  | 'overview'
  | 'profile'
  | 'security'
  | 'recovery'
  | 'sessions'
  | 'apps'
  | 'passwords'
  | 'export'
  | 'lifecycle';

export interface SectionMeta {
  id: SectionId;
  label: string;
  note: string;
  number?: string;
  index?: number;
}

export type ToastType = 'info' | 'success' | 'error' | 'warning';

export interface ToastItem {
  id: string;
  type: ToastType;
  message: string;
  title?: string;
  duration?: number;
  durationMs?: number;
  dismissible?: boolean;
}

export type ModalType =
  | 'step-up'
  | 'app-password'
  | 'app-password-create'
  | 'app-password-view'
  | 'passkey-enroll'
  | 'totp-enroll'
  | 'recovery-rotate'
  | 'did-web'
  | 'export'
  | 'lifecycle-deactivate'
  | 'lifecycle-delete'
  | 'deactivate'
  | 'delete'
  | (string & {});

export interface ModalState {
  active: ModalType | null;
  props?: Record<string, any>;
}
