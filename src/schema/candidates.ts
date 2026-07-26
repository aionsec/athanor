/**
 * Base candidate record — shared across candidate types.
 * The four layers from Guide/03_Candidate_Anatomy.md:
 *   Layer 1: Identity
 *   Layer 2: Score (type-specific — defined per candidate)
 *   Layer 3: Attribution
 *   Layer 4: Enrichment (stamped by Stage 4, not by scoring)
 */

// ─── Layer 1: Identity ─────────────────────────────────────

export interface CandidateIdentity {
  candidate_id: string;
  type: CandidateType;
  time_window_start: string;  // ISO 8601
  time_window_end: string;
  host?: string;              // for endpoint/hybrid candidates
}

export type CandidateType =
  | 'beacon'
  | 'tls_anomaly'
  | 'data_transfer'
  | 'powershell_invocation_anomaly'
  | 'unusual_parent_child_anomaly';

/**
 * The same five types as a VALUE, in canon emit order.
 *
 * A union is invisible at runtime, and the config layer has to answer a runtime
 * question — "is `beacn` a candidate type?" — before a typo becomes a threshold that
 * silently does nothing. This list is the answer, and it lives here rather than in
 * `src/run/` because both the config parser and the runner registry read it and
 * neither may import the other. `runner.ts` keys its registry by `CandidateType`, so a
 * type added to the union without a runner fails to compile; `test/run/runner.test.ts`
 * pins the two lists against each other in the other direction.
 */
export const CANDIDATE_TYPES = [
  'beacon',
  'data_transfer',
  'tls_anomaly',
  'unusual_parent_child_anomaly',
  'powershell_invocation_anomaly',
] as const satisfies readonly CandidateType[];

// ─── Layer 3: Attribution ───────────────────────────────────

export type CandidateAttributionConfidence =
  | 'full'
  | 'partial_time_skew'
  | 'partial_multi_process'
  | 'inferred'
  | 'unavailable';

export type CandidateAttributionDataQualityFlag =
  | 'no_eid3_match'
  | 'partial_evidence_unattributed'
  | 'multi_process_match'
  | 'time_skew_exceeded'
  | 'missing_process_create';

export interface CandidateAttributionBlock {
  host: string | null;
  process_guid: string | null;
  process_name: string | null;
  process_path: string | null;
  process_id: number | null;
  user: string | null;
  parent_process_guid: string | null;
  parent_process_name: string | null;
  parent_process_path: string | null;
  confidence: CandidateAttributionConfidence;
  data_quality_flags: CandidateAttributionDataQualityFlag[];
}

export interface CandidateAttribution {
  process_name: string | null;
  process_id: number | null;
  attribution?: CandidateAttributionBlock;
}

// ─── Layer 4: Enrichment (stamped by pipeline, not scoring) ─

export type CandidateRarityBucket = 'very_rare' | 'rare' | 'uncommon' | 'common' | 'ubiquitous';

export interface CandidateFrequency {
  entity: string;
  host_count: number;
  population_host_count: number;
  prevalence: number;
  rarity_score: number;
  rarity_bucket: CandidateRarityBucket;
}

/**
 * Every stage-4 label a candidate can carry.
 *
 * The rule for what belongs here: a field stays only while some code path can still
 * PRODUCE it — a label spec, a stamper binding and a stamper that writes it. A field
 * no path can reach is a promise the schema cannot keep, and a student who branches
 * on it writes dead code that looks live. (Two such fields,
 * `configured_sync_account_match` and `configured_replication_allowlist_match`, were
 * removed when the specs that produced them were: their only producer was a candidate
 * type athanor does not carry.)
 *
 * `hash_frequency` / `hash_rarity` are the near miss that shows where the line sits.
 * No candidate type currently declares them applicable, so no run stamps them — but
 * the spec, the binding and the stamper are all intact, and adding the label to a
 * type's applicability entry stamps them with no other change. Dormant, not dead.
 */
export interface CandidateEnrichment {
  threat_intel_match?: boolean;
  geo_country?: string;
  geo_asn?: string;
  destination_frequency?: CandidateFrequency;
  destination_rarity?: number;
  first_seen?: string;
  business_hours_proportion?: number;
  lots_match?: boolean;
  missing_sni?: boolean;
  process_frequency?: CandidateFrequency;
  process_rarity?: number;
  hash_frequency?: CandidateFrequency;
  hash_rarity?: number;
  command_line_frequency?: CandidateFrequency;
  command_line_rarity?: number;
  parent_child_pair_frequency?: CandidateFrequency;
  parent_child_pair_rarity?: number;
  script_block_hash_frequency?: CandidateFrequency;
  script_block_hash_rarity?: number;
  domain_frequency?: CandidateFrequency;
  domain_rarity?: number;
  user_agent_frequency?: CandidateFrequency;
  user_agent_rarity?: number;
  ja3_frequency?: CandidateFrequency;
  ja3_rarity?: number;
  protocol_mismatch?: boolean | null;
}

// ─── Evidence Trail ─────────────────────────────────────────

export interface EvidenceTrail {
  constituent_event_ids: string[];
  dns_resolution?: string;
}

// ─── Beacon Candidate (Layer 2: Score) ──────────────────────

export interface BeaconScore {
  // Entity key
  src_ip: string;
  dest_ip: string;
  dest_port: number;
  /** Canonical Zeek service when the tuple has one unambiguous value. */
  observed_service: string | null;

  // Interval analysis (primary)
  regularity: number;             // 1 - (MAD / median_interval), 0-1
  mean_interval_sec: number;
  std_interval_sec: number;

  // Jitter analysis
  jitter_mad: number;             // MAD of intervals in seconds

  // Byte size analysis (corroborating)
  bytes_out_consistency: number;  // 1 - (MAD / median), 0-1
  bytes_in_consistency: number;
  bytes_out_total: number;
  bytes_in_total: number;
  bytes_ratio: number;            // out / in

  // Duration analysis (corroborating)
  duration_consistency: number;   // MAD-based: 1 - (MAD / median), 0-1
  consecutive_hours: number;      // longest consecutive hour run
  session_count: number;
  time_span_hours: number;

  // Histogram / periodicity (supporting)
  histogram_cv: number;
  bimodal_score: number;
  histogram_score: number;        // max(histogram_cv, bimodal_score)

  // Composite (pending final weights)
  beacon_score: number;
}

export interface BeaconCandidate extends CandidateIdentity, BeaconScore, CandidateAttribution {
  enrichment: CandidateEnrichment;
  evidence: EvidenceTrail;
}

// ─── Data Transfer Candidate (Layer 2: Score) ───────────────

export interface DataTransferScore {
  // Entity key
  src_ip: string;
  dest_ip: string;
  dest_port: number;

  // Scored features
  pcr_aggregate: number;             // PCR clipped to [0, 1]
  bytes_out_total_norm: number;      // normalized volume, 0-1
  burstiness: number;                // max_conn_bytes / total, 0-1

  // Composite
  data_transfer_score: number;

  // Informational
  pcr_aggregate_raw: number;         // raw PCR [-1, 1]
  pcr_consistency: number;           // MAD of per-connection PCR
  bytes_out_total: number;
  bytes_in_total: number;
  bytes_out_deviation: number | null;
  transfer_rate_bps: number;
  connection_count: number;
  mean_bytes_per_connection: number;
  time_span_hours: number;
  protocol_distribution: Record<string, number>;
  smb_file_count: number;
  smb_file_size_total: number;
  smb_file_names: string[];
  http_post_bytes_total: number;
  http_upload_count: number;
  session_count: number;
}

export interface DataTransferCandidate extends CandidateIdentity, DataTransferScore, CandidateAttribution {
  enrichment: CandidateEnrichment;
  evidence: EvidenceTrail;
}

// ─── PowerShell Invocation Anomaly Candidate (Layer 2: Score) ─

export type PowerShellInvocationHostCategory =
  | 'canonical'
  | 'ms_alternate'
  | 'vendor_alternate'
  | 'lolbin'
  | 'unknown'
  | 'renamed';

export type PowerShellInvocationParentCategory =
  | 'interactive'
  | 'script_host'
  | 'office'
  | 'lolbin'
  | 'service_host'
  | 'web_server'
  | 'browser'
  | 'wermgr'
  | 'unknown';

export type PowerShellInvocationCmdlineClassification =
  | 'tier_1_offensive_fingerprint'
  | 'tier_2_combination'
  | 'tier_3_encoded_with_other'
  | 'tier_4_partial_shape'
  | 'tier_5_encoded_alone'
  | 'benign';

export type PowerShellInvocationDataQualityFlag =
  | 'rename_uncheckable'
  | 'custom_host_uncheckable'
  | 'parent_uncheckable';

export type PowerShellInvocationDominantDimension =
  | 'rename'
  | 'custom_host'
  | 'parent'
  | 'commandline'
  | 'none';

export interface PowerShellInvocationAnomalyScore {
  // Entity key
  process_guid: string;

  // Scored dimensions
  rename_suspicion: number;
  custom_host_suspicion: number;
  parent_suspicion: number;
  commandline_suspicion: number;

  // Composite
  powershell_invocation_anomaly_score: number;

  // Classification
  dominant_dimension: PowerShellInvocationDominantDimension;
  host_category: PowerShellInvocationHostCategory;
  parent_category: PowerShellInvocationParentCategory;
  cmdline_classification: PowerShellInvocationCmdlineClassification;
  cmdline_flags_detected: string[];
  encoded_command_entropy: number | null;
  cmdline_length: number;

  // Process identity (EID 1)
  process_path: string;
  original_file_name: string | null;
  description: string | null;
  product: string | null;
  company: string | null;
  command_line: string;
  user: string;

  // Parent context
  parent_process_name: string;
  parent_process_path: string;
  parent_process_guid: string | null;

  // Optional EID 7 enrichment
  sma_dll_loaded: boolean;
  sma_dll_load_image: string | null;

  // Data quality
  data_quality_flags: PowerShellInvocationDataQualityFlag[];
}

export interface PowerShellInvocationAnomalyCandidate
  extends CandidateIdentity, PowerShellInvocationAnomalyScore, CandidateAttribution {
  enrichment: CandidateEnrichment;
  evidence: EvidenceTrail;
}

// ─── Unusual Parent-Child Anomaly Candidate (Layer 2: Score) ─

export type UnusualParentChildAnomalyTier =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'unknown'
  | 'benign';

export type UnusualParentChildAnomalyParentCategory =
  | 'office'
  | 'browser'
  | 'ai_coding_assistant'
  | 'email_client'
  | 'pdf_reader'
  | 'script_host'
  | 'lolbin'
  | 'web_server'
  | 'service_host'
  | 'unknown'
  | 'whitelisted';

export type UnusualParentChildAnomalyChildCategory =
  | 'powershell'
  | 'cmd'
  | 'wscript_cscript'
  | 'mshta'
  | 'rundll32_regsvr32'
  | 'certutil_bitsadmin'
  | 'msi_installer'
  | 'build_tool'
  | 'other_lolbin'
  | 'unknown';

export type UnusualParentChildAnomalyDataQualityFlag =
  | 'whitelist_matched'
  | 'parent_guid_missing';

export interface UnusualParentChildAnomalyScore {
  // Entity key
  process_guid: string;

  // Parent context
  parent_process_guid: string | null;

  // Process identity
  image: string;
  process_name: string | null;
  parent_image: string;
  parent_process_name: string | null;
  command_line: string;
  user: string;

  // Scoring
  parent_child_tradecraft_tier: number;
  unusual_parent_child_anomaly_score: number;

  // Classification
  tier: UnusualParentChildAnomalyTier;
  parent_category: UnusualParentChildAnomalyParentCategory;
  child_category: UnusualParentChildAnomalyChildCategory;

  // Informational fields
  grandparent_image: string | null;
  grandparent_process_guid: string | null;
  has_suspicious_commandline_flag: boolean;

  // Data quality
  data_quality_flags: UnusualParentChildAnomalyDataQualityFlag[];
}

export interface UnusualParentChildAnomalyCandidate
  extends CandidateIdentity, UnusualParentChildAnomalyScore, CandidateAttribution {
  type: 'unusual_parent_child_anomaly';
  enrichment: CandidateEnrichment;
  evidence: EvidenceTrail;
}

// ─── TLS Anomaly Candidate (Layer 2: Score) ────────────────

export interface TlsAnomalyScore {
  // Entity key
  src_ip: string;
  dest_ip: string;
  dest_port: number;

  // Dimension scores (each 0-1)
  cert_anomaly_score: number;
  fingerprint_anomaly_score: number;
  sni_anomaly_score: number;

  // Composite = max(cert, fingerprint, sni)
  tls_anomaly_score: number;

  // Cert detail (informational)
  cert_subject: string | null;
  cert_issuer: string | null;
  cert_serial: string | null;
  cert_validity_days: number | null;
  cert_not_before: string | null;
  cert_not_after: string | null;
  cert_self_signed: boolean;
  cert_expired: boolean;
  cert_key_type: string | null;
  cert_key_length: number | null;
  cert_san_dns: string[];
  cert_chain_length: number;

  // Fingerprint detail (informational)
  ja3_hash: string | null;
  ja4_hash: string | null;
  ja3s_hash: string | null;
  ja4x_hash: string | null;
  ja3_known_bad: boolean;
  ja3s_known_bad: boolean;
  ja3_ja3s_pair_known_bad: boolean;
  ja4x_known_bad: boolean;

  // SNI detail (informational)
  server_name: string | null;
  sni_matches_cert: boolean | null;
  connection_to_ip: boolean;

  // Connection context
  tls_version: string | null;
  cipher_suite: string | null;
  total_tls_connections: number;
  session_count: number;               // alias for total_tls_connections
}

export interface TlsAnomalyCandidate extends CandidateIdentity, TlsAnomalyScore, CandidateAttribution {
  enrichment: CandidateEnrichment;
  evidence: EvidenceTrail;
}
