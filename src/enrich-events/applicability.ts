export type Stage2ValueType = 'boolean' | 'string' | 'enum';

export type Stage2EventEnrichmentLabel =
  | 'business_hours'
  | 'lolbas_match'
  | 'hijacklibs_match'
  | 'filesec_match'
  | 'persistence_path_class'
  | 'security_tool_name'
  | 'account_type';

export interface Stage2LabelContract {
  valueType: Stage2ValueType;
  nullable: boolean;
  enumValues?: readonly string[];
}

export const STAGE2_LABEL_CONTRACTS_BY_LABEL = {
  business_hours: {
    valueType: 'boolean',
    nullable: true,
  },
  lolbas_match: {
    valueType: 'boolean',
    nullable: true,
  },
  hijacklibs_match: {
    valueType: 'boolean',
    nullable: true,
  },
  filesec_match: {
    valueType: 'boolean',
    nullable: true,
  },
  persistence_path_class: {
    valueType: 'enum',
    nullable: true,
    enumValues: ['registry', 'scheduled_task', 'service', 'startup', 'file_in_startup_dir'],
  },
  security_tool_name: {
    valueType: 'string',
    nullable: true,
  },
  account_type: {
    valueType: 'enum',
    nullable: true,
    enumValues: ['user', 'admin', 'service'],
  },
} as const satisfies Readonly<Record<Stage2EventEnrichmentLabel, Stage2LabelContract>>;

export type Stage2ApplicabilityMap = Readonly<Record<string, readonly Stage2EventEnrichmentLabel[]>>;

export const STAGE2_APPLICABILITY_BY_EVENT_KEY = {
  'zeek|conn': ['business_hours'],
  'zeek|dns': ['business_hours'],
  'zeek|http': ['business_hours'],
  'zeek|ssl': ['business_hours'],
  'zeek|files': ['business_hours'],
  'zeek|kerberos': ['business_hours'],
  'zeek|smb_files': ['business_hours'],
  'zeek|x509': ['business_hours'],
  'zeek|dce_rpc': ['business_hours'],
  'zeek|rdp': ['business_hours'],
  'sysmon|process_create': [
    'business_hours',
    'lolbas_match',
    'filesec_match',
    'persistence_path_class',
    'security_tool_name',
    'account_type',
  ],
  'sysmon|image_load': [
    'business_hours',
    'lolbas_match',
    'hijacklibs_match',
    'filesec_match',
    'security_tool_name',
  ],
  'sysmon|process_access': [
    'business_hours',
    'security_tool_name',
    'account_type',
  ],
  'sysmon|create_remote_thread': [
    'business_hours',
    'security_tool_name',
  ],
  'sysmon|remote_thread_create': [
    'business_hours',
    'security_tool_name',
  ],
  'sysmon|network_connect': [
    'business_hours',
    'account_type',
  ],
  'sysmon|dns_query': [
    'business_hours',
    'account_type',
  ],
  'sysmon|file_create': [
    'business_hours',
    'filesec_match',
    'persistence_path_class',
    'account_type',
  ],
  'sysmon|registry_create_delete': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'sysmon|registry_key_create_delete': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'sysmon|registry_value_set': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'sysmon|registry_rename': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'sysmon|wmi_filter': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'sysmon|wmi_consumer': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'sysmon|wmi_binding': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'security|logon_failure': [
    'business_hours',
    'account_type',
  ],
  'security|logon_success': [
    'business_hours',
    'account_type',
  ],
  'security|explicit_credential_logon': [
    'business_hours',
    'account_type',
  ],
  'security|kerberos_service_ticket': [
    'business_hours',
    'account_type',
  ],
  'security|directory_service_access': [
    'business_hours',
  ],
  'security|scheduled_task_created': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'security|service_installed': [
    'business_hours',
    'persistence_path_class',
    'account_type',
  ],
  'powershell|script_block': [
    'business_hours',
    'account_type',
  ],
  'powershell|powershell_script_block': [
    'business_hours',
    'account_type',
  ],
  'powershell|module_logging': [
    'business_hours',
    'account_type',
  ],
} as const satisfies Stage2ApplicabilityMap;

export const DEFAULT_STAGE2_LABELS_FOR_UNKNOWN_EVENT = [
  'business_hours',
] as const satisfies readonly Stage2EventEnrichmentLabel[];

export function eventKeyOf(source: unknown, eventType: unknown): string | null {
  if (typeof source !== 'string' || typeof eventType !== 'string') return null;
  const sourceNormalized = source.trim().toLowerCase();
  const eventTypeNormalized = eventType.trim().toLowerCase();
  if (sourceNormalized.length === 0 || eventTypeNormalized.length === 0) return null;
  return `${sourceNormalized}|${eventTypeNormalized}`;
}

export function applicableStage2LabelsForEvent(
  source: unknown,
  eventType: unknown,
): readonly Stage2EventEnrichmentLabel[] {
  const eventKey = eventKeyOf(source, eventType);
  if (!eventKey) return DEFAULT_STAGE2_LABELS_FOR_UNKNOWN_EVENT;
  return (STAGE2_APPLICABILITY_BY_EVENT_KEY as Stage2ApplicabilityMap)[eventKey]
    ?? DEFAULT_STAGE2_LABELS_FOR_UNKNOWN_EVENT;
}

export function applicableStage2LabelsForEventKey(eventKey: string): readonly Stage2EventEnrichmentLabel[] {
  const key = eventKey.trim().toLowerCase();
  if (key.length === 0) return DEFAULT_STAGE2_LABELS_FOR_UNKNOWN_EVENT;
  return (STAGE2_APPLICABILITY_BY_EVENT_KEY as Stage2ApplicabilityMap)[key]
    ?? DEFAULT_STAGE2_LABELS_FOR_UNKNOWN_EVENT;
}

export function assertStage2ApplicabilityCoverage(eventKeys: readonly string[]): void {
  const missing = eventKeys
    .map((eventKey) => eventKey.trim().toLowerCase())
    .filter((eventKey) => eventKey.length > 0)
    .filter((eventKey) => !Object.hasOwn(STAGE2_APPLICABILITY_BY_EVENT_KEY, eventKey));

  if (missing.length > 0) {
    throw new Error(
      `Stage 2 applicability is missing mappings for event keys: ${missing.join(', ')}`,
    );
  }
}
