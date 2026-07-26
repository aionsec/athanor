export interface TimestampedEvent {
  timestamp: string;
  source?: unknown;
  event_type?: unknown;
}

export interface EventEnrichment {
  lolbas_match?: boolean | null;
  hijacklibs_match?: boolean | null;
  filesec_match?: boolean | null;
  business_hours?: boolean | null;
  persistence_path_class?: 'registry' | 'scheduled_task' | 'service' | 'startup' | 'file_in_startup_dir' | null;
  security_tool_name?: string | null;
  account_type?: 'user' | 'admin' | 'service' | null;
}

export type EnrichedEvent<E extends TimestampedEvent> = E & { enrichment: EventEnrichment };
