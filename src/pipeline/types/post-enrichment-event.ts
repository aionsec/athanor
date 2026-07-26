import { z } from 'zod';
import type { PreEnrichmentEvent } from './pre-enrichment-event.js';

export interface EventEnrichment {
  lolbas_match?: boolean | null;
  hijacklibs_match?: boolean | null;
  filesec_match?: boolean | null;
  business_hours?: boolean | null;
  persistence_path_class?: 'registry' | 'scheduled_task' | 'service' | 'startup' | 'file_in_startup_dir' | null;
  security_tool_name?: string | null;
  account_type?: 'user' | 'admin' | 'service' | null;
}

export type PostEnrichmentEvent = PreEnrichmentEvent & { enrichment: EventEnrichment };

export const eventEnrichmentSchema = z.object({
  lolbas_match: z.boolean().nullable().optional(),
  hijacklibs_match: z.boolean().nullable().optional(),
  filesec_match: z.boolean().nullable().optional(),
  business_hours: z.boolean().nullable().optional(),
  persistence_path_class: z.enum(['registry', 'scheduled_task', 'service', 'startup', 'file_in_startup_dir']).nullable().optional(),
  security_tool_name: z.string().nullable().optional(),
  account_type: z.enum(['user', 'admin', 'service']).nullable().optional(),
}).strict();

export const postEnrichmentEventSchema = z.object({
  timestamp: z.string().min(1),
  source: z.string().min(1),
  event_type: z.string().min(1),
  enrichment: eventEnrichmentSchema,
}).passthrough();

export function isPostEnrichmentEvent(value: unknown): value is PostEnrichmentEvent {
  return postEnrichmentEventSchema.safeParse(value).success;
}
