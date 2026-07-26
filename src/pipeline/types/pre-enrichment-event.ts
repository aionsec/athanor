import { z } from 'zod';
import type { TelemetryEvent } from '../../schema/events.js';

export type PreEnrichmentEvent = TelemetryEvent;

export const preEnrichmentEventSchema = z.object({
  timestamp: z.string().min(1),
  source: z.string().min(1),
  event_type: z.string().min(1),
}).passthrough();

export function isPreEnrichmentEvent(value: unknown): value is PreEnrichmentEvent {
  return preEnrichmentEventSchema.safeParse(value).success;
}
