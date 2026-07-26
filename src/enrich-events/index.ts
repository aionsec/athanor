import { resolveBusinessHours } from './business-hours.js';
import {
  applicableStage2LabelsForEvent,
} from './applicability.js';
import type { EnrichedEvent, EventEnrichment, TimestampedEvent } from './types.js';

export { loadBusinessHoursConfig } from './business-hours.js';
export { isWithinBusinessHours, resolveBusinessHours } from './business-hours.js';
export {
  DEFAULT_STAGE2_LABELS_FOR_UNKNOWN_EVENT,
  eventKeyOf,
  STAGE2_APPLICABILITY_BY_EVENT_KEY,
  STAGE2_LABEL_CONTRACTS_BY_LABEL,
  type Stage2EventEnrichmentLabel,
  type Stage2LabelContract,
  type Stage2ValueType,
  applicableStage2LabelsForEvent,
  applicableStage2LabelsForEventKey,
  assertStage2ApplicabilityCoverage,
} from './applicability.js';
export type { BusinessHoursConfig } from './business-hours.js';
export type { EnrichedEvent, EventEnrichment, TimestampedEvent } from './types.js';

const PERSISTENCE_PATH_CLASS_VALUES = new Set(['registry', 'scheduled_task', 'service', 'startup', 'file_in_startup_dir']);
const ACCOUNT_TYPE_VALUES = new Set(['user', 'admin', 'service']);

type PersistencePathClass = NonNullable<EventEnrichment['persistence_path_class']>;
type AccountType = NonNullable<EventEnrichment['account_type']>;

function asBooleanOrNull(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value;
  return null;
}

function asStringOrNull(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function asPersistencePathClassOrNull(value: unknown): PersistencePathClass | null {
  if (typeof value !== 'string') return null;
  return PERSISTENCE_PATH_CLASS_VALUES.has(value) ? (value as PersistencePathClass) : null;
}

function asAccountTypeOrNull(value: unknown): AccountType | null {
  if (typeof value !== 'string') return null;
  return ACCOUNT_TYPE_VALUES.has(value) ? (value as AccountType) : null;
}

export function normalizeEventEnrichment(
  value: unknown,
  event?: Pick<TimestampedEvent, 'source' | 'event_type'>,
): EventEnrichment {
  const partial = value && typeof value === 'object' && !Array.isArray(value)
    ? (value as EventEnrichment)
    : {};
  const labels = applicableStage2LabelsForEvent(event?.source, event?.event_type);
  const normalized: EventEnrichment = {};

  for (const label of labels) {
    switch (label) {
      case 'business_hours':
        normalized.business_hours = asBooleanOrNull(partial.business_hours);
        break;
      case 'lolbas_match':
        normalized.lolbas_match = asBooleanOrNull(partial.lolbas_match);
        break;
      case 'hijacklibs_match':
        normalized.hijacklibs_match = asBooleanOrNull(partial.hijacklibs_match);
        break;
      case 'filesec_match':
        normalized.filesec_match = asBooleanOrNull(partial.filesec_match);
        break;
      case 'persistence_path_class':
        normalized.persistence_path_class = asPersistencePathClassOrNull(partial.persistence_path_class);
        break;
      case 'security_tool_name':
        normalized.security_tool_name = asStringOrNull(partial.security_tool_name);
        break;
      case 'account_type':
        normalized.account_type = asAccountTypeOrNull(partial.account_type);
        break;
      default: {
        const _never: never = label;
        throw new Error(`Unsupported Stage 2 enrichment label: ${String(_never)}`);
      }
    }
  }

  return normalized;
}

export function enrichEvents<E extends TimestampedEvent>(events: ReadonlyArray<E | EnrichedEvent<E>>): EnrichedEvent<E>[] {
  return events.map((event) => {
    const existing = normalizeEventEnrichment(
      (event as { enrichment?: unknown }).enrichment,
      event,
    );
    const businessHours = existing.business_hours ?? resolveBusinessHours(event.timestamp);

    return {
      ...(event as E),
      enrichment: {
        ...existing,
        business_hours: businessHours,
      },
    };
  });
}
