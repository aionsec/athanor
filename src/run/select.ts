// Per-type event selectors: which events each scorer is shown.
//
// This is the ONLY narrowing in the pipeline. Attribution, the frequency tables and
// stage-4 enrichment all see the full event set — see `runner.ts` for why that split is
// a correctness property rather than an optimization.
//
//   selectConnEvents        beacon, data_transfer
//   selectSslEvents         tls_anomaly
//   selectTelemetryEvents   unusual_parent_child_anomaly, powershell_invocation_anomaly
//                           (the process scorers filter by event type themselves,
//                           because the PowerShell one reads TWO of them)
//
// A new candidate type needs a selector here. See `docs/extending.md`.
import type { EnrichedEvent } from '../enrich-events/index.js';
import {
  loadEvents,
  type ConnLogEvent,
  type TelemetryEvent,
  type TlsSslEvent,
} from '../schema/events.js';

type LoadedEvents = Awaited<ReturnType<typeof loadEvents>>;
type LoadedEvent = LoadedEvents[number];

export type DistillationStage1Events = LoadedEvents;
export type DistillationStage1Event = LoadedEvent;
export type DistillationEnrichedEvent = EnrichedEvent<LoadedEvent>;

function isConnEvent(
  event: DistillationEnrichedEvent,
): event is EnrichedEvent<ConnLogEvent> {
  return event.source === 'zeek' && event.event_type === 'conn';
}

export function selectConnEvents(events: DistillationEnrichedEvent[]): EnrichedEvent<ConnLogEvent>[] {
  return events.filter(isConnEvent);
}

function isSslEvent(
  event: DistillationEnrichedEvent,
): event is EnrichedEvent<TlsSslEvent> {
  return event.source === 'zeek' && event.event_type === 'ssl';
}

export function selectSslEvents(events: DistillationEnrichedEvent[]): EnrichedEvent<TlsSslEvent>[] {
  return events.filter(isSslEvent);
}

export function selectTelemetryEvents(events: DistillationEnrichedEvent[]): TelemetryEvent[] {
  return events as unknown as TelemetryEvent[];
}
