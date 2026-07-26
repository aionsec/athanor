import { normalizeProcessName } from './normalize-process.js';

export interface ParentChildPairEntitySource {
  parent_process_name?: unknown;
  parent_process_path?: unknown;
  parent_image?: unknown;
  source_image?: unknown;
  process_name?: unknown;
  process_path?: unknown;
  image?: unknown;
  target_image?: unknown;
}

function parentProcess(source: ParentChildPairEntitySource): string | null {
  return normalizeProcessName(source.parent_process_name)
    ?? normalizeProcessName(source.parent_process_path)
    ?? normalizeProcessName(source.source_image)
    ?? normalizeProcessName(source.parent_image);
}

function childProcess(source: ParentChildPairEntitySource): string | null {
  return normalizeProcessName(source.process_name)
    ?? normalizeProcessName(source.process_path)
    ?? normalizeProcessName(source.target_image)
    ?? normalizeProcessName(source.image);
}

export function extractParentChildPairEntity(source: ParentChildPairEntitySource): string | null {
  const parent = parentProcess(source);
  const child = childProcess(source);
  if (!parent || !child) return null;
  return `${parent}\x1f${child}`;
}
