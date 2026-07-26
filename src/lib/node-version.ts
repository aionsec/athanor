/**
 * The Node floor, checked at the entry point.
 *
 * `package.json#engines` is advisory — npm warns and installs anyway unless the user
 * set `engine-strict` — so a student on Node 20 otherwise meets whatever the first
 * unsupported syntax or API happens to be, from deep inside the pipeline, in a
 * message that says nothing about their runtime. One check at the door names it.
 *
 * A separate module rather than a function in `cli.ts` because `cli.ts` RUNS the CLI
 * as its last statement: importing it to test one predicate would distill a folder.
 */

/** The complaint to print, or `undefined` when the runtime is new enough. */
export function nodeVersionComplaint(
  version: string,
  minimum = 22,
  program = 'athanor',
): string | undefined {
  const major = Number.parseInt(version.replace(/^v/, '').split('.')[0] ?? '', 10);
  if (!Number.isFinite(major) || major >= minimum) return undefined;
  return `${program} needs Node ${minimum} or newer; this is Node ${version}. `
    + `Install Node ${minimum} (nvm: \`nvm install ${minimum} && nvm use ${minimum}\`) `
    + 'and run it again.';
}
