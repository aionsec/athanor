# Changelog

## 0.1.1 — 2026-09-05

### Fixed

- The CLI creates missing parent directories for both `--output` and `--discards`.
  Serialized artifacts and summary lines are unchanged; other filesystem failures
  still use the existing CLI error messages. Reported in the macOS and Windows BIY
  Run 2 reports, `05-creating-skills.md` (distill setup) and `06-the-graph.md` (Start).
- `npm run build` uses a dependency-free Node script to clean, compile and set the
  executable bit on Unix, without requiring Unix `rm` or `chmod` on Windows.
  Reported in the BIY Run 2 Windows `02-athanor.md` build failure. The test command
  also uses portable double quotes around its glob so `npm test` works through
  Windows' native npm script shell.
