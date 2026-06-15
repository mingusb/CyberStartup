# Original User Request

## Initial Request — 2026-06-14T21:29:30-06:00

# Teamwork Project Prompt — Draft

> Status: Ready for launch — awaiting user approval
> Goal: Craft prompt → get user approval → delegate to teamwork_preview

Rename the project to "Cyber Startup" everywhere across the codebase and ensure the GitHub Pages deployment pipeline actually works and succeeds.

Working directory: [workspace_root]
Integrity mode: development

## Requirements

### R1. Rename the project
Rename all instances of previous project names to "Cyber Startup". This includes updating text within files as well as renaming files and directories (e.g., the old package to `src/cyberstartup`).

### R2. Fix GitHub Pages Deployment
Diagnose and fix any issues causing the GitHub Actions deployment for GitHub Pages to fail or return 404s. Ensure the pipeline successfully builds and deploys the site to the live URL.

## Acceptance Criteria

### Verification
- [ ] Programmatic check: A case-insensitive search across the codebase for previous project names returns 0 results.
- [ ] Programmatic check: `curl -s -o /dev/null -w "%{http_code}" <LIVE_GITHUB_PAGES_URL>` returns `200` after the team pushes the fixes to the repository. The team must correctly identify the live URL.
