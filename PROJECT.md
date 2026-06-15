# Project: Cyber Startup

## Architecture
- Core Package: `src/cyberstartup` (previously the old package) containing api, models, ingestion, telemetry, orchestration, and main entry point.
- Kernel components: eBPF probes in `src/ebpf`, SGX enclave in `src/sgx`, P4 switch logic in `src/p4`.
- Frontend: HTML/JS assets in `docs/` and `website/` directories.
- Deployment: GitHub Pages CI/CD workflow `.github/workflows/deploy.yml` compiling eBPF/SGX components and uploading site assets.

## Code Layout
- `src/cyberstartup/`: Main application modules.
- `src/ebpf/`: BPF filters and probes.
- `src/sgx/`: Secure hardware enclave code.
- `src/p4/`: Programmable router configurations.
- `docs/`: GitHub Pages target directory containing index.html, whitepaper, patent.
- `tests/`: Automated unit and integration tests.

## Milestones
| # | Name | Scope | Dependencies | Status | Conv ID |
|---|------|-------|-------------|--------|---------|
| 1 | Rename Project | Case-insensitive rename of previous project names to "Cyber Startup" or "cyberstartup" in all files, directories, imports, and config files. | none | DONE | 06d83103-25d6-4960-9650-95ecbaa56d2c |
| 2 | Fix GitHub Pages Pipeline | Fix Pages deployment failure, making sure it compiles, passes tests, and correctly generates documentation assets. | M1 | DONE | 669089f7-29ab-4279-b377-dd8ba8e7897f |
| 3 | Final Integration & Hardening | Opaque-box E2E test validation, Tier 5 white-box adversarial coverage hardening, and Forensic Auditor verification. | M2 | DONE | e51af930-d189-4b55-98e1-208baa890361 |

## Interface Contracts
- All package references and imports must use `cyberstartup` (e.g. `import cyberstartup` instead of the old package).
- Port binds and environment variables should use updated names where applicable (e.g., `CYBERSTARTUP_NO_SUDO` or similar, but preserving expected runner behavior).
