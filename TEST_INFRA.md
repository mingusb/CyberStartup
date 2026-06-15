# E2E Test Infra: Cyber Startup

## Test Philosophy
- Opaque-box, requirement-driven. No dependency on implementation design.
- Methodology: Category-Partition + BVA + Pairwise + Workload Testing.

## Feature Inventory
| # | Feature | Source (requirement) | Tier 1 | Tier 2 | Tier 3 |
|---|---------|---------------------|:------:|:------:|:------:|
| 1 | Rebranding Rename Correctness | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 2 | GitHub Pages Pipeline & URL | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |

## Test Architecture
- Test runner: `pytest` using virtual environment runner `venv_test/bin/pytest`.
- Test case file: `tests/test_cyberstartup_rebrand_e2e.py`.
- Formats checked: file and directory crawls, YAML workflow configurations parsing, static page relative asset paths, FastAPI openapi spec, and Playwright browser dashboard UI.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Clean Local Build | F1, F2 | Medium |
| 2 | Static Dashboard UI Rendering | F1, F2 | High |
| 3 | Release Packaging Compliance | F1 | Medium |
| 4 | E2E Site Delivery | F1, F2 | High |
| 5 | Pipeline Make Phase3 dry-run | F1, F2 | Medium |

## Coverage Thresholds
- Tier 1: 5 feature coverage checks per feature (Total: 10 tests)
- Tier 2: 5 boundary/corner cases per feature (Total: 10 tests)
- Tier 3: pairwise combination tests (Total: 4 tests)
- Tier 4: 5 realistic application scenarios (Total: 7 tests)
- Total: 31 E2E tests
