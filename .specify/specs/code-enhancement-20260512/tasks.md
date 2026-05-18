# Tasks: Code Enhancement: documentdb-mcp

Generated: 2026-05-12T14:14:40.985758+00:00
Skipped informational: 5

- [ ] [P] **T001** [Codebase Optimization] 1 functions exceed 200 lines (actionable refactoring targets): register_crud_too
  - Priority: P2-Medium | Effort: Large
- [ ] [P] **T002** [Codebase Optimization] Monolithic: mcp_server.py (761L) — 1 functions with high complexity (worst: regi
  - Priority: P1-High | Effort: Large
- [ ] [P] **T003** [Test Coverage] Test suite lacks intent diversity (only one type)
  - Priority: P2-Medium | Effort: Medium
- [ ] [P] **T004** [Test Coverage] 18 potential doc-test drift items
  - Priority: P2-Medium | Effort: Medium
- [ ] [P] **T005** [Documentation & Governance] README missing: Both bare-metal (pip) and container (Docker) deployment docs
  - Priority: P4-Enhancement | Effort: Small
- [ ] [P] **T006** [Documentation & Governance] README missing: Has a Table of Contents
  - Priority: P4-Enhancement | Effort: Small
- [ ] [P] **T007** [Documentation & Governance] README missing: References /docs directory material
  - Priority: P4-Enhancement | Effort: Small
- [ ] [P] **T008** [Documentation & Governance] README missing: Has bare-metal and container deployment instructions
  - Priority: P4-Enhancement | Effort: Small
- [ ] [P] **T009** [Architecture & Design Patterns] SRP: 1 modules exceed 500 lines (god modules)
  - Priority: P2-Medium | Effort: Large
- [ ] [P] **T010** [Architecture & Design Patterns] No discernible layer architecture (no domain/service/adapter separation)
  - Priority: P2-Medium | Effort: Medium
- [ ] [P] **T011** [Concept Traceability] Low traceability ratio: 0% concepts fully traced
  - Priority: P4-Enhancement | Effort: Medium
- [ ] [P] **T012** [Concept Traceability] 4 test functions missing concept markers
  - Priority: P4-Enhancement | Effort: Small
- [ ] [P] **T013** [Concept Traceability] 37 significant functions (>10 lines) missing concept markers in docstrings
  - Priority: P4-Enhancement | Effort: Small
- [ ] [P] **T014** [Linting & Formatting] Total lint findings: 32 (high/error: 29, medium/warning: 3, low: 0)
  - Priority: P1-High | Effort: Medium
- [ ] [P] **T015** [Pre-Commit Compliance] 2 hook(s) may be outdated: ruff-pre-commit, uv-pre-commit
  - Priority: P2-Medium | Effort: Small
- [ ] [P] **T016** [Changelog Audit] CHANGELOG.md exists but could not be parsed — check format compliance
  - Priority: P3-Low | Effort: Medium
- [ ] [P] **T017** [Changelog Audit] No changelog entries within the last 30 days
  - Priority: P3-Low | Effort: Medium
- [ ] [P] **T018** [Changelog Audit] keepachangelog not installed — pip install 'universal-skills[code-enhancer]'
  - Priority: P3-Low | Effort: Small
- [ ] [P] **T019** [Pytest Quality] 1 tests have no assertions
  - Priority: P4-Enhancement | Effort: Medium
- [ ] [P] **T020** [Environment Variables] Partial env var documentation: 32% coverage
  - Priority: P2-Medium | Effort: Medium
- [ ] [P] **T021** [Environment Variables] Undocumented env vars: ALLOWED_CLIENT_REDIRECT_URIS, AUTH_TYPE, DOCUMENT_DB_HOST
  - Priority: P2-Medium | Effort: Medium
- [ ] [P] **T022** [Environment Variables] 10 Python env vars not in .env.example: ANALYSISTOOL, COLLECTIONSTOOL, CRUDTOOL,
  - Priority: P2-Medium | Effort: Medium
