# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
-

### Changed
-

### Fixed
-

## [0.13.0] - 2026-05-22

### Added
- Programmatic Concept Traceability System with explicit concept tag mapping.
- Local domain-specific test suites for users, system, crud, and analysis.
- Full parameterization for key user administration flows using pytest mark.parametrize.
- Comprehensive Environment Variables documentation in `README.md` and `.env.example` with precise descriptions and defaults.

### Changed
- Refactored and split the monolithic test suite `tests/test_api_client.py` to target explicit code boundaries.
- Improved overall pytest assertion density to achieve 0 tests without assertions.

## [0.1.54] - 2026-04-29

### Added
- Initial release
