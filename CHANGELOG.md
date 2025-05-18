# Changelog

All notable changes to the `@re-shell/cli` package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2023-09-20

### Added
- New commands: `build`, `serve`, and `list`
- Enhanced command structure with improved help messages
- Watch mode for the build command
- HTTPS support for the serve command
- Multiple output formats for the list command
- Integration with test application
- Performance optimizations for faster builds

### Changed
- Renamed `create-mf` command to `add` for consistency
- Updated configuration format for better extensibility
- Improved templating system with more customization options
- Better error messages and logging

### Fixed
- Fixed issues with nested project structures
- Resolved path resolution in Windows environments
- Fixed template generation bugs

## [0.1.0] - 2023-08-15

### Added
- Initial release of CLI tool
- Basic commands: `create` and `create-mf`
- Simple templating system
- Core configuration management