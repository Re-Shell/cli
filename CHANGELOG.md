# Changelog

All notable changes to the `@re-shell/cli` package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.8] - 2024-12-12

### 🚀 World-Class Init Command Enhancement

The init command has been completely transformed into a world-class development experience, rivaling and exceeding industry-leading CLI tools.

### Added
- **🎨 Template System**: Built-in templates for e-commerce, dashboard, and SaaS applications
- **⚙️ Configuration Presets**: Save and reuse project configurations with `--preset` flag
- **🔍 Auto-Detection**: Automatic package manager detection (npm, yarn, pnpm, bun)
- **🔐 Security Scanning**: Automatic vulnerability assessment with remediation guidance
- **🧰 Professional Tooling**: ESLint, Prettier, Husky, CommitLint setup out-of-the-box
- **📊 Bun Support**: Added experimental support for Bun package manager
- **🐳 Enhanced Docker**: Multi-stage builds with package manager optimization
- **📚 Documentation Suite**: Auto-generated CONTRIBUTING.md, SECURITY.md, and project guidelines
- **🔄 Dependency Management**: Renovate configuration for automated updates
- **🧪 Testing Setup**: Jest configuration with 80% coverage thresholds
- **💻 IDE Integration**: VS Code workspace with recommended extensions
- **🏗️ Turborepo Config**: Advanced monorepo optimization pipeline
- **📋 Quality Gates**: Git hooks for code quality enforcement
- **🎯 Debug Mode**: `--debug` flag for troubleshooting
- **⚡ Skip Install**: `--skip-install` flag for CI environments

### Enhanced
- **Interactive Experience**: Enhanced prompts with better validation and user guidance
- **Progress Tracking**: Real-time progress indicators for all operations
- **Error Handling**: Comprehensive error messages with actionable remediation steps
- **System Validation**: Node.js version checking and system requirements validation
- **Smart Defaults**: Context-aware defaults based on environment detection

### Changed
- **Package Manager Detection**: Auto-selects the best available package manager
- **Template Architecture**: Template-specific directory structures and dependencies
- **Configuration Generation**: Comprehensive configuration files for modern development
- **Documentation**: Template-specific README and getting started guides

### Fixed
- **Repository Links**: Updated all GitHub repository links to correct public repository
- **Cross-Platform**: Improved cross-platform compatibility for disk space checks
- **TypeScript Compilation**: Fixed all TypeScript compilation warnings and errors

### Breaking Changes
- Package manager detection may select different defaults
- New configuration files are generated (can be customized)
- Template system replaces some hardcoded behaviors

### Migration Guide
Existing projects are not affected. New projects created with v0.2.8 will include all new features automatically.

## [0.2.7] - 2024-12-06

### Added
- **Comprehensive Documentation**: Updated README with detailed feature descriptions and examples
- **Enhanced Feature Set**: Added descriptions for all workspace commands, submodule management, and advanced CLI capabilities
- **Auto-Update Documentation**: Complete documentation for new update functionality with package manager detection
- **Framework Support**: Documented support for React, Vue, and Svelte with TypeScript-first approach

### Changed  
- **Improved README**: More accurate feature descriptions reflecting current CLI capabilities
- **Better Examples**: Enhanced code examples and usage patterns for all commands
- **Feature Categorization**: Organized features by functionality (workspace management, submodules, microfrontends)
- **Modern Descriptions**: Updated language to reflect advanced monorepo and microfrontend architecture

### Enhanced
- **Workspace Intelligence**: Better documentation of dependency graphs and workspace management features
- **Production Readiness**: Highlighted Docker multi-stage builds and GitHub Actions CI/CD capabilities
- **Developer Experience**: Emphasized TypeScript-first approach and modern tooling integration
- **Update System**: Documented automatic update detection and interactive package manager support

## [0.2.6] - 2024-12-06

### Fixed
- **CRITICAL**: Fixed terminal hanging after command completion that required Enter key press
- **CRITICAL**: Enhanced update command to actually perform package updates instead of just showing availability
- **CRITICAL**: Added automatic update checks before running any CLI command 
- Fixed TypeScript compilation errors in update functionality
- Improved terminal state reset and cursor management after command completion
- Enhanced spinner finalFlush() method for proper terminal cleanup

### Added  
- Automatic update detection and notification for all CLI commands
- Interactive package manager detection (npm, yarn, pnpm) for updates
- Enhanced finalFlush() method in ProgressSpinner for immediate terminal reset
- Comprehensive package manager support for automated updates
- Better error handling for update processes

### Changed
- Update command now performs actual package updates with user confirmation
- All commands now check for updates automatically (except update/version commands)
- Improved terminal output flushing and state management
- Enhanced spinner behavior with proper cleanup and cursor restoration

## [0.2.5] - 2024-12-06

### Fixed
- **CRITICAL**: Resolved terminal output buffering issue where CLI commands would hang with "Creating..." text
- **CRITICAL**: Fixed hanging issues in non-TTY environments (Docker containers, CI/CD, some terminals)
- Fixed interactive prompts appearing even when using `--yes/-y` flag
- Improved spinner behavior and progress indicators for better terminal compatibility
- Enhanced environment detection for CI environments and non-interactive terminals

### Added
- New `--yes/-y` flag to skip all interactive prompts for CI/CD environments
- Auto-detection of non-TTY environments with automatic fallback to non-interactive mode
- Step-by-step progress updates during initialization process
- Enhanced terminal compatibility across different environments

### Changed
- Improved prompts conditional logic for non-interactive mode
- Enhanced output flushing mechanisms for immediate terminal feedback
- Better spinner state management and cleanup
- More robust terminal compatibility detection

## [0.2.4] - 2024-11-20

### Fixed
- Fixed terminal output buffering issues
- Improved spinner behavior for better terminal compatibility
- Better terminal detection for non-interactive environments
- Immediate output flushing for all CLI operations

### Added
- Enhanced progress indication with step-by-step updates
- Improved error handling during initialization

## [0.2.3] - 2024-10-15

### Added
- Automatic update notifications
- New `re-shell update` command
- Framework option for better clarity (backward compatible)
- Version caching for update checks

### Changed
- Enhanced user experience with non-intrusive update notifications
- Better command option handling

## [0.2.2] - 2024-09-30

### Fixed
- Fixed all unused variables and imports
- Enhanced TypeScript strict mode compliance
- Improved error handling and code organization
- Updated dependencies and optimized performance

## [0.2.1] - 2024-09-15

### Fixed
- Fixed version mismatch in package.json
- Updated documentation to match actual CLI functionality
- Removed deprecated options that were not implemented
- Improved error handling and messages
- Enhanced test coverage and reliability
- Fixed workspace detection and path resolution issues

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