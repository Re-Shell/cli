import { BackendTemplate } from '../types';

export const haskellCabalTemplate: BackendTemplate = {
  id: 'haskell-cabal',
  name: 'haskell-cabal',
  displayName: 'Haskell Cabal Build System',
  description: 'A modern Haskell project setup with Cabal build system, featuring advanced configuration and tooling',
  framework: 'cabal',
  language: 'haskell',
  version: '3.8',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '📦',
  type: 'build-tool',
  complexity: 'intermediate',
  keywords: ['haskell', 'cabal', 'build-system', 'package-management', 'tooling'],
  
  features: [
    'Modern Cabal configuration',
    'Multi-package project support',
    'Dependency management',
    'Test suite setup',
    'Benchmark configuration',
    'Documentation generation',
    'Code coverage',
    'Profiling support',
    'CI/CD integration',
    'Nix integration',
    'HLS (Haskell Language Server) support',
    'Formatter configuration',
    'Linting setup',
    'Release automation'
  ],
  
  structure: {
    'my-project.cabal': `cabal-version:      3.8
name:               my-project
version:            0.1.0.0
synopsis:           A modern Haskell project
description:        A comprehensive Haskell project with advanced tooling and best practices
homepage:           https://github.com/yourusername/my-project
bug-reports:        https://github.com/yourusername/my-project/issues
license:            MIT
license-file:       LICENSE
author:             Your Name
maintainer:         your.email@example.com
copyright:          2024 Your Name
category:           Application
build-type:         Simple
extra-doc-files:    README.md
                    CHANGELOG.md
tested-with:        GHC == 9.2.8
                    GHC == 9.4.5
                    GHC == 9.6.2

source-repository head
  type:     git
  location: https://github.com/yourusername/my-project

common common-options
  build-depends:       base >= 4.16 && < 5
  ghc-options:         -Wall
                       -Wcompat
                       -Widentities
                       -Wincomplete-record-updates
                       -Wincomplete-uni-patterns
                       -Wmissing-export-lists
                       -Wmissing-home-modules
                       -Wpartial-fields
                       -Wredundant-constraints
                       -Wunused-packages
                       -Wunused-type-patterns
  default-language:    Haskell2010
  default-extensions:  ConstraintKinds
                       DeriveGeneric
                       DerivingStrategies
                       GeneralizedNewtypeDeriving
                       InstanceSigs
                       KindSignatures
                       LambdaCase
                       OverloadedStrings
                       RecordWildCards
                       ScopedTypeVariables
                       StandaloneDeriving
                       TupleSections
                       TypeApplications
                       ViewPatterns

library
  import:              common-options
  exposed-modules:     MyProject
                       MyProject.Core
                       MyProject.Types
                       MyProject.Utils
  other-modules:       MyProject.Internal
  build-depends:       aeson >= 2.0 && < 2.2
                     , bytestring
                     , containers
                     , mtl
                     , text
                     , time
                     , transformers
  hs-source-dirs:      src

executable my-project
  import:              common-options
  main-is:             Main.hs
  build-depends:       my-project
                     , optparse-applicative >= 0.17 && < 0.19
  hs-source-dirs:      app
  ghc-options:         -threaded
                       -rtsopts
                       -with-rtsopts=-N

test-suite my-project-test
  import:              common-options
  type:                exitcode-stdio-1.0
  main-is:             Spec.hs
  other-modules:       MyProject.CoreSpec
                       MyProject.TypesSpec
                       MyProject.UtilsSpec
  build-depends:       my-project
                     , hspec >= 2.10 && < 2.12
                     , hspec-discover >= 2.10 && < 2.12
                     , QuickCheck >= 2.14 && < 2.15
  hs-source-dirs:      test
  ghc-options:         -threaded
                       -rtsopts
                       -with-rtsopts=-N
  build-tool-depends:  hspec-discover:hspec-discover

benchmark my-project-bench
  import:              common-options
  type:                exitcode-stdio-1.0
  main-is:             Bench.hs
  build-depends:       my-project
                     , criterion >= 1.6 && < 1.7
                     , deepseq
  hs-source-dirs:      bench
  ghc-options:         -threaded
                       -rtsopts
                       -with-rtsopts=-N`,

    'cabal.project': `packages: .

package my-project
  ghc-options: -Werror

-- Use latest versions of dependencies
index-state: 2024-01-01T00:00:00Z

-- Optimization settings
optimization: 2

-- Documentation
documentation: True
doc-index-file: $datadir/doc/$arch-$os-$compiler/index.html

-- Testing
tests: True
test-show-details: direct

-- Benchmarks
benchmarks: True

-- Coverage
coverage: True

-- Allow newer versions of dependencies
allow-newer:
  *:base

-- Source repository packages
source-repository-package
  type: git
  location: https://github.com/someuser/some-package
  tag: abc123def456

-- Optional packages
optional-packages:
  ./vendor/*/*.cabal

-- Constraints
constraints:
  aeson >= 2.0,
  text >= 2.0

-- Profiling
profiling: False
library-profiling: False
executable-profiling: False`,

    'cabal.project.local': `-- Local overrides for development
-- This file is ignored by git

-- Enable profiling locally
profiling: True
library-profiling: True
executable-profiling: True

-- Use local packages
packages:
  ../my-other-project

-- Development flags
package my-project
  flags: +development -production
  
-- Faster builds during development
optimization: 0

-- Extra dependencies for development
extra-packages:
  haskell-language-server

-- Allow even newer versions during development
allow-newer: *`,

    'hie.yaml': `# HLS (Haskell Language Server) configuration
cradle:
  cabal:
    - path: "./src"
      component: "lib:my-project"
    
    - path: "./app"
      component: "exe:my-project"
    
    - path: "./test"
      component: "test:my-project-test"
    
    - path: "./bench"
      component: "bench:my-project-bench"`,

    '.github/workflows/ci.yml': `name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  cabal:
    name: Cabal - GHC ${{ matrix.ghc }} - ${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macOS-latest, windows-latest]
        ghc: ['9.2.8', '9.4.5', '9.6.2']
        cabal: ['3.8']
        exclude:
          - os: macOS-latest
            ghc: '9.2.8'
          - os: windows-latest
            ghc: '9.2.8'
    
    steps:
    - uses: actions/checkout@v3
    
    - uses: haskell/actions/setup@v2
      id: setup
      with:
        ghc-version: ${{ matrix.ghc }}
        cabal-version: ${{ matrix.cabal }}
    
    - name: Configure the build
      run: |
        cabal configure --enable-tests --enable-benchmarks --enable-documentation
        cabal build --dry-run
    
    - name: Restore cached dependencies
      uses: actions/cache/restore@v3
      id: cache
      env:
        key: ${{ runner.os }}-ghc-${{ steps.setup.outputs.ghc-version }}-cabal-${{ steps.setup.outputs.cabal-version }}
      with:
        path: ${{ steps.setup.outputs.cabal-store }}
        key: ${{ env.key }}-plan-${{ hashFiles('**/plan.json') }}
        restore-keys: ${{ env.key }}-
    
    - name: Install dependencies
      run: cabal build all --only-dependencies
    
    - name: Save cached dependencies
      uses: actions/cache/save@v3
      if: ${{ steps.cache.outputs.cache-primary-key != steps.cache.outputs.cache-matched-key }}
      with:
        path: ${{ steps.setup.outputs.cabal-store }}
        key: ${{ steps.cache.outputs.cache-primary-key }}
    
    - name: Build
      run: cabal build all
    
    - name: Run tests
      run: cabal test all
    
    - name: Check documentation
      run: cabal haddock all
    
    - name: Run benchmarks
      run: cabal bench all
    
    - name: Check cabal file
      run: cabal check`,

    'Makefile': `# Makefile for Haskell project

.PHONY: all build test bench doc clean install format lint setup ci

# Default target
all: build

# Setup development environment
setup:
	cabal update
	cabal install --lib --package-env . \
		hspec hspec-discover QuickCheck \
		criterion haskell-language-server \
		hlint fourmolu

# Build the project
build:
	cabal build all

# Run tests
test:
	cabal test all --test-show-details=direct

# Run tests with coverage
test-coverage:
	cabal test all --enable-coverage
	hpc report dist-newstyle/build/*/ghc-*/my-project-*/t/my-project-test/hpc_index.html

# Run benchmarks
bench:
	cabal bench all

# Generate documentation
doc:
	cabal haddock all --haddock-hyperlink-source

# Clean build artifacts
clean:
	cabal clean
	rm -rf dist-newstyle

# Install the executable
install:
	cabal install exe:my-project

# Format code
format:
	fourmolu --mode inplace src app test

# Lint code
lint:
	hlint src app test

# Run continuous integration checks locally
ci: format lint build test doc

# REPL with project loaded
repl:
	cabal repl lib:my-project

# Update dependencies
update:
	cabal update
	cabal outdated

# Generate ctags
tags:
	hasktags -c src

# Profile the application
profile:
	cabal configure --enable-profiling
	cabal build
	cabal run my-project -- +RTS -p`,

    '.gitignore': `# Cabal
dist
dist-*
cabal-dev
*.o
*.hi
*.hie
*.chi
*.chs.h
*.dyn_o
*.dyn_hi
.hpc
.hsenv
.cabal-sandbox/
cabal.sandbox.config
*.prof
*.aux
*.hp
*.eventlog
cabal.project.local
cabal.project.local~
.HTF/
.ghc.environment.*

# Stack (if also using Stack)
.stack-work/
stack.yaml.lock

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Project specific
/result
/tags
TAGS`,

    'fourmolu.yaml': `# Fourmolu configuration for consistent formatting

indentation: 2
column-limit: 100
function-arrows: leading
comma-style: leading
import-export-style: leading
indent-wheres: true
record-brace-space: true
newlines-between-decls: 1
haddock-style: multi-line
let-style: inline
in-style: right-align
respectful: true
fixities: []
unicode: never`,

    '.hlint.yaml': `# HLint configuration

- arguments: [--color=auto, --cpp-simple]

# Specify additional command line arguments
- group:
    name: dollar
    enabled: true
    imports:
    - package base

# Custom rules
- error: {lhs: "map f (map g x)", rhs: "map (f . g) x"}
- warning: {lhs: "foldr f z (map g x)", rhs: "foldr (f . g) z x"}

# Ignore some builtin hints
- ignore: {name: "Use newtype instead of data"}
- ignore: {name: "Use camelCase"}
- ignore: {name: "Redundant do"}

# Define some custom infix operators
- fixity: "infixr 9 ."
- fixity: "infixr 5 ++"
- fixity: "infixl 4 <$>"
- fixity: "infixl 4 <*>"

# Add custom warnings
- warn: {name: Use explicit exports}
- suggest: {lhs: "[] ++ x", rhs: "x"}
- suggest: {lhs: "x ++ []", rhs: "x"}

# Restrict specific modules
- modules:
  - {name: [Data.Set, Data.HashSet], as: Set}
  - {name: [Data.Map, Data.HashMap], as: Map}`,

    'README.md': `# My Haskell Project

A modern Haskell project with Cabal build system and comprehensive tooling.

## Features

- Modern Cabal 3.8 configuration
- Multi-GHC support (9.2, 9.4, 9.6)
- Comprehensive test suite with HSpec and QuickCheck
- Benchmarking with Criterion
- Documentation generation
- Code formatting with Fourmolu
- Linting with HLint
- CI/CD with GitHub Actions
- HLS (Haskell Language Server) support
- Code coverage reporting
- Profiling configuration

## Prerequisites

- GHC 9.2.8 or higher
- Cabal 3.8 or higher
- Git

## Quick Start

1. **Clone and setup**
   \`\`\`bash
   git clone <repository-url>
   cd my-project
   make setup
   \`\`\`

2. **Build the project**
   \`\`\`bash
   make build
   # or
   cabal build all
   \`\`\`

3. **Run tests**
   \`\`\`bash
   make test
   # or with coverage
   make test-coverage
   \`\`\`

4. **Run the application**
   \`\`\`bash
   cabal run my-project -- --help
   \`\`\`

## Project Structure

\`\`\`
.
├── app/                 # Executable source
│   └── Main.hs
├── src/                 # Library source
│   ├── MyProject.hs
│   ├── MyProject/
│   │   ├── Core.hs
│   │   ├── Types.hs
│   │   └── Utils.hs
│   └── MyProject/Internal.hs
├── test/                # Test suite
│   ├── Spec.hs
│   └── MyProject/
│       ├── CoreSpec.hs
│       ├── TypesSpec.hs
│       └── UtilsSpec.hs
├── bench/               # Benchmarks
│   └── Bench.hs
├── my-project.cabal     # Package description
├── cabal.project        # Build configuration
├── hie.yaml            # HLS configuration
├── fourmolu.yaml       # Code formatter config
├── .hlint.yaml         # Linter configuration
└── Makefile            # Build automation
\`\`\`

## Development

### Code Style

Format code with Fourmolu:
\`\`\`bash
make format
\`\`\`

Lint code with HLint:
\`\`\`bash
make lint
\`\`\`

### Testing

Run all tests:
\`\`\`bash
cabal test all
\`\`\`

Run specific test suite:
\`\`\`bash
cabal test my-project-test
\`\`\`

Generate coverage report:
\`\`\`bash
make test-coverage
\`\`\`

### Benchmarking

Run benchmarks:
\`\`\`bash
make bench
\`\`\`

### Documentation

Generate Haddock documentation:
\`\`\`bash
make doc
\`\`\`

### REPL

Start a REPL with the project loaded:
\`\`\`bash
make repl
# or
cabal repl
\`\`\`

### Profiling

Build with profiling enabled:
\`\`\`bash
cabal configure --enable-profiling
cabal build
cabal run my-project -- +RTS -p
\`\`\`

## CI/CD

The project includes GitHub Actions workflows that:
- Build and test on multiple GHC versions
- Run on Linux, macOS, and Windows
- Check code formatting and linting
- Generate and upload documentation
- Create releases

## Dependencies

Update dependencies:
\`\`\`bash
make update
\`\`\`

Check for outdated dependencies:
\`\`\`bash
cabal outdated
\`\`\`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run \`make ci\` to ensure all checks pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details`,

    'Setup.hs': `import Distribution.Simple
main = defaultMain`,

    'src/MyProject.hs': `{-# LANGUAGE OverloadedStrings #-}

-- | Main module for MyProject
module MyProject
  ( -- * Core functionality
    runMyProject
  , Config(..)
  , defaultConfig
  
    -- * Re-exports
  , module MyProject.Types
  , module MyProject.Core
  ) where

import MyProject.Core
import MyProject.Types
import MyProject.Utils

-- | Main entry point for the library
runMyProject :: Config -> IO ()
runMyProject config = do
  putStrLn $ "Running MyProject with config: " ++ show config
  result <- processWithConfig config
  case result of
    Left err -> putStrLn $ "Error: " ++ show err
    Right val -> putStrLn $ "Success: " ++ show val`,

    'app/Main.hs': `{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import MyProject
import Options.Applicative

-- | Command line arguments
data Args = Args
  { argsConfigFile :: Maybe FilePath
  , argsVerbose :: Bool
  , argsCommand :: Command
  } deriving (Show)

data Command
  = Run
  | Check
  | Version
  deriving (Show)

-- | Parse command line arguments
parseArgs :: Parser Args
parseArgs = do
  argsConfigFile <- optional $ strOption
    ( long "config"
   <> short 'c'
   <> metavar "FILE"
   <> help "Configuration file path"
    )
  
  argsVerbose <- switch
    ( long "verbose"
   <> short 'v'
   <> help "Enable verbose output"
    )
  
  argsCommand <- subparser
    ( command "run" (info (pure Run) (progDesc "Run the application"))
   <> command "check" (info (pure Check) (progDesc "Check configuration"))
   <> command "version" (info (pure Version) (progDesc "Show version"))
    )
  
  pure Args{..}

main :: IO ()
main = do
  args <- execParser opts
  case argsCommand args of
    Run -> runMyProject defaultConfig
    Check -> putStrLn "Configuration is valid"
    Version -> putStrLn "my-project version 0.1.0.0"
  where
    opts = info (parseArgs <**> helper)
      ( fullDesc
     <> progDesc "A modern Haskell application"
     <> header "my-project - a comprehensive example"
      )`
  }
};