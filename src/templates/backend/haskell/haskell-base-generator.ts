/**
 * Haskell Backend Template Base Generator
 * Shared functionality for all Haskell web frameworks
 */

import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class HaskellBackendGenerator extends BackendTemplateGenerator {
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Haskell',
      framework,
      packageManager: 'cabal',
      buildTool: 'stack',
      testFramework: 'hspec',
      features: [
        'Pure functional programming',
        'Type-safe development',
        'Lazy evaluation',
        'Strong static typing',
        'Pattern matching',
        'Monadic composition',
        'STM for concurrency',
        'Type-level programming',
        'Property-based testing',
        'GHC optimizations'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'build': 'stack build',
        'test': 'stack test',
        'run': 'stack run',
        'repl': 'stack ghci',
        'clean': 'stack clean',
        'install': 'stack install',
        'watch': 'stack build --file-watch --fast',
        'benchmark': 'stack bench',
        'haddock': 'stack haddock',
        'format': 'ormolu --mode inplace **/*.hs'
      },
      dockerConfig: {
        baseImage: 'haskell:9.6-slim',
        workDir: '/app',
        exposedPorts: [3000],
        buildSteps: [
          'COPY stack.yaml package.yaml* ./',
          'RUN stack setup',
          'RUN stack build --only-dependencies',
          'COPY . .',
          'RUN stack build --copy-bins'
        ],
        runCommand: '/usr/local/bin/app-exe',
        multistage: true
      },
      envVars: {
        'PORT': '3000',
        'HOST': '0.0.0.0',
        'ENV': 'development',
        'LOG_LEVEL': 'info',
        'DATABASE_URL': 'postgresql://user:password@localhost:5432/haskell_db',
        'REDIS_URL': 'redis://localhost:6379',
        'JWT_SECRET': 'your-secret-key',
        'CORS_ORIGIN': '*'
      }
    };
    super(config);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate stack.yaml
    await this.generateStackConfig(projectPath);

    // Generate package.yaml or .cabal file
    await this.generatePackageConfig(projectPath, options);

    // Generate .gitignore
    await this.generateHaskellGitignore(projectPath);

    // Generate HLint configuration
    await this.generateHLintConfig(projectPath);

    // Generate stylish-haskell config
    await this.generateStylishHaskellConfig(projectPath);

    // Create directory structure
    const directories = [
      'app',
      'src',
      'src/API',
      'src/Config',
      'src/Database',
      'src/Models',
      'src/Services',
      'src/Types',
      'src/Utils',
      'test',
      'test/Unit',
      'test/Integration',
      'bench',
      'scripts'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }
  }

  private async generateStackConfig(projectPath: string): Promise<void> {
    const stackContent = `# Stack configuration for ${this.config.framework} application
resolver: lts-21.25  # GHC 9.4.8

packages:
- .

extra-deps:
${this.getExtraDeps().map(dep => `- ${dep}`).join('\n')}

# Override default flag values for local packages and extra-deps
flags: {}

# Extra package databases containing global packages
extra-package-dbs: []

# Docker image settings
docker:
  enable: false
  
# Allow newer versions of packages
allow-newer: true

# Build settings
build:
  library-profiling: false
  executable-profiling: false
  copy-bins: true
  
# GHC options
ghc-options:
  "$everything": -Wall -Wcompat -Widentities -Wincomplete-record-updates -Wincomplete-uni-patterns -Wpartial-fields -Wredundant-constraints

# Nix integration (optional)
nix:
  enable: false
`;

    await fs.writeFile(
      path.join(projectPath, 'stack.yaml'),
      stackContent
    );
  }

  private async generatePackageConfig(projectPath: string, options: any): Promise<void> {
    const packageContent = `name:                ${options.name}
version:             0.1.0.0
github:              "githubuser/${options.name}"
license:             BSD3
author:              "Author name here"
maintainer:          "example@example.com"
copyright:           "2024 Author name here"

extra-source-files:
- README.md
- CHANGELOG.md

# Metadata used when publishing your package
synopsis:            ${this.config.framework} web application
category:            Web

# To avoid duplicated efforts in documentation and dealing with the
# complications of embedding Haddock markup inside cabal files, it is
# common to point users to the README.md file.
description:         Please see the README on GitHub at <https://github.com/githubuser/${options.name}#readme>

dependencies:
- base >= 4.7 && < 5
${this.getFrameworkDependencies().map(dep => `- ${dep}`).join('\n')}

default-extensions:
- OverloadedStrings
- RecordWildCards
- LambdaCase
- TupleSections
- TypeApplications
- DataKinds
- TypeOperators
- FlexibleContexts
- FlexibleInstances
- MultiParamTypeClasses
- ScopedTypeVariables
- DeriveGeneric
- GeneralizedNewtypeDeriving
- DerivingStrategies
- StandaloneDeriving
- DeriveAnyClass

ghc-options:
- -Wall
- -Wcompat
- -Widentities
- -Wincomplete-record-updates
- -Wincomplete-uni-patterns
- -Wmissing-export-lists
- -Wmissing-home-modules
- -Wpartial-fields
- -Wredundant-constraints

library:
  source-dirs: src
  
executables:
  ${options.name}-exe:
    main:                Main.hs
    source-dirs:         app
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - ${options.name}

tests:
  ${options.name}-test:
    main:                Spec.hs
    source-dirs:         test
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - ${options.name}
    - hspec
    - hspec-wai
    - hspec-wai-json
    - QuickCheck
    - quickcheck-instances

benchmarks:
  ${options.name}-bench:
    main:                Main.hs
    source-dirs:         bench
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - ${options.name}
    - criterion
`;

    await fs.writeFile(
      path.join(projectPath, 'package.yaml'),
      packageContent
    );
  }

  private async generateHaskellGitignore(projectPath: string): Promise<void> {
    const gitignoreContent = `# Haskell
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
.stack-work/
cabal.project.local
cabal.project.local~
.HTF/
.ghc.environment.*

# Stack
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
.env
.env.local
.env.*.local
logs/
*.log
`;

    await fs.writeFile(
      path.join(projectPath, '.gitignore'),
      gitignoreContent
    );
  }

  private async generateHLintConfig(projectPath: string): Promise<void> {
    const hlintContent = `# HLint configuration file
# https://github.com/ndmitchell/hlint

# Specify additional command line arguments
- arguments: [--color]

# Warnings currently triggered by our code
- ignore: {name: "Use newtype instead of data"}
- ignore: {name: "Redundant do"}
- ignore: {name: "Use <$>"}
- ignore: {name: "Use list comprehension"}

# Ignore some builtin hints
- ignore: {name: "Use camelCase"}
- ignore: {name: "Eta reduce"}

# Custom hints
- warn: {lhs: "mappend", rhs: "(<>)"}
- warn: {lhs: "map f (map g x)", rhs: "map (f . g) x"}
- warn: {lhs: "concat (map f x)", rhs: "concatMap f x"}

# Modules to ignore
- ignore: {name: "Use module export list", within: ["Main"]}

# Extensions we allow
- extensions:
  - default: true
  - name: [OverloadedStrings, RecordWildCards, ViewPatterns]
`;

    await fs.writeFile(
      path.join(projectPath, '.hlint.yaml'),
      hlintContent
    );
  }

  private async generateStylishHaskellConfig(projectPath: string): Promise<void> {
    const stylishContent = `# stylish-haskell configuration
steps:
  - simple_align:
      cases: true
      top_level_patterns: true
      records: true

  - imports:
      align: global
      list_align: after_alias
      pad_module_names: true
      long_list_align: inline
      empty_list_align: inherit
      list_padding: 4
      separate_lists: true
      space_surround: false

  - language_pragmas:
      style: vertical
      align: true
      remove_redundant: true

  - trailing_whitespace: {}

columns: 100
newline: native

language_extensions:
  - OverloadedStrings
  - RecordWildCards
  - TypeApplications
  - DataKinds
  - TypeOperators
`;

    await fs.writeFile(
      path.join(projectPath, '.stylish-haskell.yaml'),
      stylishContent
    );
  }

  protected abstract getFrameworkDependencies(): string[];
  protected abstract getExtraDeps(): string[];

  protected async generateCommonFiles(projectPath: string, options: any): Promise<void> {
    await super.generateCommonFiles(projectPath, options);

    // Generate Haskell-specific common files
    await this.generateCabalConfig(projectPath);
    await this.generateTestSetup(projectPath);
    await this.generateBenchmarkSetup(projectPath);
    await this.generateMakefile(projectPath);
  }

  private async generateCabalConfig(projectPath: string): Promise<void> {
    const cabalConfigContent = `-- Cabal configuration
repository stackage
  url: https://github.com/commercialhaskell/all-cabal-files/archive/hackage.tar.gz

jobs: $ncpus
documentation: true
doc-index-file: $datadir/doc/$arch-$os-$compiler/index.html
`;

    await fs.writeFile(
      path.join(projectPath, 'cabal.config'),
      cabalConfigContent
    );
  }

  private async generateTestSetup(projectPath: string): Promise<void> {
    const specContent = `{-# LANGUAGE OverloadedStrings #-}

import Test.Hspec
import Test.QuickCheck
import Control.Exception (evaluate)

main :: IO ()
main = hspec $ do
  describe "Prelude.head" $ do
    it "returns the first element of a list" $ do
      head [23 ..] \`shouldBe\` (23 :: Int)

    it "returns the first element of an *arbitrary* list" $
      property $ \\x xs -> head (x:xs) == (x :: Int)

    it "throws an exception if used with an empty list" $ do
      evaluate (head []) \`shouldThrow\` anyException
`;

    await fs.writeFile(
      path.join(projectPath, 'test', 'Spec.hs'),
      specContent
    );
  }

  private async generateBenchmarkSetup(projectPath: string): Promise<void> {
    const benchContent = `import Criterion.Main

-- Our benchmark harness.
main :: IO ()
main = defaultMain [
  bgroup "example" [ bench "1" $ whnf (\\x -> x + 1) (1 :: Int)
                   , bench "2" $ whnf (\\x -> x + 2) (1 :: Int)
                   ]
  ]
`;

    await fs.writeFile(
      path.join(projectPath, 'bench', 'Main.hs'),
      benchContent
    );
  }

  private async generateMakefile(projectPath: string): Promise<void> {
    const makefileContent = `.PHONY: all build test bench clean run watch format lint setup

all: build

setup:
	stack setup
	stack build --dependencies-only --test --no-run-tests

build:
	stack build --fast

test:
	stack test

bench:
	stack bench

clean:
	stack clean

run:
	stack run

watch:
	stack build --file-watch --fast

format:
	find src app test -name "*.hs" -exec ormolu --mode inplace {} \\;

lint:
	hlint src app test

ghci:
	stack ghci

docs:
	stack haddock

install:
	stack install

docker-build:
	docker build -t ${this.config.framework.toLowerCase()}-app .

docker-run:
	docker run -p 3000:3000 ${this.config.framework.toLowerCase()}-app
`;

    await fs.writeFile(
      path.join(projectPath, 'Makefile'),
      makefileContent
    );
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Test structure is already created in generateLanguageFiles
    // Additional test files can be added here if needed
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is typically implemented in the framework files
    // Can be overridden by specific frameworks if needed
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are framework-specific and implemented in framework generators
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerContent = this.getDockerfileContent(options);
    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerContent);

    // Docker Compose file
    const dockerComposeContent = `version: '3.8'

services:
  app:
    build: .
    ports:
      - "\${PORT:-3000}:3000"
    environment:
      - PORT=3000
      - ENV=production
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/haskell_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=haskell_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
`;

    await fs.writeFile(
      path.join(projectPath, 'docker-compose.yml'),
      dockerComposeContent
    );
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    const readmeContent = `# ${options.name}

A ${this.config.framework} web application built with Haskell.

## Prerequisites

- GHC 9.4+ or Stack
- PostgreSQL 12+
- Redis (optional)

## Getting Started

\`\`\`bash
# Install dependencies
stack setup
stack build

# Run tests
stack test

# Start development server
stack run

# Build for production
stack build --copy-bins
\`\`\`

## Project Structure

\`\`\`
.
├── app/           # Application entry point
├── src/           # Source code
├── test/          # Test files
├── bench/         # Benchmarks
├── stack.yaml     # Stack configuration
└── package.yaml   # Package configuration
\`\`\`

## Development

\`\`\`bash
# Watch mode
stack build --file-watch --fast

# REPL
stack ghci

# Format code
make format

# Lint code
make lint
\`\`\`

## Testing

\`\`\`bash
# Run all tests
stack test

# Run with coverage
stack test --coverage

# Run specific test
stack test --test-arguments="-m TestName"
\`\`\`

## Deployment

\`\`\`bash
# Build Docker image
docker build -t ${options.name} .

# Run with Docker Compose
docker-compose up -d
\`\`\`
`;

    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readmeContent
    );
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      'dist/',
      'dist-*/',
      '.stack-work/',
      '.cabal-sandbox/',
      'cabal.sandbox.config',
      '*.hi',
      '*.o',
      '*.prof',
      '*.hp',
      '*.eventlog',
      '.hpc/',
      '.hsenv/',
      '.HTF/',
      '.ghc.environment.*',
      'stack.yaml.lock'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'Haskell Stack or GHC 9.4+';
  }

  protected getInstallCommand(): string {
    return 'stack setup && stack build';
  }

  protected getDevCommand(): string {
    return 'stack run';
  }

  protected getProdCommand(): string {
    return './app-exe';
  }

  protected getTestCommand(): string {
    return 'stack test';
  }

  protected getCoverageCommand(): string {
    return 'stack test --coverage';
  }

  protected getLintCommand(): string {
    return 'hlint src app test';
  }

  protected getBuildCommand(): string {
    return 'stack build --copy-bins';
  }

  protected getSetupAction(): string {
    return 'haskell/actions/setup@v2';
  }

  protected async generateBuildScript(projectPath: string, options: any): Promise<void> {
    const buildScriptContent = `#!/bin/bash

# Build script for Haskell ${this.config.framework} application

set -e

echo "Building Haskell ${this.config.framework} application..."

# Setup Stack
echo "Setting up Stack..."
stack setup

# Install dependencies
echo "Installing dependencies..."
stack build --dependencies-only --test --no-run-tests

# Run tests
echo "Running tests..."
stack test

# Build application
echo "Building application..."
stack build --copy-bins

# Generate documentation
echo "Generating documentation..."
stack haddock

echo "Build complete!"
echo "Run 'stack run' to start the application"
`;

    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'scripts', 'build.sh'),
      buildScriptContent
    );

    await fs.chmod(path.join(projectPath, 'scripts', 'build.sh'), 0o755);
  }

  protected getDockerfileContent(options: any): string {
    return `# Multi-stage Dockerfile for Haskell ${this.config.framework} application

# Build stage
FROM haskell:9.6 AS build

RUN mkdir -p /app
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \\
    libpq-dev \\
    && rm -rf /var/lib/apt/lists/*

# Copy stack configuration
COPY stack.yaml package.yaml ./

# Setup GHC and dependencies
RUN stack setup
RUN stack build --dependencies-only

# Copy source code
COPY . .

# Build application
RUN stack build --copy-bins

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \\
    ca-certificates \\
    libpq5 \\
    libgmp10 \\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 haskell

WORKDIR /app

# Copy binary from build stage
COPY --from=build /root/.local/bin/${options.name}-exe /usr/local/bin/app

# Copy any necessary runtime files
COPY --from=build /app/static ./static
COPY --from=build /app/config ./config

# Switch to non-root user
USER haskell

# Expose port
EXPOSE 3000

# Set environment variables
ENV PORT=3000
ENV HOST=0.0.0.0

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:3000/health || exit 1

# Run the application
CMD ["app"]
`;
  }
}