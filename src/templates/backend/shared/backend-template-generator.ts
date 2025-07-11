/**
 * Shared Backend Template Generator System
 * Provides unified architecture for all backend framework templates
 */

import { promises as fs } from 'fs';
import * as path from 'path';
import { TemplateEngine } from '../../../utils/template-engine';

export interface BackendTemplateConfig {
  language: string;
  framework: string;
  packageManager: string;
  buildTool?: string;
  testFramework: string;
  orm?: string;
  features: string[];
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  scripts: Record<string, string>;
  dockerConfig?: DockerConfig;
  envVars?: Record<string, string>;
}

export interface DockerConfig {
  baseImage: string;
  workDir: string;
  exposedPorts: number[];
  buildSteps: string[];
  runCommand: string;
  multistage?: boolean;
}

export abstract class BackendTemplateGenerator {
  protected templateEngine: TemplateEngine;
  protected config: BackendTemplateConfig;

  constructor(config: BackendTemplateConfig) {
    this.config = config;
    this.templateEngine = new TemplateEngine();
  }

  /**
   * Generate complete backend project structure
   */
  async generate(projectPath: string, options: any): Promise<void> {
    // Create base directory structure
    await this.createDirectoryStructure(projectPath);

    // Generate language-specific files
    await this.generateLanguageFiles(projectPath, options);

    // Generate framework-specific files
    await this.generateFrameworkFiles(projectPath, options);

    // Generate common files
    await this.generateCommonFiles(projectPath, options);

    // Generate Docker configuration
    if (this.config.dockerConfig) {
      await this.generateDockerFiles(projectPath, options);
    }

    // Generate test structure
    await this.generateTestStructure(projectPath, options);

    // Generate documentation
    await this.generateDocumentation(projectPath, options);
  }

  /**
   * Create standard directory structure
   */
  protected async createDirectoryStructure(projectPath: string): Promise<void> {
    const directories = [
      'src',
      'src/controllers',
      'src/services',
      'src/models',
      'src/middleware',
      'src/utils',
      'src/config',
      'tests',
      'tests/unit',
      'tests/integration',
      'scripts',
      'docs',
      '.github/workflows'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }
  }

  /**
   * Generate common files across all backends
   */
  protected async generateCommonFiles(projectPath: string, options: any): Promise<void> {
    // .gitignore
    await this.generateGitignore(projectPath);

    // README.md
    await this.generateReadme(projectPath, options);

    // Environment files
    await this.generateEnvFiles(projectPath);

    // CI/CD workflows
    await this.generateCICD(projectPath);

    // Health check endpoint
    await this.generateHealthCheck(projectPath);

    // API documentation
    await this.generateAPIDocs(projectPath);
  }

  /**
   * Generate .gitignore with language-specific patterns
   */
  protected async generateGitignore(projectPath: string): Promise<void> {
    const commonPatterns = [
      '# Dependencies',
      'node_modules/',
      'vendor/',
      '.venv/',
      'target/',
      'build/',
      'dist/',
      '',
      '# Environment',
      '.env',
      '.env.local',
      '.env.*.local',
      '',
      '# Logs',
      '*.log',
      'logs/',
      '',
      '# IDE',
      '.vscode/',
      '.idea/',
      '*.swp',
      '*.swo',
      '.DS_Store',
      '',
      '# Testing',
      'coverage/',
      '.coverage',
      '*.cover',
      '.pytest_cache/',
      '',
      '# Build artifacts',
      '*.exe',
      '*.dll',
      '*.so',
      '*.dylib',
      '*.pyc',
      '*.pyo',
      '__pycache__/',
      '',
      '# Language specific',
      ...this.getLanguageSpecificIgnorePatterns()
    ];

    await fs.writeFile(
      path.join(projectPath, '.gitignore'),
      commonPatterns.join('\\n')
    );
  }

  /**
   * Generate comprehensive README
   */
  protected async generateReadme(projectPath: string, options: any): Promise<void> {
    const content = `# ${options.name}

A ${this.config.framework} ${this.config.language} microservice built with Re-Shell CLI.

## 🚀 Features

${this.config.features.map(f => `- ${f}`).join('\\n')}

## 📋 Prerequisites

- ${this.getLanguagePrerequisites()}
- Docker (optional)
- Re-Shell CLI

## 🛠️ Installation

\`\`\`bash
# Clone the repository
git clone <repository-url>
cd ${options.name}

# Install dependencies
${this.getInstallCommand()}
\`\`\`

## 🔧 Configuration

Copy the example environment file:

\`\`\`bash
cp .env.example .env
\`\`\`

Update the environment variables in \`.env\`:

\`\`\`env
${Object.entries(this.config.envVars || {}).map(([k, v]) => `${k}=${v}`).join('\\n')}
\`\`\`

## 🏃 Running the Application

### Development

\`\`\`bash
${this.getDevCommand()}
\`\`\`

### Production

\`\`\`bash
${this.getProdCommand()}
\`\`\`

### Docker

\`\`\`bash
# Build the image
docker build -t ${options.name} .

# Run the container
docker run -p ${this.config.dockerConfig?.exposedPorts?.[0] || 3000}:${this.config.dockerConfig?.exposedPorts?.[0] || 3000} ${options.name}
\`\`\`

## 🧪 Testing

\`\`\`bash
# Run all tests
${this.getTestCommand()}

# Run with coverage
${this.getCoverageCommand()}
\`\`\`

## 📚 API Documentation

- Swagger UI: http://localhost:${options.port}/docs
- OpenAPI JSON: http://localhost:${options.port}/openapi.json

## 🏗️ Project Structure

\`\`\`
${options.name}/
├── src/
│   ├── controllers/    # Request handlers
│   ├── services/       # Business logic
│   ├── models/         # Data models
│   ├── middleware/     # Middleware functions
│   ├── utils/          # Utility functions
│   └── config/         # Configuration files
├── tests/
│   ├── unit/          # Unit tests
│   └── integration/   # Integration tests
├── scripts/           # Utility scripts
├── docs/             # Documentation
└── .github/          # GitHub workflows
\`\`\`

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (\`git checkout -b feature/amazing-feature\`)
3. Commit your changes (\`git commit -m 'Add some amazing feature'\`)
4. Push to the branch (\`git push origin feature/amazing-feature\`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

---

Built with ❤️ using [Re-Shell CLI](https://github.com/re-shell/cli)
`;

    await fs.writeFile(path.join(projectPath, 'README.md'), content);
  }

  /**
   * Generate environment files
   */
  protected async generateEnvFiles(projectPath: string): Promise<void> {
    const envExample = Object.entries(this.config.envVars || {})
      .map(([key, value]) => `${key}=${value}`)
      .join('\\n');

    await fs.writeFile(path.join(projectPath, '.env.example'), envExample);
  }

  /**
   * Generate CI/CD workflows
   */
  protected async generateCICD(projectPath: string): Promise<void> {
    const workflow = `name: CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup ${this.config.language}
      uses: ${this.getSetupAction()}
      
    - name: Install dependencies
      run: ${this.getInstallCommand()}
      
    - name: Run tests
      run: ${this.getTestCommand()}
      
    - name: Run linter
      run: ${this.getLintCommand()}
      
    - name: Build
      run: ${this.getBuildCommand()}

  docker:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Build and push Docker image
      uses: docker/build-push-action@v4
      with:
        push: true
        tags: |
          ghcr.io/\${{ github.repository }}:latest
          ghcr.io/\${{ github.repository }}:\${{ github.sha }}
`;

    await fs.writeFile(
      path.join(projectPath, '.github/workflows/ci.yml'),
      workflow
    );
  }

  // Abstract methods to be implemented by language-specific generators
  protected abstract generateLanguageFiles(projectPath: string, options: any): Promise<void>;
  protected abstract generateFrameworkFiles(projectPath: string, options: any): Promise<void>;
  protected abstract generateTestStructure(projectPath: string, options: any): Promise<void>;
  protected abstract generateHealthCheck(projectPath: string): Promise<void>;
  protected abstract generateAPIDocs(projectPath: string): Promise<void>;
  protected abstract generateDockerFiles(projectPath: string, options: any): Promise<void>;
  protected abstract generateDocumentation(projectPath: string, options: any): Promise<void>;
  
  // Helper methods to be implemented
  protected abstract getLanguageSpecificIgnorePatterns(): string[];
  protected abstract getLanguagePrerequisites(): string;
  protected abstract getInstallCommand(): string;
  protected abstract getDevCommand(): string;
  protected abstract getProdCommand(): string;
  protected abstract getTestCommand(): string;
  protected abstract getCoverageCommand(): string;
  protected abstract getLintCommand(): string;
  protected abstract getBuildCommand(): string;
  protected abstract getSetupAction(): string;
}

/**
 * Common utilities for all backend templates
 */
export class BackendTemplateUtils {
  /**
   * Generate JWT authentication middleware
   */
  static generateJWTAuth(language: string): string {
    // Language-specific JWT implementation
    return '';
  }

  /**
   * Generate rate limiting middleware
   */
  static generateRateLimit(language: string): string {
    // Language-specific rate limiting
    return '';
  }

  /**
   * Generate logging configuration
   */
  static generateLogging(language: string): string {
    // Language-specific logging setup
    return '';
  }

  /**
   * Generate database configuration
   */
  static generateDatabaseConfig(language: string, orm: string): string {
    // Language and ORM specific database setup
    return '';
  }

  /**
   * Generate OpenAPI/Swagger documentation
   */
  static generateOpenAPISpec(framework: string): string {
    // Framework-specific OpenAPI integration
    return '';
  }

  /**
   * Generate health check endpoint
   */
  static generateHealthEndpoint(language: string, framework: string): string {
    // Language and framework specific health check
    return '';
  }

  /**
   * Generate Docker configuration
   */
  static generateDockerfile(config: DockerConfig): string {
    // Multi-stage Dockerfile generation
    return '';
  }
}