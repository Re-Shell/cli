import * as fs from 'fs-extra';
import * as path from 'path';
import chalk from 'chalk';
import { findMonorepoRoot } from '../utils/monorepo';

interface GenerateOptions {
  spinner?: any;
  verbose?: boolean;
  type?: 'component' | 'hook' | 'service' | 'test' | 'config' | 'documentation';
  framework?: 'react' | 'vue' | 'svelte' | 'angular';
  workspace?: string;
  template?: string;
  export?: boolean;
}

interface ComponentTemplate {
  name: string;
  files: { path: string; content: string }[];
  dependencies?: string[];
}

export async function generateCode(name: string, options: GenerateOptions = {}) {
  try {
    const monorepoRoot = await findMonorepoRoot(process.cwd());
    if (!monorepoRoot) {
      throw new Error('Not in a Re-Shell monorepo. Run this command from within a monorepo.');
    }

    if (options.spinner) {
      options.spinner.text = `Generating ${options.type || 'component'}...`;
    }

    const generator = getGenerator(options.type || 'component');
    await generator(monorepoRoot, name, options);

    if (options.spinner) {
      options.spinner.succeed(chalk.green(`${options.type || 'Component'} "${name}" generated successfully!`));
    }

    console.log('\n' + chalk.bold('Generated:'));
    console.log(`  Type: ${options.type || 'component'}`);
    console.log(`  Name: ${name}`);
    console.log(`  Framework: ${options.framework || 'react'}`);

  } catch (error) {
    if (options.spinner) {
      options.spinner.fail(chalk.red('Code generation failed'));
    }
    throw error;
  }
}

export async function generateTests(workspace: string, options: GenerateOptions = {}) {
  try {
    const monorepoRoot = await findMonorepoRoot(process.cwd());
    if (!monorepoRoot) {
      throw new Error('Not in a Re-Shell monorepo');
    }

    if (options.spinner) {
      options.spinner.text = 'Generating tests...';
    }

    const workspacePath = path.join(monorepoRoot, workspace);
    if (!await fs.pathExists(workspacePath)) {
      throw new Error(`Workspace not found: ${workspace}`);
    }

    await generateTestSuite(workspacePath, options);

    if (options.spinner) {
      options.spinner.succeed(chalk.green('Test suite generated successfully!'));
    }

  } catch (error) {
    if (options.spinner) {
      options.spinner.fail(chalk.red('Test generation failed'));
    }
    throw error;
  }
}

export async function generateDocumentation(options: GenerateOptions = {}) {
  try {
    const monorepoRoot = await findMonorepoRoot(process.cwd());
    if (!monorepoRoot) {
      throw new Error('Not in a Re-Shell monorepo');
    }

    if (options.spinner) {
      options.spinner.text = 'Generating documentation...';
    }

    await generateProjectDocs(monorepoRoot, options);
    await generateAPIDocumentation(monorepoRoot, options);
    await generateReadme(monorepoRoot, options);

    if (options.spinner) {
      options.spinner.succeed(chalk.green('Documentation generated successfully!'));
    }

  } catch (error) {
    if (options.spinner) {
      options.spinner.fail(chalk.red('Documentation generation failed'));
    }
    throw error;
  }
}

function getGenerator(type: string) {
  const generators = {
    component: generateComponent,
    hook: generateHook,
    service: generateService,
    test: generateTestFile,
    config: generateConfig,
    documentation: generateDocs
  };

  const generator = generators[type as keyof typeof generators];
  if (!generator) {
    throw new Error(`Unknown generator type: ${type}`);
  }

  return generator;
}

async function generateComponent(monorepoRoot: string, name: string, options: GenerateOptions) {
  const framework = options.framework || 'react';
  const workspace = options.workspace || findBestWorkspace(monorepoRoot, 'component');
  const workspacePath = path.join(monorepoRoot, workspace);

  if (!await fs.pathExists(workspacePath)) {
    throw new Error(`Workspace not found: ${workspace}`);
  }

  const template = getComponentTemplate(name, framework, options);
  
  for (const file of template.files) {
    const filePath = path.join(workspacePath, file.path);
    await fs.ensureDir(path.dirname(filePath));
    await fs.writeFile(filePath, file.content);
    
    if (options.verbose) {
      console.log(chalk.green(`  ✓ Created ${file.path}`));
    }
  }

  // Update exports if requested
  if (options.export) {
    await updateExports(workspacePath, name, template);
  }
}

async function generateHook(monorepoRoot: string, name: string, options: GenerateOptions) {
  const framework = options.framework || 'react';
  
  if (framework !== 'react') {
    throw new Error('Hooks are currently only supported for React');
  }

  const workspace = options.workspace || findBestWorkspace(monorepoRoot, 'hook');
  const workspacePath = path.join(monorepoRoot, workspace);

  const hookName = name.startsWith('use') ? name : `use${name.charAt(0).toUpperCase() + name.slice(1)}`;
  
  const hookContent = `import { useState, useEffect } from 'react';

export interface ${hookName.charAt(3).toUpperCase() + hookName.slice(4)}Options {
  // Add your options here
}

export function ${hookName}(options?: ${hookName.charAt(3).toUpperCase() + hookName.slice(4)}Options) {
  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    // Implement your hook logic here
    setLoading(true);
    
    // Example async operation
    const performOperation = async () => {
      try {
        // Your logic here
        setState(null);
      } catch (err) {
        setError(err instanceof Error ? err : new Error('Unknown error'));
      } finally {
        setLoading(false);
      }
    };

    performOperation();
  }, []);

  return {
    state,
    loading,
    error,
    // Add your return values here
  };
}
`;

  const testContent = `import { renderHook } from '@testing-library/react';
import { ${hookName} } from './${hookName}';

describe('${hookName}', () => {
  it('should initialize with default values', () => {
    const { result } = renderHook(() => ${hookName}());
    
    expect(result.current.state).toBeNull();
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('should handle options', () => {
    const options = { /* your options */ };
    const { result } = renderHook(() => ${hookName}(options));
    
    // Add your assertions here
  });
});
`;

  const hooksDir = path.join(workspacePath, 'src', 'hooks');
  await fs.ensureDir(hooksDir);
  
  await fs.writeFile(path.join(hooksDir, `${hookName}.ts`), hookContent);
  await fs.writeFile(path.join(hooksDir, `${hookName}.test.ts`), testContent);

  if (options.verbose) {
    console.log(chalk.green(`  ✓ Created src/hooks/${hookName}.ts`));
    console.log(chalk.green(`  ✓ Created src/hooks/${hookName}.test.ts`));
  }
}

async function generateService(monorepoRoot: string, name: string, options: GenerateOptions) {
  const workspace = options.workspace || findBestWorkspace(monorepoRoot, 'service');
  const workspacePath = path.join(monorepoRoot, workspace);

  const serviceName = `${name.charAt(0).toUpperCase() + name.slice(1)}Service`;
  
  const serviceContent = `export interface ${serviceName}Config {
  baseURL?: string;
  timeout?: number;
  retries?: number;
}

export class ${serviceName} {
  private config: ${serviceName}Config;

  constructor(config: ${serviceName}Config = {}) {
    this.config = {
      baseURL: process.env.API_BASE_URL || 'http://localhost:3000',
      timeout: 10000,
      retries: 3,
      ...config
    };
  }

  async get<T>(endpoint: string): Promise<T> {
    return this.request<T>('GET', endpoint);
  }

  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>('POST', endpoint, data);
  }

  async put<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>('PUT', endpoint, data);
  }

  async delete<T>(endpoint: string): Promise<T> {
    return this.request<T>('DELETE', endpoint);
  }

  private async request<T>(
    method: string,
    endpoint: string,
    data?: any
  ): Promise<T> {
    const url = \`\${this.config.baseURL}\${endpoint}\`;
    
    const requestConfig: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    if (data) {
      requestConfig.body = JSON.stringify(data);
    }

    let lastError: Error;
    
    for (let attempt = 0; attempt < (this.config.retries || 1); attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
        
        const response = await fetch(url, {
          ...requestConfig,
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(\`HTTP error! status: \${response.status}\`);
        }

        return await response.json();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');
        
        if (attempt < (this.config.retries || 1) - 1) {
          await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
        }
      }
    }

    throw lastError!;
  }
}

// Export singleton instance
export const ${name}Service = new ${serviceName}();
`;

  const testContent = `import { ${serviceName} } from './${serviceName}';

// Mock fetch
global.fetch = jest.fn();

describe('${serviceName}', () => {
  let service: ${serviceName};

  beforeEach(() => {
    service = new ${serviceName}();
    (fetch as jest.MockedFunction<typeof fetch>).mockClear();
  });

  it('should make GET requests', async () => {
    const mockResponse = { id: 1, name: 'test' };
    (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValueOnce(
      new Response(JSON.stringify(mockResponse), { status: 200 })
    );

    const result = await service.get('/api/test');
    expect(result).toEqual(mockResponse);
    expect(fetch).toHaveBeenCalledWith(
      'http://localhost:3000/api/test',
      expect.objectContaining({ method: 'GET' })
    );
  });

  it('should make POST requests', async () => {
    const mockData = { name: 'test' };
    const mockResponse = { id: 1, ...mockData };
    
    (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValueOnce(
      new Response(JSON.stringify(mockResponse), { status: 200 })
    );

    const result = await service.post('/api/test', mockData);
    expect(result).toEqual(mockResponse);
    expect(fetch).toHaveBeenCalledWith(
      'http://localhost:3000/api/test',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify(mockData)
      })
    );
  });

  it('should handle errors', async () => {
    (fetch as jest.MockedFunction<typeof fetch>).mockRejectedValueOnce(
      new Error('Network error')
    );

    await expect(service.get('/api/test')).rejects.toThrow('Network error');
  });
});
`;

  const servicesDir = path.join(workspacePath, 'src', 'services');
  await fs.ensureDir(servicesDir);
  
  await fs.writeFile(path.join(servicesDir, `${serviceName}.ts`), serviceContent);
  await fs.writeFile(path.join(servicesDir, `${serviceName}.test.ts`), testContent);

  if (options.verbose) {
    console.log(chalk.green(`  ✓ Created src/services/${serviceName}.ts`));
    console.log(chalk.green(`  ✓ Created src/services/${serviceName}.test.ts`));
  }
}

async function generateTestFile(monorepoRoot: string, name: string, options: GenerateOptions) {
  const workspace = options.workspace || findBestWorkspace(monorepoRoot, 'test');
  const workspacePath = path.join(monorepoRoot, workspace);

  const testContent = `describe('${name}', () => {
  beforeEach(() => {
    // Setup before each test
  });

  afterEach(() => {
    // Cleanup after each test
  });

  it('should work correctly', () => {
    // Your test implementation
    expect(true).toBe(true);
  });

  it('should handle edge cases', () => {
    // Edge case testing
    expect(true).toBe(true);
  });

  it('should handle errors gracefully', () => {
    // Error handling tests
    expect(true).toBe(true);
  });
});
`;

  const testsDir = path.join(workspacePath, 'src', '__tests__');
  await fs.ensureDir(testsDir);
  
  await fs.writeFile(path.join(testsDir, `${name}.test.ts`), testContent);

  if (options.verbose) {
    console.log(chalk.green(`  ✓ Created src/__tests__/${name}.test.ts`));
  }
}

async function generateConfig(monorepoRoot: string, name: string, options: GenerateOptions) {
  const configContent = `export interface ${name.charAt(0).toUpperCase() + name.slice(1)}Config {
  // Add your configuration properties here
  environment: 'development' | 'staging' | 'production';
  apiUrl: string;
  features: {
    [key: string]: boolean;
  };
}

const config: ${name.charAt(0).toUpperCase() + name.slice(1)}Config = {
  environment: (process.env.NODE_ENV as any) || 'development',
  apiUrl: process.env.API_URL || 'http://localhost:3000',
  features: {
    // Feature flags
    newFeature: process.env.ENABLE_NEW_FEATURE === 'true',
  },
};

export default config;
`;

  const configDir = path.join(monorepoRoot, 'config');
  await fs.ensureDir(configDir);
  
  await fs.writeFile(path.join(configDir, `${name}.config.ts`), configContent);

  if (options.verbose) {
    console.log(chalk.green(`  ✓ Created config/${name}.config.ts`));
  }
}

async function generateDocs(monorepoRoot: string, name: string, options: GenerateOptions) {
  const docsContent = `# ${name.charAt(0).toUpperCase() + name.slice(1)}

## Overview

Brief description of ${name}.

## Installation

\`\`\`bash
pnpm install
\`\`\`

## Usage

\`\`\`typescript
// Example usage
import { ${name} } from './${name}';

const result = ${name}();
\`\`\`

## API Reference

### Functions

#### \`${name}()\`

Description of the function.

**Parameters:**
- \`param1\` (string): Description of parameter 1
- \`param2\` (number): Description of parameter 2

**Returns:**
- \`ReturnType\`: Description of return value

**Example:**
\`\`\`typescript
const result = ${name}('example', 42);
\`\`\`

## Examples

### Basic Example

\`\`\`typescript
// Basic usage example
\`\`\`

### Advanced Example

\`\`\`typescript
// Advanced usage example
\`\`\`

## Contributing

Please read our [Contributing Guide](../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
`;

  const docsDir = path.join(monorepoRoot, 'docs');
  await fs.ensureDir(docsDir);
  
  await fs.writeFile(path.join(docsDir, `${name}.md`), docsContent);

  if (options.verbose) {
    console.log(chalk.green(`  ✓ Created docs/${name}.md`));
  }
}

function getComponentTemplate(name: string, framework: string, options: GenerateOptions): ComponentTemplate {
  const pascalName = name.charAt(0).toUpperCase() + name.slice(1);
  
  switch (framework) {
    case 'react':
      return {
        name: pascalName,
        files: [
          {
            path: `src/components/${pascalName}/${pascalName}.tsx`,
            content: `import React from 'react';
import './${pascalName}.css';

export interface ${pascalName}Props {
  children?: React.ReactNode;
  className?: string;
}

export const ${pascalName}: React.FC<${pascalName}Props> = ({
  children,
  className = '',
  ...props
}) => {
  return (
    <div className={\`${name.toLowerCase()} \${className}\`} {...props}>
      {children || <p>Hello from ${pascalName}!</p>}
    </div>
  );
};
`
          },
          {
            path: `src/components/${pascalName}/${pascalName}.css`,
            content: `.${name.toLowerCase()} {
  /* Add your styles here */
  padding: 1rem;
  border: 1px solid #ccc;
  border-radius: 4px;
}
`
          },
          {
            path: `src/components/${pascalName}/${pascalName}.test.tsx`,
            content: `import React from 'react';
import { render, screen } from '@testing-library/react';
import { ${pascalName} } from './${pascalName}';

describe('${pascalName}', () => {
  it('renders without crashing', () => {
    render(<${pascalName} />);
    expect(screen.getByText('Hello from ${pascalName}!')).toBeInTheDocument();
  });

  it('renders children when provided', () => {
    render(<${pascalName}>Custom content</${pascalName}>);
    expect(screen.getByText('Custom content')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(<${pascalName} className="custom-class" />);
    expect(container.firstChild).toHaveClass('${name.toLowerCase()}', 'custom-class');
  });
});
`
          },
          {
            path: `src/components/${pascalName}/index.ts`,
            content: `export { ${pascalName} } from './${pascalName}';
export type { ${pascalName}Props } from './${pascalName}';
`
          }
        ]
      };

    case 'vue':
      return {
        name: pascalName,
        files: [
          {
            path: `src/components/${pascalName}.vue`,
            content: `<template>
  <div class="${name.toLowerCase()}">
    <slot>Hello from ${pascalName}!</slot>
  </div>
</template>

<script setup lang="ts">
interface Props {
  modelValue?: any;
}

defineProps<Props>();
defineEmits<{
  'update:modelValue': [value: any];
}>();
</script>

<style scoped>
.${name.toLowerCase()} {
  /* Add your styles here */
  padding: 1rem;
  border: 1px solid #ccc;
  border-radius: 4px;
}
</style>
`
          }
        ]
      };

    case 'svelte':
      return {
        name: pascalName,
        files: [
          {
            path: `src/components/${pascalName}.svelte`,
            content: `<script lang="ts">
  export let className: string = '';
</script>

<div class="${name.toLowerCase()} {className}">
  <slot>Hello from ${pascalName}!</slot>
</div>

<style>
  .${name.toLowerCase()} {
    /* Add your styles here */
    padding: 1rem;
    border: 1px solid #ccc;
    border-radius: 4px;
  }
</style>
`
          }
        ]
      };

    default:
      throw new Error(`Unsupported framework: ${framework}`);
  }
}

async function generateTestSuite(workspacePath: string, options: GenerateOptions) {
  // Generate Jest configuration
  const jestConfig = `module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts'],
  moduleNameMapping: {
    '\\\\.(css|less|scss|sass)$': 'identity-obj-proxy',
  },
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/index.ts',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
};
`;

  await fs.writeFile(path.join(workspacePath, 'jest.config.js'), jestConfig);

  // Generate test setup
  const setupTests = `import '@testing-library/jest-dom';

// Mock IntersectionObserver
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
};

// Mock ResizeObserver
global.ResizeObserver = class ResizeObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
};
`;

  await fs.writeFile(path.join(workspacePath, 'src', 'setupTests.ts'), setupTests);

  // Generate example test utilities
  const testUtils = `import React from 'react';
import { render, RenderOptions } from '@testing-library/react';

// Add providers here if needed
const AllTheProviders: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return <>{children}</>;
};

const customRender = (ui: React.ReactElement, options?: Omit<RenderOptions, 'wrapper'>) =>
  render(ui, { wrapper: AllTheProviders, ...options });

export * from '@testing-library/react';
export { customRender as render };
`;

  const testUtilsDir = path.join(workspacePath, 'src', 'test-utils');
  await fs.ensureDir(testUtilsDir);
  await fs.writeFile(path.join(testUtilsDir, 'index.ts'), testUtils);
}

async function generateProjectDocs(monorepoRoot: string, options: GenerateOptions) {
  const packageJson = await fs.readJson(path.join(monorepoRoot, 'package.json'));
  
  const readme = `# ${packageJson.name || 'Re-Shell Project'}

${packageJson.description || 'A Re-Shell monorepo project'}

## 📁 Project Structure

\`\`\`
${packageJson.name || 'project'}/
├── apps/                 # Applications
├── packages/             # Shared packages  
├── libs/                 # Libraries
├── tools/                # Build tools and scripts
├── docs/                 # Documentation
└── README.md
\`\`\`

## 🚀 Quick Start

1. **Install dependencies**
   \`\`\`bash
   pnpm install
   \`\`\`

2. **Start development**
   \`\`\`bash
   pnpm run dev
   \`\`\`

3. **Build all packages**
   \`\`\`bash
   pnpm run build
   \`\`\`

## 📋 Available Commands

| Command | Description |
|---------|-------------|
| \`pnpm run dev\` | Start development servers |
| \`pnpm run build\` | Build all packages |
| \`pnpm run test\` | Run all tests |
| \`pnpm run lint\` | Lint all packages |
| \`re-shell doctor\` | Health check |
| \`re-shell analyze\` | Bundle analysis |

## 🏗️ Development

### Adding New Packages

\`\`\`bash
re-shell create my-package --type package
\`\`\`

### Running Tests

\`\`\`bash
# Run all tests
pnpm run test

# Run tests for specific package
pnpm --filter my-package test
\`\`\`

### Health Check

\`\`\`bash
re-shell doctor --verbose
\`\`\`

## 📚 Documentation

- [Architecture](./docs/architecture.md)
- [Contributing](./CONTRIBUTING.md)
- [Deployment](./docs/deployment.md)

## 🤝 Contributing

Please read our [Contributing Guide](./CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
`;

  await fs.writeFile(path.join(monorepoRoot, 'README.md'), readme);
}

async function generateAPIDocumentation(monorepoRoot: string, options: GenerateOptions) {
  // Generate TypeDoc configuration
  const typeDocConfig = `{
  "entryPoints": ["packages/*/src/index.ts"],
  "out": "docs/api",
  "exclude": ["**/*.test.ts", "**/*.spec.ts"],
  "excludePrivate": true,
  "excludeProtected": true,
  "hideGenerator": true,
  "sort": ["source-order"],
  "gitRevision": "main",
  "readme": "README.md"
}
`;

  await fs.writeFile(path.join(monorepoRoot, 'typedoc.json'), typeDocConfig);
}

async function generateReadme(monorepoRoot: string, options: GenerateOptions) {
  // This is handled by generateProjectDocs
}

function findBestWorkspace(monorepoRoot: string, type: string): string {
  // Default workspace patterns based on type
  const workspacePatterns = {
    component: ['apps/*', 'packages/ui', 'packages/components'],
    hook: ['packages/hooks', 'packages/ui', 'apps/*'],
    service: ['packages/services', 'packages/api', 'apps/*'],
    test: ['apps/*', 'packages/*'],
    config: ['packages/config', 'packages/core'],
    documentation: ['docs']
  };

  const patterns = workspacePatterns[type as keyof typeof workspacePatterns] || ['apps/*'];
  
  // Return the first pattern (simplified logic)
  return patterns[0].replace('*', 'web');
}

async function updateExports(workspacePath: string, name: string, template: ComponentTemplate) {
  const indexPath = path.join(workspacePath, 'src', 'index.ts');
  
  if (await fs.pathExists(indexPath)) {
    const content = await fs.readFile(indexPath, 'utf8');
    const exportLine = `export { ${template.name} } from './components/${template.name}';`;
    
    if (!content.includes(exportLine)) {
      await fs.appendFile(indexPath, `\n${exportLine}\n`);
    }
  } else {
    const content = `export { ${template.name} } from './components/${template.name}';\n`;
    await fs.writeFile(indexPath, content);
  }
}