import * as fs from 'fs-extra';
import * as path from 'path';
import prompts from 'prompts';
import chalk from 'chalk';
import { getFrameworkChoices, getFrameworkConfig, validateFramework } from '../utils/framework';
import { findMonorepoRoot } from '../utils/monorepo';
import { ReactTemplate } from '../templates/react';
import { VueTemplate } from '../templates/vue';
import { SvelteTemplate } from '../templates/svelte';
import { BaseTemplate, TemplateContext } from '../templates/index';
import { ProgressSpinner, flushOutput } from '../utils/spinner';

interface CreateProjectOptions {
  team?: string;
  org?: string;
  description?: string;
  template?: string;
  framework?: string;
  packageManager?: string;
  type?: 'app' | 'package' | 'lib' | 'tool';
  port?: string;
  route?: string;
  isProject?: boolean;
  spinner?: ProgressSpinner;
}

/**
 * Creates a new Re-Shell project or workspace
 *
 * @param name - Name of the project/workspace
 * @param options - Additional options for project creation
 * @version 0.2.5
 */
export async function createProject(name: string, options: CreateProjectOptions): Promise<void> {
  // Check if we're in a monorepo
  const monorepoRoot = await findMonorepoRoot();
  const inMonorepo = !!monorepoRoot;

  // Determine if this is a monorepo project creation or workspace creation
  const isWorkspaceCreation = inMonorepo || options.type;

  if (isWorkspaceCreation) {
    await createWorkspace(name, options, monorepoRoot);
  } else {
    await createMonorepoProject(name, options);
  }
}

/**
 * Creates a new workspace (app/package/lib/tool) in an existing monorepo
 */
async function createWorkspace(
  name: string,
  options: CreateProjectOptions,
  monorepoRoot?: string | null
): Promise<void> {
  const {
    team,
    org = 're-shell',
    description,
    framework,
    packageManager = 'pnpm',
    type = 'app',
    port = '5173',
    route,
    spinner,
  } = options;

  const normalizedName = name.toLowerCase().replace(/\s+/g, '-');
  const rootPath = monorepoRoot || process.cwd();

  console.log(chalk.cyan(`Creating ${type} "${normalizedName}"...`));

  // Stop spinner for interactive prompts
  if (spinner) {
    spinner.stop();
  }

  // Interactive prompts for missing options
  const responses = await prompts([
    {
      type: !framework ? 'select' : null,
      name: 'framework',
      message: 'Select a framework:',
      choices: getFrameworkChoices(),
      initial: 1, // Default to react-ts
    },
    {
      type: type === 'app' && !port ? 'text' : null,
      name: 'port',
      message: 'Development server port:',
      initial: '5173',
      validate: (value: string) => {
        const num = parseInt(value);
        return num > 0 && num < 65536 ? true : 'Port must be between 1 and 65535';
      },
    },
    {
      type: type === 'app' && !route ? 'text' : null,
      name: 'route',
      message: 'Route path:',
      initial: `/${normalizedName}`,
      validate: (value: string) => (value.startsWith('/') ? true : 'Route must start with /'),
    },
  ]);

  // Restart spinner for file operations
  if (spinner) {
    spinner.start();
    spinner.setText(`Creating ${type} files...`);
    flushOutput();
  }

  // Merge responses with options
  const finalFramework = framework || responses.framework || 'react-ts';
  const finalPort = port || responses.port || '5173';
  const finalRoute = route || responses.route || `/${normalizedName}`;

  // Validate framework
  if (!validateFramework(finalFramework)) {
    throw new Error(`Unsupported framework: ${finalFramework}`);
  }

  // Determine workspace path based on type
  const typeDir =
    type === 'app' ? 'apps' : type === 'package' ? 'packages' : type === 'lib' ? 'libs' : 'tools';

  const workspacePath = path.join(rootPath, typeDir, normalizedName);

  // Check if directory already exists and handle it gracefully
  if (fs.existsSync(workspacePath)) {
    if (spinner) spinner.stop();

    const { action } = await prompts({
      type: 'select',
      name: 'action',
      message: `Directory "${normalizedName}" already exists in ${typeDir}/. What would you like to do?`,
      choices: [
        { title: 'Overwrite existing directory', value: 'overwrite' },
        { title: 'Cancel', value: 'cancel' },
      ],
      initial: 0,
    });

    if (action === 'cancel') {
      console.log(chalk.yellow('Operation cancelled.'));
      return;
    }

    if (action === 'overwrite') {
      if (spinner) {
        spinner.start();
        spinner.setText('Removing existing directory...');
        flushOutput();
      }
      await fs.remove(workspacePath);
    }

    if (spinner) {
      spinner.start();
      spinner.setText(`Creating ${type} files...`);
      flushOutput();
    }
  }

  // Get framework configuration
  const frameworkConfig = getFrameworkConfig(finalFramework);

  // Create template context
  const templateContext: TemplateContext = {
    name,
    normalizedName,
    framework: finalFramework,
    hasTypeScript: frameworkConfig.hasTypeScript || false,
    port: finalPort,
    route: type === 'app' ? finalRoute : undefined,
    org,
    team,
    description: description || `${name} - A ${frameworkConfig.displayName} ${type}`,
    packageManager,
  };

  // Generate files using appropriate template
  const template = createTemplate(frameworkConfig, templateContext);
  const files = await template.generateFiles();

  // Create workspace directory
  await fs.ensureDir(workspacePath);

  // Write all generated files
  for (const file of files) {
    const filePath = path.join(workspacePath, file.path);
    await fs.ensureDir(path.dirname(filePath));
    await fs.writeFile(filePath, file.content);

    if (file.executable) {
      await fs.chmod(filePath, '755');
    }
  }

  console.log(
    chalk.green(
      `✓ ${type.charAt(0).toUpperCase() + type.slice(1)} "${normalizedName}" created successfully!`
    )
  );
  console.log(chalk.gray(`Path: ${path.relative(process.cwd(), workspacePath)}`));
  console.log('\nNext steps:');
  console.log(`  1. cd ${path.relative(process.cwd(), workspacePath)}`);
  console.log(`  2. ${packageManager} install`);
  console.log(`  3. ${packageManager} run dev`);
}

/**
 * Creates a new monorepo project (legacy function for backward compatibility)
 */
async function createMonorepoProject(name: string, options: CreateProjectOptions): Promise<void> {
  const {
    team,
    org = 're-shell',
    description = `${name} - A Re-Shell microfrontend project`,
    spinner,
  } = options;

  // Normalize name to kebab-case for consistency
  const normalizedName = name.toLowerCase().replace(/\s+/g, '-');

  console.log(chalk.cyan(`Creating Re-Shell project "${normalizedName}"...`));

  // Stop spinner for interactive prompts
  if (spinner) {
    spinner.stop();
  }

  // Ask for additional information if not provided
  const responses = await prompts([
    {
      type: options.template ? null : 'select',
      name: 'template',
      message: 'Select a template:',
      choices: [
        { title: 'React', value: 'react' },
        { title: 'React with TypeScript', value: 'react-ts' },
      ],
      initial: 1, // Default to react-ts
    },
    {
      type: options.packageManager ? null : 'select',
      name: 'packageManager',
      message: 'Select a package manager:',
      choices: [
        { title: 'npm', value: 'npm' },
        { title: 'yarn', value: 'yarn' },
        { title: 'pnpm', value: 'pnpm' },
      ],
      initial: 2, // Default to pnpm
    },
  ]);

  // Merge responses with options
  const finalOptions = {
    ...options,
    template: options.template || responses.template,
    packageManager: options.packageManager || responses.packageManager,
  };

  // Restart spinner for file operations
  if (spinner) {
    spinner.start();
    spinner.setText('Creating project structure...');
    flushOutput();
  }

  // Create project structure
  const projectPath = path.resolve(process.cwd(), normalizedName);

  // Check if directory already exists
  if (fs.existsSync(projectPath)) {
    throw new Error(`Directory already exists: ${projectPath}`);
  }

  // Create directory structure
  fs.mkdirSync(projectPath);
  fs.mkdirSync(path.join(projectPath, 'apps'));
  fs.mkdirSync(path.join(projectPath, 'packages'));
  fs.mkdirSync(path.join(projectPath, 'docs'));

  // Create package.json for the project
  const packageJson = {
    name: normalizedName,
    version: '0.1.0',
    description,
    private: true,
    workspaces: ['apps/*', 'packages/*'],
    scripts: {
      dev: `${finalOptions.packageManager} run --parallel -r dev`,
      build: `${finalOptions.packageManager} run --parallel -r build`,
      lint: `${finalOptions.packageManager} run --parallel -r lint`,
      test: `${finalOptions.packageManager} run --parallel -r test`,
      clean: `${finalOptions.packageManager} run --parallel -r clean`,
    },
    author: team || org,
    license: 'MIT',
  };

  fs.writeFileSync(path.join(projectPath, 'package.json'), JSON.stringify(packageJson, null, 2));

  // Create workspace config
  if (finalOptions.packageManager === 'pnpm') {
    fs.writeFileSync(
      path.join(projectPath, 'pnpm-workspace.yaml'),
      `packages:\n  - 'apps/*'\n  - 'packages/*'\n`
    );
  }

  // Create README.md
  const readmeContent = `# ${normalizedName}

## Overview
A microfrontend project created with Re-Shell CLI.

## Project Structure
\`\`\`
${normalizedName}/
├── apps/                 # Microfrontend applications
│   └── shell/            # Main shell application
├── packages/             # Shared libraries
└── docs/                 # Documentation
\`\`\`

## Getting Started

### Installation
\`\`\`bash
# Install dependencies
${finalOptions.packageManager} install
\`\`\`

### Development
\`\`\`bash
# Start all applications in development mode
${finalOptions.packageManager} run dev
\`\`\`

### Building
\`\`\`bash
# Build all applications
${finalOptions.packageManager} run build
\`\`\`

## Adding Microfrontends
To add a new microfrontend to this project:

\`\`\`bash
re-shell add my-feature
\`\`\`

## Documentation
For more information, see the [Re-Shell documentation](https://github.com/your-org/re-shell)
`;

  fs.writeFileSync(path.join(projectPath, 'README.md'), readmeContent);

  console.log(
    chalk.green(`\nRe-Shell project "${normalizedName}" created successfully at ${projectPath}`)
  );
  console.log('\nNext steps:');
  console.log(`  1. cd ${normalizedName}`);
  console.log(`  2. ${finalOptions.packageManager} install`);
  console.log(`  3. ${finalOptions.packageManager} run dev`);
  console.log(`  4. re-shell add my-feature (to add your first microfrontend)`);
}

/**
 * Creates appropriate template instance based on framework
 */
function createTemplate(framework: any, context: TemplateContext): BaseTemplate {
  switch (framework.name) {
    case 'react':
    case 'react-ts':
      return new ReactTemplate(framework, context);
    case 'vue':
    case 'vue-ts':
      return new VueTemplate(framework, context);
    case 'svelte':
    case 'svelte-ts':
      return new SvelteTemplate(framework, context);
    // Add more frameworks as templates are implemented
    default:
      // Fallback to React template for unsupported frameworks
      return new ReactTemplate(framework, context);
  }
}
