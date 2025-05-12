import * as fs from 'fs-extra';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import prompts from 'prompts';
import chalk from 'chalk';

const execAsync = promisify(exec);

interface CreateProjectOptions {
  team?: string;
  org?: string;
  description?: string;
  template?: string;
  packageManager?: string;
  isProject: boolean;
}

/**
 * Creates a new Re-Shell project with shell application
 * 
 * @param name - Name of the project
 * @param options - Additional options for project creation
 * @version 0.1.0
 */
export async function createProject(
  name: string,
  options: CreateProjectOptions
): Promise<void> {
  const { 
    team,
    org = 're-shell', 
    description = `${name} - A Re-Shell microfrontend project`,
    template = 'react-ts',
    packageManager = 'pnpm'
  } = options;

  // Normalize name to kebab-case for consistency
  const normalizedName = name.toLowerCase().replace(/\s+/g, '-');
  
  console.log(chalk.cyan(`Creating Re-Shell project "${normalizedName}"...`));

  // Ask for additional information if not provided
  const responses = await prompts([
    {
      type: options.template ? null : 'select',
      name: 'template',
      message: 'Select a template:',
      choices: [
        { title: 'React', value: 'react' },
        { title: 'React with TypeScript', value: 'react-ts' }
      ],
      initial: 1 // Default to react-ts
    },
    {
      type: options.packageManager ? null : 'select',
      name: 'packageManager',
      message: 'Select a package manager:',
      choices: [
        { title: 'npm', value: 'npm' },
        { title: 'yarn', value: 'yarn' },
        { title: 'pnpm', value: 'pnpm' }
      ],
      initial: 2 // Default to pnpm
    }
  ]);

  // Merge responses with options
  const finalOptions = {
    ...options,
    template: options.template || responses.template,
    packageManager: options.packageManager || responses.packageManager
  };
  
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
  
  // Create shell application
  fs.mkdirSync(path.join(projectPath, 'apps', 'shell'));
  fs.mkdirSync(path.join(projectPath, 'apps', 'shell', 'src'));
  fs.mkdirSync(path.join(projectPath, 'apps', 'shell', 'public'));

  // Create package.json for the project
  const packageJson = {
    name: normalizedName,
    version: '0.1.0',
    description,
    private: true,
    workspaces: [
      "apps/*",
      "packages/*"
    ],
    scripts: {
      dev: `${finalOptions.packageManager} run --parallel -r dev`,
      build: `${finalOptions.packageManager} run --parallel -r build`,
      lint: `${finalOptions.packageManager} run --parallel -r lint`,
      test: `${finalOptions.packageManager} run --parallel -r test`,
      clean: `${finalOptions.packageManager} run --parallel -r clean`
    },
    author: team || org,
    license: 'MIT'
  };

  fs.writeFileSync(
    path.join(projectPath, 'package.json'),
    JSON.stringify(packageJson, null, 2)
  );

  // Create workspace config
  if (finalOptions.packageManager === 'pnpm') {
    const workspaceConfig = {
      packages: [
        "apps/*",
        "packages/*"
      ]
    };
    
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

  console.log(chalk.green(`\nRe-Shell project "${normalizedName}" created successfully at ${projectPath}`));
  console.log('\nNext steps:');
  console.log(`  1. cd ${normalizedName}`);
  console.log(`  2. ${finalOptions.packageManager} install`);
  console.log(`  3. ${finalOptions.packageManager} run dev`);
  console.log(`  4. re-shell add my-feature (to add your first microfrontend)`);
}