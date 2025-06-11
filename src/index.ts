#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs-extra';
import * as path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { createProject } from './commands/create';
import { addMicrofrontend } from './commands/add';
import { removeMicrofrontend } from './commands/remove';
import { listMicrofrontends } from './commands/list';
import { buildMicrofrontend } from './commands/build';
import { serveMicrofrontend } from './commands/serve';
import { initMonorepo } from './commands/init';
import { listWorkspaces, updateWorkspaces, generateWorkspaceGraph } from './commands/workspace';
import {
  addGitSubmodule,
  removeGitSubmodule,
  updateGitSubmodules,
  showSubmoduleStatus,
  initSubmodules,
  manageSubmodules
} from './commands/submodule';
import { getFrameworkChoices } from './utils/framework';

// Get version from package.json
const packageJsonPath = path.resolve(__dirname, '../package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
const version = packageJson.version;

// ASCII art banner for CLI
const banner = `
██████╗ ███████╗           ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██╔════╝           ██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝█████╗  ████████╗  ███████╗███████║█████╗  ██║     ██║
██╔══██╗██╔══╝  ╚═══════╝  ╚════██║██╔══██║██╔══╝  ██║     ██║
██║  ██║███████╗           ███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═╝╚══════╝           ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                v${version}
`;

const program = new Command();

// Display banner for main command
if (process.argv.length <= 2 ||
    (process.argv.length === 3 && ['-h', '--help', '-V', '--version'].includes(process.argv[2]))) {
  console.log(chalk.cyan(banner));
}

program
  .name('re-shell')
  .description('Re-Shell CLI - Tools for managing multi-framework monorepo and microfrontend architecture')
  .version(version);

// Initialize monorepo command
program
  .command('init')
  .description('Initialize a new monorepo workspace')
  .argument('<name>', 'Name of the monorepo')
  .option('--package-manager <pm>', 'Package manager to use (npm, yarn, pnpm)', 'pnpm')
  .option('--no-git', 'Skip Git repository initialization')
  .option('--no-submodules', 'Skip submodule support setup')
  .option('--force', 'Overwrite existing directory')
  .action(async (name, options) => {
    const spinner = ora('Initializing monorepo...').start();
    try {
      await initMonorepo(name, {
        packageManager: options.packageManager,
        git: options.git !== false,
        submodules: options.submodules !== false,
        force: options.force
      });
      spinner.succeed(chalk.green(`Monorepo "${name}" initialized successfully!`));
    } catch (error) {
      spinner.fail(chalk.red('Error initializing monorepo'));
      console.error(error);
      process.exit(1);
    }
  });

// Create project command
program
  .command('create')
  .description('Create a new Re-Shell project with shell application')
  .argument('<name>', 'Name of the project')
  .option('-t, --team <team>', 'Team name')
  .option('-o, --org <organization>', 'Organization name', 're-shell')
  .option('-d, --description <description>', 'Project description')
  .option('--template <template>', 'Template to use (react, react-ts)', 'react-ts')
  .option('--package-manager <pm>', 'Package manager to use (npm, yarn, pnpm)', 'pnpm')
  .action(async (name, options) => {
    const spinner = ora('Creating Re-Shell project...').start();
    try {
      await createProject(name, { ...options, isProject: true });
      spinner.succeed(chalk.green(`Re-Shell project "${name}" created successfully!`));
    } catch (error) {
      spinner.fail(chalk.red('Error creating project'));
      console.error(error);
      process.exit(1);
    }
  });

// Add microfrontend command
program
  .command('add')
  .description('Add a new microfrontend to existing Re-Shell project')
  .argument('<name>', 'Name of the microfrontend')
  .option('-t, --team <team>', 'Team name')
  .option('-o, --org <organization>', 'Organization name', 're-shell')
  .option('-d, --description <description>', 'Microfrontend description')
  .option('--template <template>', 'Template to use (react, react-ts)', 'react-ts')
  .option('--route <route>', 'Route path for the microfrontend')
  .option('--port <port>', 'Dev server port', '5173')
  .action(async (name, options) => {
    const spinner = ora('Adding microfrontend...').start();
    try {
      await addMicrofrontend(name, options);
      spinner.succeed(chalk.green(`Microfrontend "${name}" added successfully!`));
    } catch (error) {
      spinner.fail(chalk.red('Error adding microfrontend'));
      console.error(error);
      process.exit(1);
    }
  });

// Remove microfrontend command
program
  .command('remove')
  .description('Remove a microfrontend from existing Re-Shell project')
  .argument('<name>', 'Name of the microfrontend to remove')
  .option('--force', 'Force removal without confirmation')
  .action(async (name, options) => {
    const spinner = ora('Removing microfrontend...').start();
    try {
      await removeMicrofrontend(name, options);
      spinner.succeed(chalk.green(`Microfrontend "${name}" removed successfully!`));
    } catch (error) {
      spinner.fail(chalk.red('Error removing microfrontend'));
      console.error(error);
      process.exit(1);
    }
  });

// List microfrontends command
program
  .command('list')
  .description('List all microfrontends in the current project')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      await listMicrofrontends(options);
    } catch (error) {
      console.error(chalk.red('Error listing microfrontends:'), error);
      process.exit(1);
    }
  });

// Build command
program
  .command('build')
  .description('Build all or specific microfrontends')
  .argument('[name]', 'Name of the microfrontend to build (builds all if omitted)')
  .option('--production', 'Build for production environment')
  .option('--analyze', 'Analyze bundle size')
  .action(async (name, options) => {
    const spinner = ora('Building...').start();
    try {
      await buildMicrofrontend(name, options);
      spinner.succeed(chalk.green(name ? `Microfrontend "${name}" built successfully!` : 'All microfrontends built successfully!'));
    } catch (error) {
      spinner.fail(chalk.red('Build failed'));
      console.error(error);
      process.exit(1);
    }
  });

// Serve command
program
  .command('serve')
  .description('Start development server')
  .argument('[name]', 'Name of the microfrontend to serve (serves all if omitted)')
  .option('--port <port>', 'Port to serve on', '3000')
  .option('--host <host>', 'Host to serve on', 'localhost')
  .option('--open', 'Open in browser')
  .action(async (name, options) => {
    try {
      await serveMicrofrontend(name, options);
    } catch (error) {
      console.error(chalk.red('Error starting development server:'), error);
      process.exit(1);
    }
  });

// Workspace management commands
const workspaceCommand = program
  .command('workspace')
  .description('Manage monorepo workspaces');

workspaceCommand
  .command('list')
  .description('List all workspaces')
  .option('--json', 'Output as JSON')
  .option('--type <type>', 'Filter by workspace type (app, package, lib, tool)')
  .option('--framework <framework>', 'Filter by framework')
  .action(async (options) => {
    try {
      await listWorkspaces(options);
    } catch (error) {
      console.error(chalk.red('Error listing workspaces:'), error);
      process.exit(1);
    }
  });

workspaceCommand
  .command('update')
  .description('Update workspace dependencies')
  .option('--workspace <name>', 'Update specific workspace')
  .option('--dependency <name>', 'Update specific dependency')
  .option('--version <version>', 'Target version for dependency')
  .option('--dev', 'Update dev dependency')
  .action(async (options) => {
    const spinner = ora('Updating workspaces...').start();
    try {
      await updateWorkspaces(options);
      spinner.succeed(chalk.green('Workspaces updated successfully!'));
    } catch (error) {
      spinner.fail(chalk.red('Error updating workspaces'));
      console.error(error);
      process.exit(1);
    }
  });

workspaceCommand
  .command('graph')
  .description('Generate workspace dependency graph')
  .option('--output <file>', 'Output file path')
  .option('--format <format>', 'Output format (text, json, mermaid)', 'text')
  .action(async (options) => {
    try {
      await generateWorkspaceGraph(options);
    } catch (error) {
      console.error(chalk.red('Error generating workspace graph:'), error);
      process.exit(1);
    }
  });

// Submodule management commands
const submoduleCommand = program
  .command('submodule')
  .description('Manage Git submodules');

submoduleCommand
  .command('add <url>')
  .description('Add a new Git submodule')
  .option('--path <path>', 'Submodule path')
  .option('--branch <branch>', 'Branch to track', 'main')
  .action(async (url, options) => {
    const spinner = ora('Adding submodule...').start();
    try {
      await addGitSubmodule(url, options);
      spinner.succeed(chalk.green('Submodule added successfully!'));
    } catch (error) {
      spinner.fail(chalk.red('Error adding submodule'));
      console.error(error);
      process.exit(1);
    }
  });

submoduleCommand
  .command('remove <path>')
  .description('Remove a Git submodule')
  .option('--force', 'Force removal without confirmation')
  .action(async (path, options) => {
    const spinner = ora('Removing submodule...').start();
    try {
      await removeGitSubmodule(path, options);
      spinner.succeed(chalk.green('Submodule removed successfully!'));
    } catch (error) {
      spinner.fail(chalk.red('Error removing submodule'));
      console.error(error);
      process.exit(1);
    }
  });

submoduleCommand
  .command('update')
  .description('Update Git submodules')
  .option('--path <path>', 'Update specific submodule')
  .action(async (options) => {
    const spinner = ora('Updating submodules...').start();
    try {
      await updateGitSubmodules(options);
      spinner.succeed(chalk.green('Submodules updated successfully!'));
    } catch (error) {
      spinner.fail(chalk.red('Error updating submodules'));
      console.error(error);
      process.exit(1);
    }
  });

submoduleCommand
  .command('status')
  .description('Show Git submodule status')
  .action(async () => {
    try {
      await showSubmoduleStatus();
    } catch (error) {
      console.error(chalk.red('Error getting submodule status:'), error);
      process.exit(1);
    }
  });

submoduleCommand
  .command('init')
  .description('Initialize Git submodules')
  .action(async () => {
    const spinner = ora('Initializing submodules...').start();
    try {
      await initSubmodules();
      spinner.succeed(chalk.green('Submodules initialized successfully!'));
    } catch (error) {
      spinner.fail(chalk.red('Error initializing submodules'));
      console.error(error);
      process.exit(1);
    }
  });

submoduleCommand
  .command('manage')
  .description('Interactive submodule management')
  .action(async () => {
    try {
      await manageSubmodules();
    } catch (error) {
      console.error(chalk.red('Error managing submodules:'), error);
      process.exit(1);
    }
  });

// Deprecated create-mf command removed in v0.2.0

// Display help by default if no command is provided
if (process.argv.length <= 2) {
  program.help();
}

program.parse(process.argv);