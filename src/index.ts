#!/usr/bin/env node

// Ensure immediate output for better terminal experience
process.env.FORCE_COLOR = '1'; // Enable colors in terminal
if (process.stdout.isTTY) {
  process.stdout.setEncoding('utf8');
}
if (process.stderr.isTTY) {
  process.stderr.setEncoding('utf8');
}

import { Command } from 'commander';
import * as fs from 'fs-extra';
import * as path from 'path';
import chalk from 'chalk';
import { createSpinner, flushOutput } from './utils/spinner';
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
import { checkForUpdates, runUpdateCommand } from './utils/checkUpdate';

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

// Check for updates in the background (non-blocking)
if (!process.argv.includes('update') && !process.argv.includes('--version') && !process.argv.includes('-V')) {
  checkForUpdates(version);
}

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
  .option('--package-manager <pm>', 'Package manager to use (npm, yarn, pnpm, bun)', 'pnpm')
  .option('--template <template>', 'Template to use (blank, ecommerce, dashboard, saas)', 'blank')
  .option('--preset <name>', 'Use saved configuration preset')
  .option('--skip-install', 'Skip dependency installation')
  .option('--no-git', 'Skip Git repository initialization')
  .option('--no-submodules', 'Skip submodule support setup')
  .option('--force', 'Overwrite existing directory')
  .option('--debug', 'Enable debug output')
  .option('-y, --yes', 'Skip interactive prompts and use defaults')
  .action(async (name, options) => {
    const spinner = createSpinner('Initializing monorepo...').start();
    flushOutput();
    try {
      await initMonorepo(name, {
        packageManager: options.packageManager,
        template: options.template,
        preset: options.preset,
        skipInstall: options.skipInstall,
        git: options.git !== false,
        submodules: options.submodules !== false,
        force: options.force,
        debug: options.debug,
        yes: options.yes,
        spinner: spinner
      });
      
      // Get success info stored by initMonorepo
      const successInfo = (global as any).__RE_SHELL_INIT_SUCCESS__;
      spinner.succeed(chalk.green(`Monorepo "${name}" initialized successfully!`));
      
      // Display next steps
      console.log('\nNext steps:');
      console.log(`  1. cd ${successInfo?.name || name}`);
      console.log(`  2. ${successInfo?.packageManager || 'pnpm'} install`);
      console.log('  3. re-shell create my-app --framework react-ts');
      console.log('  4. re-shell workspace list');

      if (successInfo?.submodules) {
        console.log('\nSubmodule commands:');
        console.log('  • re-shell submodule add <url> <path>');
        console.log('  • re-shell submodule status');
      }
      
      // Clean up global state
      delete (global as any).__RE_SHELL_INIT_SUCCESS__;
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
  .option('--framework <framework>', 'Framework to use (react|react-ts|vue|vue-ts|svelte|svelte-ts)')
  .option('--type <type>', 'Workspace type (app|package|lib|tool) - monorepo only')
  .option('--port <port>', 'Development server port [default: 5173]')
  .option('--route <route>', 'Route path (for apps)')
  .option('--package-manager <pm>', 'Package manager to use (npm, yarn, pnpm)', 'pnpm')
  .action(async (name, options) => {
    // Handle backward compatibility: if template is provided but not framework, map it
    if (options.template && !options.framework) {
      options.framework = options.template;
    }
    const spinner = createSpinner('Creating Re-Shell project...').start();
    flushOutput();
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
    const spinner = createSpinner('Adding microfrontend...').start();
    flushOutput();
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
    const spinner = createSpinner('Removing microfrontend...').start();
    flushOutput();
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
    const spinner = createSpinner('Building...').start();
    flushOutput();
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
    const spinner = createSpinner('Updating workspaces...').start();
    flushOutput();
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
    const spinner = createSpinner('Adding submodule...').start();
    flushOutput();
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
    const spinner = createSpinner('Removing submodule...').start();
    flushOutput();
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
    const spinner = createSpinner('Updating submodules...').start();
    flushOutput();
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
    const spinner = createSpinner('Initializing submodules...').start();
    flushOutput();
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

// Update command
program
  .command('update')
  .description('Check for CLI updates')
  .action(async () => {
    await runUpdateCommand();
  });

// Deprecated create-mf command removed in v0.2.0
// Enhanced with --yes flag in v0.2.5 for non-interactive mode

// Display help by default if no command is provided
if (process.argv.length <= 2) {
  program.help();
}

program.parse(process.argv);