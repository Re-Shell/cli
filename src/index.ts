#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs-extra';
import * as path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { createMicrofrontend } from './commands/create-mf';
import { createProject } from './commands/create';
import { addMicrofrontend } from './commands/add';
import { removeMicrofrontend } from './commands/remove';
import { listMicrofrontends } from './commands/list';
import { buildMicrofrontend } from './commands/build';
import { serveMicrofrontend } from './commands/serve';

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
  .description('Re-Shell CLI - Tools for managing microfrontend architecture')
  .version(version);

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

// Deprecated create-mf command removed in v0.2.0

// Display help by default if no command is provided
if (process.argv.length <= 2) {
  program.help();
}

program.parse(process.argv);