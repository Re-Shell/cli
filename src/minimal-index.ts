#!/usr/bin/env node

// Minimal startup optimization test
const startTime = Date.now();

// Read package.json for version
const { readFileSync } = require('fs');
const { join } = require('path');
const packageJson = JSON.parse(
  readFileSync(join(__dirname, '../package.json'), 'utf-8')
);

// Fast path for version
if (process.argv.includes('--version') || process.argv.includes('-v')) {
  const chalk = require('chalk');
  console.log(chalk.cyan(`
██████╗ ███████╗           ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██╔════╝           ██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝█████╗  ████████╗  ███████╗███████║█████╗  ██║     ██║
██╔══██╗██╔══╝  ╚═══════╝  ╚════██║██╔══██║██╔══╝  ██║     ██║
██║  ██║███████╗           ███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═╝╚══════╝           ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                v${packageJson.version}
`));
  console.log(packageJson.version);
  const endTime = Date.now();
  if (process.env.DEBUG) {
    console.error(`Startup time: ${endTime - startTime}ms`);
  }
  process.exit(0);
}

// Defer heavy imports
import { Command } from 'commander';

const program = new Command();

// Basic program setup
program
  .name('re-shell')
  .description('Re-Shell CLI - Universal Full-Stack Development Platform')
  .version(packageJson.version);

// Minimal commands for testing
program
  .command('test')
  .description('Test command')
  .action(() => {
    console.log('Test command executed');
  });

// Show help if no commands
if (process.argv.length <= 2) {
  const chalk = require('chalk');
  console.log(chalk.cyan(`
██████╗ ███████╗           ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██╔════╝           ██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝█████╗  ████████╗  ███████╗███████║█████╗  ██║     ██║
██╔══██╗██╔══╝  ╚═══════╝  ╚════██║██╔══██║██╔══╝  ██║     ██║
██║  ██║███████╗           ███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═╝╚══════╝           ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                v${packageJson.version}
`));
  program.outputHelp();
}

program.parse();

const endTime = Date.now();
if (process.env.DEBUG) {
  console.error(`Total startup time: ${endTime - startTime}ms`);
}