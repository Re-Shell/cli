#!/usr/bin/env node

import { Command } from 'commander';
import { createMicrofrontend } from './commands/create-mf';

// Get version from package.json
const version = '0.1.0';

const program = new Command();

program
  .name('reshell')
  .description('ReShell CLI - Tools for managing microfrontend architecture')
  .version(version);

program
  .command('create-mf')
  .description('Create a new microfrontend repository')
  .argument('<name>', 'Name of the microfrontend')
  .option('-t, --team <team>', 'Team name')
  .option('-o, --org <organization>', 'GitHub organization name', 'Re-Shell')
  .option('-d, --description <description>', 'Repository description')
  .action(async (name, options) => {
    try {
      await createMicrofrontend(name, options);
    } catch (error) {
      console.error('Error creating microfrontend:', error);
      process.exit(1);
    }
  });

program.parse(process.argv);