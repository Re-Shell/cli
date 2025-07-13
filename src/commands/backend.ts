import { Command } from 'commander';
import chalk from 'chalk';
import { addBackend } from './add-backend';
import { listBackendTemplates } from '../utils/backend-selector';
import { createSpinner } from '../utils/spinner';

export function createBackendCommand(): Command {
  const backendCommand = new Command('backend');
  
  backendCommand
    .description('Create and manage backend microservices')
    .argument('[name]', 'Name of the backend service')
    .option('-t, --template <template>', 'Backend template to use (e.g., express, fastapi, nestjs)')
    .option('-p, --port <port>', 'Service port')
    .option('-d, --description <description>', 'Service description')
    .option('-l, --list', 'List all available backend templates')
    .option('--use-case <useCase>', 'Describe your use case for template recommendations')
    .action(async (name, options) => {
      try {
        if (options.list) {
          listBackendTemplates();
          return;
        }
        
        if (!name) {
          console.log(chalk.red('Error: Service name is required'));
          console.log(chalk.gray('Usage: reshell backend <service-name> [options]'));
          console.log(chalk.gray('       reshell backend --list'));
          console.log(chalk.gray('\nExamples:'));
          console.log(chalk.gray('  reshell backend auth-service --template fastapi'));
          console.log(chalk.gray('  reshell backend user-service --template nestjs --port 3001'));
          console.log(chalk.gray('  reshell backend api-gateway --use-case "I need an API gateway"'));
          return;
        }
        
        const spinner = createSpinner('Creating backend service...').start();
        
        try {
          await addBackend(name, { ...options, spinner });
        } finally {
          spinner.stop();
        }
        
      } catch (error) {
        console.error(chalk.red('Error:'), error);
        process.exit(1);
      }
    });

  return backendCommand;
}