#!/usr/bin/env node

// Ensure immediate output for better terminal experience
process.env.FORCE_COLOR = '1'; // Enable colors in terminal
if (process.stdout.isTTY) {
  process.stdout.setEncoding('utf8');
}
if (process.stderr.isTTY) {
  process.stderr.setEncoding('utf8');
}

// Enhanced error handling and signal management
import { setupStreamErrorHandlers, processManager } from './utils/error-handler';

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
  manageSubmodules,
} from './commands/submodule';
import { checkForUpdates, runUpdateCommand } from './utils/checkUpdate';
import { createAsyncCommand, handleError, withTimeout } from './utils/error-handler';
import { runDoctorCheck } from './commands/doctor';
import { importProject, exportProject, backupProject, restoreProject } from './commands/migrate';
import { analyzeProject } from './commands/analyze';
import { generateCICDConfig, generateDeployConfig, setupEnvironments } from './commands/cicd';
import { generateCode, generateTests, generateDocumentation } from './commands/generate';
import { manageConfig } from './commands/config';
import { manageEnvironment } from './commands/environment';
import { manageMigration } from './commands/migration';
import { validateConfiguration } from './commands/validate';
import { manageProjectConfig } from './commands/project-config';
import { manageWorkspaceConfig } from './commands/workspace-config';
import { manageTemplates } from './commands/template';
import { manageConfigDiff } from './commands/config-diff';
import { manageBackups } from './commands/backup';
import { manageDevMode } from './commands/dev-mode';
import { manageWorkspaceDefinition } from './commands/workspace-definition';
import { manageWorkspaceGraph } from './commands/workspace-graph';

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
if (
  !process.argv.includes('update') &&
  !process.argv.includes('--version') &&
  !process.argv.includes('-V')
) {
  checkForUpdates(version);
}

// Display banner for main command
if (
  process.argv.length <= 2 ||
  (process.argv.length === 3 && ['-h', '--help', '-V', '--version'].includes(process.argv[2]))
) {
  console.log(chalk.cyan(banner));
}

program
  .name('re-shell')
  .description(
    'Re-Shell CLI - Tools for managing multi-framework monorepo and microfrontend architecture'
  )
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
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner('Initializing monorepo...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
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
          spinner: spinner,
        });
      }, 300000); // 5 minute timeout for init

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
    })
  );

// Create project command
program
  .command('create')
  .description('Create a new Re-Shell project with shell application')
  .argument('<name>', 'Name of the project')
  .option('-t, --team <team>', 'Team name')
  .option('-o, --org <organization>', 'Organization name', 're-shell')
  .option('-d, --description <description>', 'Project description')
  .option('--template <template>', 'Template to use (react, react-ts)', 'react-ts')
  .option(
    '--framework <framework>',
    'Framework to use (react|react-ts|vue|vue-ts|svelte|svelte-ts)'
  )
  .option('--type <type>', 'Workspace type (app|package|lib|tool) - monorepo only')
  .option('--port <port>', 'Development server port [default: 5173]')
  .option('--route <route>', 'Route path (for apps)')
  .option('--package-manager <pm>', 'Package manager to use (npm, yarn, pnpm)', 'pnpm')
  .action(
    createAsyncCommand(async (name, options) => {
      // Handle backward compatibility: if template is provided but not framework, map it
      if (options.template && !options.framework) {
        options.framework = options.template;
      }
      const spinner = createSpinner('Creating Re-Shell project...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await createProject(name, { ...options, isProject: true, spinner });
      }, 180000); // 3 minute timeout

      spinner.succeed(chalk.green(`Re-Shell project "${name}" created successfully!`));
    })
  );

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
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner('Adding microfrontend...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await addMicrofrontend(name, { ...options, spinner });
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green(`Microfrontend "${name}" added successfully!`));
    })
  );

// Remove microfrontend command
program
  .command('remove')
  .description('Remove a microfrontend from existing Re-Shell project')
  .argument('<name>', 'Name of the microfrontend to remove')
  .option('--force', 'Force removal without confirmation')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner('Removing microfrontend...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await removeMicrofrontend(name, { ...options, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green(`Microfrontend "${name}" removed successfully!`));
    })
  );

// List microfrontends command
program
  .command('list')
  .description('List all microfrontends in the current project')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async options => {
      const spinner = createSpinner('Loading microfrontends...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await listMicrofrontends({ ...options, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Microfrontends listed successfully!'));
      } else {
        spinner.stop();
      }
    })
  );

// Build command
program
  .command('build')
  .description('Build all or specific microfrontends')
  .argument('[name]', 'Name of the microfrontend to build (builds all if omitted)')
  .option('--production', 'Build for production environment')
  .option('--analyze', 'Analyze bundle size')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner('Building...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await buildMicrofrontend(name, { ...options, spinner });
      }, 600000); // 10 minute timeout for builds

      spinner.succeed(
        chalk.green(
          name
            ? `Microfrontend "${name}" built successfully!`
            : 'All microfrontends built successfully!'
        )
      );
    })
  );

// Serve command
program
  .command('serve')
  .description('Start development server')
  .argument('[name]', 'Name of the microfrontend to serve (serves all if omitted)')
  .option('--port <port>', 'Port to serve on', '3000')
  .option('--host <host>', 'Host to serve on', 'localhost')
  .option('--open', 'Open in browser')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner('Starting development server...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await serveMicrofrontend(name, { ...options, spinner });
    })
  );

// Workspace management commands
const workspaceCommand = program.command('workspace').description('Manage monorepo workspaces');

workspaceCommand
  .command('list')
  .description('List all workspaces')
  .option('--json', 'Output as JSON')
  .option('--type <type>', 'Filter by workspace type (app, package, lib, tool)')
  .option('--framework <framework>', 'Filter by framework')
  .action(
    createAsyncCommand(async options => {
      const spinner = createSpinner('Loading workspaces...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await listWorkspaces({ ...options, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Workspaces listed successfully!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceCommand
  .command('update')
  .description('Update workspace dependencies')
  .option('--workspace <name>', 'Update specific workspace')
  .option('--dependency <name>', 'Update specific dependency')
  .option('--version <version>', 'Target version for dependency')
  .option('--dev', 'Update dev dependency')
  .action(
    createAsyncCommand(async options => {
      const spinner = createSpinner('Updating workspaces...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await updateWorkspaces({ ...options, spinner });
      }, 300000); // 5 minute timeout for updates

      spinner.succeed(chalk.green('Workspaces updated successfully!'));
    })
  );

workspaceCommand
  .command('graph')
  .description('Generate workspace dependency graph')
  .option('--output <file>', 'Output file path')
  .option('--format <format>', 'Output format (text, json, mermaid)', 'text')
  .action(
    createAsyncCommand(async options => {
      const spinner = createSpinner('Generating workspace graph...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await generateWorkspaceGraph({ ...options, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Workspace graph generated successfully!'));
    })
  );

// Submodule management commands
const submoduleCommand = program.command('submodule').description('Manage Git submodules');

submoduleCommand
  .command('add <url>')
  .description('Add a new Git submodule')
  .option('--path <path>', 'Submodule path')
  .option('--branch <branch>', 'Branch to track', 'main')
  .action(
    createAsyncCommand(async (url, options) => {
      const spinner = createSpinner('Adding submodule...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await addGitSubmodule(url, { ...options, spinner });
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green('Submodule added successfully!'));
    })
  );

submoduleCommand
  .command('remove <path>')
  .description('Remove a Git submodule')
  .option('--force', 'Force removal without confirmation')
  .action(
    createAsyncCommand(async (path, options) => {
      const spinner = createSpinner('Removing submodule...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await removeGitSubmodule(path, { ...options, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Submodule removed successfully!'));
    })
  );

submoduleCommand
  .command('update')
  .description('Update Git submodules')
  .option('--path <path>', 'Update specific submodule')
  .action(
    createAsyncCommand(async options => {
      const spinner = createSpinner('Updating submodules...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await updateGitSubmodules({ ...options, spinner });
      }, 180000); // 3 minute timeout

      spinner.succeed(chalk.green('Submodules updated successfully!'));
    })
  );

submoduleCommand
  .command('status')
  .description('Show Git submodule status')
  .action(
    createAsyncCommand(async () => {
      await withTimeout(async () => {
        await showSubmoduleStatus();
      }, 30000); // 30 second timeout
    })
  );

// Submodule init command
submoduleCommand
  .command('init')
  .description('Initialize Git submodules')
  .action(
    createAsyncCommand(async () => {
      const spinner = createSpinner('Initializing submodules...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await initSubmodules(); // No spinner param for this function
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green('Submodules initialized successfully!'));
    })
  );

submoduleCommand
  .command('manage')
  .description('Interactive submodule management')
  .action(
    createAsyncCommand(async () => {
      await manageSubmodules();
    })
  );

// Update command
program
  .command('update')
  .description('Check for CLI updates')
  .action(async () => {
    await runUpdateCommand();
  });

// Doctor command - Health check and diagnostics
program
  .command('doctor')
  .description('Diagnose project health and identify issues')
  .option('--fix', 'Automatically fix issues where possible')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output results as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Running health check...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await runDoctorCheck({ ...options, spinner });
      }, 120000); // 2 minute timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Health check completed!'));
      } else {
        spinner.stop();
      }
    })
  );

// Analyze command - Bundle and dependency analysis
program
  .command('analyze')
  .description('Analyze bundle size, dependencies, and performance')
  .option('--workspace <name>', 'Analyze specific workspace')
  .option('--type <type>', 'Analysis type (bundle, dependencies, performance, security, all)', 'all')
  .option('--output <file>', 'Save results to file')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output results as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Analyzing project...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await analyzeProject({ ...options, spinner });
      }, 300000); // 5 minute timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Analysis completed!'));
      } else {
        spinner.stop();
      }
    })
  );

// Migration commands
const migrateCommand = program.command('migrate').description('Import/export projects and manage migrations');

migrateCommand
  .command('import <source>')
  .description('Import existing project into Re-Shell monorepo')
  .option('--dry-run', 'Show what would be imported without making changes')
  .option('--verbose', 'Show detailed information')
  .option('--backup', 'Create backup before import')
  .option('--force', 'Overwrite existing files')
  .action(
    createAsyncCommand(async (source, options) => {
      const spinner = createSpinner('Importing project...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await importProject(source, { ...options, spinner });
      }, 600000); // 10 minute timeout

      spinner.succeed(chalk.green('Project imported successfully!'));
    })
  );

migrateCommand
  .command('export <target>')
  .description('Export Re-Shell project to external location')
  .option('--force', 'Overwrite target directory if it exists')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (target, options) => {
      const spinner = createSpinner('Exporting project...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await exportProject(target, { ...options, spinner });
      }, 300000); // 5 minute timeout

      spinner.succeed(chalk.green('Project exported successfully!'));
    })
  );

migrateCommand
  .command('backup')
  .description('Create backup of current project')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Creating backup...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await backupProject({ ...options, spinner });
      }, 300000); // 5 minute timeout

      spinner.succeed(chalk.green('Backup created successfully!'));
    })
  );

migrateCommand
  .command('restore <backup> <target>')
  .description('Restore project from backup')
  .option('--force', 'Overwrite target directory if it exists')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (backup, target, options) => {
      const spinner = createSpinner('Restoring from backup...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await restoreProject(backup, target, { ...options, spinner });
      }, 300000); // 5 minute timeout

      spinner.succeed(chalk.green('Project restored successfully!'));
    })
  );

// CI/CD commands
const cicdCommand = program.command('cicd').description('Generate CI/CD configurations and deployment scripts');

cicdCommand
  .command('generate')
  .description('Generate CI/CD configuration files')
  .option('--provider <provider>', 'CI/CD provider (github, gitlab, jenkins, circleci, azure)', 'github')
  .option('--template <template>', 'Configuration template (basic, advanced, custom)', 'basic')
  .option('--force', 'Overwrite existing configuration')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Generating CI/CD configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await generateCICDConfig({ ...options, spinner });
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green('CI/CD configuration generated!'));
    })
  );

cicdCommand
  .command('deploy <environment>')
  .description('Generate deployment configuration for environment')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (environment, options) => {
      const spinner = createSpinner(`Generating deployment config for ${environment}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await generateDeployConfig(environment, { ...options, spinner });
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green(`Deployment configuration for ${environment} generated!`));
    })
  );

// Configuration management commands
const configCommand = program.command('config').description('Manage Re-Shell configuration');

configCommand
  .command('show')
  .description('Show current configuration')
  .option('--global', 'Show only global configuration')
  .option('--project', 'Show only project configuration')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfig({ ...options, list: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Configuration loaded successfully!'));
      } else {
        spinner.stop();
      }
    })
  );

configCommand
  .command('get <key>')
  .description('Get configuration value')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (key, options) => {
      const spinner = createSpinner(`Getting ${key}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfig({ ...options, get: key, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Configuration value retrieved!'));
      } else {
        spinner.stop();
      }
    })
  );

configCommand
  .command('set <key> <value>')
  .description('Set configuration value')
  .option('--global', 'Set in global configuration')
  .option('--project', 'Set in project configuration')
  .action(
    createAsyncCommand(async (key, value, options) => {
      const spinner = createSpinner(`Setting ${key}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfig({ ...options, set: key, value, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Configuration updated: ${key}`));
    })
  );

configCommand
  .command('preset <action> [name]')
  .description('Manage configuration presets (save|load|list|delete)')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (action, name, options) => {
      const spinner = createSpinner(`Managing preset...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      let presetOptions: Parameters<typeof manageConfig>[0] = { ...options, spinner };
      
      switch (action) {
        case 'save':
          if (!name) throw new Error('Preset name required for save action');
          presetOptions = { ...presetOptions, save: name };
          break;
        case 'load':
          if (!name) throw new Error('Preset name required for load action');
          presetOptions = { ...presetOptions, load: name };
          break;
        case 'list':
          presetOptions = { ...presetOptions, list: true };
          break;
        case 'delete':
          if (!name) throw new Error('Preset name required for delete action');
          presetOptions = { ...presetOptions, delete: name };
          break;
        default:
          throw new Error(`Unknown action: ${action}`);
      }

      await withTimeout(async () => {
        await manageConfig(presetOptions);
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green(`Preset ${action} completed successfully!`));
      } else {
        spinner.stop();
      }
    })
  );

configCommand
  .command('backup')
  .description('Create configuration backup')
  .action(
    createAsyncCommand(async () => {
      const spinner = createSpinner('Creating backup...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfig({ backup: true, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Configuration backup created!'));
    })
  );

configCommand
  .command('restore <backup>')
  .description('Restore configuration from backup')
  .action(
    createAsyncCommand(async (backup) => {
      const spinner = createSpinner('Restoring configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfig({ restore: backup, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Configuration restored!'));
    })
  );

configCommand
  .command('interactive')
  .description('Interactive configuration management')
  .action(
    createAsyncCommand(async () => {
      await manageConfig({ interactive: true });
    })
  );

// Environment management commands
const envCommand = program.command('env').description('Manage environment configurations');

envCommand
  .command('list')
  .description('List all environments')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading environments...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageEnvironment({ ...options, list: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Environments loaded successfully!'));
      } else {
        spinner.stop();
      }
    })
  );

envCommand
  .command('active')
  .description('Show active environment')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Getting active environment...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageEnvironment({ ...options, active: true, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Active environment retrieved!'));
      } else {
        spinner.stop();
      }
    })
  );

envCommand
  .command('set <name>')
  .description('Set active environment')
  .action(
    createAsyncCommand(async (name) => {
      const spinner = createSpinner(`Setting active environment to ${name}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageEnvironment({ set: name, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Environment '${name}' activated!`));
    })
  );

envCommand
  .command('create <name>')
  .description('Create new environment')
  .option('--extends <env>', 'Inherit from existing environment')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Creating environment ${name}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageEnvironment({ ...options, create: name, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green(`Environment '${name}' created!`));
    })
  );

envCommand
  .command('delete <name>')
  .description('Delete environment')
  .action(
    createAsyncCommand(async (name) => {
      const spinner = createSpinner(`Deleting environment ${name}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageEnvironment({ delete: name, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Environment '${name}' deleted!`));
    })
  );

envCommand
  .command('compare <env1> <env2>')
  .description('Compare two environments')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (env1, env2, options) => {
      const spinner = createSpinner(`Comparing ${env1} and ${env2}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageEnvironment({ ...options, compare: [env1, env2], spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Environment comparison completed!'));
      } else {
        spinner.stop();
      }
    })
  );

envCommand
  .command('generate <name>')
  .description('Generate .env file for environment')
  .option('--output <file>', 'Output file path')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Generating .env file for ${name}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageEnvironment({ ...options, generate: name, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Environment file generated for '${name}'!`));
    })
  );

envCommand
  .command('interactive')
  .description('Interactive environment management')
  .action(
    createAsyncCommand(async () => {
      await manageEnvironment({ interactive: true });
    })
  );

// Configuration migration commands
const configMigrateCommand = program.command('config-migrate').description('Manage configuration migrations');

configMigrateCommand
  .command('auto')
  .description('Auto-migrate all configurations')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Running auto-migration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageMigration({ ...options, auto: true, spinner });
      }, 60000); // 60 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Auto-migration completed!'));
      } else {
        spinner.stop();
      }
    })
  );

configMigrateCommand
  .command('check')
  .description('Check migration status')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Checking migration status...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageMigration({ ...options, check: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Migration status checked!'));
      } else {
        spinner.stop();
      }
    })
  );

configMigrateCommand
  .command('global')
  .description('Migrate global configuration')
  .option('--json', 'Output as JSON')
  .option('--force', 'Force migration without confirmation')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Migrating global configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageMigration({ ...options, global: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Global configuration migrated!'));
      } else {
        spinner.stop();
      }
    })
  );

configMigrateCommand
  .command('project')
  .description('Migrate project configuration')
  .option('--json', 'Output as JSON')
  .option('--force', 'Force migration without confirmation')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Migrating project configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageMigration({ ...options, project: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Project configuration migrated!'));
      } else {
        spinner.stop();
      }
    })
  );

configMigrateCommand
  .command('rollback <version>')
  .description('Rollback to previous version')
  .option('--global', 'Rollback global configuration')
  .option('--project', 'Rollback project configuration')
  .option('--json', 'Output as JSON')
  .option('--force', 'Force rollback without confirmation')
  .action(
    createAsyncCommand(async (version, options) => {
      const configType = options.global ? 'global' : 'project';
      const spinner = createSpinner(`Rolling back ${configType} to ${version}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageMigration({ ...options, rollback: version, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green(`Rollback to ${version} completed!`));
      } else {
        spinner.stop();
      }
    })
  );

configMigrateCommand
  .command('history')
  .description('Show migration history')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading migration history...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageMigration({ ...options, history: true, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Migration history loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

configMigrateCommand
  .command('interactive')
  .description('Interactive migration management')
  .action(
    createAsyncCommand(async () => {
      await manageMigration({ interactive: true });
    })
  );

// Validation commands
const validateCommand = program.command('validate').description('Validate configurations with detailed error messages');

validateCommand
  .command('all')
  .description('Validate all configurations')
  .option('--warnings', 'Show warnings')
  .option('--suggestions', 'Show suggestions')
  .option('--fix', 'Auto-fix issues where possible')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Validating configurations...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await validateConfiguration({ ...options, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Configuration validation completed!'));
      } else {
        spinner.stop();
      }
    })
  );

validateCommand
  .command('global')
  .description('Validate global configuration')
  .option('--warnings', 'Show warnings')
  .option('--suggestions', 'Show suggestions')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Validating global configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await validateConfiguration({ ...options, global: true, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Global configuration validated!'));
      } else {
        spinner.stop();
      }
    })
  );

validateCommand
  .command('project')
  .description('Validate project configuration')
  .option('--warnings', 'Show warnings')
  .option('--suggestions', 'Show suggestions')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Validating project configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await validateConfiguration({ ...options, project: true, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Project configuration validated!'));
      } else {
        spinner.stop();
      }
    })
  );

validateCommand
  .command('file <path>')
  .description('Validate specific configuration file')
  .option('--warnings', 'Show warnings')
  .option('--suggestions', 'Show suggestions')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (filePath, options) => {
      const spinner = createSpinner(`Validating ${filePath}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await validateConfiguration({ ...options, file: filePath, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green(`File validation completed: ${filePath}`));
      } else {
        spinner.stop();
      }
    })
  );

validateCommand
  .command('interactive')
  .description('Interactive configuration validation')
  .action(
    createAsyncCommand(async () => {
      await validateConfiguration({ interactive: true });
    })
  );

// Project configuration commands
const projectConfigCommand = program.command('project-config').description('Manage project-level configuration with inheritance');

projectConfigCommand
  .command('init')
  .description('Initialize project configuration')
  .option('--framework <framework>', 'Default framework')
  .option('--package-manager <pm>', 'Package manager (npm, yarn, pnpm, bun)')
  .option('--interactive', 'Interactive initialization')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Initializing project configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageProjectConfig({ ...options, init: true, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Project configuration initialized!'));
    })
  );

projectConfigCommand
  .command('show')
  .description('Show project configuration with inheritance')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show merged configuration')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading project configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageProjectConfig({ ...options, show: true, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Project configuration loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

projectConfigCommand
  .command('get <key>')
  .description('Get project configuration value')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (key, options) => {
      const spinner = createSpinner(`Getting ${key}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageProjectConfig({ ...options, get: key, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Configuration value retrieved!'));
      } else {
        spinner.stop();
      }
    })
  );

projectConfigCommand
  .command('set <key> <value>')
  .description('Set project configuration value')
  .action(
    createAsyncCommand(async (key, value, options) => {
      const spinner = createSpinner(`Setting ${key}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageProjectConfig({ ...options, set: key, value, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Configuration updated: ${key}`));
    })
  );

projectConfigCommand
  .command('interactive')
  .description('Interactive project configuration management')
  .action(
    createAsyncCommand(async () => {
      await manageProjectConfig({ interactive: true });
    })
  );

// Workspace configuration commands
const workspaceConfigCommand = program.command('workspace-config').description('Manage workspace-specific configuration with cascading inheritance');

workspaceConfigCommand
  .command('init')
  .description('Initialize workspace configuration')
  .option('--workspace <path>', 'Workspace path', process.cwd())
  .option('--type <type>', 'Workspace type (app, package, lib, tool)', 'app')
  .option('--framework <framework>', 'Framework override')
  .option('--package-manager <pm>', 'Package manager override')
  .option('--interactive', 'Interactive initialization')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Initializing workspace configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConfig({ ...options, init: true, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Workspace configuration initialized!'));
    })
  );

workspaceConfigCommand
  .command('show')
  .description('Show workspace configuration with inheritance chain')
  .option('--workspace <path>', 'Workspace path', process.cwd())
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show final merged configuration')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading workspace configuration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConfig({ ...options, show: true, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Workspace configuration loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceConfigCommand
  .command('get <key>')
  .description('Get workspace configuration value with inheritance info')
  .option('--workspace <path>', 'Workspace path', process.cwd())
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (key, options) => {
      const spinner = createSpinner(`Getting configuration value: ${key}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConfig({ ...options, get: key, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green(`Configuration value retrieved: ${key}`));
      } else {
        spinner.stop();
      }
    })
  );

workspaceConfigCommand
  .command('set <key> <value>')
  .description('Set workspace configuration value')
  .option('--workspace <path>', 'Workspace path', process.cwd())
  .action(
    createAsyncCommand(async (key, value, options) => {
      const spinner = createSpinner(`Setting configuration: ${key} = ${value}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConfig({ ...options, set: key, value, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Configuration updated: ${key}`));
    })
  );

workspaceConfigCommand
  .command('interactive')
  .description('Interactive workspace configuration management')
  .option('--workspace <path>', 'Workspace path', process.cwd())
  .action(
    createAsyncCommand(async (options) => {
      await manageWorkspaceConfig({ ...options, interactive: true });
    })
  );

// Template management commands
const templateCommand = program.command('template').description('Manage configuration templates with variable substitution');

templateCommand
  .command('list')
  .description('List available configuration templates')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading templates...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageTemplates({ ...options, list: true, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Templates loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

templateCommand
  .command('create')
  .description('Create a new configuration template')
  .option('--interactive', 'Interactive template creation')
  .action(
    createAsyncCommand(async (options) => {
      await manageTemplates({ ...options, create: true });
    })
  );

templateCommand
  .command('show <name>')
  .description('Show template details and variables')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show template structure')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Loading template: ${name}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageTemplates({ ...options, show: true, template: name, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green(`Template '${name}' loaded!`));
      } else {
        spinner.stop();
      }
    })
  );

templateCommand
  .command('apply <name>')
  .description('Apply template to generate configuration')
  .option('--variables <json>', 'Variables as JSON string')
  .option('--output <file>', 'Output file path')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Applying template: ${name}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageTemplates({ ...options, apply: true, template: name, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green(`Template '${name}' applied successfully!`));
    })
  );

templateCommand
  .command('delete <name>')
  .description('Delete a configuration template')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Deleting template: ${name}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageTemplates({ ...options, delete: true, template: name, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Template '${name}' deleted!`));
    })
  );

templateCommand
  .command('interactive')
  .description('Interactive template management')
  .action(
    createAsyncCommand(async (options) => {
      await manageTemplates({ ...options, interactive: true });
    })
  );

// Configuration diff and merge commands
const configDiffCommand = program.command('config-diff').description('Compare and merge configurations with advanced diffing capabilities');

configDiffCommand
  .command('diff')
  .description('Compare two configurations and show differences')
  .option('--left <source>', 'Left configuration source (file, global, project, workspace:path)')
  .option('--right <source>', 'Right configuration source (file, global, project, workspace:path)')
  .option('--format <format>', 'Output format (text, html, json)', 'text')
  .option('--output <file>', 'Output file for diff report')
  .option('--ignore-order', 'Ignore array order in comparison')
  .option('--ignore-paths <paths>', 'Comma-separated paths to ignore')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      if (!options.left || !options.right) {
        console.log(chalk.red('Error: Both --left and --right sources are required'));
        process.exit(1);
      }

      const spinner = createSpinner('Comparing configurations...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfigDiff({ ...options, diff: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Configuration comparison completed!'));
      } else {
        spinner.stop();
      }
    })
  );

configDiffCommand
  .command('merge')
  .description('Merge two configurations with conflict resolution')
  .option('--left <source>', 'Base configuration source')
  .option('--right <source>', 'Incoming configuration source')
  .option('--output <file>', 'Output file for merged configuration')
  .option('--strategy <strategy>', 'Merge strategy (left, right, smart, conservative, interactive)', 'smart')
  .option('--interactive', 'Interactive conflict resolution')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      if (!options.left || !options.right) {
        console.log(chalk.red('Error: Both --left and --right sources are required'));
        process.exit(1);
      }

      const spinner = createSpinner('Merging configurations...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfigDiff({ ...options, merge: true, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Configuration merge completed!'));
    })
  );

configDiffCommand
  .command('apply')
  .description('Apply a diff patch to a configuration')
  .option('--left <config>', 'Base configuration file')
  .option('--right <diff>', 'Diff file (JSON format)')
  .option('--output <file>', 'Output file for patched configuration')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      if (!options.left || !options.right) {
        console.log(chalk.red('Error: Both --left (config) and --right (diff) are required'));
        process.exit(1);
      }

      const spinner = createSpinner('Applying diff patch...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfigDiff({ ...options, apply: true, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Diff patch applied successfully!'));
    })
  );

configDiffCommand
  .command('status')
  .description('Show configuration status and inheritance analysis')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Analyzing configuration status...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageConfigDiff({ ...options, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Configuration analysis completed!'));
      } else {
        spinner.stop();
      }
    })
  );

configDiffCommand
  .command('interactive')
  .description('Interactive configuration diffing and merging')
  .action(
    createAsyncCommand(async (options) => {
      await manageConfigDiff({ ...options, interactive: true });
    })
  );

// Configuration backup and restore commands
const backupCommand = program.command('backup').description('Backup and restore configurations with versioning and rollback capabilities');

backupCommand
  .command('create')
  .description('Create a configuration backup')
  .option('--full', 'Create full backup (all configurations)')
  .option('--selective', 'Create selective backup (choose components)')
  .option('--name <name>', 'Backup name')
  .option('--description <desc>', 'Backup description')
  .option('--tags <tags>', 'Comma-separated tags')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Creating backup...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageBackups({ ...options, create: true, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Backup created successfully!'));
    })
  );

backupCommand
  .command('list')
  .description('List all available backups')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading backups...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageBackups({ ...options, list: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Backups loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

backupCommand
  .command('restore <id>')
  .description('Restore configuration from backup')
  .option('--force', 'Skip confirmation prompt')
  .option('--dry-run', 'Preview restoration without making changes')
  .option('--no-pre-backup', 'Skip creating backup before restoration')
  .option('--merge-strategy <strategy>', 'Merge strategy (replace, merge, skip-existing)', 'replace')
  .action(
    createAsyncCommand(async (id, options) => {
      const spinner = createSpinner(`Restoring from backup: ${id}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageBackups({ ...options, restore: id, spinner });
      }, 120000); // 2 minute timeout

      if (!options.dryRun) {
        spinner.succeed(chalk.green('Configuration restored successfully!'));
      } else {
        spinner.stop();
      }
    })
  );

backupCommand
  .command('delete <id>')
  .description('Delete a backup')
  .option('--force', 'Skip confirmation prompt')
  .action(
    createAsyncCommand(async (id, options) => {
      const spinner = createSpinner(`Deleting backup: ${id}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageBackups({ ...options, delete: id, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green('Backup deleted successfully!'));
    })
  );

backupCommand
  .command('export <id>')
  .description('Export backup to file')
  .option('--output <file>', 'Output file path')
  .action(
    createAsyncCommand(async (id, options) => {
      if (!options.output) {
        console.log(chalk.red('Error: --output file path is required'));
        process.exit(1);
      }

      const spinner = createSpinner(`Exporting backup: ${id}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageBackups({ ...options, export: id, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Backup exported successfully!'));
    })
  );

backupCommand
  .command('import <file>')
  .description('Import backup from file')
  .action(
    createAsyncCommand(async (file, options) => {
      const spinner = createSpinner(`Importing backup from: ${file}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageBackups({ ...options, import: file, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Backup imported successfully!'));
    })
  );

backupCommand
  .command('cleanup')
  .description('Clean up old backups')
  .option('--keep-count <count>', 'Number of recent backups to keep', '10')
  .option('--keep-days <days>', 'Keep backups newer than N days', '30')
  .option('--dry-run', 'Preview cleanup without deleting')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Analyzing backups for cleanup...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageBackups({ 
          ...options, 
          cleanup: true, 
          keepCount: parseInt(options.keepCount),
          keepDays: parseInt(options.keepDays),
          spinner 
        });
      }, 30000); // 30 second timeout

      if (!options.dryRun) {
        spinner.succeed(chalk.green('Backup cleanup completed!'));
      } else {
        spinner.stop();
      }
    })
  );

backupCommand
  .command('stats')
  .description('Show backup statistics')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Calculating backup statistics...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageBackups({ ...options, stats: true, spinner });
      }, 15000); // 15 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Statistics calculated!'));
      } else {
        spinner.stop();
      }
    })
  );

backupCommand
  .command('interactive')
  .description('Interactive backup management')
  .action(
    createAsyncCommand(async (options) => {
      await manageBackups({ ...options, interactive: true });
    })
  );

// Generate commands
const generateCommand = program.command('generate').description('Generate code, tests, and documentation');

generateCommand
  .command('component <name>')
  .description('Generate a new component')
  .option('--framework <framework>', 'Framework (react, vue, svelte, angular)', 'react')
  .option('--workspace <workspace>', 'Target workspace')
  .option('--export', 'Add to index exports')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Generating component ${name}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await generateCode(name, { ...options, type: 'component', spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green(`Component ${name} generated!`));
    })
  );

generateCommand
  .command('hook <name>')
  .description('Generate a React hook')
  .option('--workspace <workspace>', 'Target workspace')
  .option('--export', 'Add to index exports')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Generating hook ${name}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await generateCode(name, { ...options, type: 'hook', framework: 'react', spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green(`Hook ${name} generated!`));
    })
  );

generateCommand
  .command('service <name>')
  .description('Generate a service class')
  .option('--workspace <workspace>', 'Target workspace')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Generating service ${name}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await generateCode(name, { ...options, type: 'service', spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green(`Service ${name} generated!`));
    })
  );

generateCommand
  .command('test <workspace>')
  .description('Generate test suite for workspace')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (workspace, options) => {
      const spinner = createSpinner(`Generating tests for ${workspace}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await generateTests(workspace, { ...options, spinner });
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green(`Test suite for ${workspace} generated!`));
    })
  );

generateCommand
  .command('docs')
  .description('Generate project documentation')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Generating documentation...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await generateDocumentation({ ...options, spinner });
      }, 180000); // 3 minute timeout

      spinner.succeed(chalk.green('Documentation generated!'));
    })
  );

// Development mode commands
const devCommand = program.command('dev').description('Development mode with configuration hot-reloading');

devCommand
  .command('start')
  .description('Start development mode with hot-reloading')
  .option('--verbose', 'Enable detailed change notifications')
  .option('--debounce <ms>', 'Change detection delay in milliseconds', '500')
  .option('--no-validation', 'Skip configuration validation on changes')
  .option('--no-backup', 'Disable automatic backups before changes')
  .option('--no-restore', 'Disable error recovery from backups')
  .option('--exclude-workspaces', 'Skip workspace configuration watching')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Starting development mode...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageDevMode({ ...options, start: true, spinner });
      }, 30000); // 30 second timeout

      // Don't auto-succeed for dev mode as it stays running
      spinner.stop();
    })
  );

devCommand
  .command('stop')
  .description('Stop development mode')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Stopping development mode...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageDevMode({ ...options, stop: true, spinner });
      }, 10000); // 10 second timeout

      spinner.succeed(chalk.green('Development mode stopped!'));
    })
  );

devCommand
  .command('restart')
  .description('Restart development mode')
  .option('--verbose', 'Enable detailed change notifications')
  .option('--debounce <ms>', 'Change detection delay in milliseconds', '500')
  .option('--no-validation', 'Skip configuration validation on changes')
  .option('--no-backup', 'Disable automatic backups before changes')
  .option('--no-restore', 'Disable error recovery from backups')
  .option('--exclude-workspaces', 'Skip workspace configuration watching')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Restarting development mode...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageDevMode({ ...options, restart: true, spinner });
      }, 30000); // 30 second timeout

      spinner.stop();
    })
  );

devCommand
  .command('status')
  .description('Show development mode status')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Checking development mode status...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageDevMode({ ...options, status: true, spinner });
      }, 10000); // 10 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Status checked!'));
      } else {
        spinner.stop();
      }
    })
  );

devCommand
  .command('interactive')
  .description('Interactive development mode management')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading development mode interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageDevMode({ ...options, interactive: true, spinner });
      }, 60000); // 1 minute timeout

      spinner.stop();
    })
  );

// Workspace definition commands
const workspaceDefCommand = program.command('workspace-def').description('Manage workspace definitions and schemas');

workspaceDefCommand
  .command('init')
  .description('Initialize workspace definition file')
  .option('--output <file>', 'Output file path', 're-shell.workspaces.yaml')
  .option('--dry-run', 'Preview without creating file')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Initializing workspace definition...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceDefinition({ ...options, init: true, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Workspace definition initialized!'));
    })
  );

workspaceDefCommand
  .command('validate')
  .description('Validate workspace definition')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--strict', 'Treat warnings as errors')
  .option('--ignore-warnings', 'Ignore validation warnings')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Validating workspace definition...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceDefinition({ ...options, validate: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Validation completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceDefCommand
  .command('structure')
  .description('Validate workspace structure on disk')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--strict', 'Treat warnings as errors')
  .option('--ignore-warnings', 'Ignore validation warnings')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Validating workspace structure...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceDefinition({ ...options, structure: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Structure validation completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceDefCommand
  .command('auto-detect')
  .description('Auto-detect workspaces based on patterns')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--output <file>', 'Output file (defaults to input file)')
  .option('--merge', 'Merge with existing definition')
  .option('--dry-run', 'Preview without making changes')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Auto-detecting workspaces...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceDefinition({ ...options, autoDetect: true, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Workspace auto-detection completed!'));
    })
  );

workspaceDefCommand
  .command('fix')
  .description('Fix workspace definition issues')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--dry-run', 'Preview fixes without applying')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Analyzing workspace definition...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceDefinition({ ...options, fix: true, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Fix analysis completed!'));
    })
  );

workspaceDefCommand
  .command('interactive')
  .description('Interactive workspace definition management')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading workspace definition interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceDefinition({ ...options, interactive: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

// Workspace graph commands
const workspaceGraphCommand = program.command('workspace-graph').description('Analyze workspace dependency graphs and detect cycles');

workspaceGraphCommand
  .command('analyze')
  .description('Comprehensive workspace dependency graph analysis')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--detailed', 'Show detailed analysis information')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show verbose information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Analyzing workspace dependency graph...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceGraph({ ...options, analyze: true, spinner });
      }, 60000); // 1 minute timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Graph analysis completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceGraphCommand
  .command('cycles')
  .description('Detect and analyze dependency cycles')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--detailed', 'Show detailed cycle information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Detecting dependency cycles...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceGraph({ ...options, cycles: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Cycle detection completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceGraphCommand
  .command('order')
  .description('Generate optimal build order')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--detailed', 'Show detailed build order information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Generating build order...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceGraph({ ...options, order: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Build order generated!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceGraphCommand
  .command('critical')
  .description('Find critical path through dependency graph')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Finding critical path...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceGraph({ ...options, critical: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Critical path analysis completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceGraphCommand
  .command('visualize')
  .description('Generate graph visualization data')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--output <file>', 'Save visualization data to file (JSON format)')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Generating graph visualization...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceGraph({ ...options, visualize: true, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Visualization generated!'));
    })
  );

workspaceGraphCommand
  .command('interactive')
  .description('Interactive graph analysis interface')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading graph analysis interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceGraph({ ...options, interactive: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

// Deprecated create-mf command removed in v0.2.0
// Enhanced with --yes flag in v0.2.5 for non-interactive mode

// Display help by default if no command is provided
if (process.argv.length <= 2) {
  program.help();
}

// Ensure clean exit for all commands - no hanging processes
setTimeout(() => {
  process.exit(0);
}, 30000); // 30 second maximum for any command

program.parse(process.argv);

// Force exit after command completion to prevent hanging
process.nextTick(() => {
  setTimeout(() => {
    process.exit(0);
  }, 2000); // 2 second grace period after command completion
});
