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
