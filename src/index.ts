#!/usr/bin/env node

// Start performance tracking
import { mark, isVersionRequest, getFromCache, setCache } from './startup-optimizer';
mark('startup-begin');

// Ensure immediate output for better terminal experience
process.env.FORCE_COLOR = '1'; // Enable colors in terminal
if (process.stdout.isTTY) {
  process.stdout.setEncoding('utf8');
}
if (process.stderr.isTTY) {
  process.stderr.setEncoding('utf8');
}

mark('env-setup-done');

// Fast path for version requests
if (isVersionRequest()) {
  mark('version-fast-path');
  const chalk = require('chalk');
  console.log(chalk.cyan(`
██████╗ ███████╗           ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██╔════╝           ██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝█████╗  ████████╗  ███████╗███████║█████╗  ██║     ██║
██╔══██╗██╔══╝  ╚═══════╝  ╚════██║██╔══██║██╔══╝  ██║     ██║
██║  ██║███████╗           ███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═╝╚══════╝           ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                v0.7.1
`));
  console.log('0.7.1');
  process.exit(0);
}

mark('version-check-done');

// Enhanced error handling and signal management
import { setupStreamErrorHandlers, processManager } from './utils/error-handler';

// Core imports only
import { Command } from 'commander';
import * as path from 'path';
import chalk from 'chalk';

mark('core-imports-done');

// Defer heavy imports until needed (simplified)
const lazyImports = {
  spinner: () => import('./utils/spinner'),
  errorHandler: () => import('./utils/error-handler'),
  // Commands - loaded on demand
  create: () => import('./commands/create'),
  add: () => import('./commands/add'),
  remove: () => import('./commands/remove'),
  list: () => import('./commands/list'),
  build: () => import('./commands/build'),
  serve: () => import('./commands/serve'),
  init: () => import('./commands/init'),
  workspace: () => import('./commands/workspace'),
  submodule: () => import('./commands/submodule'),
  doctor: () => import('./commands/doctor'),
  migrate: () => import('./commands/migrate'),
  analyze: () => import('./commands/analyze'),
  cicd: () => import('./commands/cicd'),
  generate: () => import('./commands/generate'),
  config: () => import('./commands/config'),
  environment: () => import('./commands/environment'),
  migration: () => import('./commands/migration'),
  validate: () => import('./commands/validate'),
  projectConfig: () => import('./commands/project-config'),
  workspaceConfig: () => import('./commands/workspace-config'),
  template: () => import('./commands/template'),
  configDiff: () => import('./commands/config-diff'),
  backup: () => import('./commands/backup'),
  devMode: () => import('./commands/dev-mode'),
  workspaceDefinition: () => import('./commands/workspace-definition'),
  workspaceGraph: () => import('./commands/workspace-graph'),
  workspaceHealth: () => import('./commands/workspace-health'),
  workspaceState: () => import('./commands/workspace-state'),
  workspaceTemplate: () => import('./commands/workspace-template'),
  workspaceBackup: () => import('./commands/workspace-backup'),
  workspaceMigration: () => import('./commands/workspace-migration'),
  workspaceConflict: () => import('./commands/workspace-conflict'),
  fileWatcher: () => import('./commands/file-watcher'),
  changeDetector: () => import('./commands/change-detector'),
  changeImpact: () => import('./commands/change-impact'),
  incrementalBuild: () => import('./commands/incremental-build'),
  platformTest: () => import('./commands/platform-test'),
  plugin: () => import('./commands/plugin'),
  pluginDependency: () => import('./commands/plugin-dependency'),
  pluginMarketplace: () => import('./commands/plugin-marketplace'),
  pluginSecurity: () => import('./commands/plugin-security'),
  pluginCommand: () => import('./commands/plugin-command'),
  pluginMiddleware: () => import('./commands/plugin-middleware'),
  pluginConflicts: () => import('./commands/plugin-conflicts'),
  pluginDocs: () => import('./commands/plugin-docs'),
  pluginValidation: () => import('./commands/plugin-validation'),
  pluginCache: () => import('./commands/plugin-cache'),
  // Utils - loaded on demand
  checkUpdate: () => import('./utils/checkUpdate')
};

// Get version from package.json (cached)
let version = '0.7.1'; // fallback
const packageVersion = getFromCache('package-version');
if (packageVersion) {
  version = packageVersion;
} else {
  try {
    const fs = require('fs');
    const packageJsonPath = path.resolve(__dirname, '../package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    version = packageJson.version;
    setCache('package-version', version);
  } catch {
    // Use fallback
  }
}

mark('version-resolved');

// Lazy banner generation
const getBanner = () => {
  return chalk.cyan(`
██████╗ ███████╗           ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██╔════╝           ██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝█████╗  ████████╗  ███████╗███████║█████╗  ██║     ██║
██╔══██╗██╔══╝  ╚═══════╝  ╚════██║██╔══██║██╔══╝  ██║     ██║
██║  ██║███████╗           ███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═╝╚══════╝           ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                v${version}
`);
};

const program = new Command();
mark('program-created');

// Defer update check to avoid blocking startup
const checkUpdate = () => {
  setTimeout(async () => {
    if (
      !process.argv.includes('update') &&
      !process.argv.includes('--version') &&
      !process.argv.includes('-V')
    ) {
      try {
        const { checkForUpdates } = await lazyImports.checkUpdate();
        checkForUpdates(version);
      } catch {
        // Ignore update check errors
      }
    }
  }, 100);
};

checkUpdate();
mark('update-check-deferred');

// Display banner for main command
if (
  process.argv.length <= 2 ||
  (process.argv.length === 3 && ['-h', '--help', '-V', '--version'].includes(process.argv[2]))
) {
  console.log(getBanner());
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

// Workspace health commands
const workspaceHealthCommand = program.command('workspace-health').description('Validate workspace topology and perform health checks');

workspaceHealthCommand
  .command('check')
  .description('Perform comprehensive workspace health check')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--category <category>', 'Check specific category (structure, dependencies, build, etc.)')
  .option('--output <file>', 'Save health report to file')
  .option('--detailed', 'Show detailed check information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Performing workspace health check...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceHealth({ ...options, check: true, spinner });
      }, 120000); // 2 minute timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Health check completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceHealthCommand
  .command('topology')
  .description('Validate workspace topology and structure')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Validating workspace topology...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceHealth({ ...options, topology: true, spinner });
      }, 60000); // 1 minute timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Topology validation completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceHealthCommand
  .command('quick')
  .description('Quick workspace health check')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Running quick health check...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceHealth({ ...options, quick: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Quick check completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceHealthCommand
  .command('watch')
  .description('Monitor workspace health continuously')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Starting health monitoring...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      // Note: watch command runs indefinitely, no timeout
      await manageWorkspaceHealth({ ...options, watch: true, spinner });
    })
  );

workspaceHealthCommand
  .command('fix')
  .description('Analyze and suggest fixes for health issues')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Analyzing fixable health issues...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceHealth({ ...options, fix: true, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Fix analysis completed!'));
    })
  );

workspaceHealthCommand
  .command('interactive')
  .description('Interactive workspace health management')
  .option('--file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading health management interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceHealth({ ...options, interactive: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

// Workspace state commands
const workspaceStateCommand = program.command('workspace-state').description('Manage workspace state persistence and caching');

workspaceStateCommand
  .command('status')
  .description('Show workspace state and cache status')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading workspace state status...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceState({ ...options, status: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('State status loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceStateCommand
  .command('clear')
  .description('Clear workspace state')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Clearing workspace state...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceState({ ...options, clear: true, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green('Workspace state cleared!'));
    })
  );

workspaceStateCommand
  .command('backup')
  .description('Backup workspace state')
  .option('--output <file>', 'Backup file path')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Creating state backup...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceState({ ...options, backup: true, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('State backup created!'));
    })
  );

workspaceStateCommand
  .command('restore <file>')
  .description('Restore workspace state from backup')
  .action(
    createAsyncCommand(async (file, options) => {
      const spinner = createSpinner(`Restoring state from ${file}...`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceState({ ...options, restore: true, file, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('State restored!'));
    })
  );

workspaceStateCommand
  .command('cache')
  .description('Manage workspace cache')
  .option('--clear', 'Clear all cache')
  .option('--pattern <pattern>', 'Invalidate cache entries matching pattern')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Managing workspace cache...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceState({ ...options, cache: true, spinner });
      }, 30000); // 30 second timeout

      if (options.clear) {
        spinner.succeed(chalk.green('Cache cleared!'));
      } else {
        spinner.succeed(chalk.green('Cache operation completed!'));
      }
    })
  );

workspaceStateCommand
  .command('optimize')
  .description('Optimize workspace storage (remove expired cache entries)')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Optimizing workspace storage...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceState({ ...options, optimize: true, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Storage optimized!'));
    })
  );

workspaceStateCommand
  .command('interactive')
  .description('Interactive workspace state management')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading state management interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceState({ ...options, interactive: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

// Workspace template commands
const workspaceTemplateCommand = program.command('workspace-template').description('Manage workspace templates and inheritance');

workspaceTemplateCommand
  .command('list')
  .description('List available workspace templates')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading templates...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceTemplate({ ...options, list: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Templates loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceTemplateCommand
  .command('create')
  .description('Create new workspace template')
  .option('--name <name>', 'Template name')
  .option('--extends <template>', 'Parent template to extend')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Creating template...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceTemplate({ ...options, create: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

workspaceTemplateCommand
  .command('show <name>')
  .description('Show template details and inheritance chain')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show template content')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Loading template: ${name}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceTemplate({ ...options, show: true, template: name, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green(`Template '${name}' loaded!`));
      } else {
        spinner.stop();
      }
    })
  );

workspaceTemplateCommand
  .command('apply <name>')
  .description('Apply template with variable substitution')
  .option('--variables <json>', 'Variables as JSON string')
  .option('--vars-file <file>', 'Load variables from YAML file')
  .option('--output <file>', 'Save result to file')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Applying template: ${name}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceTemplate({ ...options, apply: true, template: name, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green(`Template '${name}' applied!`));
    })
  );

workspaceTemplateCommand
  .command('delete <name>')
  .description('Delete workspace template')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner(`Deleting template: ${name}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceTemplate({ ...options, delete: true, template: name, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Template '${name}' deleted!`));
    })
  );

workspaceTemplateCommand
  .command('export <name>')
  .description('Export workspace definition as template')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--output <file>', 'Save template to file instead of registry')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner('Exporting workspace as template...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceTemplate({ ...options, export: true, name, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green(`Template '${name}' exported!`));
    })
  );

workspaceTemplateCommand
  .command('interactive')
  .description('Interactive template management')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading template management interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceTemplate({ ...options, interactive: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

// Workspace backup commands
const workspaceBackupCommand = program.command('workspace-backup').description('Manage workspace backups and restore capabilities');

workspaceBackupCommand
  .command('create')
  .description('Create workspace backup')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--name <name>', 'Backup name')
  .option('--description <description>', 'Backup description')
  .option('--include-state', 'Include workspace state', true)
  .option('--include-cache', 'Include cache data')
  .option('--include-templates', 'Include templates', true)
  .option('--include-files', 'Include additional files')
  .option('--file-patterns <patterns>', 'File patterns to include (comma-separated)')
  .option('--tags <tags>', 'Backup tags (comma-separated)')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Creating workspace backup...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ ...options, create: true, spinner });
      }, 60000); // 1 minute timeout

      spinner.succeed(chalk.green('Backup created successfully!'));
    })
  );

workspaceBackupCommand
  .command('list')
  .description('List workspace backups')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading backups...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ ...options, list: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Backups loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceBackupCommand
  .command('show <id>')
  .description('Show backup details')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (id, options) => {
      const spinner = createSpinner(`Loading backup: ${id}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ ...options, show: true, name: id, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green(`Backup '${id}' loaded!`));
      } else {
        spinner.stop();
      }
    })
  );

workspaceBackupCommand
  .command('restore <id>')
  .description('Restore workspace from backup')
  .option('--force', 'Overwrite existing files')
  .option('--selective', 'Selective restoration')
  .option('--restore-state', 'Restore workspace state', true)
  .option('--restore-cache', 'Restore cache data')
  .option('--restore-templates', 'Restore templates', true)
  .option('--restore-files', 'Restore additional files')
  .option('--target-path <path>', 'Target directory for restoration')
  .action(
    createAsyncCommand(async (id, options) => {
      const spinner = createSpinner(`Restoring backup: ${id}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ ...options, restore: true, name: id, spinner });
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green('Backup restored successfully!'));
    })
  );

workspaceBackupCommand
  .command('delete <id>')
  .description('Delete workspace backup')
  .action(
    createAsyncCommand(async (id, options) => {
      const spinner = createSpinner(`Deleting backup: ${id}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ ...options, delete: true, name: id, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green(`Backup '${id}' deleted!`));
    })
  );

workspaceBackupCommand
  .command('export <id>')
  .description('Export backup to file')
  .option('--output <file>', 'Output file path', true)
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
        await manageWorkspaceBackup({ ...options, export: true, name: id, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Backup exported successfully!'));
    })
  );

workspaceBackupCommand
  .command('import <file>')
  .description('Import backup from file')
  .action(
    createAsyncCommand(async (file, options) => {
      const spinner = createSpinner(`Importing backup from: ${file}`).start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ ...options, import: true, file, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Backup imported successfully!'));
    })
  );

workspaceBackupCommand
  .command('cleanup')
  .description('Clean up old backups')
  .option('--keep-count <count>', 'Number of recent backups to keep', '10')
  .option('--keep-days <days>', 'Keep backups newer than N days', '30')
  .option('--dry-run', 'Preview cleanup without deleting')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Analyzing backups for cleanup...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ 
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

workspaceBackupCommand
  .command('compare <id1> <id2>')
  .description('Compare two backups')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed comparison')
  .action(
    createAsyncCommand(async (id1, id2, options) => {
      const spinner = createSpinner('Comparing backups...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ 
          ...options, 
          compare: true, 
          backup1: id1, 
          backup2: id2, 
          spinner 
        });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Comparison completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceBackupCommand
  .command('interactive')
  .description('Interactive backup management')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading backup management interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceBackup({ ...options, interactive: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

// Workspace migration commands
const workspaceMigrationCommand = program.command('workspace-migration').description('Manage workspace migrations and upgrades');

workspaceMigrationCommand
  .command('check')
  .description('Check for available workspace upgrades')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Checking for upgrades...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceMigration({ ...options, check: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Upgrade check completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceMigrationCommand
  .command('plan')
  .description('Create migration plan to target version')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--target-version <version>', 'Target version for migration', true)
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed plan information')
  .action(
    createAsyncCommand(async (options) => {
      if (!options.targetVersion) {
        console.log(chalk.red('Error: --target-version is required'));
        process.exit(1);
      }

      const spinner = createSpinner('Creating migration plan...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceMigration({ ...options, plan: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Migration plan created!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceMigrationCommand
  .command('upgrade')
  .description('Upgrade workspace to target version')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--target-version <version>', 'Target version for upgrade', true)
  .option('--force', 'Force upgrade without confirmations')
  .option('--dry-run', 'Preview upgrade without making changes')
  .option('--no-backup', 'Skip automatic backup creation')
  .option('--skip-validation', 'Skip pre-migration validation')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      if (!options.targetVersion) {
        console.log(chalk.red('Error: --target-version is required'));
        process.exit(1);
      }

      const spinner = createSpinner('Upgrading workspace...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceMigration({ 
          ...options, 
          upgrade: true, 
          backup: !options.noBackup,
          spinner 
        });
      }, 300000); // 5 minute timeout

      if (options.dryRun) {
        spinner.succeed(chalk.green('Dry run completed!'));
      } else {
        spinner.succeed(chalk.green('Upgrade completed!'));
      }
    })
  );

workspaceMigrationCommand
  .command('validate')
  .description('Validate workspace definition')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Validating workspace...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceMigration({ ...options, validate: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('Validation completed!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceMigrationCommand
  .command('history')
  .description('Show migration history')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading migration history...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceMigration({ ...options, history: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.json) {
        spinner.succeed(chalk.green('History loaded!'));
      } else {
        spinner.stop();
      }
    })
  );

workspaceMigrationCommand
  .command('rollback')
  .description('Rollback last migration using backup')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--force', 'Force rollback without confirmation')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Rolling back migration...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceMigration({ ...options, rollback: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green('Rollback completed!'));
    })
  );

workspaceMigrationCommand
  .command('interactive')
  .description('Interactive migration management')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading migration management interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceMigration({ ...options, interactive: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

// Workspace conflict commands
const workspaceConflictCommand = program.command('workspace-conflict').description('Detect and resolve workspace conflicts');

workspaceConflictCommand
  .command('detect')
  .description('Detect conflicts in workspace definition')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--include-warnings', 'Include warning-level conflicts')
  .option('--check-dependencies', 'Check dependency conflicts')
  .option('--check-ports', 'Check port collisions')
  .option('--check-paths', 'Check path collisions')
  .option('--check-types', 'Check type mismatches')
  .option('--group-by <type>', 'Group results by type|severity|workspace')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Detecting workspace conflicts...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConflict({ ...options, detect: true, spinner });
      }, 30000); // 30 second timeout

      spinner.succeed(chalk.green('Conflict detection completed!'));
    })
  );

workspaceConflictCommand
  .command('resolve')
  .description('Resolve a specific conflict')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--conflict-id <id>', 'Conflict ID to resolve')
  .option('--resolution-id <id>', 'Resolution ID to apply')
  .option('--force', 'Apply resolution without confirmation')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Resolving workspace conflict...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConflict({ ...options, resolve: true, spinner });
      }, 60000); // 60 second timeout

      spinner.succeed(chalk.green('Conflict resolved!'));
    })
  );

workspaceConflictCommand
  .command('preview')
  .description('Preview resolution changes')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--conflict-id <id>', 'Conflict ID to preview')
  .option('--resolution-id <id>', 'Resolution ID to preview')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Previewing resolution...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConflict({ ...options, preview: true, spinner });
      }, 30000); // 30 second timeout

      spinner.stop();
    })
  );

workspaceConflictCommand
  .command('auto-resolve')
  .description('Automatically resolve all low-risk conflicts')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Auto-resolving conflicts...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConflict({ ...options, autoResolve: true, spinner });
      }, 120000); // 2 minute timeout

      spinner.succeed(chalk.green('Auto-resolution completed!'));
    })
  );

workspaceConflictCommand
  .command('interactive')
  .description('Interactive conflict management')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading conflict management interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageWorkspaceConflict({ ...options, interactive: true, spinner });
      }, 300000); // 5 minute timeout

      spinner.stop();
    })
  );

// File watcher commands
const fileWatcherCommand = program.command('file-watcher').description('Manage real-time file watching and change propagation');

fileWatcherCommand
  .command('start')
  .description('Start file watcher for workspace')
  .option('--workspace-file <file>', 'Workspace definition file', 're-shell.workspaces.yaml')
  .option('--use-polling', 'Use polling instead of native events')
  .option('--interval <ms>', 'Polling interval in milliseconds', '1000')
  .option('--depth <number>', 'Maximum watch depth')
  .option('--ignored <patterns...>', 'Patterns to ignore')
  .option('--follow', 'Follow changes in real-time')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Starting file watcher...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageFileWatcher({ ...options, start: true, spinner });
      }, 30000); // 30 second timeout

      if (!options.follow) {
        spinner.succeed(chalk.green('File watcher started!'));
      }
    })
  );

fileWatcherCommand
  .command('stop')
  .description('Stop active file watcher')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed statistics')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Stopping file watcher...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageFileWatcher({ ...options, stop: true, spinner });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green('File watcher stopped!'));
    })
  );

fileWatcherCommand
  .command('status')
  .description('Show file watcher status')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Checking watcher status...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageFileWatcher({ ...options, status: true, spinner });
      }, 10000); // 10 second timeout

      spinner.stop();
    })
  );

fileWatcherCommand
  .command('stats')
  .description('Show file watcher statistics')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Gathering statistics...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageFileWatcher({ ...options, stats: true, spinner });
      }, 10000); // 10 second timeout

      spinner.stop();
    })
  );

fileWatcherCommand
  .command('rules')
  .description('Show change propagation rules')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading propagation rules...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageFileWatcher({ ...options, rules: true, spinner });
      }, 10000); // 10 second timeout

      spinner.stop();
    })
  );

fileWatcherCommand
  .command('add-rule')
  .description('Add change propagation rule')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Adding propagation rule...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageFileWatcher({ ...options, addRule: true, spinner });
      }, 60000); // 60 second timeout

      spinner.stop();
    })
  );

fileWatcherCommand
  .command('remove-rule')
  .description('Remove change propagation rule')
  .option('--rule-id <id>', 'Rule ID to remove')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Removing propagation rule...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageFileWatcher({ ...options, removeRule: options.ruleId, spinner });
      }, 10000); // 10 second timeout

      spinner.succeed(chalk.green('Rule removed!'));
    })
  );

fileWatcherCommand
  .command('interactive')
  .description('Interactive file watcher management')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading file watcher interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageFileWatcher({ ...options, interactive: true, spinner });
      }, 300000); // 5 minute timeout

      spinner.stop();
    })
  );

// Change detector commands
const changeDetectorCommand = program.command('change-detector').description('Intelligent change detection with content hashing');

changeDetectorCommand
  .command('scan')
  .description('Scan for changes in workspace')
  .option('--path <directory>', 'Directory to scan', process.cwd())
  .option('--use-hashing', 'Use content hashing for detection', true)
  .option('--metadata-only', 'Use metadata-only detection')
  .option('--track-moves', 'Track file moves', true)
  .option('--max-depth <number>', 'Maximum scan depth', '10')
  .option('--max-file-size <bytes>', 'Maximum file size for hashing')
  .option('--algorithm <name>', 'Hashing algorithm', 'sha256')
  .option('--skip-binary', 'Skip binary files')
  .option('--chunk-size <bytes>', 'Chunk size for hashing')
  .option('--enable-cache', 'Enable cache', true)
  .option('--cache-location <path>', 'Cache file location')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Scanning for changes...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeDetector({ ...options, scan: true, spinner });
      }, 60000); // 60 second timeout

      spinner.succeed(chalk.green('Change scan completed!'));
    })
  );

changeDetectorCommand
  .command('status')
  .description('Show change detector status')
  .option('--path <directory>', 'Directory to check', process.cwd())
  .option('--enable-cache', 'Enable cache', true)
  .option('--cache-location <path>', 'Cache file location')
  .option('--json', 'Output as JSON')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Checking detector status...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeDetector({ ...options, status: true, spinner });
      }, 15000); // 15 second timeout

      spinner.stop();
    })
  );

changeDetectorCommand
  .command('stats')
  .description('Show change detection statistics')
  .option('--path <directory>', 'Directory to analyze', process.cwd())
  .option('--enable-cache', 'Enable cache', true)
  .option('--cache-location <path>', 'Cache file location')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Gathering statistics...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeDetector({ ...options, stats: true, spinner });
      }, 30000); // 30 second timeout

      spinner.stop();
    })
  );

changeDetectorCommand
  .command('check')
  .description('Check if specific file has changed')
  .option('--path <directory>', 'Root directory', process.cwd())
  .option('--file <path>', 'File path to check')
  .option('--use-hashing', 'Use content hashing', true)
  .option('--enable-cache', 'Enable cache', true)
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Checking file changes...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeDetector({ ...options, check: options.file, spinner });
      }, 15000); // 15 second timeout

      spinner.stop();
    })
  );

changeDetectorCommand
  .command('clear')
  .description('Clear change detection cache')
  .option('--path <directory>', 'Root directory', process.cwd())
  .option('--cache-location <path>', 'Cache file location')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Clearing cache...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeDetector({ ...options, clear: true, spinner });
      }, 10000); // 10 second timeout

      spinner.succeed(chalk.green('Cache cleared!'));
    })
  );

changeDetectorCommand
  .command('watch')
  .description('Watch for changes continuously')
  .option('--path <directory>', 'Directory to watch', process.cwd())
  .option('--use-hashing', 'Use content hashing', true)
  .option('--track-moves', 'Track file moves', true)
  .option('--enable-cache', 'Enable cache', true)
  .option('--verbose', 'Show verbose output')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Starting change monitoring...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeDetector({ ...options, watch: true, spinner });
      }, Infinity); // No timeout for watch mode

      spinner.stop();
    })
  );

changeDetectorCommand
  .command('compare')
  .description('Compare changes over time')
  .option('--path <directory>', 'Directory to compare', process.cwd())
  .option('--use-hashing', 'Use content hashing', true)
  .option('--track-moves', 'Track file moves', true)
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Comparing changes...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeDetector({ ...options, compare: true, spinner });
      }, 30000); // 30 second timeout

      spinner.stop();
    })
  );

changeDetectorCommand
  .command('interactive')
  .description('Interactive change detection management')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Loading change detection interface...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeDetector({ ...options, interactive: true, spinner });
      }, 300000); // 5 minute timeout

      spinner.stop();
    })
  );

// Change Impact Analysis command
const changeImpactCommand = program
  .command('change-impact')
  .alias('impact')
  .description('Analyze change impact across workspace dependencies');

changeImpactCommand
  .command('analyze')
  .description('Analyze impact of file changes')
  .option('--files <files...>', 'Specific files to analyze')
  .option('--output <file>', 'Output file path')
  .option('--format <format>', 'Output format (text|json|mermaid)', 'text')
  .option('--verbose', 'Show detailed information')
  .option('--max-depth <depth>', 'Maximum dependency depth', '10')
  .option('--include-tests', 'Include test dependencies')
  .option('--include-dev-deps', 'Include dev dependencies')
  .option('--visualization', 'Generate visualization data')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Analyzing change impact...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageChangeImpact({
          ...options,
          maxDepth: parseInt(options.maxDepth)
        });
      }, 120000); // 2 minute timeout

      spinner.stop();
    })
  );

changeImpactCommand
  .command('workspace <name>')
  .description('Analyze impact for specific workspace')
  .option('--verbose', 'Show detailed information')
  .option('--output <file>', 'Output file path')
  .option('--format <format>', 'Output format (text|json)', 'text')
  .action(
    createAsyncCommand(async (name, options) => {
      const spinner = createSpinner('Analyzing workspace impact...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await analyzeWorkspaceImpact(name, options);
      }, 60000); // 1 minute timeout

      spinner.stop();
    })
  );

changeImpactCommand
  .command('graph')
  .description('Show workspace dependency graph')
  .option('--output <file>', 'Output file path')
  .option('--format <format>', 'Output format (text|json|mermaid)', 'text')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Building dependency graph...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await showDependencyGraph(options);
      }, 60000); // 1 minute timeout

      spinner.stop();
    })
  );

// Incremental Build command
const incrementalBuildCommand = program
  .command('incremental-build')
  .alias('ibuild')
  .description('Intelligent incremental building with change detection');

incrementalBuildCommand
  .command('build')
  .description('Run incremental build')
  .option('--targets <targets...>', 'Specific targets to build')
  .option('--changed-files <files...>', 'Specific changed files to analyze')
  .option('--max-parallel <num>', 'Maximum parallel builds', '4')
  .option('--no-cache', 'Disable build caching')
  .option('--cache-location <path>', 'Build cache location')
  .option('--clean', 'Clean build (ignore cache)')
  .option('--dry-run', 'Show what would be built without building')
  .option('--verbose', 'Show detailed information')
  .option('--skip-tests', 'Skip test execution')
  .option('--no-fail-fast', 'Continue building after failures')
  .option('--build-timeout <ms>', 'Build timeout in milliseconds', '300000')
  .option('--output <file>', 'Output file path')
  .option('--format <format>', 'Output format (text|json)', 'text')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Running incremental build...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageIncrementalBuild({
          ...options,
          maxParallelBuilds: parseInt(options.maxParallel),
          buildTimeout: parseInt(options.buildTimeout),
          enableCache: options.cache !== false,
          cleanBuild: options.clean,
          dryRun: options.dryRun,
          failFast: options.failFast !== false
        });
      }, 600000); // 10 minute timeout

      spinner.stop();
    })
  );

incrementalBuildCommand
  .command('plan')
  .description('Show build plan without executing')
  .option('--changed-files <files...>', 'Specific changed files to analyze')
  .option('--verbose', 'Show detailed information')
  .option('--output <file>', 'Output file path')
  .option('--format <format>', 'Output format (text|json)', 'text')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Creating build plan...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageIncrementalBuild({
          ...options,
          plan: true
        });
      }, 60000); // 1 minute timeout

      spinner.stop();
    })
  );

incrementalBuildCommand
  .command('stats')
  .description('Show build statistics and performance metrics')
  .option('--output <file>', 'Output file path')
  .option('--format <format>', 'Output format (text|json)', 'text')
  .action(
    createAsyncCommand(async (options) => {
      const spinner = createSpinner('Gathering build statistics...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageIncrementalBuild({
          ...options,
          stats: true
        });
      }, 30000); // 30 second timeout

      spinner.stop();
    })
  );

incrementalBuildCommand
  .command('clear-cache')
  .description('Clear build cache')
  .action(
    createAsyncCommand(async () => {
      const spinner = createSpinner('Clearing build cache...').start();
      processManager.addCleanup(() => spinner.stop());
      flushOutput();

      await withTimeout(async () => {
        await manageIncrementalBuild({
          clearCache: true
        });
      }, 15000); // 15 second timeout

      spinner.succeed(chalk.green('Build cache cleared!'));
    })
  );

// Platform Test command
const platformTestCommand = program
  .command('platform-test')
  .alias('ptest')
  .description('Test cross-platform file watching capabilities');

platformTestCommand
  .command('capabilities')
  .description('Show platform file watching capabilities')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await testPlatformCapabilities({ capabilities: true, ...options });
    })
  );

platformTestCommand
  .command('test')
  .description('Test file watching methods')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await testPlatformCapabilities({ test: true, ...options });
    })
  );

platformTestCommand
  .command('diagnostics')
  .description('Run comprehensive platform diagnostics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await runPlatformDiagnostics(options);
    })
  );

platformTestCommand
  .command('all')
  .description('Run all platform tests and diagnostics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await testPlatformCapabilities({ all: true, ...options });
    })
  );

// Add standalone platform-test command (without subcommand)
program
  .command('platform-test-quick')
  .alias('pcheck')
  .description('Quick platform file watching check')
  .action(
    createAsyncCommand(async () => {
      const healthy = await quickPlatformCheck();
      if (!healthy) {
        process.exit(1);
      }
    })
  );

// Plugin Management command
const pluginCommand = program
  .command('plugin')
  .description('Manage CLI plugins and extensions');

pluginCommand
  .command('list')
  .description('List installed plugins')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await managePlugins(options);
    })
  );

pluginCommand
  .command('discover')
  .description('Discover available plugins')
  .option('--source <source>', 'Plugin source (local, npm, builtin)')
  .option('--include-disabled', 'Include disabled plugins')
  .option('--include-dev', 'Include development plugins')
  .option('--timeout <ms>', 'Discovery timeout in milliseconds', '10000')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await discoverPlugins(options);
    })
  );

pluginCommand
  .command('install <plugin>')
  .description('Install a plugin')
  .option('--global', 'Install globally')
  .option('--force', 'Force installation')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await installPlugin(plugin, options);
    })
  );

pluginCommand
  .command('uninstall <plugin>')
  .description('Uninstall a plugin')
  .option('--force', 'Force uninstallation')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await uninstallPlugin(plugin, options);
    })
  );

pluginCommand
  .command('info <plugin>')
  .description('Show plugin information')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await showPluginInfo(plugin, options);
    })
  );

pluginCommand
  .command('enable <plugin>')
  .description('Enable a plugin')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await enablePlugin(plugin, options);
    })
  );

pluginCommand
  .command('disable <plugin>')
  .description('Disable a plugin')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await disablePlugin(plugin, options);
    })
  );

pluginCommand
  .command('update')
  .description('Update all plugins')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      await updatePlugins(options);
    })
  );

pluginCommand
  .command('validate <path>')
  .description('Validate a plugin')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (path, options) => {
      await validatePlugin(path, options);
    })
  );

pluginCommand
  .command('clear-cache')
  .description('Clear plugin discovery cache')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      await clearPluginCache(options);
    })
  );

pluginCommand
  .command('stats')
  .description('Show plugin lifecycle statistics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showPluginStats(options);
    })
  );

pluginCommand
  .command('reload <plugin>')
  .description('Reload a plugin')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await reloadPlugin(plugin, options);
    })
  );

pluginCommand
  .command('hooks [plugin]')
  .description('Show plugin hooks')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await showPluginHooks(plugin, options);
    })
  );

pluginCommand
  .command('execute-hook <hook-type> [data]')
  .description('Execute a hook manually')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (hookType, data, options) => {
      await executeHook(hookType, data, options);
    })
  );

pluginCommand
  .command('hook-types')
  .description('List available hook types')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await listHookTypes(options);
    })
  );

pluginCommand
  .command('resolve <plugin>')
  .description('Resolve plugin dependencies')
  .option('--strategy <strategy>', 'Resolution strategy (strict, loose, latest)', 'strict')
  .option('--allow-prerelease', 'Allow prerelease versions')
  .option('--ignore-optional', 'Ignore optional dependencies')
  .option('--auto-install', 'Automatically install missing dependencies')
  .option('--dry-run', 'Show what would be installed without installing')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await resolveDependencies(plugin, options);
    })
  );

pluginCommand
  .command('deps [plugin]')
  .description('Show dependency tree')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await showDependencyTree(plugin, options);
    })
  );

pluginCommand
  .command('conflicts')
  .description('Check for dependency conflicts')
  .option('--strategy <strategy>', 'Resolution strategy (strict, loose, latest)', 'strict')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await checkConflicts(options);
    })
  );

pluginCommand
  .command('validate-versions')
  .description('Validate plugin versions')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await validateVersions(options);
    })
  );

pluginCommand
  .command('update-deps <plugin>')
  .description('Update plugin dependencies')
  .option('--dry-run', 'Show what would be updated without updating')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await updateDependencies(plugin, options);
    })
  );

pluginCommand
  .command('security-scan [plugin]')
  .description('Scan plugins for security issues')
  .option('--severity <level>', 'Filter by severity (low, medium, high, critical)')
  .option('--include-warnings', 'Include security warnings')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await scanPluginSecurity(plugin, options);
    })
  );

pluginCommand
  .command('security-policy')
  .description('Check security policy compliance')
  .option('--policy <file>', 'Custom security policy file')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await checkSecurityPolicy(options);
    })
  );

pluginCommand
  .command('security-report')
  .description('Generate comprehensive security report')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await generateSecurityReport(options);
    })
  );

pluginCommand
  .command('security-fix [plugin]')
  .description('Analyze and fix security issues')
  .option('--fix', 'Apply automatic fixes')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await fixSecurityIssues(plugin, options);
    })
  );

// Plugin marketplace commands
pluginCommand
  .command('search [query]')
  .description('Search plugins in marketplace')
  .option('--category <category>', 'Filter by category')
  .option('--featured', 'Show only featured plugins')
  .option('--verified', 'Show only verified plugins')
  .option('--free', 'Show only free plugins')
  .option('--sort <field>', 'Sort by field (relevance, downloads, rating, updated, created, name)', 'relevance')
  .option('--order <order>', 'Sort order (asc, desc)', 'desc')
  .option('--limit <number>', 'Number of results to show', '10')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (query, options) => {
      await searchMarketplace(query, options);
    })
  );

pluginCommand
  .command('show <plugin>')
  .description('Show detailed plugin information from marketplace')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await showPluginDetails(plugin, options);
    })
  );

pluginCommand
  .command('install-marketplace <plugin> [version]')
  .description('Install plugin from marketplace')
  .option('--global', 'Install globally')
  .option('--force', 'Force installation')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, version, options) => {
      await installMarketplacePlugin(plugin, version, options);
    })
  );

pluginCommand
  .command('reviews <plugin>')
  .description('Show plugin reviews from marketplace')
  .option('--limit <number>', 'Number of reviews to show', '10')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (plugin, options) => {
      await showPluginReviews(plugin, options);
    })
  );

pluginCommand
  .command('featured')
  .description('Show featured plugins from marketplace')
  .option('--limit <number>', 'Number of plugins to show', '6')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showFeaturedPlugins(options);
    })
  );

pluginCommand
  .command('popular [category]')
  .description('Show popular plugins from marketplace')
  .option('--limit <number>', 'Number of plugins to show', '10')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (category, options) => {
      await showPopularPlugins(category, options);
    })
  );

pluginCommand
  .command('categories')
  .description('Show available plugin categories')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showCategories(options);
    })
  );

pluginCommand
  .command('clear-cache')
  .description('Clear marketplace cache')
  .action(
    createAsyncCommand(async () => {
      await clearMarketplaceCache();
    })
  );

pluginCommand
  .command('marketplace-stats')
  .description('Show marketplace statistics')
  .action(
    createAsyncCommand(async () => {
      await showMarketplaceStats();
    })
  );

// Plugin command registration commands
pluginCommand
  .command('commands')
  .description('List registered plugin commands')
  .option('--plugin <name>', 'Filter by plugin name')
  .option('--category <category>', 'Filter by command category')
  .option('--active', 'Show only active commands')
  .option('--conflicts', 'Show only commands with conflicts')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await listPluginCommands(options);
    })
  );

pluginCommand
  .command('command-conflicts')
  .description('Show command registration conflicts')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showCommandConflicts(options);
    })
  );

pluginCommand
  .command('resolve-conflicts <command> <resolution>')
  .description('Resolve command conflicts (resolution: disable, priority)')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (commandName, resolution, options) => {
      await resolveCommandConflicts(commandName, resolution, options);
    })
  );

pluginCommand
  .command('command-stats')
  .description('Show command registry statistics')
  .option('--usage', 'Include usage statistics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showCommandStats(options);
    })
  );

pluginCommand
  .command('register-command <plugin> <definition>')
  .description('Register a test command from plugin (JSON definition)')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (plugin, definition, options) => {
      await registerTestCommand(plugin, definition, options);
    })
  );

pluginCommand
  .command('unregister-command <commandId>')
  .description('Unregister a plugin command')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (commandId, options) => {
      await unregisterCommand(commandId, options);
    })
  );

pluginCommand
  .command('command-info <commandId>')
  .description('Show detailed information about a command')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (commandId, options) => {
      await showCommandInfo(commandId, options);
    })
  );

// Plugin middleware commands
pluginCommand
  .command('middleware')
  .description('List registered command middleware')
  .option('--type <type>', 'Filter by middleware type')
  .option('--plugin <name>', 'Filter by plugin name')
  .option('--active', 'Show only active middleware')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await listMiddleware(options);
    })
  );

pluginCommand
  .command('middleware-stats')
  .description('Show middleware system statistics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showMiddlewareStats(options);
    })
  );

pluginCommand
  .command('test-middleware <type> <testData>')
  .description('Test middleware execution with sample data (JSON)')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (type, testData, options) => {
      await testMiddleware(type, testData, options);
    })
  );

pluginCommand
  .command('clear-middleware-cache')
  .description('Clear middleware cache')
  .action(
    createAsyncCommand(async () => {
      await clearMiddlewareCache();
    })
  );

pluginCommand
  .command('middleware-chain <command>')
  .description('Show middleware execution chain for a command')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (commandName, options) => {
      await showMiddlewareChain(commandName, options);
    })
  );

pluginCommand
  .command('middleware-example <type>')
  .description('Show example middleware code (types: validation, authorization, rateLimit, cache, logger, transform, custom)')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (type, options) => {
      await createExampleMiddleware(type, options);
    })
  );

// Plugin conflict resolution commands
pluginCommand
  .command('command-conflicts')
  .description('List command conflicts and their resolution status')
  .option('--type <type>', 'Filter by conflict type')
  .option('--severity <severity>', 'Filter by conflict severity')
  .option('--auto-resolvable', 'Show only auto-resolvable conflicts')
  .option('--resolved', 'Show only resolved conflicts')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await listCommandConflicts(options);
    })
  );

pluginCommand
  .command('conflict-strategies')
  .description('Show available conflict resolution strategies')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showConflictStrategies(options);
    })
  );

pluginCommand
  .command('resolve-conflict <conflictId> <strategy>')
  .description('Resolve a specific conflict using given strategy')
  .option('--dry-run', 'Simulate resolution without applying changes')
  .option('--confirm', 'Skip confirmation prompts')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (conflictId, strategy, options) => {
      await resolveConflict(conflictId, strategy, options);
    })
  );

pluginCommand
  .command('auto-resolve')
  .description('Automatically resolve all auto-resolvable conflicts')
  .option('--dry-run', 'Simulate resolution without applying changes')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (options) => {
      await autoResolveConflicts(options);
    })
  );

pluginCommand
  .command('conflict-stats')
  .description('Show conflict resolution statistics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showConflictStats(options);
    })
  );

pluginCommand
  .command('set-priority <commandId> <priority>')
  .description('Set priority override for a command')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (commandId, priority, options) => {
      await setPriorityOverride(commandId, priority, options);
    })
  );

pluginCommand
  .command('resolution-history')
  .description('Show conflict resolution history')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showResolutionHistory(options);
    })
  );

// Plugin documentation commands
pluginCommand
  .command('generate-docs [commands...]')
  .description('Generate documentation for plugin commands')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .option('--format <format>', 'Documentation format (markdown, html, json, plain-text, man-page)', 'markdown')
  .option('--output <dir>', 'Output directory for generated files')
  .option('--template <template>', 'Documentation template to use', 'markdown')
  .option('--include-private', 'Include private/hidden commands')
  .option('--include-deprecated', 'Include deprecated commands')
  .option('--no-examples', 'Exclude examples from documentation')
  .option('--no-index', 'Skip generating documentation index')
  .action(
    createAsyncCommand(async (commands, options) => {
      await generatePluginDocumentation(commands, options);
    })
  );

pluginCommand
  .command('help <command>')
  .description('Show detailed help for a specific command')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .option('--mode <mode>', 'Help display mode (compact, detailed, interactive, hierarchical)', 'detailed')
  .action(
    createAsyncCommand(async (command, options) => {
      await showCommandHelp(command, options);
    })
  );

pluginCommand
  .command('list-docs')
  .description('List all documented commands')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .option('--plugin <plugin>', 'Filter by plugin name')
  .option('--category <category>', 'Filter by command category')
  .option('--complexity <complexity>', 'Filter by complexity (basic, intermediate, advanced)')
  .action(
    createAsyncCommand(async (options) => {
      await listDocumentedCommands(options);
    })
  );

pluginCommand
  .command('search-docs <query>')
  .description('Search documentation for commands and topics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .option('--plugin <plugin>', 'Filter by plugin name')
  .option('--category <category>', 'Filter by command category')
  .option('--complexity <complexity>', 'Filter by complexity level')
  .action(
    createAsyncCommand(async (query, options) => {
      await searchDocumentation(query, options);
    })
  );

pluginCommand
  .command('docs-stats')
  .description('Show documentation coverage and statistics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showDocumentationStats(options);
    })
  );

pluginCommand
  .command('configure-help <setting> <value>')
  .description('Configure help system behavior')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (setting, value, options) => {
      await configureHelpSystem(setting, value, options);
    })
  );

pluginCommand
  .command('docs-templates')
  .description('Show available documentation templates')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showDocumentationTemplates(options);
    })
  );

// Plugin validation commands
pluginCommand
  .command('test-validation <command> <testData>')
  .description('Test command validation with sample data (JSON format)')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .option('--dry-run', 'Simulate validation without applying changes')
  .option('--strict', 'Enable strict validation mode')
  .action(
    createAsyncCommand(async (command, testData, options) => {
      await testCommandValidation(command, testData, options);
    })
  );

pluginCommand
  .command('create-schema <command> <schemaDefinition>')
  .description('Create validation schema for a command (JSON format)')
  .option('--verbose', 'Show detailed information')
  .option('--dry-run', 'Show what would be created without applying')
  .action(
    createAsyncCommand(async (command, schemaDefinition, options) => {
      await createCommandValidationSchema(command, schemaDefinition, options);
    })
  );

pluginCommand
  .command('validation-rules')
  .description('List available validation rules')
  .option('--verbose', 'Show detailed information and examples')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await listValidationRules(options);
    })
  );

pluginCommand
  .command('transformations')
  .description('List available parameter transformations')
  .option('--verbose', 'Show detailed information and examples')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await listTransformations(options);
    })
  );

pluginCommand
  .command('show-schema <command>')
  .description('Show validation schema for a command')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (command, options) => {
      await showCommandValidationSchema(command, options);
    })
  );

pluginCommand
  .command('validation-stats')
  .description('Show validation system statistics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showValidationStats(options);
    })
  );

pluginCommand
  .command('generate-template <command>')
  .description('Generate validation schema template for a command')
  .option('--verbose', 'Show detailed information and usage examples')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (command, options) => {
      await generateValidationTemplate(command, options);
    })
  );

// Plugin cache commands
pluginCommand
  .command('cache-stats')
  .description('Show command cache statistics and performance metrics')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (options) => {
      await showCacheStats(options);
    })
  );

pluginCommand
  .command('configure-cache <setting> <value>')
  .description('Configure cache system settings')
  .option('--verbose', 'Show detailed information')
  .action(
    createAsyncCommand(async (setting, value, options) => {
      await configureCacheSettings(setting, value, options);
    })
  );

pluginCommand
  .command('clear-cache')
  .description('Clear command cache')
  .option('--verbose', 'Show detailed information')
  .option('--command <command>', 'Clear cache for specific command')
  .option('--tags <tags>', 'Clear cache for specific tags (comma-separated)')
  .option('--force', 'Confirm cache clearing operation')
  .action(
    createAsyncCommand(async (options) => {
      await clearCache(options);
    })
  );

pluginCommand
  .command('test-cache <iterations>')
  .description('Test cache performance with specified number of iterations')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .action(
    createAsyncCommand(async (iterations, options) => {
      await testCachePerformance(iterations, options);
    })
  );

pluginCommand
  .command('optimize-cache')
  .description('Analyze and optimize cache configuration')
  .option('--verbose', 'Show detailed information')
  .option('--force', 'Apply optimizations automatically')
  .action(
    createAsyncCommand(async (options) => {
      await optimizeCache(options);
    })
  );

pluginCommand
  .command('list-cached')
  .description('List cached command results')
  .option('--verbose', 'Show detailed information')
  .option('--json', 'Output as JSON')
  .option('--include-errors', 'Include failed command results')
  .action(
    createAsyncCommand(async (options) => {
      await listCachedCommands(options);
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
