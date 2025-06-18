import chalk from 'chalk';
import prompts from 'prompts';
import { configWatcher, setupConfigHotReload, startDevMode, HotReloadOptions } from '../utils/config-watcher';
import { ProgressSpinner } from '../utils/spinner';
import { ValidationError } from '../utils/error-handler';

export interface DevModeCommandOptions {
  start?: boolean;
  stop?: boolean;
  status?: boolean;
  restart?: boolean;
  interactive?: boolean;
  verbose?: boolean;
  debounce?: number;
  noValidation?: boolean;
  noBackup?: boolean;
  noRestore?: boolean;
  excludeWorkspaces?: boolean;
  json?: boolean;
  spinner?: ProgressSpinner;
}

export async function manageDevMode(options: DevModeCommandOptions = {}): Promise<void> {
  const { spinner, verbose, json } = options;

  try {
    if (options.start) {
      await startDevelopmentMode(options, spinner);
      return;
    }

    if (options.stop) {
      await stopDevelopmentMode(options, spinner);
      return;
    }

    if (options.restart) {
      await restartDevelopmentMode(options, spinner);
      return;
    }

    if (options.status) {
      await showDevModeStatus(options, spinner);
      return;
    }

    if (options.interactive) {
      await interactiveDevMode(options, spinner);
      return;
    }

    // Default: show status if already running, otherwise show help
    if (configWatcher.isActive()) {
      await showDevModeStatus(options, spinner);
    } else {
      await showDevModeHelp();
    }

  } catch (error) {
    if (spinner) spinner.fail(chalk.red('Development mode operation failed'));
    throw error;
  }
}

async function startDevelopmentMode(options: DevModeCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (configWatcher.isActive()) {
    if (spinner) spinner.warn(chalk.yellow('Development mode is already running'));
    console.log(chalk.yellow('⚠️  Development mode is already active'));
    return;
  }

  if (spinner) spinner.setText('Starting development mode with hot-reloading...');

  const hotReloadOptions: HotReloadOptions = {
    enabled: true,
    verbose: options.verbose || false,
    debounceMs: options.debounce || 500,
    validateOnChange: !options.noValidation,
    autoBackup: !options.noBackup,
    restoreOnError: !options.noRestore,
    includeWorkspaces: !options.excludeWorkspaces
  };

  try {
    await setupConfigHotReload(hotReloadOptions);

    if (spinner) {
      spinner.succeed(chalk.green('Development mode started with hot-reloading'));
    }

    console.log(chalk.green('🚀 Development mode active'));
    console.log(chalk.cyan('   Configuration files are now being watched for changes'));
    
    if (hotReloadOptions.verbose) {
      console.log(chalk.gray('   Use --verbose for detailed change notifications'));
    }

    console.log(chalk.gray('   Run `re-shell dev stop` to disable hot-reloading\n'));

    // Setup event listeners for development feedback
    setupDevModeListeners(hotReloadOptions.verbose || false);

  } catch (error) {
    if (spinner) spinner.fail(chalk.red('Failed to start development mode'));
    throw error;
  }
}

async function stopDevelopmentMode(options: DevModeCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (!configWatcher.isActive()) {
    if (spinner) spinner.warn(chalk.yellow('Development mode is not running'));
    console.log(chalk.yellow('⚠️  Development mode is not active'));
    return;
  }

  if (spinner) spinner.setText('Stopping development mode...');

  try {
    await configWatcher.stopWatching();

    if (spinner) {
      spinner.succeed(chalk.green('Development mode stopped'));
    }

    console.log(chalk.green('🛑 Development mode deactivated'));
    console.log(chalk.gray('   Configuration hot-reloading has been disabled\n'));

  } catch (error) {
    if (spinner) spinner.fail(chalk.red('Failed to stop development mode'));
    throw error;
  }
}

async function restartDevelopmentMode(options: DevModeCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText('Restarting development mode...');

  try {
    if (configWatcher.isActive()) {
      await configWatcher.stopWatching();
    }

    // Brief pause to ensure cleanup
    await new Promise(resolve => setTimeout(resolve, 100));

    await startDevelopmentMode(options, spinner);

    if (spinner) {
      spinner.succeed(chalk.green('Development mode restarted'));
    }

  } catch (error) {
    if (spinner) spinner.fail(chalk.red('Failed to restart development mode'));
    throw error;
  }
}

async function showDevModeStatus(options: DevModeCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText('Checking development mode status...');

  const status = configWatcher.getStatus();

  if (spinner) spinner.stop();

  if (options.json) {
    console.log(JSON.stringify(status, null, 2));
    return;
  }

  console.log(chalk.cyan('\\n🔧 Development Mode Status'));
  console.log(chalk.gray('═'.repeat(40)));

  if (status.isWatching) {
    console.log(`\\n✅ ${chalk.green('Active')} - Configuration hot-reloading enabled`);
    
    if (status.watchedPaths.length > 0) {
      console.log(`\\n📁 Watched paths (${status.watchedPaths.length}):`);
      for (const path of status.watchedPaths) {
        console.log(`  • ${chalk.gray(path)}`);
      }
    }

    console.log(`\\n⚙️  Options:`);
    console.log(`   Debounce: ${status.options.debounceMs}ms`);
    console.log(`   Validation: ${status.options.validateOnChange ? '✅' : '❌'}`);
    console.log(`   Auto backup: ${status.options.autoBackup ? '✅' : '❌'}`);
    console.log(`   Error restore: ${status.options.restoreOnError ? '✅' : '❌'}`);
    console.log(`   Include workspaces: ${status.options.includeWorkspaces ? '✅' : '❌'}`);
    console.log(`   Verbose logging: ${status.options.verbose ? '✅' : '❌'}`);
  } else {
    console.log(`\\n❌ ${chalk.red('Inactive')} - Configuration hot-reloading disabled`);
    console.log(chalk.gray('   Run `re-shell dev start` to enable hot-reloading'));
  }

  console.log(chalk.cyan('\\n🛠️  Available Commands:'));
  console.log('  • re-shell dev start [options]');
  console.log('  • re-shell dev stop');
  console.log('  • re-shell dev restart [options]');
  console.log('  • re-shell dev interactive');
}

async function showDevModeHelp(): Promise<void> {
  console.log(chalk.cyan('\\n🔧 Development Mode - Configuration Hot-Reloading'));
  console.log(chalk.gray('═'.repeat(60)));

  console.log('\\nDevelopment mode enables automatic reloading of configuration files');
  console.log('when they change, providing instant feedback during development.');

  console.log(chalk.cyan('\\n🚀 Quick Start:'));
  console.log('  re-shell dev start              # Start with default settings');
  console.log('  re-shell dev start --verbose    # Start with detailed logging');
  console.log('  re-shell dev interactive        # Interactive setup');

  console.log(chalk.cyan('\\n📋 Features:'));
  console.log('  • Real-time configuration file watching');
  console.log('  • Automatic validation on changes');
  console.log('  • Error recovery with backup/restore');
  console.log('  • Debounced change detection');
  console.log('  • Support for global, project, and workspace configs');

  console.log(chalk.cyan('\\n⚙️  Options:'));
  console.log('  --verbose               Enable detailed change notifications');
  console.log('  --debounce <ms>        Change detection delay (default: 500ms)');
  console.log('  --no-validation        Skip configuration validation');
  console.log('  --no-backup            Disable automatic backups');
  console.log('  --no-restore           Disable error recovery');
  console.log('  --exclude-workspaces   Skip workspace configuration watching');
}

async function interactiveDevMode(options: DevModeCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.stop();

  const currentStatus = configWatcher.getStatus();

  const response = await prompts([
    {
      type: 'select',
      name: 'action',
      message: 'What would you like to do?',
      choices: [
        { 
          title: currentStatus.isWatching ? '🛑 Stop development mode' : '🚀 Start development mode', 
          value: currentStatus.isWatching ? 'stop' : 'start' 
        },
        { title: '🔄 Restart development mode', value: 'restart' },
        { title: '⚙️  Configure hot-reload options', value: 'configure' },
        { title: '📊 Show current status', value: 'status' },
        { title: '🔄 Force reload configurations', value: 'force-reload' }
      ]
    }
  ]);

  if (!response.action) return;

  switch (response.action) {
    case 'start':
      await interactiveStart();
      break;
    case 'stop':
      await stopDevelopmentMode(options);
      break;
    case 'restart':
      await restartDevelopmentMode(options);
      break;
    case 'configure':
      await interactiveConfigure();
      break;
    case 'status':
      await showDevModeStatus(options);
      break;
    case 'force-reload':
      await forceReloadConfigs();
      break;
  }
}

async function interactiveStart(): Promise<void> {
  const response = await prompts([
    {
      type: 'toggle',
      name: 'verbose',
      message: 'Enable verbose logging?',
      initial: false,
      active: 'yes',
      inactive: 'no'
    },
    {
      type: 'number',
      name: 'debounce',
      message: 'Debounce delay (milliseconds):',
      initial: 500,
      min: 100,
      max: 5000
    },
    {
      type: 'toggle',
      name: 'validation',
      message: 'Validate configurations on change?',
      initial: true,
      active: 'yes',
      inactive: 'no'
    },
    {
      type: 'toggle',
      name: 'autoBackup',
      message: 'Create automatic backups before changes?',
      initial: true,
      active: 'yes',
      inactive: 'no'
    },
    {
      type: 'toggle',
      name: 'restoreOnError',
      message: 'Restore from backup on validation errors?',
      initial: true,
      active: 'yes',
      inactive: 'no'
    },
    {
      type: 'toggle',
      name: 'includeWorkspaces',
      message: 'Watch workspace configurations?',
      initial: true,
      active: 'yes',
      inactive: 'no'
    }
  ]);

  const options: DevModeCommandOptions = {
    verbose: response.verbose,
    debounce: response.debounce,
    noValidation: !response.validation,
    noBackup: !response.autoBackup,
    noRestore: !response.restoreOnError,
    excludeWorkspaces: !response.includeWorkspaces
  };

  await startDevelopmentMode(options);
}

async function interactiveConfigure(): Promise<void> {
  const currentOptions = configWatcher.getStatus().options;

  const response = await prompts([
    {
      type: 'toggle',
      name: 'verbose',
      message: 'Verbose logging:',
      initial: currentOptions.verbose,
      active: 'enabled',
      inactive: 'disabled'
    },
    {
      type: 'number',
      name: 'debounceMs',
      message: 'Debounce delay (ms):',
      initial: currentOptions.debounceMs,
      min: 100,
      max: 5000
    },
    {
      type: 'toggle',
      name: 'validateOnChange',
      message: 'Validate on change:',
      initial: currentOptions.validateOnChange,
      active: 'enabled',
      inactive: 'disabled'
    },
    {
      type: 'toggle',
      name: 'autoBackup',
      message: 'Auto backup:',
      initial: currentOptions.autoBackup,
      active: 'enabled',
      inactive: 'disabled'
    },
    {
      type: 'toggle',
      name: 'restoreOnError',
      message: 'Restore on error:',
      initial: currentOptions.restoreOnError,
      active: 'enabled',
      inactive: 'disabled'
    },
    {
      type: 'toggle',
      name: 'includeWorkspaces',
      message: 'Include workspaces:',
      initial: currentOptions.includeWorkspaces,
      active: 'enabled',
      inactive: 'disabled'
    }
  ]);

  configWatcher.updateOptions(response);
  console.log(chalk.green('✅ Configuration updated'));
}

async function forceReloadConfigs(): Promise<void> {
  try {
    await configWatcher.forceReload();
    console.log(chalk.green('✅ Configurations force-reloaded'));
  } catch (error) {
    console.error(chalk.red('❌ Failed to force reload:'), error);
  }
}

function setupDevModeListeners(verbose: boolean): void {
  configWatcher.on('config-changed', (event) => {
    if (verbose) {
      console.log(chalk.green(`🔄 ${event.configType} config updated: ${event.path}`));
    }
  });

  configWatcher.on('config-error', (event) => {
    console.error(chalk.red(`❌ ${event.configType} config error: ${event.error?.message}`));
  });

  configWatcher.on('watching-started', () => {
    if (verbose) {
      console.log(chalk.green('👀 File watching started'));
    }
  });

  configWatcher.on('watching-stopped', () => {
    if (verbose) {
      console.log(chalk.gray('👁️  File watching stopped'));
    }
  });
}