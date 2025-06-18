import chalk from 'chalk';
import prompts from 'prompts';
import { migrationManager, MigrationResult } from '../utils/migration';
import { ProgressSpinner } from '../utils/spinner';
import { ValidationError } from '../utils/error-handler';

export interface MigrationCommandOptions {
  global?: boolean;
  project?: boolean;
  check?: boolean;
  auto?: boolean;
  rollback?: string;
  history?: boolean;
  interactive?: boolean;
  force?: boolean;
  json?: boolean;
  verbose?: boolean;
  spinner?: ProgressSpinner;
}

export async function manageMigration(options: MigrationCommandOptions = {}): Promise<void> {
  const { spinner, verbose, json } = options;

  try {
    if (options.auto) {
      await autoMigrate(options, spinner);
      return;
    }

    if (options.check) {
      await checkMigrationStatus(options, spinner);
      return;
    }

    if (options.history) {
      await showMigrationHistory(options, spinner);
      return;
    }

    if (options.rollback) {
      await rollbackMigration(options.rollback, options, spinner);
      return;
    }

    if (options.interactive) {
      await interactiveMigration(options, spinner);
      return;
    }

    if (options.global) {
      await migrateGlobalConfig(options, spinner);
      return;
    }

    if (options.project) {
      await migrateProjectConfig(options, spinner);
      return;
    }

    // Default: check migration status and prompt for action
    await checkAndPromptMigration(options, spinner);

  } catch (error) {
    if (spinner) spinner.fail(chalk.red('Migration operation failed'));
    throw error;
  }
}

async function autoMigrate(options: MigrationCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText('Running auto-migration...');
  
  const results = await migrationManager.autoMigrate();
  
  if (spinner) spinner.stop();

  if (options.json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    console.log(chalk.cyan('\n🔄 Auto-Migration Results'));
    console.log(chalk.gray('═'.repeat(40)));
    
    if (results.global) {
      console.log(chalk.cyan('\n🌐 Global Configuration:'));
      displayMigrationResult(results.global);
    } else {
      console.log(chalk.green('\n🌐 Global Configuration: Up to date'));
    }
    
    if (results.project) {
      console.log(chalk.cyan('\n🏗️  Project Configuration:'));
      displayMigrationResult(results.project);
    } else {
      console.log(chalk.green('\n🏗️  Project Configuration: Up to date or not found'));
    }
  }
}

async function checkMigrationStatus(options: MigrationCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText('Checking migration status...');
  
  const globalCheck = await migrationManager.checkIntegrity('global');
  const projectCheck = await migrationManager.checkIntegrity('project');
  
  if (spinner) spinner.stop();

  if (options.json) {
    console.log(JSON.stringify({ global: globalCheck, project: projectCheck }, null, 2));
  } else {
    console.log(chalk.cyan('\n🔍 Migration Status Check'));
    console.log(chalk.gray('═'.repeat(40)));
    
    console.log(chalk.cyan('\n🌐 Global Configuration:'));
    displayIntegrityCheck(globalCheck);
    
    console.log(chalk.cyan('\n🏗️  Project Configuration:'));
    displayIntegrityCheck(projectCheck);
  }
}

async function showMigrationHistory(options: MigrationCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText('Loading migration history...');
  
  const globalHistory = await migrationManager.getMigrationHistory('global');
  const projectHistory = await migrationManager.getMigrationHistory('project');
  
  if (spinner) spinner.stop();

  if (options.json) {
    console.log(JSON.stringify({ global: globalHistory, project: projectHistory }, null, 2));
  } else {
    console.log(chalk.cyan('\n📚 Migration History'));
    console.log(chalk.gray('═'.repeat(40)));
    
    console.log(chalk.cyan('\n🌐 Global Configuration:'));
    displayMigrationHistory(globalHistory);
    
    console.log(chalk.cyan('\n🏗️  Project Configuration:'));
    displayMigrationHistory(projectHistory);
  }
}

async function rollbackMigration(targetVersion: string, options: MigrationCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText(`Rolling back to version ${targetVersion}...`);
  
  const configType = options.global ? 'global' : 'project';
  const result = await migrationManager.rollback(configType, targetVersion);
  
  if (spinner) {
    if (result.success) {
      spinner.succeed(chalk.green(`Rollback to ${targetVersion} completed!`));
    } else {
      spinner.fail(chalk.red(`Rollback to ${targetVersion} failed!`));
    }
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    displayMigrationResult(result);
  }
}

async function migrateGlobalConfig(options: MigrationCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText('Migrating global configuration...');
  
  const result = await migrationManager.migrate('global');
  
  if (spinner) {
    if (result.success) {
      spinner.succeed(chalk.green('Global configuration migrated successfully!'));
    } else {
      spinner.fail(chalk.red('Global configuration migration failed!'));
    }
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    displayMigrationResult(result);
  }
}

async function migrateProjectConfig(options: MigrationCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText('Migrating project configuration...');
  
  const result = await migrationManager.migrate('project');
  
  if (spinner) {
    if (result.success) {
      spinner.succeed(chalk.green('Project configuration migrated successfully!'));
    } else {
      spinner.fail(chalk.red('Project configuration migration failed!'));
    }
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    displayMigrationResult(result);
  }
}

async function checkAndPromptMigration(options: MigrationCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.setText('Checking migration requirements...');
  
  const globalNeeds = await migrationManager.needsMigration('global');
  const projectNeeds = await migrationManager.needsMigration('project');
  
  if (spinner) spinner.stop();

  if (!globalNeeds && !projectNeeds) {
    console.log(chalk.green('\n✅ All configurations are up to date!'));
    return;
  }

  console.log(chalk.yellow('\n⚠️  Configuration migration required'));
  
  if (globalNeeds) {
    console.log(chalk.yellow('   Global configuration needs migration'));
  }
  
  if (projectNeeds) {
    console.log(chalk.yellow('   Project configuration needs migration'));
  }

  if (!options.force) {
    const response = await prompts([
      {
        type: 'confirm',
        name: 'migrate',
        message: 'Run migration now?',
        initial: true
      }
    ]);

    if (!response.migrate) {
      console.log(chalk.gray('Migration cancelled. Run with --auto to migrate automatically.'));
      return;
    }
  }

  await autoMigrate(options);
}

async function interactiveMigration(options: MigrationCommandOptions, spinner?: ProgressSpinner): Promise<void> {
  if (spinner) spinner.stop();

  const response = await prompts([
    {
      type: 'select',
      name: 'action',
      message: 'What would you like to do?',
      choices: [
        { title: '🔄 Auto-migrate all configurations', value: 'auto' },
        { title: '🔍 Check migration status', value: 'check' },
        { title: '📚 View migration history', value: 'history' },
        { title: '🌐 Migrate global configuration only', value: 'global' },
        { title: '🏗️  Migrate project configuration only', value: 'project' },
        { title: '⏪ Rollback to previous version', value: 'rollback' },
        { title: '🔧 Advanced options', value: 'advanced' }
      ]
    }
  ]);

  if (!response.action) return;

  switch (response.action) {
    case 'auto':
      await autoMigrate(options);
      break;
    case 'check':
      await checkMigrationStatus(options);
      break;
    case 'history':
      await showMigrationHistory(options);
      break;
    case 'global':
      await migrateGlobalConfig(options);
      break;
    case 'project':
      await migrateProjectConfig(options);
      break;
    case 'rollback':
      await interactiveRollback();
      break;
    case 'advanced':
      await interactiveAdvancedOptions();
      break;
  }
}

async function interactiveRollback(): Promise<void> {
  const globalHistory = await migrationManager.getMigrationHistory('global');
  const projectHistory = await migrationManager.getMigrationHistory('project');

  const response = await prompts([
    {
      type: 'select',
      name: 'configType',
      message: 'Which configuration to rollback?',
      choices: [
        { title: 'Global configuration', value: 'global' },
        { title: 'Project configuration', value: 'project' }
      ]
    },
    {
      type: 'select',
      name: 'version',
      message: 'Select target version:',
      choices: (prev) => {
        const history = prev.configType === 'global' ? globalHistory : projectHistory;
        return history.appliedMigrations.map(version => ({
          title: version,
          value: version
        }));
      }
    },
    {
      type: 'confirm',
      name: 'confirm',
      message: 'Are you sure you want to rollback? This action cannot be easily undone.',
      initial: false
    }
  ]);

  if (response.confirm) {
    const result = await migrationManager.rollback(response.configType, response.version);
    displayMigrationResult(result);
  }
}

async function interactiveAdvancedOptions(): Promise<void> {
  console.log(chalk.cyan('🔧 Advanced migration options coming soon...'));
  
  const options = [
    'Custom migration scripts',
    'Backup management',
    'Configuration validation',
    'Migration testing'
  ];

  console.log(chalk.gray('\nPlanned features:'));
  options.forEach(option => {
    console.log(`  • ${option}`);
  });
}

// Display helper functions
function displayMigrationResult(result: MigrationResult): void {
  if (result.success) {
    console.log(chalk.green(`✅ Migration successful: ${result.fromVersion} → ${result.toVersion}`));
    
    if (result.appliedMigrations.length > 0) {
      console.log(chalk.cyan('\nApplied migrations:'));
      result.appliedMigrations.forEach(version => {
        console.log(`  • ${version}`);
      });
    }
  } else {
    console.log(chalk.red(`❌ Migration failed: ${result.fromVersion} → ${result.toVersion}`));
  }

  if (result.warnings && result.warnings.length > 0) {
    console.log(chalk.yellow('\nWarnings:'));
    result.warnings.forEach(warning => {
      console.log(chalk.yellow(`  ⚠️  ${warning}`));
    });
  }

  if (result.errors && result.errors.length > 0) {
    console.log(chalk.red('\nErrors:'));
    result.errors.forEach(error => {
      console.log(chalk.red(`  ❌ ${error}`));
    });
  }
}

function displayIntegrityCheck(check: { valid: boolean; version: string; issues: string[]; recommendations: string[] }): void {
  console.log(`  Version: ${check.version}`);
  console.log(`  Status: ${check.valid ? chalk.green('Valid') : chalk.red('Issues found')}`);
  
  if (check.issues.length > 0) {
    console.log(chalk.red('  Issues:'));
    check.issues.forEach(issue => {
      console.log(chalk.red(`    • ${issue}`));
    });
  }
  
  if (check.recommendations.length > 0) {
    console.log(chalk.yellow('  Recommendations:'));
    check.recommendations.forEach(rec => {
      console.log(chalk.yellow(`    • ${rec}`));
    });
  }
}

function displayMigrationHistory(history: { currentVersion: string; availableVersions: string[]; appliedMigrations: string[]; pendingMigrations: string[] }): void {
  console.log(`  Current version: ${chalk.green(history.currentVersion)}`);
  
  if (history.appliedMigrations.length > 0) {
    console.log(chalk.green('  Applied migrations:'));
    history.appliedMigrations.forEach(version => {
      console.log(chalk.green(`    ✅ ${version}`));
    });
  }
  
  if (history.pendingMigrations.length > 0) {
    console.log(chalk.yellow('  Pending migrations:'));
    history.pendingMigrations.forEach(version => {
      console.log(chalk.yellow(`    ⏳ ${version}`));
    });
  }
  
  if (history.pendingMigrations.length === 0 && history.appliedMigrations.length > 0) {
    console.log(chalk.green('  Status: Up to date'));
  }
}