import * as https from 'https';
import * as semver from 'semver';
import chalk from 'chalk';
import * as fs from 'fs-extra';
import * as path from 'path';
import { spawn } from 'child_process';

interface NpmPackageInfo {
  'dist-tags': {
    latest: string;
  };
  versions: Record<string, unknown>;
}

export async function checkForUpdates(currentVersion: string): Promise<void> {
  try {
    // Check if we should skip the update check (e.g., in CI environments)
    if (process.env.CI || process.env.RE_SHELL_SKIP_UPDATE_CHECK) {
      return;
    }

    // Check if we've recently checked for updates (within last 24 hours)
    const cacheFile = path.join(process.env.HOME || process.env.USERPROFILE || '', '.re-shell-update-check');
    
    if (await fs.pathExists(cacheFile)) {
      const lastCheck = await fs.readJson(cacheFile).catch(() => null);
      if (lastCheck && Date.now() - lastCheck.timestamp < 86400000) { // 24 hours
        // If there was a cached update notification, show it
        if (lastCheck.hasUpdate) {
          showUpdateNotification(currentVersion, lastCheck.latestVersion);
        }
        return;
      }
    }

    // Fetch latest version from npm registry
    const latestVersion = await fetchLatestVersion('@re-shell/cli');
    
    if (latestVersion && semver.gt(latestVersion, currentVersion)) {
      // Cache the update check result
      await fs.writeJson(cacheFile, {
        timestamp: Date.now(),
        hasUpdate: true,
        latestVersion
      }).catch(() => { /* Ignore cache write errors */ });

      showUpdateNotification(currentVersion, latestVersion);
    } else {
      // Cache that no update is needed
      await fs.writeJson(cacheFile, {
        timestamp: Date.now(),
        hasUpdate: false,
        latestVersion
      }).catch(() => { /* Ignore cache write errors */ });
    }
  } catch (error) {
    // Silently ignore update check errors to not disrupt the CLI usage
  }
}

function fetchLatestVersion(packageName: string): Promise<string | null> {
  return new Promise((resolve) => {
    const options = {
      hostname: 'registry.npmjs.org',
      path: `/${packageName}`,
      method: 'GET',
      timeout: 3000 // 3 second timeout
    };

    const req = https.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const packageInfo: NpmPackageInfo = JSON.parse(data);
          resolve(packageInfo['dist-tags'].latest);
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    req.end();
  });
}

function showUpdateNotification(currentVersion: string, latestVersion: string): void {
  console.log();
  console.log(chalk.yellow('╔════════════════════════════════════════════════════════════════╗'));
  console.log(chalk.yellow('║') + '                                                                ' + chalk.yellow('║'));
  console.log(chalk.yellow('║') + chalk.bold.white('  Update available! ') + chalk.gray(`${currentVersion} → `) + chalk.green.bold(latestVersion) + '                              ' + chalk.yellow('║'));
  console.log(chalk.yellow('║') + '                                                                ' + chalk.yellow('║'));
  console.log(chalk.yellow('║') + '  Run ' + chalk.cyan.bold('npm install -g @re-shell/cli@latest') + ' to update        ' + chalk.yellow('║'));
  console.log(chalk.yellow('║') + '                                                                ' + chalk.yellow('║'));
  console.log(chalk.yellow('║') + chalk.gray('  Changelog: https://github.com/Re-Shell/cli/releases') + '          ' + chalk.yellow('║'));
  console.log(chalk.yellow('║') + '                                                                ' + chalk.yellow('║'));
  console.log(chalk.yellow('╚════════════════════════════════════════════════════════════════╝'));
  console.log();
  
  // Force flush output
  process.stdout.write('');
  process.stderr.write('');
}

export async function runUpdateCommand(): Promise<void> {
  const { createSpinner, flushOutput } = await import('./spinner');
  const prompts = await import('prompts');
  
  const spinner = createSpinner('Checking for updates...').start();
  flushOutput();

  try {
    const packageJsonPath = path.resolve(__dirname, '../../package.json');
    const packageJson = await fs.readJson(packageJsonPath);
    const currentVersion = packageJson.version;

    const latestVersion = await fetchLatestVersion('@re-shell/cli');

    if (!latestVersion) {
      spinner.fail(chalk.red('Unable to check for updates. Please check your internet connection.'));
      return;
    }

    if (semver.gt(latestVersion, currentVersion)) {
      spinner.succeed(chalk.green(`Update available: ${currentVersion} → ${latestVersion}`));
      console.log();
      
      // Ask user if they want to update automatically
      const response = await prompts.default({
        type: 'confirm',
        name: 'shouldUpdate',
        message: `Do you want to update to version ${latestVersion} now?`,
        initial: true
      });

      if (response.shouldUpdate) {
        // Detect package manager
        const packageManager = detectPackageManager();
        const updateSpinner = createSpinner(`Updating @re-shell/cli using ${packageManager}...`).start();
        
        try {
          await performUpdate(packageManager);
          updateSpinner.succeed(chalk.green(`Successfully updated to @re-shell/cli@${latestVersion}!`));
          console.log();
          console.log(chalk.green('🎉 Update completed! You can now use the latest features.'));
        } catch (error) {
          updateSpinner.fail(chalk.red('Update failed'));
          console.log();
          console.log(chalk.yellow('Please update manually using one of these commands:'));
          console.log(chalk.bold('  npm install -g @re-shell/cli@latest'));
          console.log('  yarn global add @re-shell/cli@latest');
          console.log('  pnpm add -g @re-shell/cli@latest');
        }
      } else {
        console.log();
        console.log(chalk.yellow('Update skipped. To update later, run:'));
        console.log(chalk.bold('  re-shell update'));
      }
    } else {
      spinner.succeed(chalk.green(`You're using the latest version (${currentVersion})`));
    }
  } catch (error) {
    spinner.fail(chalk.red('Error checking for updates'));
    console.error(error);
  }
}

function detectPackageManager(): string {
  // Try to detect which package manager was used to install re-shell
  const execPath = process.env._ || '';
  
  if (execPath.includes('pnpm')) return 'pnpm';
  if (execPath.includes('yarn')) return 'yarn';
  
  // Check if pnpm is available
  try {
    require('child_process').execSync('pnpm --version', { stdio: 'ignore' });
    return 'pnpm';
  } catch {
    // pnpm not available
  }
  
  // Check if yarn is available
  try {
    require('child_process').execSync('yarn --version', { stdio: 'ignore' });
    return 'yarn';
  } catch {
    // yarn not available
  }
  
  // Default to npm
  return 'npm';
}

function performUpdate(packageManager: string): Promise<void> {
  return new Promise((resolve, reject) => {
    
    let command: string;
    let args: string[];
    
    switch (packageManager) {
      case 'pnpm':
        command = 'pnpm';
        args = ['add', '-g', '@re-shell/cli@latest'];
        break;
      case 'yarn':
        command = 'yarn';
        args = ['global', 'add', '@re-shell/cli@latest'];
        break;
      default:
        command = 'npm';
        args = ['install', '-g', '@re-shell/cli@latest'];
    }
    
    const child = spawn(command, args, {
      stdio: 'pipe',
      shell: true
    });
    
    child.on('close', (code: number | null) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Update process exited with code ${code}`));
      }
    });
    
    child.on('error', (error: Error) => {
      reject(error);
    });
  });
}