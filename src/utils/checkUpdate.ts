import * as https from 'https';
import * as semver from 'semver';
import chalk from 'chalk';
import * as fs from 'fs-extra';
import * as path from 'path';

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
}

export async function runUpdateCommand(): Promise<void> {
  const spinner = (await import('ora')).default('Checking for updates...').start();

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
      console.log(chalk.cyan('To update, run:'));
      console.log(chalk.bold('  npm install -g @re-shell/cli@latest'));
      console.log();
      console.log(chalk.gray('Or with other package managers:'));
      console.log('  yarn global add @re-shell/cli@latest');
      console.log('  pnpm add -g @re-shell/cli@latest');
    } else {
      spinner.succeed(chalk.green(`You're using the latest version (${currentVersion})`));
    }
  } catch (error) {
    spinner.fail(chalk.red('Error checking for updates'));
    console.error(error);
  }
}