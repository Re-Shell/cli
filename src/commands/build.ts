import * as fs from 'fs-extra';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import chalk from 'chalk';

const execAsync = promisify(exec);

interface BuildOptions {
  production?: boolean;
  analyze?: boolean;
}

/**
 * Builds one or all microfrontends in the project
 * 
 * @param name - Name of the microfrontend to build (optional, builds all if omitted)
 * @param options - Build options
 * @version 0.1.0
 */
export async function buildMicrofrontend(
  name?: string,
  options: BuildOptions = {}
): Promise<void> {
  // Determine if we're in a Re-Shell project
  const isInReshellProject = fs.existsSync('package.json') && 
    (fs.existsSync('apps') || fs.existsSync('packages'));

  if (!isInReshellProject) {
    throw new Error('Not in a Re-Shell project. Please run this command from the root of a Re-Shell project.');
  }

  // Build env variables
  const env = {
    ...process.env,
    NODE_ENV: options.production ? 'production' : 'development'
  };

  if (name) {
    // Build a specific microfrontend
    const mfPath = path.resolve(process.cwd(), 'apps', name);
    
    if (!fs.existsSync(mfPath)) {
      throw new Error(`Microfrontend "${name}" not found in apps directory.`);
    }
    
    const packageJsonPath = path.join(mfPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      throw new Error(`package.json not found for microfrontend "${name}".`);
    }
    
    // Change to the microfrontend directory and build
    process.chdir(mfPath);
    console.log(chalk.cyan(`Building microfrontend "${name}"...`));
    
    // Optionally add bundle analysis
    let buildCommand = 'npm run build';
    if (options.analyze) {
      // This assumes vite-bundle-analyzer or similar is available
      buildCommand += ' -- --analyze';
    }
    
    try {
      const { stdout, stderr } = await execAsync(buildCommand, { env });
      console.log(stdout);
      if (stderr) console.error(stderr);
      console.log(chalk.green(`Successfully built microfrontend "${name}".`));
    } catch (error: any) {
      throw new Error(`Failed to build microfrontend "${name}": ${error.message}`);
    }
  } else {
    // Build all microfrontends
    const appsDir = path.resolve(process.cwd(), 'apps');
    if (!fs.existsSync(appsDir)) {
      throw new Error('Apps directory not found. Is this a valid Re-Shell project?');
    }
    
    // Get all directories in the apps folder
    const appDirs = fs.readdirSync(appsDir, { withFileTypes: true })
      .filter(dirent => dirent.isDirectory())
      .map(dirent => dirent.name);
    
    if (appDirs.length === 0) {
      console.log(chalk.yellow('No microfrontends found to build.'));
      return;
    }
    
    console.log(chalk.cyan(`Building all microfrontends...`));
    
    // Use the project's package manager if possible
    let buildCommand = 'npm run build';
    if (fs.existsSync('pnpm-lock.yaml')) {
      buildCommand = 'pnpm run build';
    } else if (fs.existsSync('yarn.lock')) {
      buildCommand = 'yarn build';
    }
    
    try {
      const { stdout, stderr } = await execAsync(buildCommand, { env });
      console.log(stdout);
      if (stderr) console.error(stderr);
      console.log(chalk.green('Successfully built all microfrontends.'));
    } catch (error: any) {
      throw new Error(`Failed to build microfrontends: ${error.message}`);
    }
  }
}