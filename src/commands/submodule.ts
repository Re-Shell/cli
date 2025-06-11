import chalk from 'chalk';
import prompts from 'prompts';
import {
  addSubmodule,
  removeSubmodule,
  updateSubmodules,
  getSubmoduleStatus,
  createSubmoduleDocumentation,
  isGitRepository,
  SubmoduleInfo
} from '../utils/submodule';
import { findMonorepoRoot } from '../utils/monorepo';

interface SubmoduleAddOptions {
  branch?: string;
  path?: string;
}

interface SubmoduleUpdateOptions {
  path?: string;
  recursive?: boolean;
}

interface SubmoduleRemoveOptions {
  force?: boolean;
}

/**
 * Add a new Git submodule
 */
export async function addGitSubmodule(
  repositoryUrl: string,
  options: SubmoduleAddOptions = {}
): Promise<void> {
  try {
    // Ensure we're in a Git repository
    if (!(await isGitRepository())) {
      throw new Error('Not in a Git repository. Initialize Git first with: git init');
    }

    // Interactive prompts for missing options
    const responses = await prompts([
      {
        type: options.path ? null : 'text',
        name: 'path',
        message: 'Submodule path:',
        initial: repositoryUrl.split('/').pop()?.replace('.git', '') || 'submodule',
        validate: (value: string) => value.trim() ? true : 'Path is required'
      },
      {
        type: options.branch ? null : 'text',
        name: 'branch',
        message: 'Branch to track:',
        initial: 'main'
      }
    ]);

    const finalOptions = {
      path: options.path || responses.path,
      branch: options.branch || responses.branch || 'main'
    };

    console.log(chalk.cyan(`Adding submodule: ${repositoryUrl}`));
    console.log(chalk.gray(`Path: ${finalOptions.path}`));
    console.log(chalk.gray(`Branch: ${finalOptions.branch}`));

    await addSubmodule(finalOptions.path, repositoryUrl, finalOptions.branch);
    
    // Update documentation
    const submodules = await getSubmoduleStatus();
    const monorepoRoot = await findMonorepoRoot() || process.cwd();
    await createSubmoduleDocumentation(monorepoRoot, submodules);

    console.log(chalk.green(`✓ Submodule added successfully: ${finalOptions.path}`));
    console.log(chalk.gray('Documentation updated in docs/SUBMODULES.md'));

  } catch (error) {
    console.error(chalk.red('Error adding submodule:'), error);
    throw error;
  }
}

/**
 * Remove a Git submodule
 */
export async function removeGitSubmodule(
  submodulePath: string,
  options: SubmoduleRemoveOptions = {}
): Promise<void> {
  try {
    // Ensure we're in a Git repository
    if (!(await isGitRepository())) {
      throw new Error('Not in a Git repository.');
    }

    // Get current submodules to validate path
    const submodules = await getSubmoduleStatus();
    const submodule = submodules.find(sub => sub.path === submodulePath || sub.name === submodulePath);
    
    if (!submodule) {
      throw new Error(`Submodule not found: ${submodulePath}`);
    }

    // Confirmation prompt unless force option is used
    if (!options.force) {
      const { confirm } = await prompts({
        type: 'confirm',
        name: 'confirm',
        message: `Are you sure you want to remove submodule "${submodule.path}"?`,
        initial: false
      });

      if (!confirm) {
        console.log(chalk.yellow('Operation cancelled.'));
        return;
      }
    }

    console.log(chalk.cyan(`Removing submodule: ${submodule.path}`));

    await removeSubmodule(submodule.path);
    
    // Update documentation
    const updatedSubmodules = await getSubmoduleStatus();
    const monorepoRoot = await findMonorepoRoot() || process.cwd();
    await createSubmoduleDocumentation(monorepoRoot, updatedSubmodules);

    console.log(chalk.green(`✓ Submodule removed successfully: ${submodule.path}`));
    console.log(chalk.gray('Documentation updated in docs/SUBMODULES.md'));

  } catch (error) {
    console.error(chalk.red('Error removing submodule:'), error);
    throw error;
  }
}

/**
 * Update Git submodules
 */
export async function updateGitSubmodules(options: SubmoduleUpdateOptions = {}): Promise<void> {
  try {
    // Ensure we're in a Git repository
    if (!(await isGitRepository())) {
      throw new Error('Not in a Git repository.');
    }

    if (options.path) {
      console.log(chalk.cyan(`Updating submodule: ${options.path}`));
      await updateSubmodules(options.path);
      console.log(chalk.green(`✓ Submodule updated: ${options.path}`));
    } else {
      console.log(chalk.cyan('Updating all submodules...'));
      await updateSubmodules();
      console.log(chalk.green('✓ All submodules updated'));
    }

    // Update documentation
    const submodules = await getSubmoduleStatus();
    const monorepoRoot = await findMonorepoRoot() || process.cwd();
    await createSubmoduleDocumentation(monorepoRoot, submodules);

  } catch (error) {
    console.error(chalk.red('Error updating submodules:'), error);
    throw error;
  }
}

/**
 * Show Git submodule status
 */
export async function showSubmoduleStatus(): Promise<void> {
  try {
    // Ensure we're in a Git repository
    if (!(await isGitRepository())) {
      throw new Error('Not in a Git repository.');
    }

    const submodules = await getSubmoduleStatus();

    if (submodules.length === 0) {
      console.log(chalk.yellow('No submodules found.'));
      return;
    }

    console.log(chalk.cyan('\n📁 Submodule Status\n'));

    submodules.forEach((submodule: SubmoduleInfo) => {
      const statusColor = getStatusColor(submodule.status);
      const statusIcon = getStatusIcon(submodule.status);
      
      console.log(`${statusIcon} ${chalk.bold(submodule.name)} ${statusColor(submodule.status)}`);
      console.log(`   ${chalk.gray('Path:')} ${submodule.path}`);
      console.log(`   ${chalk.gray('URL:')} ${submodule.url}`);
      console.log(`   ${chalk.gray('Branch:')} ${submodule.branch}`);
      console.log(`   ${chalk.gray('Commit:')} ${submodule.commit}`);
      console.log();
    });

    console.log(chalk.gray(`Total: ${submodules.length} submodules`));

    // Show summary by status
    const statusCounts = submodules.reduce((acc: Record<string, number>, sub: SubmoduleInfo) => {
      acc[sub.status] = (acc[sub.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    if (Object.keys(statusCounts).length > 1) {
      console.log(chalk.gray('\nStatus Summary:'));
      Object.entries(statusCounts).forEach(([status, count]) => {
        const color = getStatusColor(status as SubmoduleInfo['status']);
        console.log(`  ${color(status)}: ${count}`);
      });
    }

  } catch (error) {
    console.error(chalk.red('Error getting submodule status:'), error);
    throw error;
  }
}

/**
 * Initialize submodules (for new clones)
 */
export async function initSubmodules(): Promise<void> {
  try {
    // Ensure we're in a Git repository
    if (!(await isGitRepository())) {
      throw new Error('Not in a Git repository.');
    }

    console.log(chalk.cyan('Initializing submodules...'));
    await updateSubmodules(); // This will init and update
    console.log(chalk.green('✓ Submodules initialized'));

  } catch (error) {
    console.error(chalk.red('Error initializing submodules:'), error);
    throw error;
  }
}

/**
 * Interactive submodule management
 */
export async function manageSubmodules(): Promise<void> {
  try {
    // Ensure we're in a Git repository
    if (!(await isGitRepository())) {
      throw new Error('Not in a Git repository.');
    }

    const { action } = await prompts({
      type: 'select',
      name: 'action',
      message: 'What would you like to do?',
      choices: [
        { title: 'Show status', value: 'status' },
        { title: 'Add submodule', value: 'add' },
        { title: 'Update submodules', value: 'update' },
        { title: 'Remove submodule', value: 'remove' },
        { title: 'Initialize submodules', value: 'init' }
      ]
    });

    switch (action) {
      case 'status':
        await showSubmoduleStatus();
        break;
        
      case 'add':
        const { url } = await prompts({
          type: 'text',
          name: 'url',
          message: 'Repository URL:',
          validate: (value: string) => value.trim() ? true : 'URL is required'
        });
        await addGitSubmodule(url);
        break;
        
      case 'update':
        const submodules = await getSubmoduleStatus();
        if (submodules.length === 0) {
          console.log(chalk.yellow('No submodules to update.'));
          return;
        }
        
        const { updateTarget } = await prompts({
          type: 'select',
          name: 'updateTarget',
          message: 'What to update?',
          choices: [
            { title: 'All submodules', value: 'all' },
            ...submodules.map((sub: SubmoduleInfo) => ({ title: sub.path, value: sub.path }))
          ]
        });
        
        if (updateTarget === 'all') {
          await updateGitSubmodules();
        } else {
          await updateGitSubmodules({ path: updateTarget });
        }
        break;
        
      case 'remove':
        const currentSubmodules = await getSubmoduleStatus();
        if (currentSubmodules.length === 0) {
          console.log(chalk.yellow('No submodules to remove.'));
          return;
        }
        
        const { removeTarget } = await prompts({
          type: 'select',
          name: 'removeTarget',
          message: 'Which submodule to remove?',
          choices: currentSubmodules.map((sub: SubmoduleInfo) => ({ title: sub.path, value: sub.path }))
        });
        
        await removeGitSubmodule(removeTarget);
        break;
        
      case 'init':
        await initSubmodules();
        break;
    }

  } catch (error) {
    console.error(chalk.red('Error managing submodules:'), error);
    throw error;
  }
}

function getStatusColor(status: SubmoduleInfo['status']): (text: string) => string {
  switch (status) {
    case 'clean': return chalk.green;
    case 'modified': return chalk.yellow;
    case 'untracked': return chalk.red;
    case 'ahead': return chalk.blue;
    case 'behind': return chalk.magenta;
    default: return chalk.gray;
  }
}

function getStatusIcon(status: SubmoduleInfo['status']): string {
  switch (status) {
    case 'clean': return chalk.green('✓');
    case 'modified': return chalk.yellow('●');
    case 'untracked': return chalk.red('✗');
    case 'ahead': return chalk.blue('↑');
    case 'behind': return chalk.magenta('↓');
    default: return chalk.gray('?');
  }
}
