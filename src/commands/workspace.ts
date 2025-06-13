import * as fs from 'fs-extra';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import chalk from 'chalk';
import { getWorkspaces, findMonorepoRoot, WorkspaceInfo } from '../utils/monorepo';
import { ProgressSpinner } from '../utils/spinner';

const execAsync = promisify(exec);

interface WorkspaceListOptions {
  json?: boolean;
  type?: 'app' | 'package' | 'lib' | 'tool';
  framework?: string;
  spinner?: ProgressSpinner;
}

interface WorkspaceUpdateOptions {
  workspace?: string;
  dependency?: string;
  version?: string;
  dev?: boolean;
  spinner?: ProgressSpinner;
}

interface WorkspaceGraphOptions {
  output?: string;
  format?: 'text' | 'json' | 'mermaid';
  spinner?: ProgressSpinner;
}

/**
 * List all workspaces in the monorepo
 */
export async function listWorkspaces(options: WorkspaceListOptions = {}): Promise<void> {
  const { spinner } = options;

  try {
    if (spinner) {
      spinner.setText('Finding monorepo root...');
    }

    // Add timeout to prevent hanging
    const monorepoRoot = await Promise.race([
      findMonorepoRoot(),
      new Promise<null>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout finding monorepo root')), 5000)
      ),
    ]);

    if (!monorepoRoot) {
      throw new Error('Not in a monorepo. Run this command from a monorepo root or workspace.');
    }

    if (spinner) {
      spinner.setText('Loading workspace information...');
    }

    const workspaces = await getWorkspaces(monorepoRoot);

    // Filter workspaces based on options
    let filteredWorkspaces = workspaces;

    if (options.type) {
      filteredWorkspaces = filteredWorkspaces.filter(ws => ws.type === options.type);
    }

    if (options.framework) {
      filteredWorkspaces = filteredWorkspaces.filter(ws => ws.framework === options.framework);
    }

    if (spinner) {
      spinner.stop();
    }

    if (options.json) {
      console.log(JSON.stringify(filteredWorkspaces, null, 2));
      return;
    }

    // Display workspaces in a formatted table
    console.log(chalk.cyan('\n📦 Workspaces\n'));

    if (filteredWorkspaces.length === 0) {
      console.log(chalk.yellow('No workspaces found.'));
      return;
    }

    // Group by type
    const groupedWorkspaces = filteredWorkspaces.reduce(
      (acc: Record<string, WorkspaceInfo[]>, ws: WorkspaceInfo) => {
        if (!acc[ws.type]) acc[ws.type] = [];
        acc[ws.type].push(ws);
        return acc;
      },
      {} as Record<string, WorkspaceInfo[]>
    );

    for (const [type, workspaceList] of Object.entries(groupedWorkspaces)) {
      console.log(chalk.bold(`\n${type.toUpperCase()}S:`));

      workspaceList.forEach((ws: WorkspaceInfo) => {
        const frameworkBadge = ws.framework ? chalk.blue(`[${ws.framework}]`) : '';
        const versionBadge = chalk.gray(`v${ws.version}`);

        console.log(
          `  ${chalk.green('●')} ${chalk.bold(ws.name)} ${frameworkBadge} ${versionBadge}`
        );
        console.log(`    ${chalk.gray(ws.path)}`);

        if (ws.dependencies.length > 0) {
          const depCount = ws.dependencies.length;
          console.log(`    ${chalk.gray(`${depCount} dependencies`)}`);
        }
      });
    }

    console.log(chalk.gray(`\nTotal: ${filteredWorkspaces.length} workspaces`));
  } catch (error) {
    if (spinner) {
      spinner.fail(chalk.red('Error listing workspaces'));
    }
    console.error(chalk.red('Error listing workspaces:'), error);
    throw error;
  }
}

/**
 * Update dependencies across workspaces
 */
export async function updateWorkspaces(options: WorkspaceUpdateOptions = {}): Promise<void> {
  const { spinner } = options;

  try {
    if (spinner) {
      spinner.setText('Finding monorepo root...');
    }

    const monorepoRoot = await findMonorepoRoot();
    if (!monorepoRoot) {
      throw new Error('Not in a monorepo. Run this command from a monorepo root or workspace.');
    }

    if (spinner) {
      spinner.setText('Loading workspace information...');
    }

    const workspaces = await getWorkspaces(monorepoRoot);

    if (options.workspace) {
      // Update specific workspace
      const workspace = workspaces.find(
        (ws: WorkspaceInfo) =>
          ws.name === options.workspace ||
          (options.workspace && ws.path.includes(options.workspace))
      );

      if (!workspace) {
        throw new Error(`Workspace "${options.workspace}" not found.`);
      }

      if (spinner) {
        spinner.setText(`Updating workspace: ${workspace.name}...`);
      }

      await updateSingleWorkspace(monorepoRoot, workspace, options);

      if (spinner) {
        spinner.succeed(chalk.green(`✓ Workspace "${workspace.name}" updated successfully`));
      }
    } else {
      // Update all workspaces
      if (spinner) {
        spinner.setText('Updating all workspaces...');
      }

      for (let i = 0; i < workspaces.length; i++) {
        const workspace = workspaces[i];

        if (spinner) {
          spinner.setText(`Updating ${workspace.name} (${i + 1}/${workspaces.length})...`);
        }

        await updateSingleWorkspace(monorepoRoot, workspace, options);
      }

      if (spinner) {
        spinner.succeed(chalk.green('✓ All workspaces updated'));
      }
    }
  } catch (error) {
    if (spinner) {
      spinner.fail(chalk.red('Error updating workspaces'));
    }
    console.error(chalk.red('Error updating workspaces:'), error);
    throw error;
  }
}

async function updateSingleWorkspace(
  monorepoRoot: string,
  workspace: WorkspaceInfo,
  options: WorkspaceUpdateOptions
): Promise<void> {
  const workspacePath = path.join(monorepoRoot, workspace.path);

  if (options.dependency && options.version) {
    // Update specific dependency
    const depFlag = options.dev ? '--save-dev' : '--save';
    const packageManager = await detectPackageManager(monorepoRoot);

    let command: string;
    switch (packageManager) {
      case 'pnpm':
        command = `pnpm add ${depFlag} ${options.dependency}@${options.version}`;
        break;
      case 'yarn':
        command = `yarn add ${depFlag} ${options.dependency}@${options.version}`;
        break;
      default:
        command = `npm install ${depFlag} ${options.dependency}@${options.version}`;
    }

    await execAsync(command, { cwd: workspacePath });
    console.log(
      chalk.green(`✓ Updated ${options.dependency} to ${options.version} in ${workspace.name}`)
    );
  } else {
    // Update all dependencies
    const packageManager = await detectPackageManager(monorepoRoot);

    let command: string;
    switch (packageManager) {
      case 'pnpm':
        command = 'pnpm update';
        break;
      case 'yarn':
        command = 'yarn upgrade';
        break;
      default:
        command = 'npm update';
    }

    await execAsync(command, { cwd: workspacePath });
  }
}

/**
 * Generate workspace dependency graph
 */
export async function generateWorkspaceGraph(options: WorkspaceGraphOptions = {}): Promise<void> {
  const { spinner } = options;

  try {
    if (spinner) {
      spinner.setText('Finding monorepo root...');
    }

    const monorepoRoot = await findMonorepoRoot();
    if (!monorepoRoot) {
      throw new Error('Not in a monorepo. Run this command from a monorepo root or workspace.');
    }

    if (spinner) {
      spinner.setText('Loading workspace information...');
    }

    const workspaces = await getWorkspaces(monorepoRoot);

    if (spinner) {
      spinner.setText('Building dependency graph...');
    }

    const graph = await buildDependencyGraph(workspaces);

    if (spinner) {
      spinner.stop();
    }

    switch (options.format) {
      case 'json': {
        const jsonOutput = JSON.stringify(graph, null, 2);
        if (options.output) {
          await fs.writeFile(options.output, jsonOutput);
          console.log(chalk.green(`Graph saved to ${options.output}`));
        } else {
          console.log(jsonOutput);
        }
        break;
      }

      case 'mermaid': {
        const mermaidOutput = generateMermaidGraph(graph);
        if (options.output) {
          await fs.writeFile(options.output, mermaidOutput);
          console.log(chalk.green(`Mermaid graph saved to ${options.output}`));
        } else {
          console.log(mermaidOutput);
        }
        break;
      }

      default:
        displayTextGraph(graph);
    }
  } catch (error) {
    if (spinner) {
      spinner.fail(chalk.red('Error generating workspace graph'));
    }
    console.error(chalk.red('Error generating workspace graph:'), error);
    throw error;
  }
}

async function buildDependencyGraph(workspaces: WorkspaceInfo[]): Promise<any> {
  const graph = {
    nodes: workspaces.map(ws => ({
      id: ws.name,
      type: ws.type,
      framework: ws.framework,
      path: ws.path,
    })),
    edges: [] as Array<{ from: string; to: string; type: 'dependency' | 'devDependency' }>,
  };

  // Build edges based on package.json dependencies
  for (const workspace of workspaces) {
    const packageJsonPath = path.join(workspace.path, 'package.json');

    try {
      const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
      };

      for (const depName of Object.keys(allDeps)) {
        const targetWorkspace = workspaces.find(ws => ws.name === depName);
        if (targetWorkspace) {
          graph.edges.push({
            from: workspace.name,
            to: targetWorkspace.name,
            type: packageJson.dependencies?.[depName] ? 'dependency' : 'devDependency',
          });
        }
      }
    } catch (error) {
      // Skip if package.json is not readable
    }
  }

  return graph;
}

function displayTextGraph(graph: any): void {
  console.log(chalk.cyan('\n🔗 Workspace Dependency Graph\n'));

  for (const node of graph.nodes) {
    const dependencies = graph.edges.filter((edge: any) => edge.from === node.id);
    const dependents = graph.edges.filter((edge: any) => edge.to === node.id);

    console.log(chalk.bold(`${node.id} (${node.type})`));

    if (dependencies.length > 0) {
      console.log(chalk.gray('  Dependencies:'));
      dependencies.forEach((dep: any) => {
        const typeColor = dep.type === 'dependency' ? chalk.green : chalk.yellow;
        console.log(`    ${typeColor('→')} ${dep.to}`);
      });
    }

    if (dependents.length > 0) {
      console.log(chalk.gray('  Dependents:'));
      dependents.forEach((dep: any) => {
        console.log(`    ${chalk.blue('←')} ${dep.from}`);
      });
    }

    console.log();
  }
}

function generateMermaidGraph(graph: any): string {
  let mermaid = 'graph TD\n';

  // Add nodes
  for (const node of graph.nodes) {
    const shape = getNodeShape(node.type);
    mermaid += `  ${node.id}${shape}\n`;
  }

  // Add edges
  for (const edge of graph.edges) {
    const style = edge.type === 'dependency' ? '-->' : '-..->';
    mermaid += `  ${edge.from} ${style} ${edge.to}\n`;
  }

  return mermaid;
}

function getNodeShape(type: string): string {
  switch (type) {
    case 'app':
      return '[App]';
    case 'package':
      return '(Package)';
    case 'lib':
      return '{Library}';
    case 'tool':
      return '[[Tool]]';
    default:
      return '[Unknown]';
  }
}

async function detectPackageManager(rootPath: string): Promise<'npm' | 'yarn' | 'pnpm'> {
  if (await fs.pathExists(path.join(rootPath, 'pnpm-lock.yaml'))) {
    return 'pnpm';
  }
  if (await fs.pathExists(path.join(rootPath, 'yarn.lock'))) {
    return 'yarn';
  }
  return 'npm';
}
