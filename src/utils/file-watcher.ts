import * as fs from 'fs-extra';
import * as path from 'path';
import * as chokidar from 'chokidar';
import { EventEmitter } from 'events';
import chalk from 'chalk';
import { ValidationError } from './error-handler';
import { WorkspaceDefinition, WorkspaceEntry } from './workspace-schema';

// File watching interfaces
export interface FileWatchEvent {
  type: FileChangeType;
  path: string;
  workspace?: string;
  timestamp: number;
  size?: number;
  stats?: fs.Stats;
}

export type FileChangeType = 'add' | 'change' | 'unlink' | 'addDir' | 'unlinkDir';

export interface WatchOptions {
  ignored?: string | RegExp | (string | RegExp)[];
  persistent?: boolean;
  ignoreInitial?: boolean;
  followSymlinks?: boolean;
  cwd?: string;
  disableGlobbing?: boolean;
  usePolling?: boolean;
  interval?: number;
  binaryInterval?: number;
  alwaysStat?: boolean;
  depth?: number;
  awaitWriteFinish?: boolean | {
    stabilityThreshold?: number;
    pollInterval?: number;
  };
  ignorePermissionErrors?: boolean;
  atomic?: boolean;
}

export interface ChangePropagationRule {
  id: string;
  name: string;
  description: string;
  sourcePattern: RegExp | string;
  targetWorkspaces: string[] | 'all' | ((workspace: string) => boolean);
  actionType: PropagationActionType;
  condition?: (event: FileWatchEvent, workspaces: Record<string, WorkspaceEntry>) => boolean;
  transform?: (event: FileWatchEvent) => FileWatchEvent;
  debounceMs?: number;
}

export type PropagationActionType = 
  | 'rebuild'
  | 'restart-dev'
  | 'run-tests'
  | 'invalidate-cache'
  | 'notify'
  | 'custom';

export interface PropagationEvent {
  rule: ChangePropagationRule;
  sourceEvent: FileWatchEvent;
  targetWorkspaces: string[];
  timestamp: number;
  actionType: PropagationActionType;
}

export interface WatcherStats {
  totalEvents: number;
  eventsByType: Record<FileChangeType, number>;
  eventsByWorkspace: Record<string, number>;
  propagatedEvents: number;
  startTime: number;
  uptime: number;
  watchedPaths: string[];
  activeRules: number;
}

// File watcher with change propagation
export class FileWatcher extends EventEmitter {
  private watchers: Map<string, chokidar.FSWatcher> = new Map();
  private watchedPaths: Set<string> = new Set();
  private propagationRules: Map<string, ChangePropagationRule> = new Map();
  private debounceTimers: Map<string, NodeJS.Timeout> = new Map();
  private stats: WatcherStats;
  private workspaces: Record<string, WorkspaceEntry> = {};
  private rootPath: string;
  private isActive: boolean = false;

  constructor(rootPath: string = process.cwd()) {
    super();
    this.rootPath = rootPath;
    this.stats = {
      totalEvents: 0,
      eventsByType: {
        add: 0,
        change: 0,
        unlink: 0,
        addDir: 0,
        unlinkDir: 0
      },
      eventsByWorkspace: {},
      propagatedEvents: 0,
      startTime: Date.now(),
      uptime: 0,
      watchedPaths: [],
      activeRules: 0
    };

    this.initializeDefaultRules();
  }

  // Start watching workspace paths
  async startWatching(
    workspaces: Record<string, WorkspaceEntry>,
    options: WatchOptions = {}
  ): Promise<void> {
    if (this.isActive) {
      throw new ValidationError('File watcher is already active');
    }

    this.workspaces = workspaces;
    this.isActive = true;
    this.stats.startTime = Date.now();

    const defaultOptions: WatchOptions = {
      ignored: [
        '**/node_modules/**',
        '**/.git/**',
        '**/dist/**',
        '**/build/**',
        '**/.re-shell/**',
        '**/.next/**',
        '**/.nuxt/**',
        '**/coverage/**',
        '**/.nyc_output/**',
        '**/*.log',
        '**/.DS_Store',
        '**/Thumbs.db'
      ],
      persistent: true,
      ignoreInitial: true,
      followSymlinks: true,
      usePolling: false,
      interval: 1000,
      binaryInterval: 3000,
      alwaysStat: true,
      depth: undefined,
      awaitWriteFinish: {
        stabilityThreshold: 2000,
        pollInterval: 100
      },
      ignorePermissionErrors: true,
      atomic: true,
      ...options
    };

    // Watch each workspace directory
    for (const [workspaceName, workspace] of Object.entries(workspaces)) {
      if (!workspace.path) continue;

      const watchPath = path.resolve(this.rootPath, workspace.path);
      
      if (!(await fs.pathExists(watchPath))) {
        this.emit('warning', `Workspace path does not exist: ${watchPath}`);
        continue;
      }

      try {
        const watcher = chokidar.watch(watchPath, defaultOptions);
        
        // Set up event handlers
        watcher
          .on('add', (filePath, stats) => this.handleFileEvent('add', filePath, workspaceName, stats))
          .on('change', (filePath, stats) => this.handleFileEvent('change', filePath, workspaceName, stats))
          .on('unlink', (filePath) => this.handleFileEvent('unlink', filePath, workspaceName))
          .on('addDir', (dirPath, stats) => this.handleFileEvent('addDir', dirPath, workspaceName, stats))
          .on('unlinkDir', (dirPath) => this.handleFileEvent('unlinkDir', dirPath, workspaceName))
          .on('error', (error) => this.handleWatchError(error, workspaceName))
          .on('ready', () => this.handleWatchReady(workspaceName, watchPath));

        this.watchers.set(workspaceName, watcher);
        this.watchedPaths.add(watchPath);
        
      } catch (error) {
        this.emit('error', new ValidationError(
          `Failed to start watching ${workspaceName}: ${error instanceof Error ? error.message : String(error)}`
        ));
      }
    }

    // Watch root configuration files
    await this.watchRootFiles(defaultOptions);

    this.emit('started', {
      watchedWorkspaces: Object.keys(workspaces).length,
      watchedPaths: Array.from(this.watchedPaths),
      activeRules: this.propagationRules.size
    });
  }

  // Stop watching all paths
  async stopWatching(): Promise<void> {
    if (!this.isActive) return;

    this.isActive = false;

    // Clear debounce timers
    for (const timer of this.debounceTimers.values()) {
      clearTimeout(timer);
    }
    this.debounceTimers.clear();

    // Close all watchers
    const closePromises = Array.from(this.watchers.values()).map(watcher => 
      new Promise<void>((resolve) => {
        watcher.close().then(() => resolve()).catch(() => resolve());
      })
    );

    await Promise.all(closePromises);
    
    this.watchers.clear();
    this.watchedPaths.clear();
    
    this.stats.uptime = Date.now() - this.stats.startTime;
    
    this.emit('stopped', {
      uptime: this.stats.uptime,
      totalEvents: this.stats.totalEvents,
      propagatedEvents: this.stats.propagatedEvents
    });
  }

  // Add change propagation rule
  addPropagationRule(rule: ChangePropagationRule): void {
    this.propagationRules.set(rule.id, rule);
    this.stats.activeRules = this.propagationRules.size;
    this.emit('rule-added', rule);
  }

  // Remove change propagation rule
  removePropagationRule(ruleId: string): boolean {
    const removed = this.propagationRules.delete(ruleId);
    this.stats.activeRules = this.propagationRules.size;
    if (removed) {
      this.emit('rule-removed', ruleId);
    }
    return removed;
  }

  // Get current watcher statistics
  getStats(): WatcherStats {
    return {
      ...this.stats,
      uptime: this.isActive ? Date.now() - this.stats.startTime : this.stats.uptime,
      watchedPaths: Array.from(this.watchedPaths)
    };
  }

  // Check if currently watching
  isWatching(): boolean {
    return this.isActive;
  }

  // Handle file system events
  private handleFileEvent(
    type: FileChangeType,
    filePath: string,
    workspace: string,
    stats?: fs.Stats
  ): void {
    const event: FileWatchEvent = {
      type,
      path: filePath,
      workspace,
      timestamp: Date.now(),
      size: stats?.size,
      stats
    };

    // Update statistics
    this.stats.totalEvents++;
    this.stats.eventsByType[type]++;
    this.stats.eventsByWorkspace[workspace] = (this.stats.eventsByWorkspace[workspace] || 0) + 1;

    // Emit the file event
    this.emit('file-event', event);

    // Process propagation rules
    this.processPropagationRules(event);
  }

  // Process change propagation rules
  private processPropagationRules(event: FileWatchEvent): void {
    for (const rule of this.propagationRules.values()) {
      if (this.matchesRule(event, rule)) {
        this.propagateChange(event, rule);
      }
    }
  }

  // Check if event matches propagation rule
  private matchesRule(event: FileWatchEvent, rule: ChangePropagationRule): boolean {
    // Check source pattern
    const sourceMatch = typeof rule.sourcePattern === 'string'
      ? event.path.includes(rule.sourcePattern)
      : rule.sourcePattern.test(event.path);

    if (!sourceMatch) return false;

    // Check condition if provided
    if (rule.condition && !rule.condition(event, this.workspaces)) {
      return false;
    }

    return true;
  }

  // Propagate change to target workspaces
  private propagateChange(event: FileWatchEvent, rule: ChangePropagationRule): void {
    const targetWorkspaces = this.resolveTargetWorkspaces(rule.targetWorkspaces, event);
    
    if (targetWorkspaces.length === 0) return;

    const propagationEvent: PropagationEvent = {
      rule,
      sourceEvent: rule.transform ? rule.transform(event) : event,
      targetWorkspaces,
      timestamp: Date.now(),
      actionType: rule.actionType
    };

    // Handle debouncing if specified
    if (rule.debounceMs && rule.debounceMs > 0) {
      this.debouncePropagate(propagationEvent, rule);
    } else {
      this.emitPropagation(propagationEvent);
    }
  }

  // Handle debounced propagation
  private debouncePropagate(event: PropagationEvent, rule: ChangePropagationRule): void {
    const timerId = `${rule.id}-${event.sourceEvent.path}`;
    
    // Clear existing timer
    if (this.debounceTimers.has(timerId)) {
      clearTimeout(this.debounceTimers.get(timerId)!);
    }

    // Set new timer
    const timer = setTimeout(() => {
      this.debounceTimers.delete(timerId);
      this.emitPropagation(event);
    }, rule.debounceMs);

    this.debounceTimers.set(timerId, timer);
  }

  // Emit propagation event
  private emitPropagation(event: PropagationEvent): void {
    this.stats.propagatedEvents++;
    this.emit('propagate', event);
  }

  // Resolve target workspaces from rule definition
  private resolveTargetWorkspaces(
    target: string[] | 'all' | ((workspace: string) => boolean),
    event: FileWatchEvent
  ): string[] {
    if (target === 'all') {
      return Object.keys(this.workspaces);
    }

    if (Array.isArray(target)) {
      return target.filter(ws => this.workspaces[ws]);
    }

    if (typeof target === 'function') {
      return Object.keys(this.workspaces).filter(target);
    }

    return [];
  }

  // Watch root configuration files
  private async watchRootFiles(options: WatchOptions): Promise<void> {
    const rootFiles = [
      're-shell.workspaces.yaml',
      're-shell.config.yaml',
      'package.json',
      'tsconfig.json',
      '.env',
      '.env.local'
    ];

    for (const file of rootFiles) {
      const filePath = path.join(this.rootPath, file);
      
      if (await fs.pathExists(filePath)) {
        try {
          const watcher = chokidar.watch(filePath, {
            ...options,
            ignoreInitial: true
          });

          watcher
            .on('change', (changedPath, stats) => this.handleFileEvent('change', changedPath, 'root', stats))
            .on('unlink', (changedPath) => this.handleFileEvent('unlink', changedPath, 'root'))
            .on('error', (error) => this.handleWatchError(error, 'root'));

          this.watchers.set(`root-${file}`, watcher);
          this.watchedPaths.add(filePath);
          
        } catch (error) {
          this.emit('warning', `Failed to watch root file ${file}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
  }

  // Handle watch errors
  private handleWatchError(error: unknown, workspace: string): void {
    const message = error instanceof Error ? error.message : String(error);
    this.emit('error', new ValidationError(
      `File watcher error in ${workspace}: ${message}`
    ));
  }

  // Handle watcher ready state
  private handleWatchReady(workspace: string, path: string): void {
    this.emit('watcher-ready', { workspace, path });
  }

  // Initialize default propagation rules
  private initializeDefaultRules(): void {
    // Package.json changes trigger dependency updates
    this.addPropagationRule({
      id: 'package-json-changed',
      name: 'Package.json Dependencies',
      description: 'Propagate package.json changes to dependent workspaces',
      sourcePattern: /package\.json$/,
      targetWorkspaces: 'all',
      actionType: 'invalidate-cache',
      debounceMs: 3000,
      condition: (event) => event.type === 'change'
    });

    // TypeScript config changes
    this.addPropagationRule({
      id: 'tsconfig-changed',
      name: 'TypeScript Configuration',
      description: 'Rebuild TypeScript workspaces when config changes',
      sourcePattern: /tsconfig.*\.json$/,
      targetWorkspaces: (workspace) => {
        const ws = this.workspaces[workspace];
        return ws?.type === 'app' || ws?.type === 'lib';
      },
      actionType: 'rebuild',
      debounceMs: 2000
    });

    // Source code changes in libraries
    this.addPropagationRule({
      id: 'lib-source-changed',
      name: 'Library Source Changes',
      description: 'Rebuild dependent workspaces when library source changes',
      sourcePattern: /\.(ts|tsx|js|jsx)$/,
      targetWorkspaces: [],
      actionType: 'rebuild',
      debounceMs: 1000,
      condition: (event, workspaces) => {
        const workspace = workspaces[event.workspace!];
        return workspace?.type === 'lib' && event.type === 'change';
      }
    });

    // Environment file changes
    this.addPropagationRule({
      id: 'env-changed',
      name: 'Environment Variables',
      description: 'Restart development servers when environment changes',
      sourcePattern: /\.env/,
      targetWorkspaces: 'all',
      actionType: 'restart-dev',
      debounceMs: 1000
    });

    // Test file changes
    this.addPropagationRule({
      id: 'test-changed',
      name: 'Test Files',
      description: 'Run tests when test files change',
      sourcePattern: /\.(test|spec)\.(ts|tsx|js|jsx)$/,
      targetWorkspaces: (workspace) => !!workspace,
      actionType: 'run-tests',
      debounceMs: 500,
      condition: (event) => event.type === 'change' || event.type === 'add'
    });

    // Configuration file changes
    this.addPropagationRule({
      id: 'config-changed',
      name: 'Configuration Files',
      description: 'Restart when configuration files change',
      sourcePattern: /\.(config|rc)\.(js|json|yaml|yml)$/,
      targetWorkspaces: 'all',
      actionType: 'restart-dev',
      debounceMs: 2000
    });
  }
}

// Utility functions
export async function createFileWatcher(rootPath?: string): Promise<FileWatcher> {
  return new FileWatcher(rootPath);
}

// Start watching with workspace definition
export async function startWorkspaceWatcher(
  workspaceFile: string,
  options?: WatchOptions
): Promise<FileWatcher> {
  const watcher = new FileWatcher();
  
  // Load workspace definition
  const definition = await loadWorkspaceDefinition(workspaceFile);
  
  // Start watching
  await watcher.startWatching(definition.workspaces, options);
  
  return watcher;
}

// Helper function to load workspace definition
async function loadWorkspaceDefinition(filePath: string): Promise<WorkspaceDefinition> {
  if (!(await fs.pathExists(filePath))) {
    throw new ValidationError(`Workspace file not found: ${filePath}`);
  }

  const content = await fs.readFile(filePath, 'utf8');
  const yaml = await import('yaml');
  return yaml.parse(content) as WorkspaceDefinition;
}