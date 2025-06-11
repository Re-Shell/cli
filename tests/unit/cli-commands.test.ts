import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs-extra';
import * as path from 'path';
import { addMicrofrontend } from '../../src/commands/add';
import { createProject } from '../../src/commands/create';
import { removeMicrofrontend } from '../../src/commands/remove';
import { listMicrofrontends } from '../../src/commands/list';
import { buildMicrofrontend } from '../../src/commands/build';
import { serveMicrofrontend } from '../../src/commands/serve';

// Create a more comprehensive mock for fs-extra
const mockFiles = new Map();
const testDir = '/test/path';

// Helper function to check if a file exists in our mock file system
function mockExistsSync(filePath: string): boolean {
  // Handle both absolute paths and paths relative to testDir
  if (filePath.startsWith('/')) {
    return mockFiles.has(filePath);
  }

  return mockFiles.has(filePath) || mockFiles.has(`${testDir}/${filePath}`);
}

// Mock the modules
vi.mock('fs-extra', () => ({
  existsSync: vi.fn((filePath) => mockExistsSync(String(filePath))),
  mkdirSync: vi.fn((path) => { mockFiles.set(String(path), 'directory'); }),
  writeFileSync: vi.fn((path, content) => {
    mockFiles.set(String(path), content);
    return { path, content };
  }),
  readFileSync: vi.fn((path) => {
    const content = mockFiles.get(String(path)) || JSON.stringify({ version: '0.2.0' });
    return content;
  }),
  readJsonSync: vi.fn((path) => {
    const content = mockFiles.get(String(path));
    if (content) {
      if (typeof content === 'string' && content.startsWith('{')) {
        try {
          return JSON.parse(content);
        } catch {
          return content;
        }
      }
      return content;
    }
    return { microfrontends: [], workspaces: ['packages/*', 'apps/*'] };
  }),
  removeSync: vi.fn((path) => { mockFiles.delete(String(path)); }),
  readdirSync: vi.fn(() => ['mf1', 'mf2']),
  ensureDirSync: vi.fn((path) => { mockFiles.set(String(path), 'directory'); })
}));

vi.mock('prompts', () => ({
  default: vi.fn(() => Promise.resolve({
    template: 'react-ts',
    route: '/test-mf',
    force: true
  }))
}));

vi.mock('path', () => ({
  resolve: vi.fn((dir, ...segments) => `${dir}/${segments.join('/')}`),
  join: vi.fn((...args) => args.join('/'))
}));

vi.mock('child_process', () => ({
  exec: vi.fn(),
  execSync: vi.fn()
}));

// Mock console methods
vi.spyOn(console, 'log').mockImplementation(() => {});
vi.spyOn(console, 'error').mockImplementation(() => {});

describe('CLI Command Unit Tests', () => {
  const testMfName = 'test-mf';
  const testProjectName = 'test-project';

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();
    mockFiles.clear();

    // Mock process.cwd
    vi.spyOn(process, 'cwd').mockReturnValue(testDir);

    // Set up mocked files for the microfrontend
    mockFiles.set(`${testDir}/apps/${testMfName}`, 'directory');

    // Mock path.resolve to handle test paths consistently
    vi.mocked(path.resolve).mockImplementation((dir, ...segments) => {
      // Handle special case for checking microfrontend existence
      if (segments[0] === 'apps' && segments[1] === testMfName) {
        return `${dir}/apps/${testMfName}`;
      }
      return segments.length > 0
        ? `${dir}/${segments.join('/')}`
        : dir;
    });

    // Mock path.join to be consistent
    vi.mocked(path.join).mockImplementation((...args) => args.join('/'));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('createProject', () => {
    it('should create a Re-Shell project with specified options', async () => {
      // Call the function under test
      await createProject(testProjectName, {
        org: 'custom-org',
        team: 'custom-team',
        description: 'Custom description',
        template: 'react-ts',
        packageManager: 'yarn',
        isProject: true
      });

      // Verify package.json is created with correct content
      const writeFileCalls = vi.mocked(fs.writeFileSync).mock.calls;
      const packageJsonCall = writeFileCalls.find(call =>
        String(call[0]).includes('package.json')
      );

      expect(packageJsonCall).toBeDefined();
      expect(packageJsonCall![1]).toContain('"name": "test-project"');
      expect(packageJsonCall![1]).toContain('"description": "Custom description"');
      expect(packageJsonCall![1]).toContain('"author": "custom-team"');
    });

    it('should handle errors when creating a project', async () => {
      // Mock fs.mkdirSync to throw an error
      vi.mocked(fs.mkdirSync).mockImplementation(() => {
        throw new Error('Failed to create directory');
      });

      // Verify function throws error
      await expect(async () => {
        await createProject(testProjectName, {
          org: 're-shell',
          template: 'react-ts',
          packageManager: 'pnpm',
          isProject: true
        });
      }).rejects.toThrow();
    });
  });

  describe('addMicrofrontend', () => {
    it('should add a microfrontend with custom options', async () => {
      // Mock the writeFileSync to capture the package.json content
      vi.mocked(fs.writeFileSync).mockImplementation((filepath, content) => {
        mockFiles.set(String(filepath), content);
        return { filepath, content };
      });

      // Call the function under test
      await addMicrofrontend(testMfName, {
        org: 'custom-org',
        team: 'custom-team',
        description: 'Custom description',
        template: 'react-ts',
        route: '/custom-route',
        port: '8080'
      });

      // Find the package.json call by examining all writeFileSync calls
      const writeFileCalls = vi.mocked(fs.writeFileSync).mock.calls;
      let packageJsonContent: string | undefined;
      let viteConfigContent: string | undefined;

      for (const call of writeFileCalls) {
        const filepath = String(call[0]);
        if (filepath.includes('package.json')) {
          packageJsonContent = String(call[1]);
        }
        if (filepath.includes('vite.config.ts')) {
          viteConfigContent = String(call[1]);
        }
      }

      expect(packageJsonContent).toBeDefined();
      expect(packageJsonContent).toContain('@custom-org/test-mf');
      expect(packageJsonContent).toContain('"description": "Custom description"');

      expect(viteConfigContent).toBeDefined();
      expect(viteConfigContent).toContain('port: 8080');
    });
  });

  describe('removeMicrofrontend', () => {
    it('should prompt for confirmation when force flag is not set', async () => {
      // Make sure the microfrontend directory exists in the apps directory
      mockFiles.set(`apps/${testMfName}`, 'directory');

      // Mock prompts to simulate user confirmation
      const promptsMock = await import('prompts');
      vi.mocked(promptsMock.default).mockResolvedValueOnce({ confirm: true });

      // Call the function under test
      await removeMicrofrontend(testMfName, {});

      // Verify prompts was called
      expect(promptsMock.default).toHaveBeenCalled();

      // Verify remove is called
      expect(fs.removeSync).toHaveBeenCalled();
    });
  });

  describe('listMicrofrontends', () => {
    it('should handle empty project with no microfrontends', async () => {
      // Mock empty apps directory but make sure it exists
      mockFiles.set('apps', 'directory');
      vi.mocked(fs.readdirSync).mockReturnValue([]);

      // Call the function under test
      await listMicrofrontends({});

      // Verify console.log is called with "No microfrontends found"
      expect(console.log).toHaveBeenCalledWith(expect.stringContaining('No microfrontends found'));
    });
  });

  describe('buildMicrofrontend', () => {
    it('should build a specific microfrontend', async () => {
      // Make sure the microfrontend directory exists in the apps directory
      mockFiles.set(`apps/${testMfName}`, 'directory');

      // Mock child_process.execAsync
      const childProcessMock = await import('child_process');
      const execAsyncMock = vi.fn().mockResolvedValue({ stdout: 'Build successful', stderr: '' });
      vi.mocked(childProcessMock.exec).mockImplementation((cmd, opts, callback) => {
        if (callback) {
          callback(null, { stdout: 'Build successful', stderr: '' } as any, '');
        }
        return { stdout: 'Build successful', stderr: '' } as any;
      });

      // Call the function under test
      await buildMicrofrontend(testMfName, { production: true });

      // Verify exec is called with correct command
      expect(childProcessMock.exec).toHaveBeenCalled();
    });
  });

  describe('serveMicrofrontend', () => {
    it('should serve all microfrontends when no name is provided', async () => {
      // Set up the apps directory with some microfrontends
      mockFiles.set('apps/mf1', 'directory');
      mockFiles.set('apps/mf2', 'directory');

      // Mock child_process.execAsync
      const childProcessMock = await import('child_process');
      vi.mocked(childProcessMock.exec).mockImplementation((cmd, opts, callback) => {
        if (callback) {
          callback(null, { stdout: 'Server started', stderr: '' } as any, '');
        }
        return { stdout: 'Server started', stderr: '' } as any;
      });

      // Call the function under test
      await serveMicrofrontend(undefined, { port: '3000', host: 'localhost', open: true });

      // Verify exec is called
      expect(childProcessMock.exec).toHaveBeenCalled();
    });
  });
});