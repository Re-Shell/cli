import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs-extra';
import * as path from 'path';
import { addMicrofrontend } from '../../src/commands/add';
import { createProject } from '../../src/commands/create';
import { removeMicrofrontend } from '../../src/commands/remove';
import { listMicrofrontends } from '../../src/commands/list';
import { buildMicrofrontend } from '../../src/commands/build';
import { serveMicrofrontend } from '../../src/commands/serve';

// Mock the modules
vi.mock('fs-extra', () => ({
  existsSync: vi.fn(),
  mkdirSync: vi.fn(),
  writeFileSync: vi.fn(),
  readFileSync: vi.fn(() => JSON.stringify({ version: '0.2.0' })),
  readJsonSync: vi.fn(() => ({ microfrontends: [] })),
  removeSync: vi.fn(),
  readdirSync: vi.fn(),
  ensureDirSync: vi.fn()
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
  const testDir = '/test/path';
  const testMfName = 'test-mf';
  const testProjectName = 'test-project';

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();

    // Mock process.cwd
    vi.spyOn(process, 'cwd').mockReturnValue(testDir);
    
    // Setup default mock behavior
    vi.mocked(fs.existsSync).mockImplementation((p) => {
      // Mock Re-Shell project directory structure to fix "Not in a Re-Shell project" error
      if (p === 'package.json' || p === 'apps' || p === 'packages' || 
          String(p).endsWith('/apps') || String(p).includes('apps')) {
        return true;
      }
      
      return false;
    });
    
    vi.mocked(path.resolve).mockImplementation((dir, ...segments) => {
      if (segments.includes('test-mf')) {
        return `${dir}/test-mf`;
      }
      if (segments.includes('test-project')) {
        return `${dir}/test-project`;
      }
      if (segments.includes('apps')) {
        return `${dir}/apps`;
      }
      return `${dir}/${segments.join('/')}`;
    });
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
        packageManager: 'yarn'
      });

      // Verify package.json is created with correct content
      const writeFileCalls = vi.mocked(fs.writeFileSync).mock.calls;
      const packageJsonCall = writeFileCalls.find(call => 
        call[0].toString().includes('package.json')
      );
      
      expect(packageJsonCall).toBeDefined();
      expect(packageJsonCall[1]).toContain('"name": "test-project"');
      expect(packageJsonCall[1]).toContain('"description": "Custom description"');
      expect(packageJsonCall[1]).toContain('"author": "custom-team"');
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
          packageManager: 'pnpm'
        });
      }).rejects.toThrow();
    });
  });
  
  describe('addMicrofrontend', () => {
    it('should add a microfrontend with custom options', async () => {
      // Mock existsSync for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json' || p === 'apps') {
          return true;
        }
        return false;
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

      // Verify package.json is created with correct content
      const writeFileCalls = vi.mocked(fs.writeFileSync).mock.calls;
      const packageJsonCall = writeFileCalls.find(call => 
        call[0].toString().includes('package.json')
      );
      
      expect(packageJsonCall).toBeDefined();
      expect(packageJsonCall[1]).toContain('@custom-org/test-mf');
      expect(packageJsonCall[1]).toContain('"description": "Custom description"');
      
      // Verify vite.config.ts has correct port
      const viteConfigCall = writeFileCalls.find(call => 
        call[0].toString().includes('vite.config.ts')
      );
      
      expect(viteConfigCall).toBeDefined();
      expect(viteConfigCall[1]).toContain('port: 8080');
    });
  });
  
  describe('removeMicrofrontend', () => {
    it('should prompt for confirmation when force flag is not set', async () => {
      // Mock for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json') {
          return true;
        }
        if (p.includes(testMfName)) {
          return true;
        }
        return false;
      });
      
      // Mock readJsonSync to return project configuration
      vi.mocked(fs.readJsonSync).mockReturnValue({
        workspaces: ['apps/*']
      });

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
      // Mock for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json') {
          return true;
        }
        return false;
      });
      
      // Mock readJsonSync to return project configuration
      vi.mocked(fs.readJsonSync).mockReturnValue({
        workspaces: ['apps/*']
      });
      
      // Mock empty apps directory
      vi.mocked(fs.readdirSync).mockReturnValue([]);

      // Call the function under test
      await listMicrofrontends({});

      // Verify console.log is called with "No microfrontends found"
      expect(console.log).toHaveBeenCalledWith(expect.stringContaining('No microfrontends found'));
    });
  });
  
  describe('buildMicrofrontend', () => {
    it('should build a specific microfrontend', async () => {
      // Mock for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json') {
          return true;
        }
        if (p.includes(testMfName)) {
          return true;
        }
        return false;
      });
      
      // Mock child_process.execAsync
      const childProcessMock = await import('child_process');
      const execAsyncMock = vi.fn().mockResolvedValue({ stdout: 'Build successful', stderr: '' });
      vi.mocked(childProcessMock.exec).mockImplementation((cmd, opts, callback) => {
        if (callback) {
          callback(null, { stdout: 'Build successful', stderr: '' } as any);
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
      // Mock for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json') {
          return true;
        }
        return false;
      });
      
      // Mock child_process.execAsync
      const childProcessMock = await import('child_process');
      vi.mocked(childProcessMock.exec).mockImplementation((cmd, opts, callback) => {
        if (callback) {
          callback(null, { stdout: 'Server started', stderr: '' } as any);
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
