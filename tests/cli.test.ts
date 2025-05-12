import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs-extra';
import * as path from 'path';
import { addMicrofrontend } from '../src/commands/add';
import { createProject } from '../src/commands/create';
import { removeMicrofrontend } from '../src/commands/remove';
import { listMicrofrontends } from '../src/commands/list';

// Mock the modules
vi.mock('fs-extra', () => ({
  existsSync: vi.fn(),
  mkdirSync: vi.fn(),
  writeFileSync: vi.fn(),
  readFileSync: vi.fn(() => JSON.stringify({ version: '0.2.0' })),
  readJsonSync: vi.fn(() => ({ microfrontends: [] })),
  removeSync: vi.fn()
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

describe('CLI Command Tests', () => {
  const testDir = '/test/path';
  const testMfName = 'test-mf';
  const testProjectName = 'test-project';

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();

    // Mock process.cwd
    vi.spyOn(process, 'cwd').mockReturnValue(testDir);
    
    // Setup default mock behavior
    vi.mocked(fs.existsSync).mockReturnValue(false);
    vi.mocked(path.resolve).mockImplementation((dir, ...segments) => {
      if (segments.includes('test-mf')) {
        return `${dir}/test-mf`;
      }
      if (segments.includes('test-project')) {
        return `${dir}/test-project`;
      }
      return `${dir}/${segments.join('/')}`;
    });
  });
  
  afterEach(() => {
    vi.clearAllMocks();
  });
  
  describe('addMicrofrontend', () => {
    it('should create microfrontend directory structure', async () => {
      // Mock existsSync for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json' || p === 'apps') {
          return true;
        }
        return false;
      });
      
      // Call the function under test
      await addMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        route: '/test-mf',
        port: '5173'
      });

      // Verify directories are created
      expect(fs.mkdirSync).toHaveBeenCalled();
      expect(fs.writeFileSync).toHaveBeenCalled();
      
      // Check that files were created
      const writeFileCalls = vi.mocked(fs.writeFileSync).mock.calls;
      const createdFiles = writeFileCalls.map(call => call[0]);
      
      expect(createdFiles).toContain(expect.stringContaining('package.json'));
      expect(createdFiles).toContain(expect.stringContaining('vite.config.ts'));
      expect(createdFiles).toContain(expect.stringContaining('App.tsx'));
    });
    
    it('should handle existing directory error', async () => {
      // Mock existsSync to return true for directory existence check
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        // For Re-Shell project detection
        if (p === 'package.json' || p === 'apps') {
          return true;
        }
        
        // For directory existence check
        if (p.includes(testMfName)) {
          return true;
        }
        
        return false;
      });

      // Expect function to throw error for existing directory
      await expect(async () => {
        await addMicrofrontend(testMfName, {
          org: 're-shell',
          template: 'react-ts',
          route: '/test-mf',
          port: '5173'
        });
      }).rejects.toThrow(/Directory already exists/);
      
      // Verify no directories are created
      expect(fs.mkdirSync).not.toHaveBeenCalled();
    });
    
    it('should create proper package.json for Re-Shell project', async () => {
      // Mock existsSync for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json' || p === 'apps') {
          return true;
        }
        return false;
      });

      // Call the function under test
      await addMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        route: '/test-mf',
        port: '5173'
      });

      // Verify package.json is created with correct content
      const writeFileCalls = vi.mocked(fs.writeFileSync).mock.calls;
      const packageJsonCall = writeFileCalls.find(call => 
        call[0].toString().includes('package.json')
      );
      
      expect(packageJsonCall).toBeDefined();
      expect(packageJsonCall[1]).toContain('@re-shell/test-mf');
    });

    it('should create standalone package correctly', async () => {
      // Mock existsSync for non-Re-Shell project
      vi.mocked(fs.existsSync).mockReturnValue(false);

      // Call the function under test
      await addMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        route: '/test-mf',
        port: '5173'
      });

      // Verify eventBus file is created for standalone
      const writeFileCalls = vi.mocked(fs.writeFileSync).mock.calls;
      
      // Verify package.json has correct name
      const packageJsonCall = writeFileCalls.find(call => 
        call[0].toString().includes('package.json')
      );
      
      expect(packageJsonCall).toBeDefined();
      expect(packageJsonCall[1]).toContain('"name": "test-mf"');
      
      // Verify eventBus file exists
      const eventBusCall = writeFileCalls.find(call => 
        call[0].toString().includes('eventBus')
      );
      
      expect(eventBusCall).toBeDefined();
      expect(eventBusCall[1]).toContain('Simple event bus');
    });
  });

  describe('createProject', () => {
    it('should create a Re-Shell project structure', async () => {
      // Call the function under test
      await createProject(testProjectName, {
        org: 're-shell',
        template: 'react-ts',
        packageManager: 'pnpm'
      });

      // Verify package.json is created
      const writeFileCalls = vi.mocked(fs.writeFileSync).mock.calls;
      const packageJsonCall = writeFileCalls.find(call => 
        call[0].toString().includes('package.json')
      );
      
      expect(packageJsonCall).toBeDefined();
      expect(packageJsonCall[1]).toContain('"name": "test-project"');
    });

    it('should handle existing project directory error', async () => {
      // Mock existsSync to return true (directory exists)
      vi.mocked(fs.existsSync).mockReturnValue(true);

      // Verify function throws error for existing directory
      await expect(async () => {
        await createProject(testProjectName, {
          org: 're-shell',
          template: 'react-ts',
          packageManager: 'pnpm'
        });
      }).rejects.toThrow(/already exists/);

      // Verify no directories are created
      expect(fs.mkdirSync).not.toHaveBeenCalled();
    });
  });

  describe('removeMicrofrontend', () => {
    it('should remove a microfrontend', async () => {
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

      // Call the function under test
      await removeMicrofrontend(testMfName, { force: true });

      // Verify remove is called
      expect(fs.removeSync).toHaveBeenCalled();
    });

    it('should throw error if microfrontend does not exist', async () => {
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

      // Verify function throws error for non-existent microfrontend
      await expect(async () => {
        await removeMicrofrontend(testMfName, { force: true });
      }).rejects.toThrow(/not found/);
    });
  });

  describe('listMicrofrontends', () => {
    it('should list microfrontends', async () => {
      // Mock for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json') {
          return true;
        }
        return false;
      });
      
      // Mock readJsonSync to return project configuration with microfrontends
      vi.mocked(fs.readJsonSync).mockImplementation((p) => {
        if (p === `${testDir}/package.json`) {
          return {
            workspaces: ['apps/*']
          };
        }
        
        if (p.includes('apps/mf1/package.json')) {
          return {
            name: '@re-shell/mf1',
            reshell: { route: '/mf1' }
          };
        }
        
        if (p.includes('apps/mf2/package.json')) {
          return {
            name: '@re-shell/mf2',
            reshell: { route: '/mf2' }
          };
        }
        
        return {};
      });
      
      // Mock directory content
      vi.mocked(fs).readdirSync = vi.fn().mockReturnValue(['mf1', 'mf2']);

      // Call the function under test
      await listMicrofrontends({});

      // Verify console.log is called with microfrontend info
      expect(console.log).toHaveBeenCalled();
    });

    it('should output JSON when json option is true', async () => {
      // Mock for Re-Shell project detection
      vi.mocked(fs.existsSync).mockImplementation((p) => {
        if (p === 'package.json') {
          return true;
        }
        return false;
      });
      
      // Mock readJsonSync to return project configuration with microfrontends
      vi.mocked(fs.readJsonSync).mockImplementation((p) => {
        if (p === `${testDir}/package.json`) {
          return {
            workspaces: ['apps/*']
          };
        }
        
        if (p.includes('apps/mf1/package.json')) {
          return {
            name: '@re-shell/mf1',
            reshell: { route: '/mf1' }
          };
        }
        
        if (p.includes('apps/mf2/package.json')) {
          return {
            name: '@re-shell/mf2',
            reshell: { route: '/mf2' }
          };
        }
        
        return {};
      });
      
      // Mock directory content
      vi.mocked(fs).readdirSync = vi.fn().mockReturnValue(['mf1', 'mf2']);

      // Call the function under test
      await listMicrofrontends({ json: true });

      // Verify console.log is called with JSON
      expect(console.log).toHaveBeenCalledWith(expect.stringContaining('['));
    });
  });
});