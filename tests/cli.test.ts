import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs-extra';
import * as path from 'path';
import { createMicrofrontend } from '../src/commands/create-mf';

// Mock fs-extra and prompts modules
vi.mock('fs-extra', () => ({
  existsSync: vi.fn(),
  mkdirSync: vi.fn(),
  writeFileSync: vi.fn()
}));

vi.mock('prompts', () => ({
  default: vi.fn(() => Promise.resolve({
    template: 'react-ts',
    route: '/test-mf',
    standalone: false
  }))
}));

vi.mock('path', () => ({
  resolve: vi.fn(),
  join: vi.fn((base, ...args) => [base, ...args].join('/'))
}));

describe('CLI Command Tests', () => {
  const testDir = '/test/path';
  const testMfName = 'test-mf';

  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();

    // Mock fs-extra methods
    vi.mocked(fs.existsSync).mockReturnValue(false);
    vi.mocked(fs.mkdirSync).mockImplementation(() => undefined);
    vi.mocked(fs.writeFileSync).mockImplementation(() => undefined);

    // Mock path.resolve
    vi.mocked(path.resolve).mockReturnValue(`${testDir}/${testMfName}`);
  });
  
  afterEach(() => {
    vi.clearAllMocks();
  });
  
  describe('createMicrofrontend', () => {
    it('should create microfrontend directory structure', async () => {
      // Call the function under test
      await createMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        standalone: false
      });

      // Verify directories are created
      expect(fs.mkdirSync).toHaveBeenCalledWith(`${testDir}/${testMfName}`);
      expect(fs.mkdirSync).toHaveBeenCalledWith(`${testDir}/${testMfName}/src`);
      expect(fs.mkdirSync).toHaveBeenCalledWith(`${testDir}/${testMfName}/public`);
    });
    
    it('should handle existing directory error', async () => {
      // Mock existsSync to return true (directory exists)
      vi.mocked(fs.existsSync).mockReturnValue(true);

      // Verify function throws error for existing directory
      await expect(createMicrofrontend(testMfName, {}))
        .rejects.toThrow(`Directory already exists: ${testDir}/${testMfName}`);

      // Verify no directories are created
      expect(fs.mkdirSync).not.toHaveBeenCalled();
    });
    
    it('should create proper package.json', async () => {
      // Call the function under test
      await createMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        standalone: false
      });

      // Verify package.json is created with correct name
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('package.json'),
        expect.stringContaining('@re-shell/test-mf')
      );
    });

    it('should create standalone package correctly', async () => {
      // Call the function under test
      await createMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        standalone: true
      });

      // Verify package.json is created with correct name for standalone
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('package.json'),
        expect.stringContaining('"name": "test-mf"')
      );

      // Verify eventBus file is created for standalone
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('eventBus.ts'),
        expect.stringMatching(/Simple event bus/)
      );
    });
  });
});