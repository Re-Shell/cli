import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs-extra';
import * as path from 'path';
import { createMicrofrontend } from '../src/commands/create-mf';

// Mock fs-extra and prompts modules
vi.mock('fs-extra');
vi.mock('prompts', () => ({
  default: vi.fn(() => Promise.resolve({
    template: 'react-ts',
    route: '/test-mf',
    standalone: false
  }))
}));

describe('CLI Command Tests', () => {
  const mockFs = fs as jest.Mocked<typeof fs>;
  const testDir = '/test/path';
  const testMfName = 'test-mf';
  
  beforeEach(() => {
    // Reset mocks
    vi.resetAllMocks();
    
    // Mock fs-extra methods
    mockFs.existsSync.mockReturnValue(false);
    mockFs.mkdirSync.mockImplementation(() => undefined);
    mockFs.writeFileSync.mockImplementation(() => undefined);
  });
  
  afterEach(() => {
    vi.clearAllMocks();
  });
  
  describe('createMicrofrontend', () => {
    it('should create microfrontend directory structure', async () => {
      // Mock path.resolve to return test path
      vi.spyOn(path, 'resolve').mockReturnValue(`${testDir}/${testMfName}`);
      
      // Call the function under test
      await createMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        standalone: false
      });
      
      // Verify directories are created
      expect(mockFs.mkdirSync).toHaveBeenCalledWith(`${testDir}/${testMfName}`);
      expect(mockFs.mkdirSync).toHaveBeenCalledWith(path.join(`${testDir}/${testMfName}`, 'src'));
      expect(mockFs.mkdirSync).toHaveBeenCalledWith(path.join(`${testDir}/${testMfName}`, 'public'));
    });
    
    it('should handle existing directory error', async () => {
      // Mock existsSync to return true (directory exists)
      mockFs.existsSync.mockReturnValue(true);
      
      // Mock path.resolve to return test path
      vi.spyOn(path, 'resolve').mockReturnValue(`${testDir}/${testMfName}`);
      
      // Verify function throws error for existing directory
      await expect(createMicrofrontend(testMfName, {}))
        .rejects.toThrow(`Directory already exists: ${testDir}/${testMfName}`);
      
      // Verify no directories are created
      expect(mockFs.mkdirSync).not.toHaveBeenCalled();
    });
    
    it('should create proper package.json', async () => {
      // Mock path.resolve to return test path
      vi.spyOn(path, 'resolve').mockReturnValue(`${testDir}/${testMfName}`);
      
      // Call the function under test
      await createMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        standalone: false
      });
      
      // Verify package.json is created with correct name
      expect(mockFs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('package.json'),
        expect.stringContaining('@re-shell/test-mf')
      );
    });
    
    it('should create standalone package correctly', async () => {
      // Mock path.resolve to return test path
      vi.spyOn(path, 'resolve').mockReturnValue(`${testDir}/${testMfName}`);
      
      // Call the function under test
      await createMicrofrontend(testMfName, {
        org: 're-shell',
        template: 'react-ts',
        standalone: true
      });
      
      // Verify package.json is created with correct name for standalone
      expect(mockFs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('package.json'),
        expect.stringContaining('"name": "test-mf"')
      );
      
      // Verify eventBus file is created for standalone
      expect(mockFs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('eventBus.ts'),
        expect.stringMatching(/Simple event bus/)
      );
    });
  });
});