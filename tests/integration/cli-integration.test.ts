import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { execSync } from 'child_process';
import * as fs from 'fs-extra';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

// Helper function to run CLI commands
function runCommand(command: string, cwd?: string): { stdout: string; stderr: string } {
  try {
    const stdout = execSync(command, {
      cwd: cwd || process.cwd(),
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).toString();
    return { stdout, stderr: '' };
  } catch (error: any) {
    return {
      stdout: error.stdout?.toString() || '',
      stderr: error.stderr?.toString() || error.message
    };
  }
}

describe('CLI Integration Tests', () => {
  const testDir = path.join(process.cwd(), 'test-output');
  const cliPath = path.join(process.cwd(), 'dist/index.js');
  
  // Generate unique project names for each test run to avoid conflicts
  const testProjectName = `test-project-${uuidv4().substring(0, 8)}`;
  const testMfName = `test-mf-${uuidv4().substring(0, 8)}`;
  
  // Setup test directory
  beforeAll(() => {
    // Ensure CLI is built
    try {
      execSync('pnpm run build', { stdio: 'ignore' });
    } catch (error) {
      console.error('Failed to build CLI:', error);
      throw error;
    }
    
    // Create test directory
    fs.ensureDirSync(testDir);
  });
  
  // Clean up test directory after all tests
  afterAll(() => {
    fs.removeSync(testDir);
  });
  
  // Clean up project directory after each test
  afterEach(() => {
    const projectDir = path.join(testDir, testProjectName);
    if (fs.existsSync(projectDir)) {
      fs.removeSync(projectDir);
    }
  });
  
  describe('create command', () => {
    it('should create a new project with default options', () => {
      const projectDir = path.join(testDir, testProjectName);
      
      // Run create command
      const { stdout, stderr } = runCommand(
        `node ${cliPath} create ${testProjectName} --package-manager npm`,
        testDir
      );
      
      // Check command output
      expect(stderr).toBe('');
      expect(stdout).toContain(`Re-Shell project "${testProjectName}" created successfully`);
      
      // Verify project structure
      expect(fs.existsSync(projectDir)).toBe(true);
      expect(fs.existsSync(path.join(projectDir, 'package.json'))).toBe(true);
      expect(fs.existsSync(path.join(projectDir, 'apps'))).toBe(true);
      expect(fs.existsSync(path.join(projectDir, 'apps/shell'))).toBe(true);
      expect(fs.existsSync(path.join(projectDir, 'packages'))).toBe(true);
      
      // Verify package.json content
      const packageJson = fs.readJsonSync(path.join(projectDir, 'package.json'));
      expect(packageJson.name).toBe(testProjectName);
      expect(packageJson.workspaces).toContain('apps/*');
      expect(packageJson.workspaces).toContain('packages/*');
    });
    
    it('should fail when creating a project with an existing name', () => {
      // First create a project
      runCommand(
        `node ${cliPath} create ${testProjectName} --package-manager npm`,
        testDir
      );
      
      // Try to create it again
      const { stderr } = runCommand(
        `node ${cliPath} create ${testProjectName} --package-manager npm`,
        testDir
      );
      
      // Check error message
      expect(stderr).toContain('already exists');
    });
  });
  
  describe('add command', () => {
    beforeEach(() => {
      // Create a test project for each test
      runCommand(
        `node ${cliPath} create ${testProjectName} --package-manager npm`,
        testDir
      );
    });
    
    it('should add a microfrontend to an existing project', () => {
      const projectDir = path.join(testDir, testProjectName);
      
      // Run add command
      const { stdout, stderr } = runCommand(
        `node ${cliPath} add ${testMfName} --template react-ts --route /${testMfName}`,
        projectDir
      );
      
      // Check command output
      expect(stderr).toBe('');
      expect(stdout).toContain(`Microfrontend "${testMfName}" added successfully`);
      
      // Verify microfrontend structure
      const mfDir = path.join(projectDir, 'apps', testMfName);
      expect(fs.existsSync(mfDir)).toBe(true);
      expect(fs.existsSync(path.join(mfDir, 'package.json'))).toBe(true);
      expect(fs.existsSync(path.join(mfDir, 'src'))).toBe(true);
      expect(fs.existsSync(path.join(mfDir, 'vite.config.ts'))).toBe(true);
      
      // Verify package.json content
      const packageJson = fs.readJsonSync(path.join(mfDir, 'package.json'));
      expect(packageJson.name).toBe(`@re-shell/${testMfName}`);
      expect(packageJson.reshell.route).toBe(`/${testMfName}`);
    });
    
    it('should fail when adding a microfrontend with an existing name', () => {
      const projectDir = path.join(testDir, testProjectName);
      
      // First add a microfrontend
      runCommand(
        `node ${cliPath} add ${testMfName} --template react-ts`,
        projectDir
      );
      
      // Try to add it again
      const { stderr } = runCommand(
        `node ${cliPath} add ${testMfName} --template react-ts`,
        projectDir
      );
      
      // Check error message
      expect(stderr).toContain('already exists');
    });
  });
  
  describe('list command', () => {
    beforeEach(() => {
      // Create a test project with microfrontends
      const projectDir = path.join(testDir, testProjectName);
      runCommand(
        `node ${cliPath} create ${testProjectName} --package-manager npm`,
        testDir
      );
      runCommand(
        `node ${cliPath} add ${testMfName} --template react-ts`,
        projectDir
      );
      runCommand(
        `node ${cliPath} add ${testMfName}-2 --template react-ts`,
        projectDir
      );
    });
    
    it('should list all microfrontends in the project', () => {
      const projectDir = path.join(testDir, testProjectName);
      
      // Run list command
      const { stdout, stderr } = runCommand(
        `node ${cliPath} list`,
        projectDir
      );
      
      // Check command output
      expect(stderr).toBe('');
      expect(stdout).toContain(testMfName);
      expect(stdout).toContain(`${testMfName}-2`);
    });
    
    it('should output JSON when --json flag is used', () => {
      const projectDir = path.join(testDir, testProjectName);
      
      // Run list command with JSON flag
      const { stdout, stderr } = runCommand(
        `node ${cliPath} list --json`,
        projectDir
      );
      
      // Check command output
      expect(stderr).toBe('');
      
      // Parse JSON output
      const jsonOutput = JSON.parse(stdout);
      expect(Array.isArray(jsonOutput)).toBe(true);
      expect(jsonOutput.some((mf: any) => mf.name.includes(testMfName))).toBe(true);
    });
  });
  
  describe('remove command', () => {
    beforeEach(() => {
      // Create a test project with a microfrontend
      const projectDir = path.join(testDir, testProjectName);
      runCommand(
        `node ${cliPath} create ${testProjectName} --package-manager npm`,
        testDir
      );
      runCommand(
        `node ${cliPath} add ${testMfName} --template react-ts`,
        projectDir
      );
    });
    
    it('should remove a microfrontend from the project', () => {
      const projectDir = path.join(testDir, testProjectName);
      const mfDir = path.join(projectDir, 'apps', testMfName);
      
      // Verify microfrontend exists before removal
      expect(fs.existsSync(mfDir)).toBe(true);
      
      // Run remove command with force flag to skip confirmation
      const { stdout, stderr } = runCommand(
        `node ${cliPath} remove ${testMfName} --force`,
        projectDir
      );
      
      // Check command output
      expect(stderr).toBe('');
      expect(stdout).toContain(`Microfrontend "${testMfName}" removed successfully`);
      
      // Verify microfrontend directory is removed
      expect(fs.existsSync(mfDir)).toBe(false);
    });
    
    it('should fail when removing a non-existent microfrontend', () => {
      const projectDir = path.join(testDir, testProjectName);
      
      // Run remove command for non-existent microfrontend
      const { stderr } = runCommand(
        `node ${cliPath} remove non-existent-mf --force`,
        projectDir
      );
      
      // Check error message
      expect(stderr).toContain('not found');
    });
  });
});
