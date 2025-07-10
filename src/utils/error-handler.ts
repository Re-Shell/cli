import chalk from 'chalk';
import { ProgressSpinner } from './spinner';

// Enhanced error types for better handling
export class CLIError extends Error {
  constructor(
    message: string,
    public code: string = 'UNKNOWN_ERROR',
    public exitCode: number = 1,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'CLIError';
  }
}

export class NetworkError extends CLIError {
  constructor(message: string, originalError?: Error) {
    super(message, 'NETWORK_ERROR', 1, originalError);
    this.name = 'NetworkError';
  }
}

export class FileSystemError extends CLIError {
  constructor(message: string, originalError?: Error) {
    super(message, 'FILESYSTEM_ERROR', 1, originalError);
    this.name = 'FileSystemError';
  }
}

export class ValidationError extends CLIError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR', 1);
    this.name = 'ValidationError';
  }
}

// Signal handling to prevent terminal hanging
class ProcessManager {
  private static instance: ProcessManager;
  private cleanup: (() => void)[] = [];
  private isExiting = false;

  private constructor() {
    this.setupSignalHandlers();
  }

  static getInstance(): ProcessManager {
    if (!ProcessManager.instance) {
      ProcessManager.instance = new ProcessManager();
    }
    return ProcessManager.instance;
  }

  addCleanup(fn: () => void): void {
    this.cleanup.push(fn);
  }

  private setupSignalHandlers(): void {
    const signals = ['SIGINT', 'SIGTERM', 'SIGQUIT'] as const;
    
    signals.forEach(signal => {
      process.on(signal, () => {
        if (this.isExiting) return;
        this.isExiting = true;
        
        console.log(chalk.yellow(`\nReceived ${signal}, cleaning up...`));
        
        // Run cleanup functions
        this.cleanup.forEach(fn => {
          try {
            fn();
          } catch (error) {
            // Ignore cleanup errors
          }
        });
        
        // Ensure terminal state is restored
        if (process.stdout.isTTY) {
          process.stdout.write('\x1b[?25h'); // Show cursor
          process.stdout.write('\x1b[0m');   // Reset colors
        }
        
        process.exit(0);
      });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error(chalk.red('Uncaught Exception:'), error);
      this.cleanup.forEach(fn => {
        try {
          fn();
        } catch {}
      });
      process.exit(1);
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error(chalk.red('Unhandled Rejection at:'), promise, 'reason:', reason);
      this.cleanup.forEach(fn => {
        try {
          fn();
        } catch {}
      });
      process.exit(1);
    });

    // Handle EPIPE errors (broken pipe) to prevent terminal hanging
    process.stdout.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EPIPE') {
        // Broken pipe - terminal was closed, exit gracefully
        process.exit(0);
      }
    });

    process.stderr.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EPIPE') {
        // Broken pipe - terminal was closed, exit gracefully
        process.exit(0);
      }
    });
  }
}

// Initialize process manager
const processManager = ProcessManager.getInstance();

// Enhanced async operation wrapper with timeout and retry
export async function withTimeout<T>(
  operation: () => Promise<T>,
  timeoutMs = 30000,
  retries = 0
): Promise<T> {
  const attemptOperation = async (attempt: number): Promise<T> => {
    return Promise.race([
      operation(),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error(`Operation timed out after ${timeoutMs}ms`)), timeoutMs)
      )
    ]);
  };

  let lastError: Error;
  
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await attemptOperation(attempt);
    } catch (error) {
      lastError = error as Error;
      
      if (attempt < retries) {
        // Exponential backoff
        const delay = Math.min(1000 * Math.pow(2, attempt), 5000);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  throw lastError!;
}

// Enhanced error handler with better UX
export function handleError(error: Error, spinner?: ProgressSpinner): never {
  if (spinner) {
    spinner.stop();
    processManager.addCleanup(() => spinner.stop());
  }

  // Ensure terminal state is restored
  if (process.stdout.isTTY) {
    process.stdout.write('\x1b[?25h'); // Show cursor
    process.stdout.write('\x1b[0m');   // Reset colors
  }

  if (error instanceof CLIError) {
    console.error(chalk.red(`Error: ${error.message}`));
    
    if (error.originalError && process.env.DEBUG) {
      console.error(chalk.gray('Original error:'), error.originalError);
    }
    
    process.exit(error.exitCode);
  } else {
    console.error(chalk.red('Unexpected error:'), error.message);
    
    if (process.env.DEBUG) {
      console.error(chalk.gray('Stack trace:'), error.stack);
    }
    
    process.exit(1);
  }
}

// Async command wrapper with proper error handling
export function createAsyncCommand<T extends any[]>(
  fn: (...args: T) => Promise<void>
) {
  return async (...args: T): Promise<void> => {
    let spinner: ProgressSpinner | undefined;
    
    try {
      // Extract spinner from last argument if it exists
      const lastArg = args[args.length - 1];
      if (lastArg && typeof lastArg === 'object' && 'spinner' in lastArg) {
        spinner = (lastArg as any).spinner;
        processManager.addCleanup(() => spinner?.stop());
      }
      
      await fn(...args);
    } catch (error) {
      handleError(error as Error, spinner);
    }
  };
}

// Stream error handler to prevent EPIPE and other stream issues
export function setupStreamErrorHandlers(): void {
  // Handle stdout/stderr errors gracefully
  const handleStreamError = (err: NodeJS.ErrnoException) => {
    if (err.code === 'EPIPE') {
      // Broken pipe - terminal was closed, exit gracefully
      process.exit(0);
    }
    
    // For other stream errors, log but don't crash
    if (process.env.DEBUG) {
      console.error('Stream error:', err);
    }
  };

  process.stdout.on('error', handleStreamError);
  process.stderr.on('error', handleStreamError);
}

// Initialize stream error handlers
setupStreamErrorHandlers();

// Export process manager for cleanup registration
export { processManager };