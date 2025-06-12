import ora from 'ora';
import chalk from 'chalk';

interface SpinnerOptions {
  text: string;
  color?: string;
  stream?: NodeJS.WriteStream;
}

export class ProgressSpinner {
  private spinner: ora.Ora;
  private isInteractive: boolean;

  constructor(options: SpinnerOptions) {
    // Check if we're in an interactive terminal
    this.isInteractive = Boolean(
      process.stdout.isTTY && 
      process.env.TERM !== 'dumb' && 
      !process.env.CI &&
      !process.env.RE_SHELL_NO_SPINNER
    );

    if (this.isInteractive) {
      this.spinner = ora({
        text: options.text,
        color: options.color as any || 'cyan',
        stream: options.stream || process.stdout,
        // Force immediate output
        discardStdin: false
      });
    } else {
      // For non-interactive terminals, just log the message
      console.log(chalk.cyan('⏳'), options.text);
      this.spinner = ora(); // Create dummy spinner
    }
  }

  start(): this {
    if (this.isInteractive) {
      this.spinner.start();
      // Force flush the output
      process.stdout.write('');
    }
    return this;
  }

  succeed(text?: string): this {
    if (this.isInteractive) {
      this.spinner.succeed(text);
    } else {
      console.log(chalk.green('✅'), text || 'Done');
    }
    return this;
  }

  fail(text?: string): this {
    if (this.isInteractive) {
      this.spinner.fail(text);
    } else {
      console.log(chalk.red('❌'), text || 'Failed');
    }
    return this;
  }

  warn(text?: string): this {
    if (this.isInteractive) {
      this.spinner.warn(text);
    } else {
      console.log(chalk.yellow('⚠️'), text || 'Warning');
    }
    return this;
  }

  info(text?: string): this {
    if (this.isInteractive) {
      this.spinner.info(text);
    } else {
      console.log(chalk.blue('ℹ️'), text || 'Info');
    }
    return this;
  }

  stop(): this {
    if (this.isInteractive) {
      this.spinner.stop();
    }
    return this;
  }

  setText(text: string): this {
    if (this.isInteractive) {
      this.spinner.text = text;
    } else {
      console.log(chalk.cyan('⏳'), text);
    }
    return this;
  }

  setColor(color: string): this {
    if (this.isInteractive) {
      this.spinner.color = color as any;
    }
    return this;
  }

  clear(): this {
    if (this.isInteractive) {
      this.spinner.clear();
    }
    return this;
  }

  render(): this {
    if (this.isInteractive) {
      this.spinner.render();
      // Force flush
      process.stdout.write('');
    }
    return this;
  }
}

// Helper function to create a spinner
export function createSpinner(text: string, color?: string): ProgressSpinner {
  return new ProgressSpinner({ text, color });
}

// Helper function to force flush output
export function flushOutput(): void {
  if (process.stdout.write('')) {
    process.stdout.write('');
  }
  if (process.stderr.write('')) {
    process.stderr.write('');
  }
}

// Helper to detect if terminal supports interactive features
export function isInteractiveTerminal(): boolean {
  return Boolean(
    process.stdout.isTTY && 
    process.env.TERM !== 'dumb' && 
    !process.env.CI &&
    !process.env.RE_SHELL_NO_SPINNER
  );
}