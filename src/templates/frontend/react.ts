import { BaseTemplate, TemplateFile, TemplateContext } from './index';
import { FrameworkConfig } from '../utils/framework';

export class ReactTemplate extends BaseTemplate {
  constructor(framework: FrameworkConfig, context: TemplateContext) {
    super(framework, context);
  }

  async generateFiles(): Promise<TemplateFile[]> {
    const files: TemplateFile[] = [];
    const { hasTypeScript } = this.context;
    const ext = hasTypeScript ? 'tsx' : 'jsx';
    const configExt = hasTypeScript ? 'ts' : 'js';

    // Package.json
    files.push({
      path: 'package.json',
      content: JSON.stringify(this.generatePackageJson(), null, 2)
    });

    // Vite config
    files.push({
      path: `vite.config.${configExt}`,
      content: this.generateViteConfig()
    });

    // TypeScript config (if TypeScript)
    if (hasTypeScript) {
      files.push({
        path: 'tsconfig.json',
        content: this.generateTsConfig()
      });
    }

    // ESLint config
    files.push({
      path: '.eslintrc.js',
      content: this.generateEslintConfig()
    });

    // Main entry file
    files.push({
      path: `src/index.${ext}`,
      content: this.generateIndexFile()
    });

    // App component
    files.push({
      path: `src/App.${ext}`,
      content: this.generateAppComponent()
    });

    // Event bus (if needed)
    files.push({
      path: `src/eventBus.${hasTypeScript ? 'ts' : 'js'}`,
      content: this.generateEventBus()
    });

    // HTML file for development
    files.push({
      path: 'public/index.html',
      content: this.generateHtmlFile()
    });

    // README
    files.push({
      path: 'README.md',
      content: this.generateReadme()
    });

    // CSS file
    files.push({
      path: 'src/App.css',
      content: this.generateCssFile()
    });

    return files;
  }

  private generateIndexFile(): string {
    const { normalizedName, hasTypeScript } = this.context;
    const componentName = normalizedName.charAt(0).toUpperCase() + normalizedName.slice(1).replace(/-./g, x => x[1].toUpperCase());

    if (hasTypeScript) {
      return `import React from 'react';
import { createRoot, Root } from 'react-dom/client';
import App from './App';
import { eventBus } from './eventBus';

// Extend window interface for TypeScript
declare global {
  interface Window {
    ${componentName}: {
      mount: (containerId: string) => void;
      unmount: () => void;
      root?: Root;
    };
  }
}

// Entry point for the microfrontend
// This gets exposed when the script is loaded
window.${componentName} = {
  mount: (containerId: string) => {
    const container = document.getElementById(containerId);
    if (!container) {
      console.error(\`Container element with ID "\${containerId}" not found\`);
      return;
    }

    // Using React 18's createRoot API
    const root = createRoot(container);
    root.render(<App />);
    
    // Notify shell that microfrontend is loaded
    eventBus.emit('microfrontend:loaded', { id: '${normalizedName}' });
    
    // Store root for unmounting
    window.${componentName}.root = root;
  },

  unmount: () => {
    if (window.${componentName}.root) {
      window.${componentName}.root.unmount();
      eventBus.emit('microfrontend:unloaded', { id: '${normalizedName}' });
    }
  }
};

// For development mode
if (process.env.NODE_ENV === 'development') {
  const devContainer = document.getElementById('root');
  if (devContainer) {
    window.${componentName}.mount('root');
  }
}

export default App;`;
    } else {
      return `import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { eventBus } from './eventBus';

// Entry point for the microfrontend
// This gets exposed when the script is loaded
window.${componentName} = {
  mount: (containerId) => {
    const container = document.getElementById(containerId);
    if (!container) {
      console.error(\`Container element with ID "\${containerId}" not found\`);
      return;
    }

    // Using React 18's createRoot API
    const root = createRoot(container);
    root.render(<App />);
    
    // Notify shell that microfrontend is loaded
    eventBus.emit('microfrontend:loaded', { id: '${normalizedName}' });
    
    // Store root for unmounting
    window.${componentName}.root = root;
  },

  unmount: () => {
    if (window.${componentName}.root) {
      window.${componentName}.root.unmount();
      eventBus.emit('microfrontend:unloaded', { id: '${normalizedName}' });
    }
  }
};

// For development mode
if (process.env.NODE_ENV === 'development') {
  const devContainer = document.getElementById('root');
  if (devContainer) {
    window.${componentName}.mount('root');
  }
}

export default App;`;
    }
  }

  private generateAppComponent(): string {
    const { normalizedName, hasTypeScript, name } = this.context;

    if (hasTypeScript) {
      return `import React from 'react';
import './App.css';

interface AppProps {}

function App(props: AppProps): JSX.Element {
  return (
    <div className="${normalizedName}-app">
      <header className="${normalizedName}-header">
        <h1>${name}</h1>
        <p>A React microfrontend built with Re-Shell CLI</p>
      </header>
      <main className="${normalizedName}-main">
        <section className="${normalizedName}-content">
          <h2>Welcome to ${name}</h2>
          <p>This microfrontend is ready for development!</p>
          <div className="${normalizedName}-features">
            <div className="feature-card">
              <h3>🚀 Fast Development</h3>
              <p>Hot module replacement and fast refresh</p>
            </div>
            <div className="feature-card">
              <h3>📦 Modular Architecture</h3>
              <p>Independent deployment and development</p>
            </div>
            <div className="feature-card">
              <h3>🔧 TypeScript Support</h3>
              <p>Type-safe development experience</p>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;`;
    } else {
      return `import React from 'react';
import './App.css';

function App() {
  return (
    <div className="${normalizedName}-app">
      <header className="${normalizedName}-header">
        <h1>${name}</h1>
        <p>A React microfrontend built with Re-Shell CLI</p>
      </header>
      <main className="${normalizedName}-main">
        <section className="${normalizedName}-content">
          <h2>Welcome to ${name}</h2>
          <p>This microfrontend is ready for development!</p>
          <div className="${normalizedName}-features">
            <div className="feature-card">
              <h3>🚀 Fast Development</h3>
              <p>Hot module replacement and fast refresh</p>
            </div>
            <div className="feature-card">
              <h3>📦 Modular Architecture</h3>
              <p>Independent deployment and development</p>
            </div>
            <div className="feature-card">
              <h3>⚡ Modern Tooling</h3>
              <p>Vite-powered build system</p>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;`;
    }
  }

  private generateEventBus(): string {
    const { hasTypeScript } = this.context;

    if (hasTypeScript) {
      return `// Simple event bus for microfrontend communication
interface EventBusEvents {
  'microfrontend:loaded': { id: string };
  'microfrontend:unloaded': { id: string };
  [key: string]: any;
}

type EventCallback<T = any> = (data: T) => void;

class EventBus {
  private events: Map<string, EventCallback[]> = new Map();

  emit<K extends keyof EventBusEvents>(event: K, data: EventBusEvents[K]): void {
    const callbacks = this.events.get(event as string);
    if (callbacks) {
      callbacks.forEach(callback => callback(data));
    }
  }

  on<K extends keyof EventBusEvents>(event: K, callback: EventCallback<EventBusEvents[K]>): void {
    if (!this.events.has(event as string)) {
      this.events.set(event as string, []);
    }
    this.events.get(event as string)!.push(callback);
  }

  off<K extends keyof EventBusEvents>(event: K, callback: EventCallback<EventBusEvents[K]>): void {
    const callbacks = this.events.get(event as string);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }
}

export const eventBus = new EventBus();`;
    } else {
      return `// Simple event bus for microfrontend communication
class EventBus {
  constructor() {
    this.events = new Map();
  }

  emit(event, data) {
    const callbacks = this.events.get(event);
    if (callbacks) {
      callbacks.forEach(callback => callback(data));
    }
  }

  on(event, callback) {
    if (!this.events.has(event)) {
      this.events.set(event, []);
    }
    this.events.get(event).push(callback);
  }

  off(event, callback) {
    const callbacks = this.events.get(event);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }
}

export const eventBus = new EventBus();`;
    }
  }

  private generateHtmlFile(): string {
    const { name } = this.context;
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${name} - Re-Shell Microfrontend</title>
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/index.${this.context.hasTypeScript ? 'tsx' : 'jsx'}"></script>
</body>
</html>`;
  }

  private generateCssFile(): string {
    const { normalizedName } = this.context;
    
    return `.${normalizedName}-app {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  padding: 20px;
  max-width: 1200px;
  margin: 0 auto;
}

.${normalizedName}-header {
  text-align: center;
  margin-bottom: 40px;
  padding: 20px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border-radius: 8px;
}

.${normalizedName}-header h1 {
  margin: 0 0 10px 0;
  font-size: 2.5rem;
  font-weight: 600;
}

.${normalizedName}-header p {
  margin: 0;
  font-size: 1.1rem;
  opacity: 0.9;
}

.${normalizedName}-main {
  margin-top: 20px;
}

.${normalizedName}-content h2 {
  color: #333;
  margin-bottom: 20px;
  font-size: 2rem;
  text-align: center;
}

.${normalizedName}-content > p {
  text-align: center;
  font-size: 1.1rem;
  color: #666;
  margin-bottom: 40px;
}

.${normalizedName}-features {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
  margin-top: 30px;
}

.feature-card {
  background: #f8f9fa;
  padding: 30px;
  border-radius: 8px;
  border: 1px solid #e9ecef;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.feature-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.feature-card h3 {
  margin: 0 0 15px 0;
  color: #495057;
  font-size: 1.3rem;
}

.feature-card p {
  margin: 0;
  color: #6c757d;
  line-height: 1.6;
}

@media (max-width: 768px) {
  .${normalizedName}-app {
    padding: 10px;
  }
  
  .${normalizedName}-header h1 {
    font-size: 2rem;
  }
  
  .${normalizedName}-features {
    grid-template-columns: 1fr;
  }
}`;
  }
}
