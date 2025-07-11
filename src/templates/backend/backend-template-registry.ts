/**
 * Backend Template Registry
 * Central registry for all backend framework templates
 */

import { BackendTemplateGenerator } from './shared/backend-template-generator';

// Swift templates
import VaporGenerator from './swift/vapor-generator';
// import PerfectGenerator from './swift/perfect-generator';
// import KituraGenerator from './swift/kitura-generator';
// import HummingbirdGenerator from './swift/hummingbird-generator';

// Dart templates
// import ShelfGenerator from './dart/shelf-generator';
// import Angel3Generator from './dart/angel3-generator';
// import ConduitGenerator from './dart/conduit-generator';

// Existing templates (to be imported)
// import ExpressGenerator from './node/express-generator';
// import NestJSGenerator from './node/nestjs-generator';
// import FastifyGenerator from './node/fastify-generator';
// ... etc

export interface BackendTemplate {
  name: string;
  language: string;
  framework: string;
  description: string;
  features: string[];
  defaultPort: number;
  generator: new() => BackendTemplateGenerator;
}

export class BackendTemplateRegistry {
  private static templates = new Map<string, BackendTemplate>();

  static {
    // Register all backend templates
    this.registerTemplates();
  }

  private static registerTemplates(): void {
    // Swift Templates
    this.register({
      name: 'swift-vapor',
      language: 'Swift',
      framework: 'Vapor',
      description: 'Modern web framework for Swift with async/await, Fluent ORM, and WebSocket support',
      features: [
        'Async/await support',
        'Fluent ORM with migrations',
        'JWT authentication',
        'WebSocket support',
        'Redis integration',
        'Queue system',
        'Middleware pipeline',
        'Type-safe routing',
        'SwiftNIO powered'
      ],
      defaultPort: 8080,
      generator: VaporGenerator
    });

    /* Swift - Coming Soon
    this.register({
      name: 'swift-perfect',
      language: 'Swift',
      framework: 'Perfect',
      description: 'High-performance server-side Swift with HTTP/2 and WebSocket support',
      features: [
        'HTTP/2 support',
        'WebSocket server',
        'Perfect-ORM',
        'Perfect-Redis',
        'Perfect-Crypto',
        'Mustache templates',
        'MySQL/PostgreSQL/SQLite',
        'Threading and networking'
      ],
      defaultPort: 8181,
      generator: PerfectGenerator
    });

    this.register({
      name: 'swift-kitura',
      language: 'Swift',
      framework: 'Kitura',
      description: 'Enterprise Swift framework by IBM with cloud integration',
      features: [
        'IBM Cloud integration',
        'SwiftKuery ORM',
        'Stencil templating',
        'OpenAPI support',
        'Circuit breaker',
        'Health checks',
        'Metrics collection',
        'Docker optimized'
      ],
      defaultPort: 8090,
      generator: KituraGenerator
    });

    this.register({
      name: 'swift-hummingbird',
      language: 'Swift',
      framework: 'Hummingbird',
      description: 'Lightweight, flexible server framework built on SwiftNIO',
      features: [
        'Minimal footprint',
        'SwiftNIO based',
        'Async/await native',
        'Middleware system',
        'Type-safe routing',
        'WebSocket support',
        'GraphQL ready',
        'Lambda deployment'
      ],
      defaultPort: 8088,
      generator: HummingbirdGenerator
    });
    */

    // Add more templates as they are implemented...
  }

  static register(template: BackendTemplate): void {
    this.templates.set(template.name, template);
  }

  static get(name: string): BackendTemplate | undefined {
    return this.templates.get(name);
  }

  static getAll(): BackendTemplate[] {
    return Array.from(this.templates.values());
  }

  static getByLanguage(language: string): BackendTemplate[] {
    return this.getAll().filter(t => t.language.toLowerCase() === language.toLowerCase());
  }

  static getByFramework(framework: string): BackendTemplate[] {
    return this.getAll().filter(t => t.framework.toLowerCase() === framework.toLowerCase());
  }

  static getLanguages(): string[] {
    return [...new Set(this.getAll().map(t => t.language))].sort();
  }

  static getFrameworks(language?: string): string[] {
    const templates = language ? this.getByLanguage(language) : this.getAll();
    return [...new Set(templates.map(t => t.framework))].sort();
  }

  static generateTemplate(name: string, projectPath: string, options: any): Promise<void> {
    const template = this.get(name);
    if (!template) {
      throw new Error(`Backend template '${name}' not found`);
    }

    const generator = new template.generator();
    return generator.generate(projectPath, {
      ...options,
      port: options.port || template.defaultPort,
      name: options.name || 'backend-service'
    });
  }

  static getTemplateChoices(): Array<{ name: string; value: string }> {
    const choices: Array<{ name: string; value: string }> = [];
    const languages = this.getLanguages();

    for (const language of languages) {
      const templates = this.getByLanguage(language);
      
      // Add language header
      choices.push({
        name: `\\n${language.toUpperCase()} FRAMEWORKS`,
        value: ''
      });

      // Add templates for this language
      for (const template of templates) {
        const status = template.generator ? '✅' : '🚧';
        choices.push({
          name: `  ${status} ${template.framework} - ${template.description}`,
          value: template.name
        });
      }
    }

    return choices.filter(c => c.value !== ''); // Remove headers from actual choices
  }

  static async validateTemplate(name: string): Promise<boolean> {
    const template = this.get(name);
    if (!template) {
      return false;
    }

    // Check if generator class exists and can be instantiated
    try {
      new template.generator();
      return true;
    } catch {
      return false;
    }
  }

  static getTemplateInfo(name: string): string {
    const template = this.get(name);
    if (!template) {
      return `Template '${name}' not found`;
    }

    return `
${template.framework} (${template.language})
${'-'.repeat(50)}
${template.description}

Features:
${template.features.map(f => `  • ${f}`).join('\\n')}

Default Port: ${template.defaultPort}
Template ID: ${template.name}
`;
  }

  static searchTemplates(query: string): BackendTemplate[] {
    const lowerQuery = query.toLowerCase();
    return this.getAll().filter(t => 
      t.name.toLowerCase().includes(lowerQuery) ||
      t.language.toLowerCase().includes(lowerQuery) ||
      t.framework.toLowerCase().includes(lowerQuery) ||
      t.description.toLowerCase().includes(lowerQuery) ||
      t.features.some(f => f.toLowerCase().includes(lowerQuery))
    );
  }
}

// Export for CLI integration
export function listBackendTemplates(): void {
  console.log('\\n🚀 Available Backend Templates:\\n');

  const languages = BackendTemplateRegistry.getLanguages();
  
  for (const language of languages) {
    console.log(`\\n${language} Frameworks:`);
    console.log('─'.repeat(40));
    
    const templates = BackendTemplateRegistry.getByLanguage(language);
    for (const template of templates) {
      const status = template.generator ? '✅' : '🚧';
      console.log(`${status} ${template.name.padEnd(20)} - ${template.description}`);
    }
  }

  console.log('\\n✅ = Available, 🚧 = Coming Soon\\n');
}

// Template statistics
export function getTemplateStats(): {
  total: number;
  implemented: number;
  languages: number;
  byLanguage: Record<string, { total: number; implemented: number }>;
} {
  const templates = BackendTemplateRegistry.getAll();
  const languages = BackendTemplateRegistry.getLanguages();
  
  const stats = {
    total: templates.length,
    implemented: templates.filter(t => !!t.generator).length,
    languages: languages.length,
    byLanguage: {} as Record<string, { total: number; implemented: number }>
  };

  for (const language of languages) {
    const langTemplates = BackendTemplateRegistry.getByLanguage(language);
    stats.byLanguage[language] = {
      total: langTemplates.length,
      implemented: langTemplates.filter(t => !!t.generator).length
    };
  }

  return stats;
}

export default BackendTemplateRegistry;