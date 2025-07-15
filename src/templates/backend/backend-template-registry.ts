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
import { ShelfGenerator } from './dart/shelf-generator';
import { Angel3Generator } from './dart/angel3-generator';
import { ConduitGenerator } from './dart/conduit-generator';

// Haskell templates
import { ServantGenerator } from './haskell/servant-generator';
import { YesodGenerator } from './haskell/yesod-generator';
import { ScottyGenerator } from './haskell/scotty-generator';
import { SpockGenerator } from './haskell/spock-generator';

// Deno templates
import { OakGenerator } from './deno/oak-generator';
import { FreshGenerator } from './deno/fresh-generator';
import { AlephGenerator } from './deno/aleph-generator';

// Bun templates
import { ElysiaGenerator } from './bun/elysia-generator';
import { HonoGenerator } from './bun/hono-generator';

// Zig templates
import { HttpServerGenerator } from './zig/http-server-generator';
import { ZapGenerator } from './zig/zap-generator';

// Kotlin templates
import KtorGenerator from './kotlin/ktor-generator';
import SpringBootKotlinGenerator from './kotlin/spring-boot-generator';
import MicronautGenerator from './kotlin/micronaut-generator';

// Scala templates
import AkkaHttpGenerator from './scala/akka-http-generator';
import PlayGenerator from './scala/play-generator';
import Http4sGenerator from './scala/http4s-generator';

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

    // Dart Templates
    this.register({
      name: 'dart-shelf',
      language: 'Dart',
      framework: 'Shelf',
      description: 'Composable web server middleware framework with hot reload support',
      features: [
        'Middleware pipeline',
        'Hot reload development',
        'JWT authentication',
        'PostgreSQL integration',
        'Redis caching',
        'Rate limiting',
        'CORS support',
        'Request validation',
        'OpenAPI documentation'
      ],
      defaultPort: 8080,
      generator: ShelfGenerator
    });

    this.register({
      name: 'dart-angel3',
      language: 'Dart',
      framework: 'Angel3',
      description: 'Full-stack server-side framework with batteries included',
      features: [
        'Full MVC framework',
        'Angel3 ORM with migrations',
        'WebSocket support',
        'GraphQL integration',
        'Template engines',
        'Service container',
        'Dependency injection',
        'Plugin system',
        'Production mode optimizations'
      ],
      defaultPort: 3000,
      generator: Angel3Generator
    });

    this.register({
      name: 'dart-conduit',
      language: 'Dart',
      framework: 'Conduit',
      description: 'Modern HTTP framework with built-in ORM and OpenAPI support',
      features: [
        'Built-in ORM',
        'Database migrations',
        'OpenAPI generation',
        'OAuth2 server',
        'Multi-threading',
        'CLI tooling',
        'Test harness',
        'Health checks',
        'Type-safe routing'
      ],
      defaultPort: 8080,
      generator: ConduitGenerator
    });

    // Haskell Templates
    this.register({
      name: 'haskell-servant',
      language: 'Haskell',
      framework: 'Servant',
      description: 'Type-safe REST API framework with automatic client generation',
      features: [
        'Type-level API definition',
        'Automatic client generation',
        'OpenAPI/Swagger generation',
        'JWT authentication',
        'PostgreSQL integration',
        'Type-safe SQL queries',
        'Property-based testing',
        'Automatic API documentation',
        'Compile-time guarantees'
      ],
      defaultPort: 8080,
      generator: ServantGenerator
    });

    this.register({
      name: 'haskell-yesod',
      language: 'Haskell',
      framework: 'Yesod',
      description: 'Type-safe, RESTful web framework with compile-time templates',
      features: [
        'Type-safe URLs',
        'Compile-time templates',
        'Persistent ORM',
        'Authentication system',
        'Form handling',
        'Internationalization',
        'Widget system',
        'Type-safe SQL',
        'Development server'
      ],
      defaultPort: 3000,
      generator: YesodGenerator
    });

    this.register({
      name: 'haskell-scotty',
      language: 'Haskell',
      framework: 'Scotty',
      description: 'Haskell web framework inspired by Ruby\'s Sinatra',
      features: [
        'Sinatra-inspired DSL',
        'Lightweight and fast',
        'WAI/Warp based',
        'Simple routing',
        'Middleware support',
        'JSON handling',
        'PostgreSQL integration',
        'JWT authentication',
        'Async request handling'
      ],
      defaultPort: 3000,
      generator: ScottyGenerator
    });

    this.register({
      name: 'haskell-spock',
      language: 'Haskell',
      framework: 'Spock',
      description: 'Lightweight Haskell web framework for rapid development',
      features: [
        'Type-safe routing',
        'Session management',
        'Database pooling',
        'CSRF protection',
        'Type-safe actions',
        'Middleware system',
        'WebSocket support',
        'RESTful design',
        'Hot code reload'
      ],
      defaultPort: 3000,
      generator: SpockGenerator
    });

    // Deno Templates
    this.register({
      name: 'deno-oak',
      language: 'Deno',
      framework: 'Oak',
      description: 'Middleware framework for Deno\'s native HTTP server',
      features: [
        'Express-like middleware',
        'Router with params',
        'TypeScript native',
        'JWT authentication',
        'CORS support',
        'Rate limiting',
        'Request validation',
        'PostgreSQL integration',
        'Redis caching'
      ],
      defaultPort: 8000,
      generator: OakGenerator
    });

    this.register({
      name: 'deno-fresh',
      language: 'Deno',
      framework: 'Fresh',
      description: 'Next-gen web framework with islands architecture',
      features: [
        'Islands architecture',
        'Server-side rendering',
        'File-based routing',
        'TypeScript by default',
        'Zero runtime overhead',
        'Preact components',
        'Tailwind CSS support',
        'Edge deployment ready',
        'No build step'
      ],
      defaultPort: 8000,
      generator: FreshGenerator
    });

    this.register({
      name: 'deno-aleph',
      language: 'Deno',
      framework: 'Aleph.js',
      description: 'React SSR/SSG framework for Deno',
      features: [
        'React SSR/SSG',
        'File-based routing',
        'Hot module replacement',
        'TypeScript support',
        'API routes',
        'CSS-in-JS support',
        'Import maps',
        'Optimized builds',
        'Deploy anywhere'
      ],
      defaultPort: 8000,
      generator: AlephGenerator
    });

    // Bun Templates
    this.register({
      name: 'bun-elysia',
      language: 'Bun',
      framework: 'Elysia',
      description: 'Fast and friendly Bun web framework with end-to-end type safety',
      features: [
        'End-to-end type safety',
        'Auto-generated clients',
        'Swagger documentation',
        'Blazing fast performance',
        'Schema validation',
        'JWT authentication',
        'WebSocket support',
        'File uploads',
        'Plugin system'
      ],
      defaultPort: 3000,
      generator: ElysiaGenerator
    });

    this.register({
      name: 'bun-hono',
      language: 'Bun',
      framework: 'Hono',
      description: 'Small, simple, and ultrafast web framework for the Edge',
      features: [
        'Ultra-lightweight',
        'Edge computing ready',
        'Express-like syntax',
        'TypeScript support',
        'Middleware system',
        'JWT authentication',
        'OpenAPI support',
        'Cross-runtime',
        'RPC mode'
      ],
      defaultPort: 3000,
      generator: HonoGenerator
    });

    // Zig Templates
    this.register({
      name: 'zig-http',
      language: 'Zig',
      framework: 'HTTP Server',
      description: 'Native HTTP server using Zig\'s standard library',
      features: [
        'Zero dependencies',
        'Manual memory management',
        'Minimal footprint',
        'JWT authentication',
        'JSON parsing',
        'SQLite support',
        'Compile-time safety',
        'Cross-compilation',
        'Fast compilation'
      ],
      defaultPort: 8080,
      generator: HttpServerGenerator
    });

    this.register({
      name: 'zig-zap',
      language: 'Zig',
      framework: 'Zap',
      description: 'Blazingly fast web framework for Zig',
      features: [
        'High performance',
        'WebSocket support',
        'Middleware system',
        'Static file serving',
        'JSON handling',
        'Route parameters',
        'Request validation',
        'Built-in auth',
        'Production ready'
      ],
      defaultPort: 8080,
      generator: ZapGenerator
    });

    // Kotlin Templates
    this.register({
      name: 'kotlin-ktor',
      language: 'kotlin',
      framework: 'Ktor',
      description: 'Lightweight async framework with coroutines support',
      features: [
        'Kotlin coroutines',
        'Async request handling',
        'Lightweight and modular',
        'JWT authentication',
        'Exposed ORM integration',
        'WebSocket support',
        'Content negotiation',
        'Rate limiting',
        'Metrics with Micrometer'
      ],
      defaultPort: 8080,
      generator: KtorGenerator
    });

    this.register({
      name: 'kotlin-spring-boot',
      language: 'kotlin',
      framework: 'Spring Boot',
      description: 'Enterprise Java framework with full Kotlin support',
      features: [
        'Spring ecosystem',
        'Spring Data JPA',
        'Spring Security',
        'Actuator metrics',
        'OpenAPI documentation',
        'Flyway migrations',
        'Redis caching',
        'AOP support',
        'Production-ready features'
      ],
      defaultPort: 8080,
      generator: SpringBootKotlinGenerator
    });

    this.register({
      name: 'kotlin-micronaut',
      language: 'kotlin',
      framework: 'Micronaut',
      description: 'Modern JVM framework with GraalVM native support',
      features: [
        'GraalVM native images',
        'Compile-time DI',
        'Reactive programming',
        'Micronaut Data',
        'Cloud-native features',
        'Fast startup time',
        'Low memory footprint',
        'Built-in security',
        'Distributed tracing'
      ],
      defaultPort: 8080,
      generator: MicronautGenerator
    });

    // Scala Templates
    this.register({
      name: 'scala-akka-http',
      language: 'Scala',
      framework: 'Akka HTTP',
      description: 'High-performance toolkit for building REST/HTTP-based services',
      features: [
        'Actor model',
        'Streaming HTTP',
        'Async non-blocking',
        'Type-safe routing',
        'WebSocket support',
        'JWT authentication',
        'Swagger integration',
        'Akka Streams',
        'Clustering support'
      ],
      defaultPort: 8080,
      generator: AkkaHttpGenerator
    });

    this.register({
      name: 'scala-play',
      language: 'Scala',
      framework: 'Play Framework',
      description: 'Reactive web framework for modern web applications',
      features: [
        'MVC architecture',
        'Hot reload',
        'Built-in testing',
        'Async I/O',
        'RESTful by default',
        'WebSocket support',
        'Slick ORM',
        'Action composition',
        'Production ready'
      ],
      defaultPort: 9000,
      generator: PlayGenerator
    });

    this.register({
      name: 'scala-http4s',
      language: 'Scala',
      framework: 'http4s',
      description: 'Typeful, functional, streaming HTTP for Scala',
      features: [
        'Pure functional',
        'Cats Effect',
        'FS2 streaming',
        'Type-safe routing',
        'Doobie integration',
        'JWT authentication',
        'WebSocket support',
        'Prometheus metrics',
        'Tapir integration'
      ],
      defaultPort: 8080,
      generator: Http4sGenerator
    });

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