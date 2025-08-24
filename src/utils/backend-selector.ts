import * as inquirer from 'inquirer';
import chalk from 'chalk';
import { BackendTemplate } from '../templates/types';
import { backendTemplates } from '../templates/backend';
import BackendTemplateRegistry from '../templates/backend/backend-template-registry';

interface TemplateCategory {
  name: string;
  value: string;
  description: string;
  icon: string;
  templates: BackendTemplate[];
}

export class BackendTemplateSelector {
  private categories: TemplateCategory[];

  constructor() {
    this.categories = this.categorizeTemplates();
  }

  private categorizeTemplates(): TemplateCategory[] {
    const categories: TemplateCategory[] = [
      {
        name: 'Node.js/TypeScript',
        value: 'nodejs',
        description: 'JavaScript/TypeScript frameworks for Node.js',
        icon: '🟨',
        templates: []
      },
      {
        name: 'Python',
        value: 'python',
        description: 'Python web frameworks and APIs',
        icon: '🐍',
        templates: []
      },
      {
        name: 'Go',
        value: 'go',
        description: 'High-performance Go frameworks',
        icon: '🐹',
        templates: []
      },
      {
        name: 'Kotlin',
        value: 'kotlin',
        description: 'Kotlin JVM frameworks',
        icon: '🏗️',
        templates: []
      }
    ];

    // Categorize templates by language
    Object.values(backendTemplates).forEach(template => {
      if (template.language === 'typescript' || template.language === 'javascript') {
        categories[0].templates.push(template);
      } else if (template.language === 'python') {
        categories[1].templates.push(template);
      } else if (template.language === 'go') {
        categories[2].templates.push(template);
      } else if (template.language === 'kotlin') {
        categories[3].templates.push(template);
      }
    });

    // Sort templates within each category by popularity/recommendation
    categories.forEach(category => {
      category.templates.sort((a, b) => {
        // Prioritize certain frameworks
        const priority: Record<string, number> = {
          'express': 1,
          'nestjs': 2,
          'fastify': 3,
          'fastapi': 1,
          'django': 2,
          'flask': 3,
          'gin': 1,
          'fiber': 2
        };
        
        const aPriority = priority[a.id] || 99;
        const bPriority = priority[b.id] || 99;
        
        return aPriority - bPriority;
      });
    });

    return categories.filter(cat => cat.templates.length > 0);
  }

  async selectTemplate(): Promise<BackendTemplate | null> {
    console.clear();
    console.log(chalk.bold.cyan('🚀 Re-Shell Backend Template Selector\n'));

    // First, select language/category
    const { category } = await inquirer.prompt([
      {
        type: 'list',
        name: 'category',
        message: 'Select a programming language:',
        choices: this.categories.map(cat => ({
          name: `${cat.icon}  ${cat.name} - ${cat.description}`,
          value: cat.value,
          short: cat.name
        }))
      }
    ]);

    const selectedCategory = this.categories.find(cat => cat.value === category);
    if (!selectedCategory) return null;

    console.clear();
    console.log(chalk.bold.cyan(`🚀 ${selectedCategory.name} Backend Frameworks\n`));

    // Show templates for selected category
    const choices = selectedCategory.templates.map(template => {
      const tags = template.tags.slice(0, 3).join(', ');
      const popularity = this.getPopularityStars(template.id);
      
      return {
        name: `${chalk.bold(template.displayName)}${popularity}\n   ${chalk.gray(template.description || tags)}`,
        value: template.id,
        short: template.displayName
      };
    });

    // Add back option
    choices.push({
      name: chalk.gray('← Back to language selection'),
      value: 'back',
      short: 'Back'
    });

    const { templateId } = await inquirer.prompt([
      {
        type: 'list',
        name: 'templateId',
        message: 'Select a framework:',
        choices,
        pageSize: 15
      }
    ]);

    if (templateId === 'back') {
      return this.selectTemplate();
    }

    const template = backendTemplates[templateId];
    
    // Show template details
    console.clear();
    this.showTemplateDetails(template);

    const { confirm } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'confirm',
        message: 'Use this template?',
        default: true
      }
    ]);

    if (!confirm) {
      return this.selectTemplate();
    }

    return template;
  }

  async selectTemplateWithRecommendations(useCase?: string): Promise<BackendTemplate | null> {
    console.clear();
    console.log(chalk.bold.cyan('🚀 Re-Shell Backend Template Selector\n'));

    const recommendations = this.getRecommendations(useCase);
    
    if (recommendations.length > 0) {
      console.log(chalk.yellow('📌 Recommended for your use case:\n'));
      
      const { quickSelect } = await inquirer.prompt([
        {
          type: 'list',
          name: 'quickSelect',
          message: 'Select from recommendations or browse all:',
          choices: [
            ...recommendations.map(rec => ({
              name: `${chalk.bold.green('★')} ${rec.template.displayName} - ${rec.reason}`,
              value: rec.template.id
            })),
            new inquirer.Separator(),
            {
              name: chalk.gray('Browse all templates →'),
              value: 'browse'
            }
          ]
        }
      ]);

      if (quickSelect !== 'browse') {
        const template = backendTemplates[quickSelect];
        this.showTemplateDetails(template);
        
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: 'Use this template?',
            default: true
          }
        ]);

        if (confirm) {
          return template;
        }
      }
    }

    return this.selectTemplate();
  }

  private getRecommendations(useCase?: string): Array<{ template: BackendTemplate; reason: string }> {
    const recommendations: Array<{ template: BackendTemplate; reason: string }> = [];

    if (!useCase) return recommendations;

    const useCaseLower = useCase.toLowerCase();

    // API Gateway
    if (useCaseLower.includes('gateway') || useCaseLower.includes('proxy')) {
      recommendations.push({
        template: backendTemplates.express,
        reason: 'Lightweight and perfect for API gateways'
      });
    }

    // Real-time
    if (useCaseLower.includes('realtime') || useCaseLower.includes('websocket') || useCaseLower.includes('chat')) {
      recommendations.push({
        template: backendTemplates.feathersjs,
        reason: 'Built-in real-time support with Socket.io'
      });
    }

    // Enterprise
    if (useCaseLower.includes('enterprise') || useCaseLower.includes('large')) {
      recommendations.push({
        template: backendTemplates.nestjs,
        reason: 'Enterprise-grade with DI and modular architecture'
      });
    }

    // High performance
    if (useCaseLower.includes('performance') || useCaseLower.includes('fast') || useCaseLower.includes('speed')) {
      recommendations.push({
        template: backendTemplates.gin,
        reason: 'Extremely fast Go framework'
      });
      recommendations.push({
        template: backendTemplates.fastify,
        reason: 'Fastest Node.js framework'
      });
    }

    // GraphQL
    if (useCaseLower.includes('graphql')) {
      recommendations.push({
        template: backendTemplates['apollo-server'],
        reason: 'Purpose-built for GraphQL APIs'
      });
    }

    // CMS
    if (useCaseLower.includes('cms') || useCaseLower.includes('content')) {
      recommendations.push({
        template: backendTemplates.strapi,
        reason: 'Headless CMS with admin panel'
      });
      recommendations.push({
        template: backendTemplates.django,
        reason: 'Includes powerful admin interface'
      });
    }

    // Microservices
    if (useCaseLower.includes('microservice') || useCaseLower.includes('micro')) {
      recommendations.push({
        template: backendTemplates.moleculer,
        reason: 'Built specifically for microservices'
      });
      recommendations.push({
        template: backendTemplates.fastapi,
        reason: 'Async Python perfect for microservices'
      });
    }

    return recommendations.slice(0, 3); // Return top 3 recommendations
  }

  private showTemplateDetails(template: BackendTemplate): void {
    console.log(chalk.bold.cyan(`\n📦 ${template.displayName}\n`));
    
    console.log(chalk.bold('Language:'), template.language);
    console.log(chalk.bold('Framework:'), template.framework);
    console.log(chalk.bold('Port:'), template.port);
    console.log(chalk.bold('Tags:'), template.tags.join(', '));
    
    if (template.dependencies) {
      console.log(chalk.bold('\nKey Dependencies:'));
      Object.entries(template.dependencies).slice(0, 5).forEach(([dep, version]) => {
        console.log(`  - ${dep}: ${version}`);
      });
    }

    console.log(chalk.bold('\nFeatures:'));
    this.getTemplateFeatures(template.id).forEach(feature => {
      console.log(`  ✓ ${feature}`);
    });

    console.log();
  }

  private getTemplateFeatures(templateId: string): string[] {
    const features: Record<string, string[]> = {
      express: ['Fast routing', 'Middleware support', 'Large ecosystem', 'REST APIs'],
      nestjs: ['Dependency injection', 'TypeScript first', 'Modular architecture', 'Enterprise ready'],
      fastify: ['High performance', 'Schema validation', 'TypeScript support', 'Plugin system'],
      feathersjs: ['Real-time events', 'Service oriented', 'Database agnostic', 'Authentication'],
      fastapi: ['Auto documentation', 'Type hints', 'Async support', 'High performance'],
      django: ['Admin panel', 'ORM included', 'Authentication', 'Full-featured'],
      gin: ['Blazing fast', 'Minimal footprint', 'Middleware support', 'JSON validation'],
      strapi: ['Headless CMS', 'Admin panel', 'REST & GraphQL', 'Plugin system'],
      'apollo-server': ['GraphQL first', 'Type safety', 'Federation', 'Subscriptions'],
      moleculer: ['Microservices', 'Service discovery', 'Load balancing', 'Event driven']
    };

    return features[templateId] || ['Modern framework', 'Production ready', 'Active community'];
  }

  private getPopularityStars(templateId: string): string {
    const popularity: Record<string, number> = {
      express: 5,
      nestjs: 5,
      fastify: 4,
      django: 5,
      fastapi: 5,
      flask: 4,
      gin: 5,
      feathersjs: 4,
      strapi: 4,
      'apollo-server': 4
    };

    const stars = popularity[templateId] || 3;
    return ' ' + chalk.yellow('★'.repeat(stars)) + chalk.gray('★'.repeat(5 - stars));
  }
}

// Interactive CLI function
export async function selectBackendTemplate(useCase?: string): Promise<BackendTemplate | null> {
  const selector = new BackendTemplateSelector();
  
  if (useCase) {
    return selector.selectTemplateWithRecommendations(useCase);
  }
  
  return selector.selectTemplate();
}

// Quick selection by ID
export function getBackendTemplate(templateId: string): BackendTemplate | null {
  return backendTemplates[templateId] || null;
}

// List all templates
export function listBackendTemplates(): void {
  console.log(chalk.bold.cyan('\n🚀 Available Backend Templates\n'));
  
  // Get all templates from the new registry
  const registryTemplates = BackendTemplateRegistry.getAll();
  
  // Group by language
  const languages = BackendTemplateRegistry.getLanguages();
  
  for (const language of languages) {
    const langTemplates = BackendTemplateRegistry.getByLanguage(language);
    const langIcon = getLanguageIcon(language);
    
    console.log(chalk.bold.yellow(`\n${langIcon} ${language}`));
    console.log(chalk.gray('─'.repeat(40)));
    
    for (const template of langTemplates) {
      const status = '✅'; // All registered templates should work
      const featuresText = template.features.slice(0, 3).join(', ');
      console.log(`  ${status} ${chalk.bold(template.framework.padEnd(15))} ${chalk.gray(featuresText)}`);
    }
  }
  
  // Also show old system templates for backward compatibility
  const oldSelector = new BackendTemplateSelector();
  const oldCategories = oldSelector['categories']; // Access private property
  
  if (oldCategories.length > 0) {
    console.log(chalk.bold.blue('\n🔄 Legacy Templates (Fallback System)'));
    console.log(chalk.gray('─'.repeat(40)));
    
    oldCategories.forEach(category => {
      if (category.templates.length > 0) {
        console.log(chalk.bold.cyan(`\n${category.name}:`));
        category.templates.forEach(template => {
          const tags = template.tags.slice(0, 3).join(', ');
          console.log(`  🔄 ${chalk.bold(template.displayName.padEnd(15))} ${chalk.gray(tags)}`);
        });
      }
    });
  }
  
  console.log(chalk.gray(`\nTotal Templates: ${registryTemplates.length + oldCategories.reduce((sum, cat) => sum + cat.templates.length, 0)}`));
  console.log();
}

function getLanguageIcon(language: string): string {
  const icons: Record<string, string> = {
    'Node.js': '🟨',
    'TypeScript': '🔷', 
    'JavaScript': '🟡',
    'Python': '🐍',
    'Go': '🐹',
    'Rust': '🦀',
    'Java': '☕',
    'Kotlin': '🏗️',
    'Scala': '🔴',
    'C#': '🟣',
    'Swift': '🧡',
    'Dart': '🎯',
    'Haskell': '💜',
    'Deno': '🦕',
    'Bun': '🍞',
    'Zig': '⚡',
    'Crystal': '💎',
    'Nim': '👑',
    'V': '💚',
    'Gleam': '✨',
    'PHP': '🐘',
    'OCaml': '🐪',
    'Elixir': '🧪',
    'ReScript': '📜'
  };
  return icons[language] || '🔧';
}