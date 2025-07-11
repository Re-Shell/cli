/**
 * List available backend templates command
 */

import chalk from 'chalk';
import BackendTemplateRegistry, { listBackendTemplates, getTemplateStats } from '../templates/backend/backend-template-registry';

interface ListTemplatesOptions {
  language?: string;
  framework?: string;
  verbose?: boolean;
  stats?: boolean;
}

export async function listTemplatesCommand(options: ListTemplatesOptions = {}) {
  console.log(chalk.bold.blue('\n🚀 Re-Shell Backend Templates\n'));

  if (options.stats) {
    displayStats();
    return;
  }

  if (options.language) {
    // Show templates for specific language
    const templates = BackendTemplateRegistry.getByLanguage(options.language);
    
    if (templates.length === 0) {
      console.log(chalk.yellow(`No templates found for language: ${options.language}`));
      console.log(chalk.gray('Available languages:'), BackendTemplateRegistry.getLanguages().join(', '));
      return;
    }

    console.log(chalk.bold(`${options.language} Templates:`));
    console.log('─'.repeat(60));

    for (const template of templates) {
      displayTemplate(template, options.verbose);
    }
  } else if (options.framework) {
    // Search by framework
    const templates = BackendTemplateRegistry.searchTemplates(options.framework);
    
    if (templates.length === 0) {
      console.log(chalk.yellow(`No templates found matching: ${options.framework}`));
      return;
    }

    console.log(chalk.bold(`Templates matching "${options.framework}":`));
    console.log('─'.repeat(60));

    for (const template of templates) {
      displayTemplate(template, options.verbose);
    }
  } else {
    // Show all templates grouped by language
    listBackendTemplates();
  }

  console.log(chalk.gray('\nUsage:'));
  console.log(chalk.gray('  re-shell generate backend <name> --template <template-id>'));
  console.log(chalk.gray('  re-shell generate backend user-api --template swift-vapor --port 8080'));
}

function displayTemplate(template: any, verbose: boolean = false) {
  const status = template.generator ? chalk.green('✅') : chalk.yellow('🚧');
  const name = chalk.cyan(template.name.padEnd(20));
  const framework = chalk.bold(template.framework.padEnd(15));
  
  console.log(`${status} ${name} ${framework} - ${template.description}`);
  
  if (verbose) {
    console.log(chalk.gray('   Features:'));
    for (const feature of template.features) {
      console.log(chalk.gray(`     • ${feature}`));
    }
    console.log(chalk.gray(`   Default Port: ${template.defaultPort}`));
    console.log('');
  }
}

function displayStats() {
  const stats = getTemplateStats();
  
  console.log(chalk.bold('Template Statistics:'));
  console.log('─'.repeat(60));
  console.log(`Total Templates:      ${chalk.cyan(stats.total)}`);
  console.log(`Implemented:          ${chalk.green(stats.implemented)} (${Math.round(stats.implemented / stats.total * 100)}%)`);
  console.log(`Coming Soon:          ${chalk.yellow(stats.total - stats.implemented)}`);
  console.log(`Languages:            ${chalk.blue(stats.languages)}`);
  console.log('');
  
  console.log(chalk.bold('By Language:'));
  console.log('─'.repeat(60));
  
  for (const [language, langStats] of Object.entries(stats.byLanguage)) {
    const percentage = Math.round(langStats.implemented / langStats.total * 100);
    const progressBar = createProgressBar(percentage, 20);
    
    console.log(
      `${language.padEnd(15)} ${progressBar} ${chalk.green(langStats.implemented)}/${langStats.total} (${percentage}%)`
    );
  }
}

function createProgressBar(percentage: number, width: number): string {
  const filled = Math.round((percentage / 100) * width);
  const empty = width - filled;
  
  return chalk.green('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));
}

export default listTemplatesCommand;