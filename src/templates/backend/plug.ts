import { BackendTemplate } from '../types';
import { PlugGenerator } from './elixir/plug-generator';

export const plugTemplate: BackendTemplate = {
  id: 'plug',
  name: 'plug',
  displayName: 'Plug Framework',
  description: 'Minimalist web framework for Elixir focusing on composability',
  version: '1.14.0',
  author: 'Elixir Core Team',
  language: 'elixir',
  framework: 'plug',
  type: 'api',
  complexity: 'beginner',
  tags: ['elixir', 'plug', 'lightweight', 'middleware', 'otp'],
  port: 4000,
  features: ['authentication', 'middleware', 'routing', 'testing', 'docker', 'hot-reload'],
  keywords: ['elixir', 'plug', 'lightweight', 'api', 'middleware'],
  dependencies: {},
  icon: '🔌',
  files: {}
};

// Create a function to generate Plug projects
export async function generatePlugProject(projectPath: string, options: any): Promise<void> {
  const generator = new PlugGenerator();
  await generator.generate(projectPath, options);
}