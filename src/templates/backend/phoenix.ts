import { BackendTemplate } from '../types';
import { PhoenixGenerator } from './elixir/phoenix-generator';

export const phoenixTemplate: BackendTemplate = {
  id: 'phoenix',
  name: 'phoenix',
  displayName: 'Phoenix Framework',
  description: 'Full-featured web framework for Elixir with real-time features',
  version: '1.7.10',
  author: 'Elixir Core Team',
  language: 'elixir',
  framework: 'phoenix',
  type: 'fullstack',
  complexity: 'intermediate',
  tags: ['elixir', 'phoenix', 'real-time', 'websockets', 'liveview', 'otp'],
  port: 4000,
  features: ['authentication', 'websockets', 'real-time', 'database', 'orm', 'hot-reload', 'testing', 'docker'],
  keywords: ['elixir', 'phoenix', 'real-time', 'websockets', 'liveview'],
  dependencies: {},
  icon: '🔥',
  files: {}
};

// Create a function to generate Phoenix projects
export async function generatePhoenixProject(projectPath: string, options: any): Promise<void> {
  const generator = new PhoenixGenerator();
  await generator.generate(projectPath, options);
}