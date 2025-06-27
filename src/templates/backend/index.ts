import { hapiTypeScriptTemplate } from './hapi-ts';
import { djangoEnhancedTemplate } from './django-enhanced';
import { actixWebTemplate } from './actix-web';
import { BackendTemplate } from '../types';

export const backendTemplates: Record<string, BackendTemplate> = {
  'hapi-ts': hapiTypeScriptTemplate,
  'django-enhanced': djangoEnhancedTemplate,
  'actix-web': actixWebTemplate,
};

export function getBackendTemplate(id: string): BackendTemplate | undefined {
  return backendTemplates[id];
}

export function listBackendTemplates(): BackendTemplate[] {
  return Object.values(backendTemplates);
}

export function getBackendTemplatesByLanguage(language: string): BackendTemplate[] {
  return Object.values(backendTemplates).filter(template => template.language === language);
}

export function getBackendTemplatesByFramework(framework: string): BackendTemplate[] {
  return Object.values(backendTemplates).filter(template => template.framework === framework);
}

// Export individual templates for backward compatibility
export { hapiTypeScriptTemplate } from './hapi-ts';
export { djangoEnhancedTemplate } from './django-enhanced';
export { actixWebTemplate } from './actix-web';