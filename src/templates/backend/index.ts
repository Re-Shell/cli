import { hapiTypeScriptTemplate } from './hapi-ts';
import { djangoEnhancedTemplate } from './django-enhanced';
import { actixWebTemplate } from './actix-web';
import { warpTemplate } from './warp';
import { rocketTemplate } from './rocket';
import { axumTemplate } from './axum';
import { springBootTemplate } from './spring-boot';
import { quarkusTemplate } from './quarkus';
import { micronautTemplate } from './micronaut';
import { vertxTemplate } from './vertx';
import { aspnetCoreWebApiTemplate } from './aspnet-core-webapi';
import { aspnetCoreMinimalTemplate } from './aspnet-core-minimal';
import { blazorServerTemplate } from './blazor-server';
import { grpcServiceTemplate } from './grpc-service';
import { aspnetDapperTemplate } from './aspnet-dapper';
import { aspnetAutoMapperTemplate } from './aspnet-automapper';
import { aspnetXUnitTemplate } from './aspnet-xunit';
import { aspnetEFCoreTemplate } from './aspnet-efcore';
import { aspnetHotReloadTemplate } from './aspnet-hotreload';
import { aspnetSerilogTemplate } from './aspnet-serilog';
import { aspnetSwaggerTemplate } from './aspnet-swagger';
import { aspnetJwtTemplate } from './aspnet-jwt';
import { laravelTemplate } from './laravel';
import { symfonyTemplate } from './symfony';
import { BackendTemplate } from '../types';

export const backendTemplates: Record<string, BackendTemplate> = {
  'hapi-ts': hapiTypeScriptTemplate,
  'django-enhanced': djangoEnhancedTemplate,
  'actix-web': actixWebTemplate,
  'warp': warpTemplate,
  'rocket': rocketTemplate,
  'axum': axumTemplate,
  'spring-boot': springBootTemplate,
  'quarkus': quarkusTemplate,
  'micronaut': micronautTemplate,
  'vertx': vertxTemplate,
  'aspnet-core-webapi': aspnetCoreWebApiTemplate,
  'aspnet-core-minimal': aspnetCoreMinimalTemplate,
  'blazor-server': blazorServerTemplate,
  'grpc-service': grpcServiceTemplate,
  'aspnet-dapper': aspnetDapperTemplate,
  'aspnet-automapper': aspnetAutoMapperTemplate,
  'aspnet-xunit': aspnetXUnitTemplate,
  'aspnet-efcore': aspnetEFCoreTemplate,
  'aspnet-hotreload': aspnetHotReloadTemplate,
  'aspnet-serilog': aspnetSerilogTemplate,
  'aspnet-swagger': aspnetSwaggerTemplate,
  'aspnet-jwt': aspnetJwtTemplate,
  'laravel': laravelTemplate,
  'symfony': symfonyTemplate,
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
export { warpTemplate } from './warp';
export { rocketTemplate } from './rocket';
export { axumTemplate } from './axum';
export { springBootTemplate } from './spring-boot';
export { quarkusTemplate } from './quarkus';
export { micronautTemplate } from './micronaut';
export { vertxTemplate } from './vertx';
export { aspnetCoreWebApiTemplate } from './aspnet-core-webapi';
export { aspnetCoreMinimalTemplate } from './aspnet-core-minimal';
export { blazorServerTemplate } from './blazor-server';
export { grpcServiceTemplate } from './grpc-service';
export { aspnetDapperTemplate } from './aspnet-dapper';
export { aspnetAutoMapperTemplate } from './aspnet-automapper';
export { aspnetXUnitTemplate } from './aspnet-xunit';
export { aspnetEFCoreTemplate } from './aspnet-efcore';
export { aspnetHotReloadTemplate } from './aspnet-hotreload';
export { aspnetSerilogTemplate } from './aspnet-serilog';
export { aspnetSwaggerTemplate } from './aspnet-swagger';
export { aspnetJwtTemplate } from './aspnet-jwt';
export { laravelTemplate } from './laravel';
export { symfonyTemplate } from './symfony';