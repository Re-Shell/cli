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
import { slimTemplate } from './slim';
import { codeigniterTemplate } from './codeigniter';
import { ginTemplate } from './gin';
import { echoTemplate } from './echo';
import { fiberTemplate } from './fiber';
import { chiTemplate } from './chi';
import { grpcGoTemplate } from './grpc-go';
import { goSqlxTemplate } from './go-sqlx';
import { railsApiTemplate } from './rails-api';
import { sinatraTemplate } from './sinatra';
import { grapeTemplate } from './grape';
import { openrestyTemplate } from './openresty';
import { lapisTemplate } from './lapis';
import { luaHttpTemplate } from './lua-http';
import { kongPluginTemplate } from './kong-plugin';
import { crowTemplate } from './crow';
import { drogonTemplate } from './drogon';
import { cppHttplibTemplate } from './cpp-httplib';
import { pistacheTemplate } from './pistache';
import { beastTemplate } from './beast';
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
  'slim': slimTemplate,
  'codeigniter': codeigniterTemplate,
  'gin': ginTemplate,
  'echo': echoTemplate,
  'fiber': fiberTemplate,
  'chi': chiTemplate,
  'grpc-go': grpcGoTemplate,
  'go-sqlx': goSqlxTemplate,
  'rails-api': railsApiTemplate,
  'sinatra': sinatraTemplate,
  'grape': grapeTemplate,
  'openresty': openrestyTemplate,
  'lapis': lapisTemplate,
  'lua-http': luaHttpTemplate,
  'kong-plugin': kongPluginTemplate,
  'crow': crowTemplate,
  'drogon': drogonTemplate,
  'cpp-httplib': cppHttplibTemplate,
  'pistache': pistacheTemplate,
  'beast': beastTemplate,
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
export { slimTemplate } from './slim';
export { codeigniterTemplate } from './codeigniter';
export { ginTemplate } from './gin';
export { echoTemplate } from './echo';
export { fiberTemplate } from './fiber';
export { chiTemplate } from './chi';
export { grpcGoTemplate } from './grpc-go';
export { goSqlxTemplate } from './go-sqlx';
export { railsApiTemplate } from './rails-api';
export { sinatraTemplate } from './sinatra';
export { grapeTemplate } from './grape';
export { openrestyTemplate } from './openresty';
export { lapisTemplate } from './lapis';
export { luaHttpTemplate } from './lua-http';
export { kongPluginTemplate } from './kong-plugin';
export { crowTemplate } from './crow';
export { drogonTemplate } from './drogon';
export { cppHttplibTemplate } from './cpp-httplib';
export { pistacheTemplate } from './pistache';
export { beastTemplate } from './beast';
export { ComposerGenerator, generateComposerFiles } from './php-composer';
export type { ComposerConfig } from './php-composer';
export { PhpFpmGenerator, generatePhpFpmConfig } from './php-fpm';
export type { PhpFpmConfig } from './php-fpm';
export { generateCppOpenApiFiles } from './cpp-openapi';
export type { CppOpenApiConfig } from './cpp-openapi';
export { generateCppSanitizersFiles } from './cpp-sanitizers';
export type { CppSanitizersConfig } from './cpp-sanitizers';
export { generateCppQualityToolsFiles } from './cpp-quality-tools';
export type { CppQualityToolsConfig } from './cpp-quality-tools';