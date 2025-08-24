import { hapiTypeScriptTemplate } from './hapi-ts';
import { tornadoTemplate } from './tornado-py';
import { sanicTemplate } from './sanic-py';
import { blazorServerTemplate } from './blazor-server';
import { grpcServiceTemplate } from './grpc-service';
import { laravelTemplate } from './laravel';
import { symfonyTemplate } from './symfony';
import { slimTemplate } from './slim';
import { codeigniterTemplate } from './codeigniter';
import { grpcGoTemplate } from './grpc-go';
import { railsApiTemplate } from './rails-api';
import { sinatraTemplate } from './sinatra';
import { grapeTemplate } from './grape';
import { openrestyTemplate } from './openresty';
import { lapisTemplate } from './lapis';
import { luaHttpTemplate } from './lua-http';
import { kongPluginTemplate } from './kong-plugin';
import { crowTemplate } from './crow';
import { drogonTemplate } from './drogon';
import { pistacheTemplate } from './pistache';
import { vaporTemplate } from './vapor';
import { perfectTemplate } from './perfect';
import { kituraTemplate } from './kitura';
import { hummingbirdTemplate } from './hummingbird';
import { shelfTemplate } from './shelf';
import { angel3Template } from './angel3';
import { conduitTemplate } from './conduit';
import { loopbackTemplate } from './loopback';
import { adonisjsTemplate } from './adonisjs';
import { restifyTemplate } from './restify';
import { feathersjsTemplate } from './feathersjs';
import { moleculerTemplate } from './moleculer';
import { sailsjsTemplate } from './sailsjs';
import { strapiTemplate } from './strapi';
import { meteorjsTemplate } from './meteorjs';
import { totaljsTemplate } from './totaljs';
import { eggjsTemplate } from './eggjs';
import { thinkjsTemplate } from './thinkjs';
import { actionheroTemplate } from './actionherojs';
import { foaltsTemplate } from './foalts';
import { marblejsTemplate } from './marblejs';
import { tsedTemplate } from './tsed';
import { middyTemplate } from './middy';
import { polkaTemplate } from './polka';
import { tinyhttpTemplate } from './tinyhttp';
import { hyperExpressTemplate } from './hyper-express';
import { apolloServerTemplate } from './apollo-server';
import { graphqlYogaTemplate } from './graphql-yoga';
import { BackendTemplate } from '../types';

export const backendTemplates: Record<string, BackendTemplate> = {
  // Node.js/TypeScript
  'loopback': loopbackTemplate,
  'adonisjs': adonisjsTemplate,
  'restify': restifyTemplate,
  'feathersjs': feathersjsTemplate,
  'moleculer': moleculerTemplate,
  'sailsjs': sailsjsTemplate,
  'strapi': strapiTemplate,
  'meteorjs': meteorjsTemplate,
  'totaljs': totaljsTemplate,
  'eggjs': eggjsTemplate,
  'thinkjs': thinkjsTemplate,
  'actionherojs': actionheroTemplate,
  'foalts': foaltsTemplate,
  'marblejs': marblejsTemplate,
  'tsed': tsedTemplate,
  'middy': middyTemplate,
  'polka': polkaTemplate,
  'tinyhttp': tinyhttpTemplate,
  'hyper-express': hyperExpressTemplate,
  'apollo-server': apolloServerTemplate,
  'graphql-yoga': graphqlYogaTemplate,
  'hapi-ts': hapiTypeScriptTemplate,
  
  // Python
  'tornado-py': tornadoTemplate,
  'sanic-py': sanicTemplate,
  'blazor-server': blazorServerTemplate,
  'grpc-service': grpcServiceTemplate,
  'laravel': laravelTemplate,
  'symfony': symfonyTemplate,
  'slim': slimTemplate,
  'codeigniter': codeigniterTemplate,
  'grpc-go': grpcGoTemplate,
  'rails-api': railsApiTemplate,
  'sinatra': sinatraTemplate,
  'grape': grapeTemplate,
  'openresty': openrestyTemplate,
  'lapis': lapisTemplate,
  'lua-http': luaHttpTemplate,
  'kong-plugin': kongPluginTemplate,
  'crow': crowTemplate,
  'drogon': drogonTemplate,
  'pistache': pistacheTemplate,
  'vapor': vaporTemplate,
  'perfect': perfectTemplate,
  'kitura': kituraTemplate,
  'hummingbird': hummingbirdTemplate,
  'shelf': shelfTemplate,
  'angel3': angel3Template,
  'conduit': conduitTemplate,
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
export { tornadoTemplate } from './tornado-py';
export { sanicTemplate } from './sanic-py';
export { blazorServerTemplate } from './blazor-server';
export { grpcServiceTemplate } from './grpc-service';
export { laravelTemplate } from './laravel';
export { symfonyTemplate } from './symfony';
export { slimTemplate } from './slim';
export { codeigniterTemplate } from './codeigniter';
export { grpcGoTemplate } from './grpc-go';
export { railsApiTemplate } from './rails-api';
export { sinatraTemplate } from './sinatra';
export { grapeTemplate } from './grape';
export { openrestyTemplate } from './openresty';
export { lapisTemplate } from './lapis';
export { luaHttpTemplate } from './lua-http';
export { kongPluginTemplate } from './kong-plugin';
export { crowTemplate } from './crow';
export { drogonTemplate } from './drogon';
export { pistacheTemplate } from './pistache';
export { vaporTemplate } from './vapor';
export { perfectTemplate } from './perfect';
export { kituraTemplate } from './kitura';
export { hummingbirdTemplate } from './hummingbird';
export { shelfTemplate } from './shelf';
export { angel3Template } from './angel3';
export { conduitTemplate } from './conduit';
export { loopbackTemplate } from './loopback';
export { adonisjsTemplate } from './adonisjs';
export { restifyTemplate } from './restify';
export { feathersjsTemplate } from './feathersjs';
export { moleculerTemplate } from './moleculer';
export { sailsjsTemplate } from './sailsjs';
export { strapiTemplate } from './strapi';
export { meteorjsTemplate } from './meteorjs';
export { totaljsTemplate } from './totaljs';
export { eggjsTemplate } from './eggjs';
export { thinkjsTemplate } from './thinkjs';
export { actionheroTemplate } from './actionherojs';
export { foaltsTemplate } from './foalts';
export { marblejsTemplate } from './marblejs';
export { tsedTemplate } from './tsed';
export { middyTemplate } from './middy';
export { polkaTemplate } from './polka';
export { tinyhttpTemplate } from './tinyhttp';
export { hyperExpressTemplate } from './hyper-express';
export { apolloServerTemplate } from './apollo-server';
export { graphqlYogaTemplate } from './graphql-yoga';
export { ComposerGenerator, generateComposerFiles } from './php-composer';
export type { ComposerConfig } from './php-composer';
export { PhpFpmGenerator, generatePhpFpmConfig } from './php-fpm';
export type { PhpFpmConfig } from './php-fpm';
