import { BackendTemplate } from '../types';

export const strapiTemplate: BackendTemplate = {
  id: 'strapi',
  name: 'Strapi Headless CMS',
  description: 'Flexible, open-source headless CMS with admin panel, Content-Type Builder, and REST/GraphQL APIs',
  author: 'Re-Shell Team',
  featured: true,
  language: 'javascript',
  framework: 'strapi',
  featured_frameworks: ['strapi', 'koa', 'bookshelf', 'knex'],
  type: 'cms',
  complexity: 'advanced',
  keywords: [
    'cms',
    'headless',
    'content-management',
    'admin-panel',
    'api-builder',
    'graphql',
    'rest-api',
    'media-library',
    'authentication',
    'rbac',
    'i18n',
    'webhooks',
    'plugins'
  ],
  dependencies: {
    '@strapi/strapi': '^4.15.0',
    '@strapi/plugin-users-permissions': '^4.15.0',
    '@strapi/plugin-i18n': '^4.15.0',
    '@strapi/plugin-graphql': '^4.15.0',
    '@strapi/plugin-email': '^4.15.0',
    '@strapi/plugin-upload': '^4.15.0',
    '@strapi/plugin-sentry': '^4.15.0',
    '@strapi/provider-email-sendgrid': '^4.15.0',
    '@strapi/provider-upload-cloudinary': '^4.15.0',
    'pg': '^8.11.3',
    'mysql2': '^3.6.5',
    'sqlite3': '^5.1.6',
    'strapi-plugin-webhooks': '^4.0.0',
    'strapi-plugin-import-export-entries': '^1.21.0',
    'strapi-plugin-slugify': '^2.3.3',
    'uuid': '^9.0.1'
  },
  devDependencies: {
    '@types/node': '^20.10.0',
    'typescript': '^5.3.0',
    '@strapi/typescript-utils': '^4.15.0',
    'nodemon': '^3.0.1',
    'jest': '^29.7.0',
    '@testing-library/jest-dom': '^6.1.5',
    'supertest': '^6.3.3'
  },
  files: [
    {
      name: 'package.json',
      content: `{
  "name": "strapi-cms",
  "private": true,
  "version": "0.1.0",
  "description": "A Strapi headless CMS application",
  "scripts": {
    "develop": "strapi develop",
    "start": "strapi start",
    "build": "strapi build",
    "strapi": "strapi",
    "test": "jest --forceExit --detectOpenHandles",
    "test:watch": "jest --watch",
    "lint": "eslint . --ext .js,.jsx,.ts,.tsx",
    "seed": "node scripts/seed.js",
    "generate:types": "strapi ts:generate-types",
    "docker:dev": "docker-compose up -d",
    "docker:prod": "docker-compose -f docker-compose.prod.yml up -d"
  },
  "devDependencies": {
    "@types/node": "^20.10.0",
    "typescript": "^5.3.0",
    "@strapi/typescript-utils": "^4.15.0",
    "nodemon": "^3.0.1",
    "jest": "^29.7.0",
    "@testing-library/jest-dom": "^6.1.5",
    "supertest": "^6.3.3"
  },
  "dependencies": {
    "@strapi/strapi": "4.15.0",
    "@strapi/plugin-users-permissions": "4.15.0",
    "@strapi/plugin-i18n": "4.15.0",
    "@strapi/plugin-graphql": "4.15.0",
    "@strapi/plugin-email": "4.15.0",
    "@strapi/plugin-upload": "4.15.0",
    "@strapi/plugin-sentry": "4.15.0",
    "@strapi/provider-email-sendgrid": "4.15.0",
    "@strapi/provider-upload-cloudinary": "4.15.0",
    "pg": "^8.11.3",
    "mysql2": "^3.6.5",
    "sqlite3": "^5.1.6",
    "strapi-plugin-webhooks": "^4.0.0",
    "strapi-plugin-import-export-entries": "^1.21.0",
    "strapi-plugin-slugify": "^2.3.3",
    "uuid": "^9.0.1"
  },
  "strapi": {
    "uuid": "strapi-cms-template"
  },
  "engines": {
    "node": ">=16.x.x <=20.x.x",
    "npm": ">=6.0.0"
  },
  "license": "MIT"
}`
    },
    {
      name: 'config/server.ts',
      content: `export default ({ env }) => ({
  host: env('HOST', '0.0.0.0'),
  port: env.int('PORT', 1337),
  app: {
    keys: env.array('APP_KEYS'),
  },
  webhooks: {
    populateRelations: env.bool('WEBHOOKS_POPULATE_RELATIONS', false),
  },
  // Cron jobs configuration
  cron: {
    enabled: true,
    tasks: {
      /**
       * Simple example of cron job
       */
      '0 0 * * *': async ({ strapi }) => {
        // Daily cleanup task
        console.log('Running daily cleanup task...');
        
        // Example: Clean up old drafts
        const drafts = await strapi.entityService.findMany('api::article.article', {
          filters: {
            publishedAt: null,
            createdAt: {
              $lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days old
            }
          }
        });
        
        for (const draft of drafts) {
          await strapi.entityService.delete('api::article.article', draft.id);
        }
      },
      
      /**
       * Send weekly newsletter
       */
      '0 9 * * 1': async ({ strapi }) => {
        console.log('Sending weekly newsletter...');
        
        const subscribers = await strapi.entityService.findMany('api::subscriber.subscriber', {
          filters: { active: true }
        });
        
        for (const subscriber of subscribers) {
          await strapi.plugin('email').service('email').send({
            to: subscriber.email,
            from: 'noreply@strapi.io',
            subject: 'Weekly Newsletter',
            text: 'Check out our latest content!',
            html: '<h1>Weekly Newsletter</h1><p>Check out our latest content!</p>'
          });
        }
      }
    }
  }
});`
    },
    {
      name: 'config/database.ts',
      content: `export default ({ env }) => {
  const client = env('DATABASE_CLIENT', 'sqlite');

  const connections = {
    mysql: {
      connection: {
        connectionString: env('DATABASE_URL'),
        host: env('DATABASE_HOST', 'localhost'),
        port: env.int('DATABASE_PORT', 3306),
        database: env('DATABASE_NAME', 'strapi'),
        user: env('DATABASE_USERNAME', 'strapi'),
        password: env('DATABASE_PASSWORD', 'strapi'),
        ssl: env.bool('DATABASE_SSL', false) && {
          key: env('DATABASE_SSL_KEY', undefined),
          cert: env('DATABASE_SSL_CERT', undefined),
          ca: env('DATABASE_SSL_CA', undefined),
          capath: env('DATABASE_SSL_CAPATH', undefined),
          cipher: env('DATABASE_SSL_CIPHER', undefined),
          rejectUnauthorized: env.bool(
            'DATABASE_SSL_REJECT_UNAUTHORIZED',
            true
          ),
        },
      },
      pool: {
        min: env.int('DATABASE_POOL_MIN', 2),
        max: env.int('DATABASE_POOL_MAX', 10),
      },
    },
    postgres: {
      connection: {
        connectionString: env('DATABASE_URL'),
        host: env('DATABASE_HOST', 'localhost'),
        port: env.int('DATABASE_PORT', 5432),
        database: env('DATABASE_NAME', 'strapi'),
        user: env('DATABASE_USERNAME', 'strapi'),
        password: env('DATABASE_PASSWORD', 'strapi'),
        ssl: env.bool('DATABASE_SSL', false) && {
          key: env('DATABASE_SSL_KEY', undefined),
          cert: env('DATABASE_SSL_CERT', undefined),
          ca: env('DATABASE_SSL_CA', undefined),
          capath: env('DATABASE_SSL_CAPATH', undefined),
          cipher: env('DATABASE_SSL_CIPHER', undefined),
          rejectUnauthorized: env.bool(
            'DATABASE_SSL_REJECT_UNAUTHORIZED',
            true
          ),
        },
        schema: env('DATABASE_SCHEMA', 'public'),
      },
      pool: {
        min: env.int('DATABASE_POOL_MIN', 2),
        max: env.int('DATABASE_POOL_MAX', 10),
      },
    },
    sqlite: {
      connection: {
        filename: env('DATABASE_FILENAME', '.tmp/data.db'),
      },
      useNullAsDefault: true,
    },
  };

  return {
    connection: {
      client,
      ...connections[client],
      acquireConnectionTimeout: env.int('DATABASE_CONNECTION_TIMEOUT', 60000),
    },
  };
};`
    },
    {
      name: 'config/admin.ts',
      content: `export default ({ env }) => ({
  auth: {
    secret: env('ADMIN_JWT_SECRET'),
  },
  apiToken: {
    salt: env('API_TOKEN_SALT'),
  },
  transfer: {
    token: {
      salt: env('TRANSFER_TOKEN_SALT'),
    },
  },
  // Admin panel customization
  head: {
    favicon: '/favicon.ico',
  },
  // Theme customization
  theme: {
    light: {
      colors: {
        primary100: '#f6ecfc',
        primary200: '#e0c1f4',
        primary500: '#ac73e6',
        primary600: '#9736e8',
        primary700: '#8312d1',
        danger700: '#b72b1a'
      },
    },
    dark: {
      colors: {
        primary100: '#030415',
        primary200: '#151625',
        primary500: '#ac73e6',
        primary600: '#9736e8',
        primary700: '#8312d1',
        danger700: '#b72b1a'
      }
    }
  },
  // Locales configuration
  locales: ['en', 'es', 'fr', 'de', 'pt', 'it', 'zh', 'ja'],
  // Disable video tutorials
  tutorials: false,
  // Disable notifications about new Strapi releases
  notifications: { releases: false },
});`
    },
    {
      name: 'config/plugins.ts',
      content: `export default ({ env }) => ({
  // GraphQL plugin
  graphql: {
    enabled: true,
    config: {
      endpoint: '/graphql',
      shadowCRUD: true,
      playgroundAlways: false,
      depthLimit: 7,
      amountLimit: 100,
      apolloServer: {
        tracing: false,
      },
    },
  },
  
  // Email plugin with SendGrid
  email: {
    config: {
      provider: 'sendgrid',
      providerOptions: {
        apiKey: env('SENDGRID_API_KEY'),
      },
      settings: {
        defaultFrom: env('EMAIL_DEFAULT_FROM', 'noreply@strapi.io'),
        defaultReplyTo: env('EMAIL_DEFAULT_REPLY_TO', 'noreply@strapi.io'),
      },
    },
  },
  
  // Upload plugin with Cloudinary
  upload: {
    config: {
      provider: 'cloudinary',
      providerOptions: {
        cloud_name: env('CLOUDINARY_NAME'),
        api_key: env('CLOUDINARY_KEY'),
        api_secret: env('CLOUDINARY_SECRET'),
      },
      actionOptions: {
        upload: {},
        uploadStream: {},
        delete: {},
      },
    },
  },
  
  // Internationalization plugin
  i18n: {
    enabled: true,
    config: {
      defaultLocale: 'en',
      locales: ['en', 'es', 'fr', 'de', 'pt', 'it', 'zh', 'ja'],
    },
  },
  
  // Sentry plugin for error tracking
  sentry: {
    enabled: true,
    config: {
      dsn: env('SENTRY_DSN'),
      sendMetadata: true,
    },
  },
  
  // Webhooks plugin
  webhooks: {
    enabled: true,
    config: {
      defaultHeaders: {
        'Content-Type': 'application/json',
      },
    },
  },
  
  // Import/Export plugin
  'import-export-entries': {
    enabled: true,
    config: {
      // Configure content types that can be imported/exported
      contentTypes: {
        article: {
          enabled: true,
          options: {
            populateCreatorFields: true,
          },
        },
        category: {
          enabled: true,
        },
        tag: {
          enabled: true,
        },
      },
    },
  },
  
  // Slugify plugin
  slugify: {
    enabled: true,
    config: {
      contentTypes: {
        article: {
          field: 'slug',
          references: 'title',
        },
        category: {
          field: 'slug',
          references: 'name',
        },
      },
    },
  },
});`
    },
    {
      name: 'config/middlewares.ts',
      content: `export default [
  'strapi::errors',
  'strapi::security',
  'strapi::cors',
  'strapi::poweredBy',
  'strapi::logger',
  'strapi::query',
  'strapi::body',
  'strapi::session',
  'strapi::favicon',
  'strapi::public',
  {
    name: 'strapi::security',
    config: {
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          'connect-src': ["'self'", 'https:'],
          'img-src': ["'self'", 'data:', 'blob:', 'dl.airtable.com', 'strapi.io', 'res.cloudinary.com'],
          'media-src': ["'self'", 'data:', 'blob:', 'dl.airtable.com', 'strapi.io', 'res.cloudinary.com'],
          upgradeInsecureRequests: null,
        },
      },
    },
  },
  {
    name: 'strapi::cors',
    config: {
      enabled: true,
      headers: '*',
      origin: ['http://localhost:3000', 'http://localhost:5173', 'https://yourdomain.com'],
    },
  },
];`
    },
    {
      name: 'src/api/article/content-types/article/schema.json',
      content: `{
  "kind": "collectionType",
  "collectionName": "articles",
  "info": {
    "singularName": "article",
    "pluralName": "articles",
    "displayName": "Article",
    "description": "Blog articles with rich content"
  },
  "options": {
    "draftAndPublish": true
  },
  "pluginOptions": {
    "i18n": {
      "localized": true
    }
  },
  "attributes": {
    "title": {
      "type": "string",
      "required": true,
      "pluginOptions": {
        "i18n": {
          "localized": true
        }
      }
    },
    "slug": {
      "type": "uid",
      "targetField": "title",
      "required": true
    },
    "content": {
      "type": "richtext",
      "required": true,
      "pluginOptions": {
        "i18n": {
          "localized": true
        }
      }
    },
    "excerpt": {
      "type": "text",
      "maxLength": 300,
      "pluginOptions": {
        "i18n": {
          "localized": true
        }
      }
    },
    "featuredImage": {
      "type": "media",
      "multiple": false,
      "required": false,
      "allowedTypes": ["images"]
    },
    "author": {
      "type": "relation",
      "relation": "manyToOne",
      "target": "plugin::users-permissions.user",
      "inversedBy": "articles"
    },
    "categories": {
      "type": "relation",
      "relation": "manyToMany",
      "target": "api::category.category",
      "inversedBy": "articles"
    },
    "tags": {
      "type": "relation",
      "relation": "manyToMany",
      "target": "api::tag.tag",
      "inversedBy": "articles"
    },
    "seo": {
      "type": "component",
      "repeatable": false,
      "component": "shared.seo"
    },
    "views": {
      "type": "integer",
      "default": 0,
      "min": 0
    },
    "readingTime": {
      "type": "integer",
      "min": 1
    }
  }
}`
    },
    {
      name: 'src/api/article/controllers/article.ts',
      content: `import { factories } from '@strapi/strapi';

export default factories.createCoreController('api::article.article', ({ strapi }) => ({
  
  // Custom find method with view count increment
  async findOne(ctx) {
    const { id } = ctx.params;
    
    // Call default findOne
    const response = await super.findOne(ctx);
    
    // Increment view count
    if (response && response.data) {
      await strapi.entityService.update('api::article.article', id, {
        data: {
          views: (response.data.attributes.views || 0) + 1
        }
      });
    }
    
    return response;
  },
  
  // Custom method to get trending articles
  async trending(ctx) {
    const { locale = 'en' } = ctx.query;
    
    const articles = await strapi.entityService.findMany('api::article.article', {
      sort: { views: 'desc' },
      limit: 10,
      populate: ['featuredImage', 'author', 'categories'],
      locale,
      filters: {
        publishedAt: {
          $notNull: true
        }
      }
    });
    
    return this.transformResponse(articles);
  },
  
  // Custom method to get related articles
  async related(ctx) {
    const { id } = ctx.params;
    const { locale = 'en' } = ctx.query;
    
    // Get current article
    const article = await strapi.entityService.findOne('api::article.article', id, {
      populate: ['categories', 'tags']
    });
    
    if (!article) {
      return ctx.notFound('Article not found');
    }
    
    // Find related articles by categories and tags
    const categoryIds = article.categories?.map(cat => cat.id) || [];
    const tagIds = article.tags?.map(tag => tag.id) || [];
    
    const relatedArticles = await strapi.entityService.findMany('api::article.article', {
      filters: {
        $and: [
          { id: { $ne: id } },
          { publishedAt: { $notNull: true } },
          {
            $or: [
              { categories: { id: { $in: categoryIds } } },
              { tags: { id: { $in: tagIds } } }
            ]
          }
        ]
      },
      limit: 5,
      populate: ['featuredImage', 'author', 'categories'],
      locale
    });
    
    return this.transformResponse(relatedArticles);
  }
}));`
    },
    {
      name: 'src/api/article/services/article.ts',
      content: `import { factories } from '@strapi/strapi';

export default factories.createCoreService('api::article.article', ({ strapi }) => ({
  
  // Calculate reading time based on content
  calculateReadingTime(content: string): number {
    const wordsPerMinute = 200;
    const wordCount = content.trim().split(/\\s+/).length;
    const readingTime = Math.ceil(wordCount / wordsPerMinute);
    return readingTime;
  },
  
  // Generate excerpt from content
  generateExcerpt(content: string, maxLength = 300): string {
    const plainText = content.replace(/<[^>]*>/g, '').trim();
    if (plainText.length <= maxLength) {
      return plainText;
    }
    return plainText.substring(0, maxLength).trim() + '...';
  },
  
  // Send notification on article publish
  async sendPublishNotification(article) {
    // Get all subscribers
    const subscribers = await strapi.entityService.findMany('api::subscriber.subscriber', {
      filters: { active: true }
    });
    
    // Send email to each subscriber
    for (const subscriber of subscribers) {
      await strapi.plugin('email').service('email').send({
        to: subscriber.email,
        from: 'noreply@strapi.io',
        subject: \`New Article: \${article.title}\`,
        text: \`Check out our new article: \${article.title}\`,
        html: \`
          <h2>New Article Published!</h2>
          <h3>\${article.title}</h3>
          <p>\${article.excerpt}</p>
          <a href="https://yoursite.com/articles/\${article.slug}">Read More</a>
        \`
      });
    }
  },
  
  // Search articles with full-text search
  async searchArticles(query: string, locale = 'en') {
    return await strapi.entityService.findMany('api::article.article', {
      filters: {
        $and: [
          { publishedAt: { $notNull: true } },
          {
            $or: [
              { title: { $containsi: query } },
              { content: { $containsi: query } },
              { excerpt: { $containsi: query } }
            ]
          }
        ]
      },
      populate: ['featuredImage', 'author', 'categories'],
      locale
    });
  }
}));`
    },
    {
      name: 'src/api/article/routes/article.ts',
      content: `import { factories } from '@strapi/strapi';

export default factories.createCoreRouter('api::article.article', {
  config: {
    find: {
      middlewares: ['api::article.article-populate-middleware']
    },
    findOne: {
      middlewares: ['api::article.article-populate-middleware']
    }
  }
});`
    },
    {
      name: 'src/api/article/routes/custom-article.ts',
      content: `export default {
  routes: [
    {
      method: 'GET',
      path: '/articles/trending',
      handler: 'article.trending',
      config: {
        policies: [],
        middlewares: [],
      },
    },
    {
      method: 'GET',
      path: '/articles/:id/related',
      handler: 'article.related',
      config: {
        policies: [],
        middlewares: [],
      },
    },
  ],
};`
    },
    {
      name: 'src/api/article/middlewares/article-populate-middleware.ts',
      content: `export default (config, { strapi }) => {
  return async (ctx, next) => {
    // Add default population for articles
    ctx.query = {
      ...ctx.query,
      populate: {
        featuredImage: true,
        author: {
          fields: ['username', 'email'],
          populate: {
            avatar: true
          }
        },
        categories: {
          fields: ['name', 'slug']
        },
        tags: {
          fields: ['name', 'slug']
        },
        seo: true
      }
    };

    await next();
  };
};`
    },
    {
      name: 'src/api/category/content-types/category/schema.json',
      content: `{
  "kind": "collectionType",
  "collectionName": "categories",
  "info": {
    "singularName": "category",
    "pluralName": "categories",
    "displayName": "Category",
    "description": "Article categories"
  },
  "options": {
    "draftAndPublish": false
  },
  "pluginOptions": {
    "i18n": {
      "localized": true
    }
  },
  "attributes": {
    "name": {
      "type": "string",
      "required": true,
      "unique": true,
      "pluginOptions": {
        "i18n": {
          "localized": true
        }
      }
    },
    "slug": {
      "type": "uid",
      "targetField": "name",
      "required": true
    },
    "description": {
      "type": "text",
      "pluginOptions": {
        "i18n": {
          "localized": true
        }
      }
    },
    "articles": {
      "type": "relation",
      "relation": "manyToMany",
      "target": "api::article.article",
      "mappedBy": "categories"
    },
    "icon": {
      "type": "media",
      "multiple": false,
      "required": false,
      "allowedTypes": ["images"]
    },
    "color": {
      "type": "string",
      "regex": "^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$"
    }
  }
}`
    },
    {
      name: 'src/api/subscriber/content-types/subscriber/schema.json',
      content: `{
  "kind": "collectionType",
  "collectionName": "subscribers",
  "info": {
    "singularName": "subscriber",
    "pluralName": "subscribers",
    "displayName": "Subscriber",
    "description": "Newsletter subscribers"
  },
  "options": {
    "draftAndPublish": false
  },
  "attributes": {
    "email": {
      "type": "email",
      "required": true,
      "unique": true
    },
    "name": {
      "type": "string"
    },
    "active": {
      "type": "boolean",
      "default": true
    },
    "preferences": {
      "type": "json",
      "default": {
        "frequency": "weekly",
        "categories": []
      }
    },
    "subscribedAt": {
      "type": "datetime",
      "default": "2023-01-01T00:00:00.000Z"
    },
    "unsubscribeToken": {
      "type": "string",
      "unique": true,
      "private": true
    }
  }
}`
    },
    {
      name: 'src/api/subscriber/controllers/subscriber.ts',
      content: `import { factories } from '@strapi/strapi';
import { v4 as uuidv4 } from 'uuid';

export default factories.createCoreController('api::subscriber.subscriber', ({ strapi }) => ({
  
  // Custom subscribe endpoint
  async subscribe(ctx) {
    const { email, name, preferences } = ctx.request.body;
    
    // Check if already subscribed
    const existing = await strapi.entityService.findMany('api::subscriber.subscriber', {
      filters: { email }
    });
    
    if (existing.length > 0) {
      return ctx.badRequest('Email already subscribed');
    }
    
    // Create subscriber with unsubscribe token
    const subscriber = await strapi.entityService.create('api::subscriber.subscriber', {
      data: {
        email,
        name,
        preferences,
        unsubscribeToken: uuidv4(),
        subscribedAt: new Date()
      }
    });
    
    // Send welcome email
    await strapi.plugin('email').service('email').send({
      to: email,
      from: 'noreply@strapi.io',
      subject: 'Welcome to our newsletter!',
      text: 'Thank you for subscribing to our newsletter.',
      html: \`
        <h2>Welcome!</h2>
        <p>Thank you for subscribing to our newsletter.</p>
        <p>You'll receive updates based on your preferences.</p>
        <p><a href="https://yoursite.com/unsubscribe?token=\${subscriber.unsubscribeToken}">Unsubscribe</a></p>
      \`
    });
    
    return {
      data: {
        message: 'Successfully subscribed!',
        subscriber: {
          email: subscriber.email,
          name: subscriber.name
        }
      }
    };
  },
  
  // Custom unsubscribe endpoint
  async unsubscribe(ctx) {
    const { token } = ctx.query;
    
    if (!token) {
      return ctx.badRequest('Unsubscribe token required');
    }
    
    const subscriber = await strapi.entityService.findMany('api::subscriber.subscriber', {
      filters: { unsubscribeToken: token }
    });
    
    if (subscriber.length === 0) {
      return ctx.notFound('Invalid unsubscribe token');
    }
    
    // Update subscriber status
    await strapi.entityService.update('api::subscriber.subscriber', subscriber[0].id, {
      data: { active: false }
    });
    
    return {
      data: {
        message: 'Successfully unsubscribed'
      }
    };
  }
}));`
    },
    {
      name: 'src/components/shared/seo.json',
      content: `{
  "collectionName": "components_shared_seos",
  "info": {
    "displayName": "SEO",
    "description": "SEO metadata component",
    "icon": "search"
  },
  "options": {},
  "attributes": {
    "metaTitle": {
      "type": "string",
      "required": true,
      "maxLength": 60
    },
    "metaDescription": {
      "type": "text",
      "required": true,
      "maxLength": 160
    },
    "metaImage": {
      "type": "media",
      "multiple": false,
      "required": false,
      "allowedTypes": ["images"]
    },
    "metaSocial": {
      "type": "component",
      "repeatable": true,
      "component": "shared.meta-social"
    },
    "keywords": {
      "type": "text"
    },
    "metaRobots": {
      "type": "string"
    },
    "structuredData": {
      "type": "json"
    },
    "metaViewport": {
      "type": "string",
      "default": "width=device-width, initial-scale=1"
    },
    "canonicalURL": {
      "type": "string"
    }
  }
}`
    },
    {
      name: 'src/components/shared/meta-social.json',
      content: `{
  "collectionName": "components_shared_meta_socials",
  "info": {
    "displayName": "Meta Social",
    "description": "Social media meta tags",
    "icon": "share"
  },
  "options": {},
  "attributes": {
    "socialNetwork": {
      "type": "enumeration",
      "enum": ["Facebook", "Twitter", "LinkedIn"],
      "required": true
    },
    "title": {
      "type": "string",
      "required": true,
      "maxLength": 60
    },
    "description": {
      "type": "text",
      "required": true,
      "maxLength": 160
    },
    "image": {
      "type": "media",
      "multiple": false,
      "required": false,
      "allowedTypes": ["images"]
    }
  }
}`
    },
    {
      name: 'src/extensions/users-permissions/content-types/user/schema.json',
      content: `{
  "kind": "collectionType",
  "collectionName": "up_users",
  "info": {
    "name": "user",
    "description": "",
    "singularName": "user",
    "pluralName": "users",
    "displayName": "User"
  },
  "options": {
    "draftAndPublish": false
  },
  "attributes": {
    "username": {
      "type": "string",
      "minLength": 3,
      "unique": true,
      "configurable": false,
      "required": true
    },
    "email": {
      "type": "email",
      "minLength": 6,
      "configurable": false,
      "required": true
    },
    "provider": {
      "type": "string",
      "configurable": false
    },
    "password": {
      "type": "password",
      "minLength": 6,
      "configurable": false,
      "private": true
    },
    "resetPasswordToken": {
      "type": "string",
      "configurable": false,
      "private": true
    },
    "confirmationToken": {
      "type": "string",
      "configurable": false,
      "private": true
    },
    "confirmed": {
      "type": "boolean",
      "default": false,
      "configurable": false
    },
    "blocked": {
      "type": "boolean",
      "default": false,
      "configurable": false
    },
    "role": {
      "type": "relation",
      "relation": "manyToOne",
      "target": "plugin::users-permissions.role",
      "inversedBy": "users",
      "configurable": false
    },
    "articles": {
      "type": "relation",
      "relation": "oneToMany",
      "target": "api::article.article",
      "mappedBy": "author"
    },
    "avatar": {
      "type": "media",
      "multiple": false,
      "required": false,
      "allowedTypes": ["images"]
    },
    "bio": {
      "type": "text",
      "maxLength": 500
    },
    "website": {
      "type": "string"
    },
    "socialLinks": {
      "type": "json",
      "default": {
        "twitter": "",
        "linkedin": "",
        "github": ""
      }
    }
  }
}`
    },
    {
      name: 'src/policies/is-owner.ts',
      content: `export default async (policyContext, config, { strapi }) => {
  const { user, auth } = policyContext.state;
  const { params } = policyContext;

  // If no authenticated user, deny access
  if (!user) {
    return false;
  }

  // Get the model from the policy config
  const { model } = config;

  // Find the entity
  const entity = await strapi.entityService.findOne(model, params.id, {
    populate: ['author', 'user', 'owner']
  });

  if (!entity) {
    return false;
  }

  // Check if user is the owner/author
  const ownerId = entity.author?.id || entity.user?.id || entity.owner?.id;
  
  return ownerId === user.id;
};`
    },
    {
      name: 'src/policies/rate-limit.ts',
      content: `const rateLimit = new Map();

export default async (policyContext, config, { strapi }) => {
  const { user } = policyContext.state;
  const { request } = policyContext;
  
  // Configuration
  const { max = 100, windowMs = 60000 } = config;
  
  // Create unique key for rate limiting
  const key = user ? \`user-\${user.id}\` : \`ip-\${request.ip}\`;
  
  // Get current data
  const now = Date.now();
  const userData = rateLimit.get(key) || { count: 0, resetTime: now + windowMs };
  
  // Reset if window expired
  if (now > userData.resetTime) {
    userData.count = 0;
    userData.resetTime = now + windowMs;
  }
  
  // Increment count
  userData.count++;
  
  // Update map
  rateLimit.set(key, userData);
  
  // Set headers
  policyContext.set('X-RateLimit-Limit', max.toString());
  policyContext.set('X-RateLimit-Remaining', Math.max(0, max - userData.count).toString());
  policyContext.set('X-RateLimit-Reset', new Date(userData.resetTime).toISOString());
  
  // Check if limit exceeded
  if (userData.count > max) {
    return false;
  }
  
  return true;
};`
    },
    {
      name: 'src/index.ts',
      content: `import { Strapi } from '@strapi/strapi';

export default {
  /**
   * An asynchronous register function that runs before
   * your application is initialized.
   *
   * This gives you an opportunity to extend code.
   */
  register(/* { strapi }: { strapi: Strapi } */) {
    // Register custom fields
    strapi.customFields.register({
      name: 'color',
      plugin: 'color-picker',
      type: 'string',
    });
  },

  /**
   * An asynchronous bootstrap function that runs before
   * your application gets started.
   *
   * This gives you an opportunity to set up your data model,
   * run jobs, or perform some special logic.
   */
  async bootstrap({ strapi }: { strapi: Strapi }) {
    // Setup webhooks for content changes
    strapi.db.lifecycles.subscribe({
      models: ['api::article.article'],
      
      async afterCreate(event) {
        const { result } = event;
        
        // Trigger webhook
        await strapi.service('plugin::webhooks.webhooks').trigger('article.created', {
          entry: result,
          model: 'article',
          event: 'created'
        });
      },
      
      async afterUpdate(event) {
        const { result, params } = event;
        
        // Check if article was just published
        if (result.publishedAt && !params.data.publishedAt) {
          // Send notification to subscribers
          await strapi.service('api::article.article').sendPublishNotification(result);
          
          // Trigger webhook
          await strapi.service('plugin::webhooks.webhooks').trigger('article.published', {
            entry: result,
            model: 'article',
            event: 'published'
          });
        }
      },
      
      async beforeCreate(event) {
        const { data } = event.params;
        
        // Auto-calculate reading time
        if (data.content && !data.readingTime) {
          data.readingTime = strapi.service('api::article.article').calculateReadingTime(data.content);
        }
        
        // Auto-generate excerpt
        if (data.content && !data.excerpt) {
          data.excerpt = strapi.service('api::article.article').generateExcerpt(data.content);
        }
      },
      
      async beforeUpdate(event) {
        const { data } = event.params;
        
        // Update reading time if content changed
        if (data.content) {
          data.readingTime = strapi.service('api::article.article').calculateReadingTime(data.content);
          
          // Update excerpt if not manually set
          if (!data.excerpt) {
            data.excerpt = strapi.service('api::article.article').generateExcerpt(data.content);
          }
        }
      }
    });
    
    // Register custom permissions
    await strapi.admin.services.permission.actionProvider.registerMany([
      {
        section: 'plugins',
        displayName: 'Access the Import/Export Plugin',
        uid: 'plugin::import-export-entries.read',
        pluginName: 'import-export-entries',
      },
    ]);
  },
};`
    },
    {
      name: 'docker-compose.yml',
      content: `version: '3.8'

services:
  strapi:
    image: strapi/strapi:4.15.0-alpine
    container_name: strapi-cms
    restart: unless-stopped
    env_file: .env
    environment:
      DATABASE_CLIENT: \${DATABASE_CLIENT}
      DATABASE_HOST: strapi-db
      DATABASE_PORT: \${DATABASE_PORT}
      DATABASE_NAME: \${DATABASE_NAME}
      DATABASE_USERNAME: \${DATABASE_USERNAME}
      DATABASE_PASSWORD: \${DATABASE_PASSWORD}
      JWT_SECRET: \${JWT_SECRET}
      ADMIN_JWT_SECRET: \${ADMIN_JWT_SECRET}
      API_TOKEN_SALT: \${API_TOKEN_SALT}
      APP_KEYS: \${APP_KEYS}
      NODE_ENV: \${NODE_ENV}
    volumes:
      - ./config:/opt/app/config
      - ./src:/opt/app/src
      - ./package.json:/opt/package.json
      - ./public/uploads:/opt/app/public/uploads
    ports:
      - '1337:1337'
    networks:
      - strapi-network
    depends_on:
      - strapi-db

  strapi-db:
    image: postgres:14-alpine
    container_name: strapi-database
    restart: unless-stopped
    env_file: .env
    environment:
      POSTGRES_USER: \${DATABASE_USERNAME}
      POSTGRES_PASSWORD: \${DATABASE_PASSWORD}
      POSTGRES_DB: \${DATABASE_NAME}
    volumes:
      - strapi-data:/var/lib/postgresql/data
    ports:
      - '5432:5432'
    networks:
      - strapi-network

  redis:
    image: redis:7-alpine
    container_name: strapi-redis
    restart: unless-stopped
    ports:
      - '6379:6379'
    networks:
      - strapi-network
    volumes:
      - redis-data:/data

  nginx:
    image: nginx:alpine
    container_name: strapi-nginx
    restart: unless-stopped
    ports:
      - '80:80'
      - '443:443'
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - ./public/uploads:/usr/share/nginx/html/uploads
    networks:
      - strapi-network
    depends_on:
      - strapi

volumes:
  strapi-data:
  redis-data:

networks:
  strapi-network:
    driver: bridge`
    },
    {
      name: 'docker-compose.prod.yml',
      content: `version: '3.8'

services:
  strapi:
    build:
      context: .
      dockerfile: Dockerfile.prod
    container_name: strapi-cms-prod
    restart: always
    env_file: .env.production
    environment:
      DATABASE_CLIENT: postgres
      DATABASE_HOST: strapi-db
      DATABASE_PORT: 5432
      NODE_ENV: production
    volumes:
      - ./public/uploads:/opt/app/public/uploads
    networks:
      - strapi-network
    depends_on:
      - strapi-db
      - redis

  strapi-db:
    image: postgres:14-alpine
    container_name: strapi-database-prod
    restart: always
    env_file: .env.production
    environment:
      POSTGRES_USER: \${DATABASE_USERNAME}
      POSTGRES_PASSWORD: \${DATABASE_PASSWORD}
      POSTGRES_DB: \${DATABASE_NAME}
    volumes:
      - strapi-data:/var/lib/postgresql/data
      - ./scripts/backup:/backup
    networks:
      - strapi-network

  redis:
    image: redis:7-alpine
    container_name: strapi-redis-prod
    restart: always
    command: redis-server --requirepass \${REDIS_PASSWORD}
    networks:
      - strapi-network
    volumes:
      - redis-data:/data

  nginx:
    image: nginx:alpine
    container_name: strapi-nginx-prod
    restart: always
    ports:
      - '80:80'
      - '443:443'
    volumes:
      - ./nginx/nginx.prod.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - ./public/uploads:/usr/share/nginx/html/uploads
      - ./nginx/cache:/var/cache/nginx
    networks:
      - strapi-network
    depends_on:
      - strapi

volumes:
  strapi-data:
  redis-data:

networks:
  strapi-network:
    driver: bridge`
    },
    {
      name: 'Dockerfile.prod',
      content: `FROM node:18-alpine as build

# Install dependencies
RUN apk update && apk add --no-cache build-base gcc autoconf automake zlib-dev libpng-dev vips-dev > /dev/null 2>&1

# Set working directory
WORKDIR /opt/app

# Copy package files
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Build admin panel
RUN npm run build

# Production stage
FROM node:18-alpine

# Install runtime dependencies
RUN apk add --no-cache vips-dev

# Set working directory
WORKDIR /opt/app

# Copy from build stage
COPY --from=build /opt/app ./

# Create upload directory
RUN mkdir -p public/uploads

# Set permissions
RUN chown -R node:node /opt/app

# Switch to node user
USER node

# Expose port
EXPOSE 1337

# Start application
CMD ["npm", "start"]`
    },
    {
      name: '.env.example',
      content: `# Server
HOST=0.0.0.0
PORT=1337
APP_KEYS=toBeModified1,toBeModified2

# Database
DATABASE_CLIENT=postgres
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=strapi
DATABASE_USERNAME=strapi
DATABASE_PASSWORD=strapi
DATABASE_SSL=false

# JWT
JWT_SECRET=toBeModified
ADMIN_JWT_SECRET=toBeModified
API_TOKEN_SALT=toBeModified
TRANSFER_TOKEN_SALT=toBeModified

# Email (SendGrid)
SENDGRID_API_KEY=your-sendgrid-api-key
EMAIL_DEFAULT_FROM=noreply@yoursite.com
EMAIL_DEFAULT_REPLY_TO=noreply@yoursite.com

# Upload (Cloudinary)
CLOUDINARY_NAME=your-cloudinary-name
CLOUDINARY_KEY=your-cloudinary-key
CLOUDINARY_SECRET=your-cloudinary-secret

# Sentry
SENTRY_DSN=your-sentry-dsn

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# OAuth Providers
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Frontend URL
FRONTEND_URL=http://localhost:3000

# Admin URL
ADMIN_URL=http://localhost:1337/admin`
    },
    {
      name: 'nginx/nginx.conf',
      content: `user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml application/atom+xml image/svg+xml;

    # Upload size
    client_max_body_size 100M;

    # Upstream
    upstream strapi {
        server strapi:1337;
    }

    # HTTP server
    server {
        listen 80;
        server_name localhost;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;

        # Strapi admin
        location /admin {
            proxy_pass http://strapi/admin;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        # Strapi API
        location / {
            proxy_pass http://strapi;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        # Static files
        location /uploads {
            alias /usr/share/nginx/html/uploads;
            expires 7d;
            add_header Cache-Control "public, immutable";
        }
    }
}`
    },
    {
      name: 'scripts/seed.js',
      content: `const { createCoreService } = require('@strapi/strapi').factories;

async function seedDatabase() {
  try {
    console.log('Starting database seeding...');

    // Create categories
    const categories = [
      { name: 'Technology', slug: 'technology', color: '#007bff' },
      { name: 'Business', slug: 'business', color: '#28a745' },
      { name: 'Design', slug: 'design', color: '#dc3545' },
      { name: 'Marketing', slug: 'marketing', color: '#ffc107' },
      { name: 'Development', slug: 'development', color: '#17a2b8' }
    ];

    for (const category of categories) {
      await strapi.entityService.create('api::category.category', {
        data: category
      });
    }

    console.log('Categories created successfully');

    // Create tags
    const tags = [
      { name: 'JavaScript', slug: 'javascript' },
      { name: 'React', slug: 'react' },
      { name: 'Node.js', slug: 'nodejs' },
      { name: 'Python', slug: 'python' },
      { name: 'Docker', slug: 'docker' },
      { name: 'AWS', slug: 'aws' },
      { name: 'DevOps', slug: 'devops' },
      { name: 'UI/UX', slug: 'ui-ux' }
    ];

    for (const tag of tags) {
      await strapi.entityService.create('api::tag.tag', {
        data: tag
      });
    }

    console.log('Tags created successfully');

    // Create sample articles
    const articles = [
      {
        title: 'Getting Started with Strapi CMS',
        content: '<p>Strapi is a leading open-source headless CMS. It\'s 100% JavaScript, fully customizable and developer-first.</p>',
        excerpt: 'Learn how to get started with Strapi, the flexible and open-source headless CMS.',
        publishedAt: new Date()
      },
      {
        title: 'Building APIs with Strapi',
        content: '<p>Strapi makes it easy to build powerful APIs. Learn how to create custom endpoints and controllers.</p>',
        excerpt: 'Discover how to build robust APIs using Strapi\'s powerful features.',
        publishedAt: new Date()
      }
    ];

    for (const article of articles) {
      await strapi.entityService.create('api::article.article', {
        data: article
      });
    }

    console.log('Articles created successfully');
    console.log('Database seeding completed!');

  } catch (error) {
    console.error('Error seeding database:', error);
    process.exit(1);
  }
}

// Only run if called directly
if (require.main === module) {
  seedDatabase();
}

module.exports = seedDatabase;`
    },
    {
      name: 'tsconfig.json',
      content: `{
  "extends": "@strapi/typescript-utils/tsconfigs/server",
  "compilerOptions": {
    "outDir": "dist",
    "rootDir": ".",
    "sourceMap": true,
    "allowJs": true
  },
  "include": [
    "./",
    "./**/*.ts",
    "./**/*.js",
    "src/**/*.json"
  ],
  "exclude": [
    "node_modules/",
    "build/",
    "dist/",
    ".cache/",
    ".tmp/",
    "src/admin/",
    "**/*.test.*",
    "src/plugins/**"
  ]
}`
    },
    {
      name: '.gitignore',
      content: `############################
# OS X
############################

.DS_Store
.AppleDouble
.LSOverride
Icon
.Spotlight-V100
.Trashes
._*

############################
# Linux
############################

*~

############################
# Windows
############################

Thumbs.db
ehthumbs.db
Desktop.ini
$RECYCLE.BIN/
*.cab
*.msi
*.msm
*.msp

############################
# Packages
############################

*.7z
*.csv
*.dat
*.dmg
*.gz
*.iso
*.jar
*.rar
*.tar
*.zip
*.com
*.class
*.dll
*.exe
*.o
*.seed
*.so
*.swo
*.swp
*.swn
*.swm
*.out
*.pid

############################
# Logs and databases
############################

.tmp
*.log
*.sql
*.sqlite
*.sqlite3

############################
# Misc.
############################

*#
ssl
.idea
nbproject
public/uploads/*
!public/uploads/.gitkeep

############################
# Node.js
############################

lib-cov
lcov.info
pids
logs
results
node_modules
.node_history

############################
# Tests
############################

coverage

############################
# Strapi
############################

.env
license.txt
exports
*.cache
dist
build
.strapi-updater.json
.strapi
.tmp
public/uploads
!public/uploads/.gitkeep`
    },
    {
      name: 'README.md',
      content: `# Strapi Headless CMS

A flexible, open-source headless CMS built with Strapi v4, featuring an admin panel, Content-Type Builder, and REST/GraphQL APIs.

## Features

- **Admin Panel**: Intuitive interface for content management
- **Content-Type Builder**: Dynamic API creation without coding
- **REST & GraphQL APIs**: Automatic API generation
- **Role-Based Access Control**: Fine-grained permissions
- **Media Library**: Built-in asset management with optimization
- **Internationalization**: Multi-language content support
- **Plugin System**: Extensible architecture
- **Webhooks**: Real-time event notifications
- **Database Support**: PostgreSQL, MySQL, SQLite, MongoDB
- **Authentication**: Local and OAuth providers
- **Draft/Publish System**: Content workflow management

## Getting Started

### Prerequisites

- Node.js 16.x - 20.x
- npm/yarn
- PostgreSQL/MySQL (or SQLite for development)

### Installation

1. Install dependencies:
\`\`\`bash
npm install
\`\`\`

2. Set up environment variables:
\`\`\`bash
cp .env.example .env
\`\`\`

3. Start development server:
\`\`\`bash
npm run develop
\`\`\`

4. Access admin panel at: http://localhost:1337/admin

### Docker Setup

Development:
\`\`\`bash
docker-compose up -d
\`\`\`

Production:
\`\`\`bash
docker-compose -f docker-compose.prod.yml up -d
\`\`\`

## Project Structure

\`\`\`
├── config/           # Configuration files
├── src/
│   ├── api/         # API endpoints and content types
│   ├── components/  # Reusable components
│   ├── extensions/  # Plugin extensions
│   ├── middlewares/ # Custom middlewares
│   ├── policies/    # Custom policies
│   └── index.ts     # Main application file
├── public/          # Public assets
├── scripts/         # Utility scripts
└── docker/          # Docker configuration
\`\`\`

## Content Types

### Article
- Title, slug, content, excerpt
- Featured image, author relation
- Categories and tags
- SEO metadata
- Draft/publish workflow
- View count tracking

### Category
- Name, slug, description
- Icon and color
- Article relations

### Subscriber
- Email newsletter management
- Preferences and unsubscribe tokens

## Custom Features

### API Endpoints
- \`GET /api/articles/trending\` - Get trending articles
- \`GET /api/articles/:id/related\` - Get related articles
- \`POST /api/subscribers/subscribe\` - Newsletter subscription
- \`GET /api/subscribers/unsubscribe\` - Unsubscribe from newsletter

### Lifecycle Hooks
- Auto-calculate reading time
- Generate excerpts
- Send publish notifications
- Webhook triggers

### Policies
- Rate limiting
- Ownership verification

## Configuration

### Database
Configure in \`config/database.ts\`:
- PostgreSQL (recommended for production)
- MySQL
- SQLite (development)
- MongoDB

### Email
SendGrid integration in \`config/plugins.ts\`

### Media Storage
Cloudinary integration for image optimization

### Authentication
- Local authentication
- OAuth providers (GitHub, Google)

## Testing

Run tests:
\`\`\`bash
npm test
\`\`\`

## Deployment

1. Build for production:
\`\`\`bash
npm run build
\`\`\`

2. Start production server:
\`\`\`bash
npm start
\`\`\`

## API Documentation

### REST API
- Base URL: \`http://localhost:1337/api\`
- Authentication: Bearer token or API key

### GraphQL
- Endpoint: \`http://localhost:1337/graphql\`
- Playground available in development

## Environment Variables

See \`.env.example\` for all configuration options.

## License

MIT`
    }
  ]
};`