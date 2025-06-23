import { BackendTemplate } from '../types';

export const hapiTypeScriptTemplate: BackendTemplate = {
  id: 'hapi-ts',
  name: 'Hapi.js + TypeScript',
  description: 'Enterprise-grade Hapi.js API server with TypeScript, built-in validation, caching, security, and plugin architecture',
  framework: 'hapi',
  language: 'typescript',
  dependencies: {
    '@hapi/hapi': '^21.3.9',
    '@hapi/joi': '^17.1.1',
    '@hapi/boom': '^10.0.1',
    '@hapi/inert': '^7.1.0',
    '@hapi/vision': '^7.0.3',
    '@hapi/good': '^9.0.1',
    '@hapi/catbox-redis': '^7.0.2',
    '@hapi/basic': '^7.0.2',
    '@hapi/jwt': '^3.2.0',
    '@hapi/bell': '^13.0.1',
    'hapi-swagger': '^17.2.1',
    'hapi-rate-limit': '^6.1.0',
    'bcrypt': '^5.1.1',
    'jsonwebtoken': '^9.0.2',
    'redis': '^4.6.13',
    'winston': '^3.11.0',
    'dotenv': '^16.4.5',
    'helmet': '^7.1.0',
    'cors': '^2.8.5'
  },
  devDependencies: {
    '@types/hapi__hapi': '^20.0.13',
    '@types/hapi__joi': '^17.1.14',
    '@types/hapi__boom': '^9.0.4',
    '@types/hapi__inert': '^5.2.10',
    '@types/hapi__vision': '^5.5.7',
    '@types/hapi__good': '^8.1.5',
    '@types/hapi__basic': '^5.0.4',
    '@types/hapi__jwt': '^2.0.4',
    '@types/hapi__bell': '^10.0.6',
    '@types/bcrypt': '^5.0.2',
    '@types/jsonwebtoken': '^9.0.6',
    '@types/node': '^20.17.0',
    '@types/redis': '^4.0.11',
    'typescript': '^5.3.3',
    'ts-node': '^10.9.2',
    'nodemon': '^3.0.2',
    '@types/lab': '^18.1.4',
    '@hapi/lab': '^25.2.0',
    '@hapi/code': '^9.0.3',
    'rimraf': '^5.0.5'
  },
  files: {
    'package.json': `{
  "name": "{{serviceName}}",
  "version": "1.0.0",
  "description": "Hapi.js TypeScript API server with built-in validation, caching, and security",
  "main": "dist/server.js",
  "scripts": {
    "build": "tsc",
    "start": "node dist/server.js",
    "dev": "nodemon --exec ts-node src/server.ts",
    "test": "lab -v --reporter console --output stdout --coverage --threshold 80",
    "test:watch": "lab -v --reporter console --output stdout --watch",
    "lint": "tsc --noEmit",
    "clean": "rimraf dist"
  },
  "keywords": ["hapi", "typescript", "api", "validation", "caching", "security"],
  "author": "{{author}}",
  "license": "MIT"
}`,
    'tsconfig.json': `{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noImplicitOverride": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "test"]
}`,
    'src/server.ts': `import Hapi from '@hapi/hapi';
import { configureServer } from './config/server';
import { logger } from './utils/logger';
import { gracefulShutdown } from './utils/gracefulShutdown';

const init = async (): Promise<Hapi.Server> => {
  const server = await configureServer();
  
  await server.start();
  logger.info(\`Server running on \${server.info.uri}\`);
  
  return server;
};

process.on('unhandledRejection', (err) => {
  logger.error('Unhandled rejection:', err);
  process.exit(1);
});

process.on('SIGTERM', () => gracefulShutdown());
process.on('SIGINT', () => gracefulShutdown());

init().catch((error) => {
  logger.error('Failed to start server:', error);
  process.exit(1);
});`,
    'src/config/server.ts': `import Hapi from '@hapi/hapi';
import { loadEnvironment } from './environment';
import { registerPlugins } from './plugins';
import { setupRoutes } from './routes';
import { setupCache } from './cache';

export const configureServer = async (): Promise<Hapi.Server> => {
  const env = loadEnvironment();
  
  const server = Hapi.server({
    port: env.PORT,
    host: env.HOST,
    routes: {
      cors: {
        origin: ['*'],
        headers: ['Accept', 'Authorization', 'Content-Type', 'If-None-Match'],
        exposedHeaders: ['WWW-Authenticate', 'Server-Authorization'],
        additionalExposedHeaders: ['Cache-Control'],
        maxAge: 60,
        credentials: true
      },
      validate: {
        failAction: async (request, h, err) => {
          if (process.env.NODE_ENV === 'production') {
            throw err;
          }
          console.error(err);
          throw err;
        }
      }
    }
  });

  // Setup cache
  await setupCache(server);
  
  // Register plugins
  await registerPlugins(server);
  
  // Setup routes
  setupRoutes(server);
  
  return server;
};`,
    'src/config/environment.ts': `import dotenv from 'dotenv';
import Joi from '@hapi/joi';

dotenv.config();

interface Environment {
  NODE_ENV: string;
  PORT: number;
  HOST: string;
  JWT_SECRET: string;
  JWT_EXPIRATION: string;
  REDIS_URL: string;
  CACHE_TTL: number;
  API_RATE_LIMIT: number;
  LOG_LEVEL: string;
}

const envSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),
  HOST: Joi.string().default('localhost'),
  JWT_SECRET: Joi.string().required(),
  JWT_EXPIRATION: Joi.string().default('24h'),
  REDIS_URL: Joi.string().default('redis://localhost:6379'),
  CACHE_TTL: Joi.number().default(300000), // 5 minutes
  API_RATE_LIMIT: Joi.number().default(100),
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info')
}).unknown();

export const loadEnvironment = (): Environment => {
  const { error, value } = envSchema.validate(process.env);
  
  if (error) {
    throw new Error(\`Environment validation error: \${error.message}\`);
  }
  
  return value;
};`,
    'src/config/plugins.ts': `import Hapi from '@hapi/hapi';
import Inert from '@hapi/inert';
import Vision from '@hapi/vision';
import Good from '@hapi/good';
import Basic from '@hapi/basic';
import Jwt from '@hapi/jwt';
import HapiSwagger from 'hapi-swagger';
import RateLimit from 'hapi-rate-limit';
import { loadEnvironment } from './environment';
import { validateUser } from '../auth/strategies';
import { logger } from '../utils/logger';

export const registerPlugins = async (server: Hapi.Server): Promise<void> => {
  const env = loadEnvironment();
  
  // Static files and templating
  await server.register([Inert, Vision]);
  
  // Logging
  await server.register({
    plugin: Good,
    options: {
      ops: {
        interval: 1000
      },
      reporters: {
        console: [{
          module: '@hapi/good-squeeze',
          name: 'Squeeze',
          args: [{ log: '*', response: '*' }]
        }, {
          module: '@hapi/good-console'
        }, 'stdout']
      }
    }
  });
  
  // Rate limiting
  await server.register({
    plugin: RateLimit,
    options: {
      userLimit: env.API_RATE_LIMIT,
      userCache: {
        expiresIn: 60000 // 1 minute
      },
      addressOnly: true,
      pathLimit: false,
      userAttribute: 'id',
      userWhitelist: ['admin'],
      addressWhitelist: ['127.0.0.1', '::1'],
      trustProxy: true,
      ipWhitelist: []
    }
  });
  
  // Authentication
  await server.register([Basic, Jwt]);
  
  // JWT Strategy
  server.auth.strategy('jwt', 'jwt', {
    keys: env.JWT_SECRET,
    verify: {
      aud: false,
      iss: false,
      sub: false,
      nbf: true,
      exp: true,
      maxAgeSec: 86400, // 24 hours
      timeSkewSec: 15
    },
    validate: validateUser
  });
  
  // Basic Auth Strategy
  server.auth.strategy('basic', 'basic', {
    validate: async (request, username, password) => {
      // Implement basic auth validation
      return { isValid: false, credentials: {} };
    }
  });
  
  server.auth.default('jwt');
  
  // Swagger documentation
  const swaggerOptions: HapiSwagger.RegisterOptions = {
    info: {
      title: 'Hapi.js TypeScript API',
      version: '1.0.0',
      description: 'API documentation for Hapi.js TypeScript server'
    },
    schemes: env.NODE_ENV === 'production' ? ['https'] : ['http'],
    host: env.NODE_ENV === 'production' ? 'api.example.com' : \`\${env.HOST}:\${env.PORT}\`,
    documentationPath: '/docs',
    grouping: 'tags',
    tags: [
      { name: 'auth', description: 'Authentication endpoints' },
      { name: 'users', description: 'User management' },
      { name: 'health', description: 'Health check endpoints' }
    ]
  };
  
  await server.register({
    plugin: HapiSwagger,
    options: swaggerOptions
  });
  
  logger.info('All plugins registered successfully');
};`,
    'src/config/routes.ts': `import Hapi from '@hapi/hapi';
import { authRoutes } from '../routes/auth';
import { userRoutes } from '../routes/users';
import { healthRoutes } from '../routes/health';

export const setupRoutes = (server: Hapi.Server): void => {
  // Health check routes (no auth required)
  server.route(healthRoutes);
  
  // Authentication routes
  server.route(authRoutes);
  
  // User routes (requires auth)
  server.route(userRoutes);
};`,
    'src/config/cache.ts': `import Hapi from '@hapi/hapi';
import { loadEnvironment } from './environment';

export const setupCache = async (server: Hapi.Server): Promise<void> => {
  const env = loadEnvironment();
  
  // Register Redis cache
  await server.register({
    plugin: require('@hapi/catbox-redis'),
    options: {
      uri: env.REDIS_URL,
      partition: 'cache'
    }
  });
  
  // Define cache policies
  const cache = server.cache({
    segment: 'sessions',
    expiresIn: env.CACHE_TTL
  });
  
  const userCache = server.cache({
    segment: 'users',
    expiresIn: 600000 // 10 minutes
  });
  
  // Make caches available to routes
  server.app.cache = cache;
  server.app.userCache = userCache;
};`,
    'src/auth/strategies.ts': `import Hapi from '@hapi/hapi';
import Boom from '@hapi/boom';
import { UserService } from '../services/userService';

export interface JWTPayload {
  id: string;
  email: string;
  role: string;
  iat: number;
  exp: number;
}

export const validateUser = async (
  decoded: JWTPayload,
  request: Hapi.Request,
  h: Hapi.ResponseToolkit
) => {
  try {
    const userService = new UserService();
    const user = await userService.findById(decoded.id);
    
    if (!user) {
      return { isValid: false };
    }
    
    return {
      isValid: true,
      credentials: {
        id: user.id,
        email: user.email,
        role: user.role,
        scope: [user.role] // For role-based access control
      }
    };
  } catch (error) {
    return { isValid: false };
  }
};

export const requireRole = (role: string) => {
  return (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    const { credentials } = request.auth;
    
    if (!credentials?.scope?.includes(role)) {
      throw Boom.forbidden('Insufficient permissions');
    }
    
    return h.continue;
  };
};`,
    'src/routes/auth.ts': `import Hapi from '@hapi/hapi';
import Joi from '@hapi/joi';
import { AuthController } from '../controllers/authController';

const authController = new AuthController();

export const authRoutes: Hapi.ServerRoute[] = [
  {
    method: 'POST',
    path: '/auth/login',
    options: {
      auth: false,
      description: 'User login',
      notes: 'Authenticate user and return JWT token',
      tags: ['api', 'auth'],
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(),
          password: Joi.string().min(6).required()
        })
      },
      response: {
        schema: Joi.object({
          token: Joi.string().required(),
          user: Joi.object({
            id: Joi.string().required(),
            email: Joi.string().email().required(),
            role: Joi.string().required()
          }).required()
        })
      }
    },
    handler: authController.login
  },
  {
    method: 'POST',
    path: '/auth/register',
    options: {
      auth: false,
      description: 'User registration',
      notes: 'Register a new user account',
      tags: ['api', 'auth'],
      validate: {
        payload: Joi.object({
          email: Joi.string().email().required(),
          password: Joi.string().min(6).required(),
          name: Joi.string().required()
        })
      },
      response: {
        schema: Joi.object({
          message: Joi.string().required(),
          user: Joi.object({
            id: Joi.string().required(),
            email: Joi.string().email().required(),
            name: Joi.string().required()
          }).required()
        })
      }
    },
    handler: authController.register
  },
  {
    method: 'POST',
    path: '/auth/refresh',
    options: {
      description: 'Refresh JWT token',
      notes: 'Get a new JWT token using the current valid token',
      tags: ['api', 'auth'],
      response: {
        schema: Joi.object({
          token: Joi.string().required()
        })
      }
    },
    handler: authController.refresh
  },
  {
    method: 'POST',
    path: '/auth/logout',
    options: {
      description: 'User logout',
      notes: 'Invalidate the current JWT token',
      tags: ['api', 'auth'],
      response: {
        schema: Joi.object({
          message: Joi.string().required()
        })
      }
    },
    handler: authController.logout
  }
];`,
    'src/routes/users.ts': `import Hapi from '@hapi/hapi';
import Joi from '@hapi/joi';
import { UserController } from '../controllers/userController';
import { requireRole } from '../auth/strategies';

const userController = new UserController();

export const userRoutes: Hapi.ServerRoute[] = [
  {
    method: 'GET',
    path: '/users',
    options: {
      description: 'Get all users',
      notes: 'Retrieve a list of all users (admin only)',
      tags: ['api', 'users'],
      pre: [{ method: requireRole('admin') }],
      validate: {
        query: Joi.object({
          page: Joi.number().min(1).default(1),
          limit: Joi.number().min(1).max(100).default(10),
          search: Joi.string().optional()
        })
      },
      response: {
        schema: Joi.object({
          users: Joi.array().items(
            Joi.object({
              id: Joi.string().required(),
              email: Joi.string().email().required(),
              name: Joi.string().required(),
              role: Joi.string().required(),
              createdAt: Joi.date().required()
            })
          ).required(),
          pagination: Joi.object({
            page: Joi.number().required(),
            limit: Joi.number().required(),
            total: Joi.number().required(),
            pages: Joi.number().required()
          }).required()
        })
      }
    },
    handler: userController.getUsers
  },
  {
    method: 'GET',
    path: '/users/me',
    options: {
      description: 'Get current user profile',
      notes: 'Retrieve the profile of the currently authenticated user',
      tags: ['api', 'users'],
      response: {
        schema: Joi.object({
          id: Joi.string().required(),
          email: Joi.string().email().required(),
          name: Joi.string().required(),
          role: Joi.string().required(),
          createdAt: Joi.date().required(),
          updatedAt: Joi.date().required()
        })
      }
    },
    handler: userController.getCurrentUser
  },
  {
    method: 'GET',
    path: '/users/{id}',
    options: {
      description: 'Get user by ID',
      notes: 'Retrieve a specific user by their ID',
      tags: ['api', 'users'],
      validate: {
        params: Joi.object({
          id: Joi.string().uuid().required()
        })
      },
      response: {
        schema: Joi.object({
          id: Joi.string().required(),
          email: Joi.string().email().required(),
          name: Joi.string().required(),
          role: Joi.string().required(),
          createdAt: Joi.date().required(),
          updatedAt: Joi.date().required()
        })
      }
    },
    handler: userController.getUserById
  },
  {
    method: 'PUT',
    path: '/users/me',
    options: {
      description: 'Update current user profile',
      notes: 'Update the profile of the currently authenticated user',
      tags: ['api', 'users'],
      validate: {
        payload: Joi.object({
          name: Joi.string().optional(),
          email: Joi.string().email().optional()
        })
      },
      response: {
        schema: Joi.object({
          id: Joi.string().required(),
          email: Joi.string().email().required(),
          name: Joi.string().required(),
          role: Joi.string().required(),
          updatedAt: Joi.date().required()
        })
      }
    },
    handler: userController.updateCurrentUser
  },
  {
    method: 'DELETE',
    path: '/users/{id}',
    options: {
      description: 'Delete user',
      notes: 'Delete a user account (admin only)',
      tags: ['api', 'users'],
      pre: [{ method: requireRole('admin') }],
      validate: {
        params: Joi.object({
          id: Joi.string().uuid().required()
        })
      },
      response: {
        schema: Joi.object({
          message: Joi.string().required()
        })
      }
    },
    handler: userController.deleteUser
  }
];`,
    'src/routes/health.ts': `import Hapi from '@hapi/hapi';
import Joi from '@hapi/joi';
import { HealthController } from '../controllers/healthController';

const healthController = new HealthController();

export const healthRoutes: Hapi.ServerRoute[] = [
  {
    method: 'GET',
    path: '/health',
    options: {
      auth: false,
      description: 'Basic health check',
      notes: 'Returns basic server health status',
      tags: ['api', 'health'],
      response: {
        schema: Joi.object({
          status: Joi.string().required(),
          timestamp: Joi.date().required()
        })
      }
    },
    handler: healthController.basic
  },
  {
    method: 'GET',
    path: '/health/detailed',
    options: {
      auth: false,
      description: 'Detailed health check',
      notes: 'Returns detailed server health information including dependencies',
      tags: ['api', 'health'],
      response: {
        schema: Joi.object({
          status: Joi.string().required(),
          timestamp: Joi.date().required(),
          uptime: Joi.number().required(),
          memory: Joi.object().required(),
          database: Joi.object().required(),
          cache: Joi.object().required()
        })
      }
    },
    handler: healthController.detailed
  },
  {
    method: 'GET',
    path: '/health/ready',
    options: {
      auth: false,
      description: 'Readiness probe',
      notes: 'Kubernetes readiness probe endpoint',
      tags: ['api', 'health']
    },
    handler: healthController.ready
  },
  {
    method: 'GET',
    path: '/health/live',
    options: {
      auth: false,
      description: 'Liveness probe',
      notes: 'Kubernetes liveness probe endpoint',
      tags: ['api', 'health']
    },
    handler: healthController.live
  }
];`,
    'src/controllers/authController.ts': `import Hapi from '@hapi/hapi';
import Boom from '@hapi/boom';
import { AuthService } from '../services/authService';
import { logger } from '../utils/logger';

export class AuthController {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  login = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { email, password } = request.payload as { email: string; password: string };
      
      const result = await this.authService.login(email, password);
      
      if (!result) {
        throw Boom.unauthorized('Invalid credentials');
      }
      
      logger.info(\`User logged in: \${email}\`);
      
      return h.response(result).code(200);
    } catch (error) {
      logger.error('Login error:', error);
      throw error;
    }
  };

  register = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { email, password, name } = request.payload as { 
        email: string; 
        password: string; 
        name: string; 
      };
      
      const result = await this.authService.register(email, password, name);
      
      logger.info(\`User registered: \${email}\`);
      
      return h.response(result).code(201);
    } catch (error) {
      logger.error('Registration error:', error);
      if (error.message.includes('already exists')) {
        throw Boom.conflict('User already exists');
      }
      throw Boom.badImplementation('Registration failed');
    }
  };

  refresh = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { credentials } = request.auth;
      const newToken = await this.authService.refreshToken(credentials.id);
      
      return h.response({ token: newToken }).code(200);
    } catch (error) {
      logger.error('Token refresh error:', error);
      throw Boom.unauthorized('Failed to refresh token');
    }
  };

  logout = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { credentials } = request.auth;
      await this.authService.logout(credentials.id);
      
      logger.info(\`User logged out: \${credentials.email}\`);
      
      return h.response({ message: 'Logged out successfully' }).code(200);
    } catch (error) {
      logger.error('Logout error:', error);
      throw Boom.badImplementation('Logout failed');
    }
  };
}`,
    'src/controllers/userController.ts': `import Hapi from '@hapi/hapi';
import Boom from '@hapi/boom';
import { UserService } from '../services/userService';
import { logger } from '../utils/logger';

export class UserController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
  }

  getUsers = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { page, limit, search } = request.query as { 
        page: number; 
        limit: number; 
        search?: string; 
      };
      
      const result = await this.userService.getUsers(page, limit, search);
      
      return h.response(result).code(200);
    } catch (error) {
      logger.error('Get users error:', error);
      throw Boom.badImplementation('Failed to retrieve users');
    }
  };

  getCurrentUser = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { credentials } = request.auth;
      const user = await this.userService.findById(credentials.id);
      
      if (!user) {
        throw Boom.notFound('User not found');
      }
      
      return h.response(user).code(200);
    } catch (error) {
      logger.error('Get current user error:', error);
      throw error;
    }
  };

  getUserById = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { id } = request.params as { id: string };
      const user = await this.userService.findById(id);
      
      if (!user) {
        throw Boom.notFound('User not found');
      }
      
      return h.response(user).code(200);
    } catch (error) {
      logger.error('Get user by ID error:', error);
      throw error;
    }
  };

  updateCurrentUser = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { credentials } = request.auth;
      const updates = request.payload as { name?: string; email?: string };
      
      const user = await this.userService.updateUser(credentials.id, updates);
      
      logger.info(\`User updated: \${credentials.email}\`);
      
      return h.response(user).code(200);
    } catch (error) {
      logger.error('Update user error:', error);
      throw Boom.badImplementation('Failed to update user');
    }
  };

  deleteUser = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    try {
      const { id } = request.params as { id: string };
      await this.userService.deleteUser(id);
      
      logger.info(\`User deleted: \${id}\`);
      
      return h.response({ message: 'User deleted successfully' }).code(200);
    } catch (error) {
      logger.error('Delete user error:', error);
      throw Boom.badImplementation('Failed to delete user');
    }
  };
}`,
    'src/controllers/healthController.ts': `import Hapi from '@hapi/hapi';
import { HealthService } from '../services/healthService';

export class HealthController {
  private healthService: HealthService;

  constructor() {
    this.healthService = new HealthService();
  }

  basic = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    const health = await this.healthService.getBasicHealth();
    return h.response(health).code(200);
  };

  detailed = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    const health = await this.healthService.getDetailedHealth();
    return h.response(health).code(200);
  };

  ready = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    const isReady = await this.healthService.isReady();
    return h.response(isReady ? 'Ready' : 'Not Ready').code(isReady ? 200 : 503);
  };

  live = async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    const isLive = await this.healthService.isLive();
    return h.response(isLive ? 'Live' : 'Not Live').code(isLive ? 200 : 503);
  };
}`,
    'src/services/authService.ts': `import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { UserService } from './userService';
import { loadEnvironment } from '../config/environment';

export interface LoginResult {
  token: string;
  user: {
    id: string;
    email: string;
    role: string;
  };
}

export interface RegisterResult {
  message: string;
  user: {
    id: string;
    email: string;
    name: string;
  };
}

export class AuthService {
  private userService: UserService;
  private env = loadEnvironment();

  constructor() {
    this.userService = new UserService();
  }

  async login(email: string, password: string): Promise<LoginResult | null> {
    const user = await this.userService.findByEmail(email);
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      return null;
    }

    const token = this.generateToken(user.id, user.email, user.role);

    return {
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    };
  }

  async register(email: string, password: string, name: string): Promise<RegisterResult> {
    const existingUser = await this.userService.findByEmail(email);
    
    if (existingUser) {
      throw new Error('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await this.userService.createUser({
      email,
      password: hashedPassword,
      name,
      role: 'user'
    });

    return {
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    };
  }

  async refreshToken(userId: string): Promise<string> {
    const user = await this.userService.findById(userId);
    
    if (!user) {
      throw new Error('User not found');
    }

    return this.generateToken(user.id, user.email, user.role);
  }

  async logout(userId: string): Promise<void> {
    // Implement token blacklisting or session invalidation
    // For now, we'll just log the action
    console.log(\`User \${userId} logged out\`);
  }

  private generateToken(id: string, email: string, role: string): string {
    return jwt.sign(
      { id, email, role },
      this.env.JWT_SECRET,
      { expiresIn: this.env.JWT_EXPIRATION }
    );
  }
}`,
    'src/services/userService.ts': `import { v4 as uuidv4 } from 'uuid';

export interface User {
  id: string;
  email: string;
  password: string;
  name: string;
  role: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserData {
  email: string;
  password: string;
  name: string;
  role: string;
}

export interface UpdateUserData {
  name?: string;
  email?: string;
}

export interface PaginatedUsers {
  users: Omit<User, 'password'>[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

// In-memory storage for demo purposes
// Replace with actual database implementation
const users: User[] = [
  {
    id: '1',
    email: 'admin@example.com',
    password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/KjB0Y8B0Y8B0Y8B0Y',
    name: 'Admin User',
    role: 'admin',
    createdAt: new Date(),
    updatedAt: new Date()
  }
];

export class UserService {
  async findById(id: string): Promise<Omit<User, 'password'> | null> {
    const user = users.find(u => u.id === id);
    if (!user) return null;
    
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }

  async findByEmail(email: string): Promise<User | null> {
    return users.find(u => u.email === email) || null;
  }

  async createUser(userData: CreateUserData): Promise<Omit<User, 'password'>> {
    const user: User = {
      id: uuidv4(),
      ...userData,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    users.push(user);
    
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }

  async updateUser(id: string, updates: UpdateUserData): Promise<Omit<User, 'password'>> {
    const userIndex = users.findIndex(u => u.id === id);
    
    if (userIndex === -1) {
      throw new Error('User not found');
    }

    users[userIndex] = {
      ...users[userIndex],
      ...updates,
      updatedAt: new Date()
    };

    const { password, ...userWithoutPassword } = users[userIndex];
    return userWithoutPassword;
  }

  async deleteUser(id: string): Promise<void> {
    const userIndex = users.findIndex(u => u.id === id);
    
    if (userIndex === -1) {
      throw new Error('User not found');
    }

    users.splice(userIndex, 1);
  }

  async getUsers(page: number = 1, limit: number = 10, search?: string): Promise<PaginatedUsers> {
    let filteredUsers = users;

    if (search) {
      filteredUsers = users.filter(u => 
        u.name.toLowerCase().includes(search.toLowerCase()) ||
        u.email.toLowerCase().includes(search.toLowerCase())
      );
    }

    const total = filteredUsers.length;
    const pages = Math.ceil(total / limit);
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;

    const paginatedUsers = filteredUsers
      .slice(startIndex, endIndex)
      .map(({ password, ...user }) => user);

    return {
      users: paginatedUsers,
      pagination: {
        page,
        limit,
        total,
        pages
      }
    };
  }
}`,
    'src/services/healthService.ts': `export interface HealthStatus {
  status: string;
  timestamp: Date;
  uptime?: number;
  memory?: NodeJS.MemoryUsage;
  database?: { status: string; latency?: number };
  cache?: { status: string; latency?: number };
}

export class HealthService {
  async getBasicHealth(): Promise<HealthStatus> {
    return {
      status: 'ok',
      timestamp: new Date()
    };
  }

  async getDetailedHealth(): Promise<HealthStatus> {
    const memoryUsage = process.memoryUsage();
    
    return {
      status: 'ok',
      timestamp: new Date(),
      uptime: process.uptime(),
      memory: memoryUsage,
      database: await this.checkDatabase(),
      cache: await this.checkCache()
    };
  }

  async isReady(): Promise<boolean> {
    try {
      const dbStatus = await this.checkDatabase();
      const cacheStatus = await this.checkCache();
      
      return dbStatus.status === 'ok' && cacheStatus.status === 'ok';
    } catch (error) {
      return false;
    }
  }

  async isLive(): Promise<boolean> {
    // Simple liveness check
    return true;
  }

  private async checkDatabase(): Promise<{ status: string; latency?: number }> {
    try {
      const start = Date.now();
      // Simulate database check
      await new Promise(resolve => setTimeout(resolve, 10));
      const latency = Date.now() - start;
      
      return { status: 'ok', latency };
    } catch (error) {
      return { status: 'error' };
    }
  }

  private async checkCache(): Promise<{ status: string; latency?: number }> {
    try {
      const start = Date.now();
      // Simulate cache check
      await new Promise(resolve => setTimeout(resolve, 5));
      const latency = Date.now() - start;
      
      return { status: 'ok', latency };
    } catch (error) {
      return { status: 'error' };
    }
  }
}`,
    'src/utils/logger.ts': `import winston from 'winston';
import { loadEnvironment } from '../config/environment';

const env = loadEnvironment();

const logger = winston.createLogger({
  level: env.LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'hapi-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

export { logger };`,
    'src/utils/gracefulShutdown.ts': `import { logger } from './logger';

export const gracefulShutdown = (): void => {
  logger.info('Received shutdown signal, closing server gracefully...');
  
  // Perform cleanup operations here
  // - Close database connections
  // - Finish pending requests
  // - Clean up resources
  
  process.exit(0);
};`,
    '.env.example': `NODE_ENV=development
PORT=3000
HOST=localhost

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRATION=24h

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Cache Configuration
CACHE_TTL=300000

# Rate Limiting
API_RATE_LIMIT=100

# Logging
LOG_LEVEL=info`,
    'Dockerfile': `# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY src ./src

# Build the application
RUN npm run build

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S hapi -u 1001

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && npm cache clean --force

# Copy built application
COPY --from=builder /app/dist ./dist

# Create logs directory
RUN mkdir -p logs && chown -R hapi:nodejs logs

# Switch to non-root user
USER hapi

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD node -e "require('http').get('http://localhost:3000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

EXPOSE 3000

CMD ["node", "dist/server.js"]`,
    'docker-compose.yml': `version: '3.8'

services:
  hapi-api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - PORT=3000
      - HOST=0.0.0.0
      - JWT_SECRET=dev-jwt-secret-change-in-production
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    volumes:
      - ./logs:/app/logs
    networks:
      - hapi-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    networks:
      - hapi-network

volumes:
  redis-data:

networks:
  hapi-network:
    driver: bridge`,
    'test/auth.test.ts': `import { expect } from '@hapi/code';
import Lab from '@hapi/lab';
import { configureServer } from '../src/config/server';

const { describe, it, before, after } = exports.lab = Lab.script();

describe('Authentication', () => {
  let server: any;

  before(async () => {
    server = await configureServer();
  });

  after(async () => {
    await server.stop();
  });

  it('should register a new user', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      }
    });

    expect(response.statusCode).to.equal(201);
    expect(response.result.user.email).to.equal('test@example.com');
  });

  it('should login with valid credentials', async () => {
    // First register a user
    await server.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'login@example.com',
        password: 'password123',
        name: 'Login User'
      }
    });

    const response = await server.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'login@example.com',
        password: 'password123'
      }
    });

    expect(response.statusCode).to.equal(200);
    expect(response.result.token).to.exist();
    expect(response.result.user.email).to.equal('login@example.com');
  });

  it('should reject invalid credentials', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'nonexistent@example.com',
        password: 'wrongpassword'
      }
    });

    expect(response.statusCode).to.equal(401);
  });
});`,
    'test/users.test.ts': `import { expect } from '@hapi/code';
import Lab from '@hapi/lab';
import { configureServer } from '../src/config/server';

const { describe, it, before, after, beforeEach } = exports.lab = Lab.script();

describe('Users', () => {
  let server: any;
  let authToken: string;

  before(async () => {
    server = await configureServer();
  });

  after(async () => {
    await server.stop();
  });

  beforeEach(async () => {
    // Login as admin to get auth token
    const loginResponse = await server.inject({
      method: 'POST',
      url: '/auth/login',
      payload: {
        email: 'admin@example.com',
        password: 'admin123'
      }
    });

    authToken = loginResponse.result.token;
  });

  it('should get current user profile', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/users/me',
      headers: {
        authorization: \`Bearer \${authToken}\`
      }
    });

    expect(response.statusCode).to.equal(200);
    expect(response.result.email).to.exist();
  });

  it('should update current user profile', async () => {
    const response = await server.inject({
      method: 'PUT',
      url: '/users/me',
      headers: {
        authorization: \`Bearer \${authToken}\`
      },
      payload: {
        name: 'Updated Name'
      }
    });

    expect(response.statusCode).to.equal(200);
    expect(response.result.name).to.equal('Updated Name');
  });

  it('should require authentication for protected routes', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/users/me'
    });

    expect(response.statusCode).to.equal(401);
  });
});`,
    'test/health.test.ts': `import { expect } from '@hapi/code';
import Lab from '@hapi/lab';
import { configureServer } from '../src/config/server';

const { describe, it, before, after } = exports.lab = Lab.script();

describe('Health Endpoints', () => {
  let server: any;

  before(async () => {
    server = await configureServer();
  });

  after(async () => {
    await server.stop();
  });

  it('should return basic health status', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health'
    });

    expect(response.statusCode).to.equal(200);
    expect(response.result.status).to.equal('ok');
    expect(response.result.timestamp).to.exist();
  });

  it('should return detailed health status', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health/detailed'
    });

    expect(response.statusCode).to.equal(200);
    expect(response.result.status).to.equal('ok');
    expect(response.result.uptime).to.exist();
    expect(response.result.memory).to.exist();
  });

  it('should return readiness status', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health/ready'
    });

    expect(response.statusCode).to.equal(200);
  });

  it('should return liveness status', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health/live'
    });

    expect(response.statusCode).to.equal(200);
  });
});`,
    'README.md': `# {{serviceName}}

Enterprise-grade Hapi.js API server with TypeScript, built-in validation, caching, security, and plugin architecture.

## Features

- **🚀 Hapi.js Framework**: High-performance, configuration-centric framework
- **📝 TypeScript**: Full type safety with strict configuration  
- **✅ Built-in Validation**: Joi schema validation for all inputs
- **🔒 Security**: JWT authentication, rate limiting, CORS, Helmet
- **💾 Caching**: Redis-based caching with configurable TTL
- **📊 Health Checks**: Kubernetes-ready health endpoints
- **🔌 Plugin Architecture**: Extensible plugin system
- **📚 API Documentation**: Auto-generated Swagger documentation
- **🧪 Testing**: Lab testing framework with high coverage
- **🐳 Docker**: Production-ready containerization

## Quick Start

### Prerequisites

- Node.js 20+
- Redis server
- npm/yarn/pnpm

### Installation

\`\`\`bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit environment variables
nano .env
\`\`\`

### Development

\`\`\`bash
# Start development server
npm run dev

# Run tests
npm test

# Build for production
npm run build

# Start production server
npm start
\`\`\`

### Docker

\`\`\`bash
# Build and run with Docker Compose
docker-compose up --build

# Or build and run manually
docker build -t {{serviceName}} .
docker run -p 3000:3000 {{serviceName}}
\`\`\`

## API Documentation

Once the server is running, visit:
- **Swagger UI**: http://localhost:3000/docs
- **Health Check**: http://localhost:3000/health

## Architecture

### Project Structure

\`\`\`
src/
├── config/          # Server configuration
│   ├── server.ts    # Main server setup
│   ├── plugins.ts   # Plugin registration
│   ├── routes.ts    # Route configuration
│   ├── cache.ts     # Cache setup
│   └── environment.ts # Environment validation
├── routes/          # Route definitions
│   ├── auth.ts      # Authentication routes
│   ├── users.ts     # User management routes
│   └── health.ts    # Health check routes
├── controllers/     # Request handlers
│   ├── authController.ts
│   ├── userController.ts
│   └── healthController.ts
├── services/        # Business logic
│   ├── authService.ts
│   ├── userService.ts
│   └── healthService.ts
├── auth/           # Authentication strategies
│   └── strategies.ts
└── utils/          # Utilities
    ├── logger.ts
    └── gracefulShutdown.ts
\`\`\`

### Key Features

#### Built-in Validation
- Joi schema validation for all endpoints
- Type-safe request/response handling
- Automatic error responses for invalid data

#### Caching System
- Redis-based caching with configurable TTL
- Multiple cache segments (sessions, users, etc.)
- Cache policies for different data types

#### Security Features
- JWT authentication with refresh tokens
- Role-based access control (RBAC)
- Rate limiting with user and IP-based limits
- CORS configuration
- Helmet security headers

#### Plugin Architecture
- Modular plugin system
- Easy extension and customization
- Built-in plugins for common functionality

## Authentication

### JWT Authentication

The API uses JWT tokens for authentication:

\`\`\`bash
# Login to get token
curl -X POST http://localhost:3000/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "user@example.com", "password": "password"}'

# Use token in requests
curl -X GET http://localhost:3000/users/me \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
\`\`\`

### Role-Based Access Control

The API supports role-based access control:

- \`user\`: Standard user access
- \`admin\`: Administrative access

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`NODE_ENV\` | Environment mode | \`development\` |
| \`PORT\` | Server port | \`3000\` |
| \`HOST\` | Server host | \`localhost\` |
| \`JWT_SECRET\` | JWT signing secret | Required |
| \`JWT_EXPIRATION\` | JWT expiration time | \`24h\` |
| \`REDIS_URL\` | Redis connection URL | \`redis://localhost:6379\` |
| \`CACHE_TTL\` | Cache TTL in milliseconds | \`300000\` |
| \`API_RATE_LIMIT\` | Rate limit per user | \`100\` |
| \`LOG_LEVEL\` | Logging level | \`info\` |

## Health Checks

The service provides multiple health check endpoints:

- \`GET /health\` - Basic health status
- \`GET /health/detailed\` - Detailed health information
- \`GET /health/ready\` - Kubernetes readiness probe
- \`GET /health/live\` - Kubernetes liveness probe

## Testing

\`\`\`bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
\`\`\`

## Performance

### Benchmarks

Hapi.js provides excellent performance characteristics:

- **High Throughput**: Optimized for high concurrent requests
- **Low Memory**: Efficient memory usage patterns
- **Built-in Caching**: Redis-based caching reduces database load
- **Connection Pooling**: Efficient resource management

### Optimization Tips

1. **Enable Caching**: Use Redis caching for frequently accessed data
2. **Rate Limiting**: Protect against abuse with rate limiting
3. **Compression**: Enable gzip compression for responses
4. **Connection Pooling**: Use connection pooling for databases
5. **Monitoring**: Monitor performance with health endpoints

## Deployment

### Docker Deployment

\`\`\`bash
# Build image
docker build -t {{serviceName}} .

# Run container
docker run -d \\
  --name {{serviceName}} \\
  -p 3000:3000 \\
  -e JWT_SECRET=your-secret \\
  -e REDIS_URL=redis://redis:6379 \\
  {{serviceName}}
\`\`\`

### Kubernetes Deployment

\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{serviceName}}
spec:
  replicas: 3
  selector:
    matchLabels:
      app: {{serviceName}}
  template:
    metadata:
      labels:
        app: {{serviceName}}
    spec:
      containers:
      - name: {{serviceName}}
        image: {{serviceName}}:latest
        ports:
        - containerPort: 3000
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: {{serviceName}}-secrets
              key: jwt-secret
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
\`\`\`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

MIT License - see LICENSE file for details.`
  },
  version: '1.0.0',
  tags: ['hapi', 'typescript', 'validation', 'caching', 'security', 'enterprise'],
  postInstall: [
    'npm install',
    'cp .env.example .env',
    'mkdir -p logs',
    'npm run build'
  ]
};