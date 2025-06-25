import { BackendTemplate } from '../types';

export const koaTypeScriptTemplate: BackendTemplate = {
  id: 'koa-ts',
  name: 'Koa.js + TypeScript',
  description: 'Modern Koa.js API server with TypeScript, async/await patterns, middleware composition, and clean architecture',
  framework: 'koa',
  language: 'typescript',
  version: '1.0.0',
  tags: ['koa', 'typescript', 'async-await', 'middleware', 'modern', 'rest-api'],
  port: 3000,
  features: [
    'authentication',
    'authorization',
    'validation',
    'logging',
    'testing',
    'cors',
    'security',
    'rest-api',
    'compression',
    'docker'
  ],
  dependencies: {
    'koa': '^2.14.2',
    '@koa/router': '^12.0.1',
    '@koa/cors': '^4.0.0',
    'koa-bodyparser': '^4.4.1',
    'koa-compress': '^5.1.1',
    'koa-helmet': '^7.0.2',
    'koa-ratelimit': '^5.1.0',
    'koa-jwt': '^4.0.4',
    'koa-logger': '^3.2.1',
    'koa-json': '^2.0.2',
    'koa-static': '^5.0.0',
    'jsonwebtoken': '^9.0.2',
    'bcryptjs': '^2.4.3',
    'joi': '^17.11.0',
    'dotenv': '^16.3.1',
    'winston': '^3.11.0',
    'ioredis': '^5.3.2'
      '@prisma/client': '^5.8.1',
      'bcrypt': '^5.1.1',
      'uuid': '^9.0.1',
  },
  devDependencies: {
    '@types/node': '^20.10.5',
    '@types/koa': '^2.13.12',
    '@types/koa__router': '^12.0.4',
    '@types/koa__cors': '^4.0.0',
    '@types/koa-bodyparser': '^4.3.12',
    '@types/koa-compress': '^4.0.6',
    '@types/koa-logger': '^3.1.5',
    '@types/koa-json': '^2.0.23',
    '@types/koa-static': '^4.0.4',
    '@types/jsonwebtoken': '^9.0.5',
    '@types/bcryptjs': '^2.4.6',
    '@types/jest': '^29.5.8',
    'typescript': '^5.3.3',
    'ts-node': '^10.9.1',
    'ts-node-dev': '^2.0.0',
    'jest': '^29.7.0',
    'ts-jest': '^29.1.1',
    'supertest': '^6.3.3',
    '@types/supertest': '^6.0.0',
    'eslint': '^8.56.0',
    '@typescript-eslint/parser': '^6.15.0',
    '@typescript-eslint/eslint-plugin': '^6.15.0',
    'prettier': '^3.1.1'
      'prisma': '^5.8.1',
      '@types/bcrypt': '^5.0.2',
      '@types/uuid': '^9.0.7',
  },
  files: {
    'package.json': {
      name: '{{projectName}}',
      version: '1.0.0',
      description: 'Koa.js TypeScript API server with modern async/await patterns',
      main: 'dist/index.js',
      scripts: {
        start: 'node dist/index.js',
        dev: 'ts-node-dev --respawn --transpile-only src/index.ts',
        build: 'tsc',
        test: 'jest',
        'test:watch': 'jest --watch',
        'test:coverage': 'jest --coverage',
        lint: 'eslint src --ext .ts',
        'lint:fix': 'eslint src --ext .ts --fix',
        format: 'prettier --write "src/**/*.ts"',
        'type-check': 'tsc --noEmit'
      },
      keywords: ['koa', 'typescript', 'api', 'server', 'async-await'],
      author: '{{author}}',
      license: 'MIT',
      engines: {
        node: '>=18.0.0'
      }
    },
    'tsconfig.json': {
      compilerOptions: {
        target: 'ES2022',
        module: 'commonjs',
        lib: ['ES2022'],
        outDir: './dist',
        rootDir: './src',
        strict: true,
        esModuleInterop: true,
        skipLibCheck: true,
        forceConsistentCasingInFileNames: true,
        declaration: true,
        declarationMap: true,
        sourceMap: true,
        removeComments: true,
        noImplicitAny: true,
        strictNullChecks: true,
        strictFunctionTypes: true,
        noImplicitThis: true,
        noImplicitReturns: true,
        noFallthroughCasesInSwitch: true,
        experimentalDecorators: true,
        emitDecoratorMetadata: true,
        resolveJsonModule: true,
        allowSyntheticDefaultImports: true,
        moduleResolution: 'node',
        baseUrl: './src',
        paths: {
          '@/*': ['./*'],
          '@config/*': ['./config/*'],
          '@middleware/*': ['./middleware/*'],
          '@routes/*': ['./routes/*'],
          '@services/*': ['./services/*'],
          '@types/*': ['./types/*'],
          '@utils/*': ['./utils/*']
        }
      },
      include: ['src/**/*'],
      exclude: ['node_modules', 'dist', '**/*.test.ts']
    },
    'src/index.ts': `import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import logger from 'koa-logger';
import json from 'koa-json';
import helmet from 'koa-helmet';
import compress from 'koa-compress';
import cors from '@koa/cors';
import rateLimit from 'koa-ratelimit';
import { config } from './config/environment';
import { setupRoutes } from './routes';
import { errorHandler } from './middleware/errorHandler';
import { responseTime } from './middleware/responseTime';
import { requestId } from './middleware/requestId';
import { setupLogger } from './config/logger';
import { redisClient } from './config/redis';

const app = new Koa();
const appLogger = setupLogger();

// Error handling
app.use(errorHandler);

// Request ID middleware
app.use(requestId);

// Response time middleware
app.use(responseTime);

// Security middleware
app.use(helmet());

// CORS
app.use(cors({
  origin: config.allowedOrigins,
  credentials: true,
}));

// Rate limiting
const rateLimitStore = new Map();
app.use(rateLimit({
  driver: 'memory',
  db: rateLimitStore,
  duration: 60000, // 1 minute
  errorMessage: 'Rate limit exceeded',
  max: 100,
  disableHeader: false,
  id: (ctx) => ctx.ip,
  headers: {
    remaining: 'Rate-Limit-Remaining',
    reset: 'Rate-Limit-Reset',
    total: 'Rate-Limit-Total'
  }
}));

// Compression
app.use(compress({
  threshold: 2048,
  gzip: {
    flush: require('zlib').constants.Z_SYNC_FLUSH
  },
  deflate: {
    flush: require('zlib').constants.Z_SYNC_FLUSH,
  },
  br: false
}));

// Logging
if (config.nodeEnv === 'development') {
  app.use(logger());
}

// Body parsing
app.use(bodyParser({
  jsonLimit: '10mb',
  formLimit: '10mb',
  textLimit: '10mb'
}));

// JSON pretty printing
app.use(json({ pretty: config.nodeEnv === 'development' }));

// Routes
setupRoutes(app);

// Graceful shutdown
const gracefulShutdown = async (signal: string) => {
  appLogger.info(\`Received \${signal}, shutting down gracefully\`);
  
  try {
    if (redisClient.status === 'ready') {
      await redisClient.quit();
    }
    
    process.exit(0);
  } catch (error) {
    appLogger.error('Error during shutdown:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const server = app.listen(config.port, () => {
  appLogger.info(\`Server running on port \${config.port}\`);
  appLogger.info(\`Environment: \${config.nodeEnv}\`);
});

// Handle server errors
server.on('error', (error: Error) => {
  appLogger.error('Server error:', error);
});

export default app;
`,
    'src/config/environment.ts': `import dotenv from 'dotenv';
import Joi from 'joi';

dotenv.config();

const envSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().port().default(3000),
  HOST: Joi.string().default('0.0.0.0'),
  JWT_SECRET: Joi.string().required(),
  JWT_EXPIRES_IN: Joi.string().default('7d'),
  BCRYPT_ROUNDS: Joi.number().integer().min(8).max(16).default(12),
  ALLOWED_ORIGINS: Joi.string().default('*'),
  REDIS_URL: Joi.string().default('redis://localhost:6379'),
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
  RATE_LIMIT_MAX: Joi.number().integer().positive().default(100),
  RATE_LIMIT_WINDOW: Joi.number().integer().positive().default(60000)
}).unknown();

const { error, value: envVars } = envSchema.validate(process.env);

if (error) {
  throw new Error(\`Config validation error: \${error.message}\`);
}

export const config = {
  nodeEnv: envVars.NODE_ENV,
  port: envVars.PORT,
  host: envVars.HOST,
  jwtSecret: envVars.JWT_SECRET,
  jwtExpiresIn: envVars.JWT_EXPIRES_IN,
  bcryptRounds: envVars.BCRYPT_ROUNDS,
  allowedOrigins: envVars.ALLOWED_ORIGINS.split(','),
  redisUrl: envVars.REDIS_URL,
  logLevel: envVars.LOG_LEVEL,
  rateLimitMax: envVars.RATE_LIMIT_MAX,
  rateLimitWindow: envVars.RATE_LIMIT_WINDOW
};
`,
    'src/config/logger.ts': `import winston from 'winston';
import { config } from './environment';

export const setupLogger = () => {
  const logger = winston.createLogger({
    level: config.logLevel,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    defaultMeta: { service: '{{projectName}}' },
    transports: [
      new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
      new winston.transports.File({ filename: 'logs/combined.log' })
    ]
  });

  if (config.nodeEnv !== 'production') {
    logger.add(new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }));
  }

  return logger;
};

export const logger = setupLogger();
`,
    'src/config/redis.ts': `import Redis from 'ioredis';
import { config } from './environment';
import { logger } from './logger';

export const redisClient = new Redis(config.redisUrl, {
  retryDelayOnFailover: 100,
  enableReadyCheck: false,
  maxRetriesPerRequest: null,
});

redisClient.on('connect', () => {
  logger.info('Redis client connected');
});

redisClient.on('error', (error) => {
  logger.error('Redis client error:', error);
});

redisClient.on('ready', () => {
  logger.info('Redis client ready');
});

redisClient.on('close', () => {
  logger.info('Redis client disconnected');
});
`,
    'src/middleware/errorHandler.ts': `import { Context, Next } from 'koa';
import { logger } from '../config/logger';

export interface AppError extends Error {
  status?: number;
  statusCode?: number;
  expose?: boolean;
}

export const errorHandler = async (ctx: Context, next: Next) => {
  try {
    await next();
  } catch (error: any) {
    const err = error as AppError;
    
    // Log error
    logger.error('Request error:', {
      message: err.message,
      stack: err.stack,
      url: ctx.url,
      method: ctx.method,
      ip: ctx.ip,
      userAgent: ctx.get('User-Agent'),
      requestId: ctx.state.requestId
    });

    // Set status code
    ctx.status = err.statusCode || err.status || 500;

    // Set response body
    ctx.body = {
      success: false,
      error: {
        message: err.expose || ctx.status < 500 ? err.message : 'Internal Server Error',
        status: ctx.status,
        timestamp: new Date().toISOString(),
        path: ctx.url,
        requestId: ctx.state.requestId,
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
      }
    };

    // Emit error event
    ctx.app.emit('error', err, ctx);
  }
};
`,
    'src/middleware/responseTime.ts': `import { Context, Next } from 'koa';

export const responseTime = async (ctx: Context, next: Next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  ctx.set('X-Response-Time', \`\${ms}ms\`);
};
`,
    'src/middleware/requestId.ts': `import { Context, Next } from 'koa';
import { randomUUID } from 'crypto';

export const requestId = async (ctx: Context, next: Next) => {
  const id = ctx.get('X-Request-ID') || randomUUID();
  ctx.state.requestId = id;
  ctx.set('X-Request-ID', id);
  await next();
};
`,
    'src/middleware/auth.ts': `import { Context, Next } from 'koa';
import jwt from 'jsonwebtoken';
import { config } from '../config/environment';

export interface User {
  id: string;
  email: string;
  role: string;
}

export interface AuthenticatedContext extends Context {
  state: Context['state'] & {
    user: User;
  };
}

export const authenticateToken = async (ctx: Context, next: Next) => {
  const authHeader = ctx.get('Authorization');
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    ctx.status = 401;
    ctx.body = {
      success: false,
      error: {
        message: 'Access token required',
        status: 401,
        timestamp: new Date().toISOString()
      }
    };
    return;
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret) as User;
    ctx.state.user = decoded;
    await next();
  } catch (error) {
    ctx.status = 401;
    ctx.body = {
      success: false,
      error: {
        message: 'Invalid or expired token',
        status: 401,
        timestamp: new Date().toISOString()
      }
    };
  }
};

export const authorizeRoles = (roles: string[]) => {
  return async (ctx: AuthenticatedContext, next: Next) => {
    if (!ctx.state.user) {
      ctx.status = 401;
      ctx.body = {
        success: false,
        error: {
          message: 'Authentication required',
          status: 401,
          timestamp: new Date().toISOString()
        }
      };
      return;
    }

    if (!roles.includes(ctx.state.user.role)) {
      ctx.status = 403;
      ctx.body = {
        success: false,
        error: {
          message: 'Insufficient permissions',
          status: 403,
          timestamp: new Date().toISOString()
        }
      };
      return;
    }

    await next();
  };
};
`,
    'src/middleware/validation.ts': `import { Context, Next } from 'koa';
import Joi from 'joi';

export const validate = (schema: Joi.ObjectSchema) => {
  return async (ctx: Context, next: Next) => {
    try {
      const { error, value } = schema.validate(ctx.request.body, {
        abortEarly: false,
        stripUnknown: true
      });

      if (error) {
        ctx.status = 400;
        ctx.body = {
          success: false,
          error: {
            message: 'Validation failed',
            status: 400,
            timestamp: new Date().toISOString(),
            details: error.details.map(detail => ({
              field: detail.path.join('.'),
              message: detail.message
            }))
          }
        };
        return;
      }

      ctx.request.body = value;
      await next();
    } catch (err) {
      ctx.status = 400;
      ctx.body = {
        success: false,
        error: {
          message: 'Invalid request body',
          status: 400,
          timestamp: new Date().toISOString()
        }
      };
    }
  };
};
`,
    'src/routes/index.ts': `import Koa from 'koa';
import Router from '@koa/router';
import { healthRoutes } from './health';
import { authRoutes } from './auth';
import { userRoutes } from './users';

export const setupRoutes = (app: Koa) => {
  const apiRouter = new Router({ prefix: '/api' });

  // Health check routes
  apiRouter.use('/health', healthRoutes.routes(), healthRoutes.allowedMethods());

  // Authentication routes
  apiRouter.use('/auth', authRoutes.routes(), authRoutes.allowedMethods());

  // User routes
  apiRouter.use('/users', userRoutes.routes(), userRoutes.allowedMethods());

  // Root route
  const rootRouter = new Router();
  rootRouter.get('/', async (ctx) => {
    ctx.body = {
      success: true,
      data: {
        message: 'Welcome to {{projectName}} API',
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        timestamp: new Date().toISOString()
      }
    };
  });

  app.use(rootRouter.routes()).use(rootRouter.allowedMethods());
  app.use(apiRouter.routes()).use(apiRouter.allowedMethods());
};
`,
    'src/routes/health.ts': `import Router from '@koa/router';

export const healthRoutes = new Router();

// Basic health check
healthRoutes.get('/', async (ctx) => {
  ctx.body = {
    success: true,
    data: {
      status: 'OK',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: '1.0.0'
    }
  };
});

// Detailed health check
healthRoutes.get('/detailed', async (ctx) => {
  const memoryUsage = process.memoryUsage();
  const cpuUsage = process.cpuUsage();

  ctx.body = {
    success: true,
    data: {
      status: 'OK',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: '1.0.0',
      memory: {
        rss: Math.round(memoryUsage.rss / 1024 / 1024) + ' MB',
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB',
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB',
        external: Math.round(memoryUsage.external / 1024 / 1024) + ' MB'
      },
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system
      }
    }
  };
});

// Readiness probe
healthRoutes.get('/ready', async (ctx) => {
  // Add your readiness checks here (database, external services, etc.)
  ctx.body = {
    success: true,
    data: {
      ready: true,
      timestamp: new Date().toISOString(),
      checks: {
        database: 'ok', // Replace with actual database check
        redis: 'ok', // Replace with actual Redis check
        externalServices: 'ok' // Replace with actual service checks
      }
    }
  };
});

// Liveness probe
healthRoutes.get('/live', async (ctx) => {
  ctx.body = {
    success: true,
    data: {
      alive: true,
      timestamp: new Date().toISOString()
    }
  };
});
`,
    'src/routes/auth.ts': `import Router from '@koa/router';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { validate } from '../middleware/validation';
import { authenticateToken } from '../middleware/auth';
import { config } from '../config/environment';
import { authSchemas } from '../schemas/auth';

export const authRoutes = new Router();

// Mock user storage (replace with database)
const users: Array<{
  id: string;
  email: string;
  password: string;
  role: string;
  createdAt: Date;
}> = [];

// Register endpoint
authRoutes.post('/register', validate(authSchemas.register), async (ctx) => {
  const { email, password, role = 'user' } = ctx.request.body as any;

  // Check if user already exists
  const existingUser = users.find(user => user.email === email);
  if (existingUser) {
    ctx.status = 409;
    ctx.body = {
      success: false,
      error: {
        message: 'User already exists',
        status: 409,
        timestamp: new Date().toISOString()
      }
    };
    return;
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, config.bcryptRounds);

  // Create user
  const newUser = {
    id: Date.now().toString(),
    email,
    password: hashedPassword,
    role,
    createdAt: new Date()
  };

  users.push(newUser);

  // Generate JWT token
  const token = jwt.sign(
    { id: newUser.id, email: newUser.email, role: newUser.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );

  ctx.status = 201;
  ctx.body = {
    success: true,
    data: {
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
        createdAt: newUser.createdAt
      },
      token
    }
  };
});

// Login endpoint
authRoutes.post('/login', validate(authSchemas.login), async (ctx) => {
  const { email, password } = ctx.request.body as any;

  // Find user
  const user = users.find(user => user.email === email);
  if (!user) {
    ctx.status = 401;
    ctx.body = {
      success: false,
      error: {
        message: 'Invalid credentials',
        status: 401,
        timestamp: new Date().toISOString()
      }
    };
    return;
  }

  // Verify password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    ctx.status = 401;
    ctx.body = {
      success: false,
      error: {
        message: 'Invalid credentials',
        status: 401,
        timestamp: new Date().toISOString()
      }
    };
    return;
  }

  // Generate JWT token
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );

  ctx.body = {
    success: true,
    data: {
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      },
      token
    }
  };
});

// Refresh token endpoint
authRoutes.post('/refresh', authenticateToken, async (ctx) => {
  const user = ctx.state.user;

  // Generate new token
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );

  ctx.body = {
    success: true,
    data: { token }
  };
});

// Get current user profile
authRoutes.get('/profile', authenticateToken, async (ctx) => {
  ctx.body = {
    success: true,
    data: {
      user: ctx.state.user
    }
  };
});
`,
    'src/routes/users.ts': `import Router from '@koa/router';
import { authenticateToken, authorizeRoles } from '../middleware/auth';

export const userRoutes = new Router();

// Get all users (admin only)
userRoutes.get('/', authenticateToken, authorizeRoles(['admin']), async (ctx) => {
  // Mock users data (replace with database query)
  const users = [
    { id: '1', email: 'admin@example.com', role: 'admin', createdAt: new Date().toISOString() },
    { id: '2', email: 'user@example.com', role: 'user', createdAt: new Date().toISOString() },
    { id: '3', email: 'user2@example.com', role: 'user', createdAt: new Date().toISOString() }
  ];

  ctx.body = {
    success: true,
    data: {
      users,
      total: users.length,
      page: 1,
      limit: 10
    }
  };
});

// Get user by ID
userRoutes.get('/:id', authenticateToken, async (ctx) => {
  const { id } = ctx.params;

  // Mock user lookup (replace with database query)
  const user = { 
    id, 
    email: \`user\${id}@example.com\`, 
    role: 'user', 
    createdAt: new Date().toISOString() 
  };

  if (!user) {
    ctx.status = 404;
    ctx.body = {
      success: false,
      error: {
        message: 'User not found',
        status: 404,
        timestamp: new Date().toISOString()
      }
    };
    return;
  }

  ctx.body = {
    success: true,
    data: { user }
  };
});

// Update user (admin only)
userRoutes.patch('/:id', authenticateToken, authorizeRoles(['admin']), async (ctx) => {
  const { id } = ctx.params;
  const updateData = ctx.request.body;

  // Mock user update (replace with database update)
  const updatedUser = {
    id,
    ...updateData,
    updatedAt: new Date().toISOString()
  };

  ctx.body = {
    success: true,
    data: { user: updatedUser }
  };
});

// Delete user (admin only)
userRoutes.delete('/:id', authenticateToken, authorizeRoles(['admin']), async (ctx) => {
  const { id } = ctx.params;

  // Mock user deletion (replace with database deletion)
  ctx.body = {
    success: true,
    data: {
      message: 'User deleted successfully',
      userId: id
    }
  };
});
`,
    'src/schemas/auth.ts': `import Joi from 'joi';

export const authSchemas = {
  register: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    role: Joi.string().valid('user', 'admin').default('user')
  }),

  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  }),

  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string().min(8).required()
  })
};
`,
    'src/schemas/user.ts': `import Joi from 'joi';

export const userSchemas = {
  create: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    name: Joi.string().optional(),
    role: Joi.string().valid('user', 'admin').default('user')
  }),

  update: Joi.object({
    email: Joi.string().email().optional(),
    name: Joi.string().optional(),
    role: Joi.string().valid('user', 'admin').optional()
  }).min(1)
};
`,
    'src/types/index.ts': `export interface User {
  id: string;
  email: string;
  role: string;
  name?: string;
  createdAt: Date;
  updatedAt?: Date;
}

export interface JWTPayload {
  id: string;
  email: string;
  role: string;
  iat?: number;
  exp?: number;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    message: string;
    status: number;
    timestamp: string;
    details?: any;
  };
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface HealthCheck {
  status: string;
  uptime: number;
  timestamp: string;
  environment: string;
  version: string;
  memory?: {
    rss: string;
    heapTotal: string;
    heapUsed: string;
    external: string;
  };
  cpu?: {
    user: number;
    system: number;
  };
}
`,
    'src/utils/password.ts': `import bcrypt from 'bcryptjs';
import { config } from '../config/environment';

export const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, config.bcryptRounds);
};

export const comparePassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};
`,
    'src/utils/jwt.ts': `import jwt from 'jsonwebtoken';
import { config } from '../config/environment';
import { JWTPayload } from '../types';

export const generateToken = (payload: Omit<JWTPayload, 'iat' | 'exp'>): string => {
  return jwt.sign(payload, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
};

export const verifyToken = (token: string): JWTPayload => {
  return jwt.verify(token, config.jwtSecret) as JWTPayload;
};

export const decodeToken = (token: string): JWTPayload | null => {
  try {
    return jwt.decode(token) as JWTPayload;
  } catch {
    return null;
  }
};
`,
    'src/utils/response.ts': `import { Context } from 'koa';
import { ApiResponse, PaginatedResponse } from '../types';

export const sendSuccess = <T>(ctx: Context, data: T, status: number = 200): void => {
  ctx.status = status;
  ctx.body = {
    success: true,
    data,
    timestamp: new Date().toISOString()
  } as ApiResponse<T>;
};

export const sendError = (ctx: Context, message: string, status: number = 500, details?: any): void => {
  ctx.status = status;
  ctx.body = {
    success: false,
    error: {
      message,
      status,
      timestamp: new Date().toISOString(),
      ...(details && { details })
    }
  } as ApiResponse;
};

export const sendPaginatedResponse = <T>(
  ctx: Context,
  items: T[],
  total: number,
  page: number,
  limit: number
): void => {
  const totalPages = Math.ceil(total / limit);
  
  ctx.body = {
    success: true,
    data: {
      items,
      total,
      page,
      limit,
      totalPages
    } as PaginatedResponse<T>,
    timestamp: new Date().toISOString()
  } as ApiResponse<PaginatedResponse<T>>;
};
`,
    '.env.example': `# Server Configuration
NODE_ENV=development
PORT=3000
HOST=0.0.0.0

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=7d

# Bcrypt Configuration
BCRYPT_ROUNDS=12

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Logging Configuration
LOG_LEVEL=info

# Rate Limiting Configuration
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000

# Database Configuration (add your database URL here)
# DATABASE_URL=postgresql://username:password@localhost:5432/database_name
`,
    '.gitignore': `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Production build
dist/
build/

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
logs/
*.log

# Runtime data
pids/
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
*.lcov

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
`,
    '.eslintrc.json': {
      env: {
        node: true,
        es2022: true,
        jest: true
      },
      extends: [
        'eslint:recommended',
        '@typescript-eslint/recommended'
      ],
      parser: '@typescript-eslint/parser',
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module'
      },
      plugins: ['@typescript-eslint'],
      rules: {
        '@typescript-eslint/no-unused-vars': 'error',
        '@typescript-eslint/explicit-function-return-type': 'off',
        '@typescript-eslint/no-explicit-any': 'warn',
        'no-console': 'warn',
        'prefer-const': 'error'
      }
    },
    '.prettierrc': {
      semi: true,
      trailingComma: 'es5',
      singleQuote: true,
      printWidth: 100,
      tabWidth: 2,
      useTabs: false
    },
    'README.md': `# {{projectName}}

A modern Koa.js API server with TypeScript, async/await patterns, middleware composition, and clean architecture.

## Features

- 🚀 **Koa.js Framework** - Next generation web framework for Node.js
- ⚡ **Async/Await** - Modern asynchronous programming patterns throughout
- 🧩 **Middleware Composition** - Elegant middleware composition with onion model
- 🔐 **JWT Authentication** - Secure token-based authentication
- ✅ **Joi Validation** - Schema-based request validation
- 🛡️ **Security First** - Helmet, CORS, rate limiting built-in
- 📝 **Structured Logging** - Winston logger with request tracking
- 🔄 **Redis Integration** - Ready for caching and sessions
- 🏥 **Health Checks** - Kubernetes-ready health endpoints
- 🧪 **Testing Ready** - Jest testing framework with TypeScript
- 🐳 **Production Ready** - Docker configuration and deployment setup
- 📦 **Clean Architecture** - Well-organized project structure

- **🗄️ Database Integration**: Prisma ORM with PostgreSQL, MySQL, SQLite support
## Quick Start

1. **Install dependencies:**
   \`\`\`bash
   npm install
   \`\`\`

2. **Set up environment variables:**
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

3. **Start Redis (optional but recommended):**
   \`\`\`bash
   docker run -d -p 6379:6379 redis:7-alpine
   \`\`\`

4. **Start development server:**
   \`\`\`bash
   npm run dev
   \`\`\`

5. **Build for production:**
   \`\`\`bash
   npm run build
   npm start
   \`\`\`

## API Endpoints

### Application
- \`GET /\` - Application information

### Health Checks
- \`GET /api/health\` - Basic health check
- \`GET /api/health/detailed\` - Detailed system information
- \`GET /api/health/ready\` - Readiness probe (Kubernetes)
- \`GET /api/health/live\` - Liveness probe (Kubernetes)

### Authentication
- \`POST /api/auth/register\` - Register new user
- \`POST /api/auth/login\` - Login user
- \`POST /api/auth/refresh\` - Refresh JWT token
- \`GET /api/auth/profile\` - Get current user profile (requires auth)

### Users
- \`GET /api/users\` - Get all users (admin only)
- \`GET /api/users/:id\` - Get user by ID (requires auth)
- \`PATCH /api/users/:id\` - Update user (admin only)
- \`DELETE /api/users/:id\` - Delete user (admin only)

## Architecture

### Middleware Stack
The application uses Koa's elegant middleware composition:

1. **Error Handling** - Global error catching and formatting
2. **Request ID** - Unique request tracking
3. **Response Time** - Performance monitoring
4. **Security** - Helmet security headers
5. **CORS** - Cross-origin resource sharing
6. **Rate Limiting** - Request throttling
7. **Compression** - Response compression
8. **Logging** - Request/response logging
9. **Body Parsing** - JSON/form parsing
10. **Routes** - Application routes

### Project Structure

\`\`\`
src/
├── config/             # Configuration files
│   ├── environment.ts  # Environment validation
│   ├── logger.ts       # Winston logger setup
│   └── redis.ts        # Redis client setup
├── middleware/         # Koa middleware
│   ├── auth.ts         # Authentication middleware
│   ├── errorHandler.ts # Global error handler
│   ├── requestId.ts    # Request ID generator
│   ├── responseTime.ts # Response time tracker
│   └── validation.ts   # Joi validation middleware
├── routes/             # API routes
│   ├── index.ts        # Route setup
│   ├── auth.ts         # Authentication routes
│   ├── health.ts       # Health check routes
│   └── users.ts        # User routes
├── schemas/            # Joi validation schemas
│   ├── auth.ts         # Auth validation schemas
│   └── user.ts         # User validation schemas
├── types/              # TypeScript type definitions
│   └── index.ts        # Common types
├── utils/              # Utility functions
│   ├── jwt.ts          # JWT utilities
│   ├── password.ts     # Password utilities
│   └── response.ts     # Response utilities
└── index.ts            # Application entry point
\`\`\`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`NODE_ENV\` | Environment | \`development\` |
| \`PORT\` | Server port | \`3000\` |
| \`HOST\` | Server host | \`0.0.0.0\` |
| \`JWT_SECRET\` | JWT secret key | Required |
| \`JWT_EXPIRES_IN\` | JWT expiration | \`7d\` |
| \`BCRYPT_ROUNDS\` | Bcrypt rounds | \`12\` |
| \`ALLOWED_ORIGINS\` | CORS allowed origins | \`*\` |
| \`REDIS_URL\` | Redis connection URL | \`redis://localhost:6379\` |
| \`LOG_LEVEL\` | Logging level | \`info\` |
| \`RATE_LIMIT_MAX\` | Rate limit max requests | \`100\` |
| \`RATE_LIMIT_WINDOW\` | Rate limit window (ms) | \`60000\` |

## Scripts

- \`npm start\` - Start production server
- \`npm run dev\` - Start development server with hot reload
- \`npm run build\` - Build for production
- \`npm test\` - Run tests
- \`npm run test:watch\` - Run tests in watch mode
- \`npm run test:coverage\` - Run tests with coverage
- \`npm run lint\` - Run ESLint
- \`npm run lint:fix\` - Fix ESLint issues
- \`npm run format\` - Format code with Prettier
- \`npm run type-check\` - Type check without emit

## Middleware Composition

Koa's middleware system uses an "onion" model where middleware executes in a stack-like manner:

\`\`\`typescript
app.use(async (ctx, next) => {
  // Before next middleware
  await next();
  // After next middleware
});
\`\`\`

This allows for powerful composition patterns like:

\`\`\`typescript
// Error handling wraps everything
app.use(errorHandler);

// Authentication middleware
app.use(authenticateToken);

// Route handlers
app.use(router.routes());
\`\`\`

## Async/Await Patterns

The template demonstrates modern async/await patterns:

### Route Handlers
\`\`\`typescript
router.get('/users', async (ctx) => {
  const users = await getUsersFromDatabase();
  ctx.body = { success: true, data: users };
});
\`\`\`

### Middleware
\`\`\`typescript
export const authenticateToken = async (ctx: Context, next: Next) => {
  const token = ctx.get('Authorization')?.split(' ')[1];
  if (!token) {
    ctx.status = 401;
    return;
  }
  
  try {
    const user = await verifyToken(token);
    ctx.state.user = user;
    await next();
  } catch (error) {
    ctx.status = 401;
  }
};
\`\`\`

## Validation

Using Joi for comprehensive validation:

\`\`\`typescript
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  role: Joi.string().valid('user', 'admin').default('user')
});

router.post('/register', validate(registerSchema), async (ctx) => {
  // ctx.request.body is now validated and sanitized
});
\`\`\`

## Error Handling

Global error handling with detailed logging:

\`\`\`typescript
export const errorHandler = async (ctx: Context, next: Next) => {
  try {
    await next();
  } catch (error) {
    logger.error('Request error:', {
      message: error.message,
      stack: error.stack,
      url: ctx.url,
      method: ctx.method,
      requestId: ctx.state.requestId
    });
    
    ctx.status = error.status || 500;
    ctx.body = {
      success: false,
      error: {
        message: error.message,
        status: ctx.status,
        requestId: ctx.state.requestId
      }
    };
  }
};
\`\`\`

## Testing

The template includes Jest setup for testing:

\`\`\`bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
\`\`\`

Example test:

\`\`\`typescript
import request from 'supertest';
import app from '../src/index';

describe('Health Check', () => {
  it('should return health status', async () => {
    const response = await request(app.callback())
      .get('/api/health')
      .expect(200);
    
    expect(response.body.success).toBe(true);
    expect(response.body.data.status).toBe('OK');
  });
});
\`\`\`

## Redis Integration

Redis client setup for caching and sessions:

\`\`\`typescript
import Redis from 'ioredis';

export const redisClient = new Redis(config.redisUrl, {
  retryDelayOnFailover: 100,
  enableReadyCheck: false,
  maxRetriesPerRequest: null,
});

// Usage in routes
router.get('/cached-data', async (ctx) => {
  const cached = await redisClient.get('data-key');
  if (cached) {
    ctx.body = JSON.parse(cached);
    return;
  }
  
  const data = await fetchData();
  await redisClient.setex('data-key', 3600, JSON.stringify(data));
  ctx.body = data;
});
\`\`\`

## Security Features

- **Helmet.js** - Security headers
- **CORS** - Cross-origin resource sharing
- **Rate Limiting** - Request throttling
- **JWT Authentication** - Secure token-based auth
- **Input Validation** - Joi schema validation
- **Password Hashing** - bcrypt with configurable rounds
- **Request ID Tracking** - Request tracing
- **Error Logging** - Comprehensive error tracking

## Performance Features

- **Async/Await** - Non-blocking operations
- **Compression** - Gzip response compression
- **Connection Pooling** - Redis connection management
- **Response Time Tracking** - Performance monitoring
- **Memory Efficient** - Koa's lightweight design

## Production Deployment

1. Set \`NODE_ENV=production\`
2. Use a strong \`JWT_SECRET\`
3. Configure proper Redis connection
4. Set up proper CORS origins
5. Use process manager (PM2, Docker)
6. Configure reverse proxy (nginx)
7. Set up SSL/TLS certificates
8. Monitor with health checks

## Docker Deployment

\`\`\`dockerfile
FROM node:18-alpine AS development
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:18-alpine AS production
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force
COPY --from=development /usr/src/app/dist ./dist
CMD ["node", "dist/index.js"]
\`\`\`

## Kubernetes Deployment

The template includes Kubernetes-ready health endpoints:

\`\`\`yaml
livenessProbe:
  httpGet:
    path: /api/health/live
    port: 3000
  initialDelaySeconds: 30
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /api/health/ready
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 5
\`\`\`

## License

MIT
`,
    'Dockerfile': `# Multi-stage build for Koa.js TypeScript application
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \\
    adduser -S koa -u 1001

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder --chown=koa:nodejs /app/dist ./dist

# Create logs directory
RUN mkdir -p logs && chown koa:nodejs logs

# Switch to non-root user
USER koa

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD node -e "require('http').get('http://localhost:3000/api/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "dist/index.js"]
`,
    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - HOST=0.0.0.0
      - JWT_SECRET=your-production-jwt-secret
      - REDIS_URL=redis://redis:6379
      - LOG_LEVEL=info
    volumes:
      - ./logs:/app/logs
    depends_on:
      - redis
    networks:
      - app-network
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - app-network
    restart: unless-stopped
    command: redis-server --appendonly yes

volumes:
  redis-data:

networks:
  app-network:
    driver: bridge
`,
    'jest.config.js': `module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@config/(.*)$': '<rootDir>/src/config/$1',
    '^@middleware/(.*)$': '<rootDir>/src/middleware/$1',
    '^@routes/(.*)$': '<rootDir>/src/routes/$1',
    '^@services/(.*)$': '<rootDir>/src/services/$1',
    '^@types/(.*)$': '<rootDir>/src/types/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
  },
};
`,
    'test/health.test.ts': `import request from 'supertest';
import app from '../src/index';

describe('Health Check Endpoints', () => {
  afterAll(async () => {
    // Close any open connections
    await new Promise((resolve) => setTimeout(resolve, 500));
  });

  describe('GET /api/health', () => {
    it('should return basic health status', async () => {
      const response = await request(app.callback())
        .get('/api/health')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.status).toBe('OK');
      expect(response.body.data.uptime).toBeGreaterThan(0);
      expect(response.body.data.timestamp).toBeDefined();
      expect(response.body.data.environment).toBeDefined();
      expect(response.body.data.version).toBe('1.0.0');
    });
  });

  describe('GET /api/health/detailed', () => {
    it('should return detailed health information', async () => {
      const response = await request(app.callback())
        .get('/api/health/detailed')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.status).toBe('OK');
      expect(response.body.data.memory).toBeDefined();
      expect(response.body.data.cpu).toBeDefined();
      expect(response.body.data.memory.rss).toMatch(/\\d+ MB/);
      expect(typeof response.body.data.cpu.user).toBe('number');
    });
  });

  describe('GET /api/health/ready', () => {
    it('should return readiness status', async () => {
      const response = await request(app.callback())
        .get('/api/health/ready')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.ready).toBe(true);
      expect(response.body.data.checks).toBeDefined();
    });
  });

  describe('GET /api/health/live', () => {
    it('should return liveness status', async () => {
      const response = await request(app.callback())
        .get('/api/health/live')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.alive).toBe(true);
      expect(response.body.data.timestamp).toBeDefined();
    });
  });
});
`,
    'test/auth.test.ts': `import request from 'supertest';
import app from '../src/index';

describe('Authentication Endpoints', () => {
  let userToken: string;

  afterAll(async () => {
    await new Promise((resolve) => setTimeout(resolve, 500));
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        role: 'user'
      };

      const response = await request(app.callback())
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(userData.email);
      expect(response.body.data.user.role).toBe(userData.role);
      expect(response.body.data.token).toBeDefined();
      expect(response.body.data.user.password).toBeUndefined();

      userToken = response.body.data.token;
    });

    it('should not register user with duplicate email', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123'
      };

      await request(app.callback())
        .post('/api/auth/register')
        .send(userData)
        .expect(409);
    });

    it('should validate email format', async () => {
      const userData = {
        email: 'invalid-email',
        password: 'password123'
      };

      await request(app.callback())
        .post('/api/auth/register')
        .send(userData)
        .expect(400);
    });

    it('should validate password length', async () => {
      const userData = {
        email: 'test2@example.com',
        password: '123'
      };

      await request(app.callback())
        .post('/api/auth/register')
        .send(userData)
        .expect(400);
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login with valid credentials', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app.callback())
        .post('/api/auth/login')
        .send(loginData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(loginData.email);
      expect(response.body.data.token).toBeDefined();
    });

    it('should not login with invalid email', async () => {
      const loginData = {
        email: 'nonexistent@example.com',
        password: 'password123'
      };

      await request(app.callback())
        .post('/api/auth/login')
        .send(loginData)
        .expect(401);
    });

    it('should not login with invalid password', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'wrongpassword'
      };

      await request(app.callback())
        .post('/api/auth/login')
        .send(loginData)
        .expect(401);
    });
  });

  describe('GET /api/auth/profile', () => {
    it('should get user profile with valid token', async () => {
      const response = await request(app.callback())
        .get('/api/auth/profile')
        .set('Authorization', \`Bearer \${userToken}\`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe('test@example.com');
    });

    it('should not get profile without token', async () => {
      await request(app.callback())
        .get('/api/auth/profile')
        .expect(401);
    });

    it('should not get profile with invalid token', async () => {
      await request(app.callback())
        .get('/api/auth/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });
  });

  describe('POST /api/auth/refresh', () => {
    it('should refresh token with valid token', async () => {
      const response = await request(app.callback())
        .post('/api/auth/refresh')
        .set('Authorization', \`Bearer \${userToken}\`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.token).toBeDefined();
    });
  });
});
`
  },
  prompts: [
    {
      type: 'input',
      name: 'projectName',
      message: 'What is your project name?',
      default: 'koa-api'
    },
    {
      type: 'input',
      name: 'author',
      message: 'Who is the author?',
      default: 'Your Name'
    },
    {
      type: 'confirm',
      name: 'includeRedis',
      message: 'Include Redis integration for caching?',
      default: true
    },
    {
      type: 'confirm',
      name: 'includeDatabase',
      message: 'Include database integration (TypeORM/Prisma)?',
      default: true
    },
    {
      type: 'list',
      name: 'database',
      message: 'Which database would you like to use?',
      choices: ['PostgreSQL', 'MySQL', 'SQLite', 'MongoDB'],
      when: (answers) => answers.includeDatabase,
      default: 'PostgreSQL'
    },
    {
      type: 'confirm',
      name: 'includeDocker',
      message: 'Include Docker configuration?',
      default: true
    }
  ],
  postInstall: [
    'npm install',
    'mkdir -p logs',
    'cp .env.example .env',
    'echo "✅ Koa.js TypeScript template created successfully!"',
    'echo "📝 Don\'t forget to:"',
    'echo "   1. Update .env with your configuration"',
    'echo "   2. Start Redis: docker run -d -p 6379:6379 redis:7-alpine"',
    'echo "   3. Run \'npm run dev\' to start development"',
    'echo "   4. Visit http://localhost:3000/api/health for health check"'
      'npx prisma generate',
    'echo "📋 Database setup:"',
    'echo "1. Set DATABASE_URL in .env"',
    'echo "2. Run: npm run db:push"',
    'echo "3. Run: npm run db:seed"',]
};