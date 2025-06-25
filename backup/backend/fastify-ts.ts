import { BackendTemplate } from '../types';

export const fastifyTypeScriptTemplate: BackendTemplate = {
  id: 'fastify-ts',
  name: 'Fastify + TypeScript',
  description: 'High-performance Fastify API server with TypeScript, schema validation, plugins, and async/await support',
  framework: 'fastify',
  language: 'typescript',
  version: '1.0.0',
  tags: ['fastify', 'typescript', 'schema-validation', 'plugins', 'async', 'rest-api'],
  port: 3000,
  features: [
    'authentication',
    'authorization',
    'validation',
    'logging',
    'testing',
    'cors',
    'rate-limiting',
    'security',
    'rest-api',
    'docker'
  ],
  dependencies: {
    fastify: '^4.25.2',
    '@fastify/cors': '^8.4.2',
    '@fastify/helmet': '^11.1.1',
    '@fastify/rate-limit': '^9.1.0',
    '@fastify/jwt': '^7.2.4',
    '@fastify/bcrypt': '^1.0.1',
    '@fastify/env': '^4.3.0',
    '@fastify/autoload': '^5.8.0',
    '@fastify/sensible': '^5.5.0',
    '@fastify/swagger': '^8.13.0',
    '@fastify/swagger-ui': '^1.10.0',
    '@fastify/cookie': '^9.2.0',
    pino: '^8.17.2',
    'pino-pretty': '^10.3.1',
    'fluent-json-schema': '^4.2.1',
    bcrypt: '^5.1.1',
    dotenv: '^16.3.1'
      '@prisma/client': '^5.8.1',
      'bcrypt': '^5.1.1',
      'uuid': '^9.0.1',
  },
  devDependencies: {
    '@types/node': '^20.10.5',
    '@types/bcrypt': '^5.0.2',
    typescript: '^5.3.3',
    'ts-node': '^10.9.1',
    'ts-node-dev': '^2.0.0',
    '@types/tap': '^15.0.11',
    tap: '^18.6.1',
    'c8': '^9.0.0',
    '@typescript-eslint/eslint-plugin': '^6.15.0',
    '@typescript-eslint/parser': '^6.15.0',
    eslint: '^8.56.0',
    prettier: '^3.1.1'
      'prisma': '^5.8.1',
      '@types/uuid': '^9.0.7',
  },
  files: {
    'package.json': {
      name: '{{projectName}}',
      version: '1.0.0',
      description: 'Fastify TypeScript API server with schema validation',
      main: 'dist/server.js',
      scripts: {
        start: 'node dist/server.js',
        dev: 'ts-node-dev --respawn --transpile-only src/server.ts',
        build: 'tsc',
        test: 'tap --ts test/**/*.test.ts',
        'test:watch': 'tap --ts --watch test/**/*.test.ts',
        'test:coverage': 'c8 tap --ts test/**/*.test.ts',
        lint: 'eslint src --ext .ts',
        'lint:fix': 'eslint src --ext .ts --fix',
        format: 'prettier --write "src/**/*.ts" "test/**/*.ts"',
        'type-check': 'tsc --noEmit'
      },
      keywords: ['fastify', 'typescript', 'api', 'server', 'schema-validation'],
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
        allowSyntheticDefaultImports: true
      },
      include: ['src/**/*'],
      exclude: ['node_modules', 'dist', 'test']
    },
    'src/server.ts': `import fastify from 'fastify';
import { config } from './config/environment';
import { registerPlugins } from './plugins';
import { registerRoutes } from './routes';

const server = fastify({
  logger: {
    level: config.LOG_LEVEL,
    ...(config.NODE_ENV === 'development' && {
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          ignore: 'pid,hostname',
          translateTime: 'SYS:standard'
        }
      }
    })
  },
  ajv: {
    customOptions: {
      removeAdditional: 'all',
      coerceTypes: true,
      useDefaults: true
    }
  }
});

async function start() {
  try {
    // Register plugins
    await registerPlugins(server);

    // Register routes
    await registerRoutes(server);

    // Start server
    await server.listen({
      port: config.PORT,
      host: config.HOST
    });

    server.log.info(\`Server running on http://\${config.HOST}:\${config.PORT}\`);

    // Graceful shutdown
    const shutdown = async (signal: string) => {
      server.log.info(\`Received \${signal}, shutting down gracefully\`);
      await server.close();
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

  } catch (error) {
    server.log.error(error);
    process.exit(1);
  }
}

start();

export default server;
`,
    'src/config/environment.ts': `import { Static, Type } from '@sinclair/typebox';
import Ajv from 'ajv';

const ConfigSchema = Type.Object({
  NODE_ENV: Type.Union([
    Type.Literal('development'),
    Type.Literal('production'),
    Type.Literal('test')
  ], { default: 'development' }),
  PORT: Type.Number({ default: 3000, minimum: 1, maximum: 65535 }),
  HOST: Type.String({ default: '0.0.0.0' }),
  LOG_LEVEL: Type.Union([
    Type.Literal('fatal'),
    Type.Literal('error'),
    Type.Literal('warn'),
    Type.Literal('info'),
    Type.Literal('debug'),
    Type.Literal('trace')
  ], { default: 'info' }),
  JWT_SECRET: Type.String({ default: 'your-super-secret-jwt-key' }),
  JWT_EXPIRES_IN: Type.String({ default: '7d' }),
  BCRYPT_ROUNDS: Type.Number({ default: 12, minimum: 8, maximum: 16 }),
  RATE_LIMIT_MAX: Type.Number({ default: 100, minimum: 1 }),
  RATE_LIMIT_WINDOW: Type.Number({ default: 900000, minimum: 1000 }) // 15 minutes
});

type Config = Static<typeof ConfigSchema>;

// Load environment variables
const env = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: parseInt(process.env.PORT || '3000', 10),
  HOST: process.env.HOST || '0.0.0.0',
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d',
  BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW || '900000', 10)
};

// Validate configuration
const ajv = new Ajv();
const validate = ajv.compile(ConfigSchema);

if (!validate(env)) {
  throw new Error(\`Invalid configuration: \${JSON.stringify(validate.errors, null, 2)}\`);
}

export const config: Config = env as Config;
`,
    'src/plugins/index.ts': `import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

export async function registerPlugins(fastify: FastifyInstance) {
  // Environment variables validation
  await fastify.register(import('@fastify/env'), {
    confKey: 'config',
    dotenv: true,
    schema: {
      type: 'object',
      required: ['JWT_SECRET'],
      properties: {
        NODE_ENV: { type: 'string', default: 'development' },
        PORT: { type: 'number', default: 3000 },
        HOST: { type: 'string', default: '0.0.0.0' },
        LOG_LEVEL: { type: 'string', default: 'info' },
        JWT_SECRET: { type: 'string' },
        JWT_EXPIRES_IN: { type: 'string', default: '7d' },
        BCRYPT_ROUNDS: { type: 'number', default: 12 },
        RATE_LIMIT_MAX: { type: 'number', default: 100 },
        RATE_LIMIT_WINDOW: { type: 'number', default: 900000 }
      }
    }
  });

  // Sensible defaults and utilities
  await fastify.register(import('@fastify/sensible'));

  // Security
  await fastify.register(import('@fastify/helmet'), {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:']
      }
    }
  });

  // CORS
  await fastify.register(import('@fastify/cors'), {
    origin: (origin, callback) => {
      // Allow all origins in development
      if (process.env.NODE_ENV === 'development') {
        callback(null, true);
        return;
      }
      
      // In production, check against allowed origins
      const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'), false);
      }
    },
    credentials: true
  });

  // Rate limiting
  await fastify.register(import('@fastify/rate-limit'), {
    max: process.env.RATE_LIMIT_MAX ? parseInt(process.env.RATE_LIMIT_MAX) : 100,
    timeWindow: process.env.RATE_LIMIT_WINDOW ? parseInt(process.env.RATE_LIMIT_WINDOW) : 900000,
    errorResponseBuilder: (request, context) => ({
      code: 429,
      error: 'Too Many Requests',
      message: \`Rate limit exceeded, retry in \${Math.round(context.ttl / 1000)} seconds\`,
      date: Date.now(),
      expiresIn: Math.round(context.ttl / 1000)
    })
  });

  // JWT support
  await fastify.register(import('@fastify/jwt'), {
    secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key'
  });

  // Bcrypt support
  await fastify.register(import('@fastify/bcrypt'), {
    saltWorkFactor: process.env.BCRYPT_ROUNDS ? parseInt(process.env.BCRYPT_ROUNDS) : 12
  });

  // Cookie support
  await fastify.register(import('@fastify/cookie'), {
    secret: process.env.COOKIE_SECRET || process.env.JWT_SECRET || 'your-super-secret-cookie-key'
  });

  // Swagger documentation
  await fastify.register(import('@fastify/swagger'), {
    swagger: {
      info: {
        title: '{{projectName}} API',
        description: 'Fastify TypeScript API with schema validation',
        version: '1.0.0'
      },
      externalDocs: {
        url: 'https://swagger.io',
        description: 'Find more info here'
      },
      host: \`localhost:\${process.env.PORT || 3000}\`,
      schemes: ['http', 'https'],
      consumes: ['application/json'],
      produces: ['application/json'],
      tags: [
        { name: 'health', description: 'Health check endpoints' },
        { name: 'auth', description: 'Authentication endpoints' },
        { name: 'users', description: 'User management endpoints' }
      ]
    }
  });

  // Swagger UI
  await fastify.register(import('@fastify/swagger-ui'), {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'full',
      deepLinking: false
    },
    staticCSP: true,
    transformSpecificationClone: true
  });

  // Auto-load plugins from plugins directory
  await fastify.register(import('@fastify/autoload'), {
    dir: \`\${__dirname}/auth\`,
    options: {}
  });
}
`,
    'src/plugins/auth/index.ts': `import { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

export interface User {
  id: string;
  email: string;
  role: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: User;
  }
}

async function authPlugin(fastify: FastifyInstance) {
  fastify.decorate('authenticate', async function(request: FastifyRequest) {
    try {
      const token = await request.jwtVerify<User>();
      request.user = token;
    } catch (error) {
      throw fastify.httpErrors.unauthorized('Invalid or expired token');
    }
  });

  fastify.decorate('authorize', function(roles: string[] = []) {
    return async function(request: FastifyRequest) {
      if (!request.user) {
        throw fastify.httpErrors.unauthorized('Authentication required');
      }

      if (roles.length > 0 && !roles.includes(request.user.role)) {
        throw fastify.httpErrors.forbidden('Insufficient permissions');
      }
    };
  });
}

export default fp(authPlugin);
`,
    'src/routes/index.ts': `import { FastifyInstance } from 'fastify';
import { healthRoutes } from './health';
import { authRoutes } from './auth';
import { userRoutes } from './users';

export async function registerRoutes(fastify: FastifyInstance) {
  // Register route modules
  await fastify.register(healthRoutes, { prefix: '/api/health' });
  await fastify.register(authRoutes, { prefix: '/api/auth' });
  await fastify.register(userRoutes, { prefix: '/api/users' });

  // Root endpoint
  fastify.get('/', {
    schema: {
      description: 'Root endpoint',
      tags: ['general'],
      response: {
        200: {
          type: 'object',
          properties: {
            message: { type: 'string' },
            version: { type: 'string' },
            environment: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' }
          }
        }
      }
    }
  }, async (request, reply) => {
    return {
      message: 'Welcome to {{projectName}} API',
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString()
    };
  });
}
`,
    'src/routes/health.ts': `import { FastifyInstance } from 'fastify';
import { Type } from '@sinclair/typebox';

const HealthResponse = Type.Object({
  status: Type.String(),
  uptime: Type.Number(),
  timestamp: Type.String({ format: 'date-time' }),
  environment: Type.String(),
  version: Type.String(),
  memory: Type.Optional(Type.Object({
    rss: Type.String(),
    heapTotal: Type.String(),
    heapUsed: Type.String(),
    external: Type.String()
  })),
  cpu: Type.Optional(Type.Object({
    user: Type.Number(),
    system: Type.Number()
  }))
});

export async function healthRoutes(fastify: FastifyInstance) {
  // Basic health check
  fastify.get('/', {
    schema: {
      description: 'Basic health check',
      tags: ['health'],
      response: {
        200: HealthResponse
      }
    }
  }, async (request, reply) => {
    return {
      status: 'OK',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0'
    };
  });

  // Detailed health check
  fastify.get('/detailed', {
    schema: {
      description: 'Detailed health check with system information',
      tags: ['health'],
      response: {
        200: HealthResponse
      }
    }
  }, async (request, reply) => {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    return {
      status: 'OK',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0',
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
    };
  });

  // Readiness probe
  fastify.get('/ready', {
    schema: {
      description: 'Readiness probe for container orchestration',
      tags: ['health'],
      response: {
        200: Type.Object({
          ready: Type.Boolean(),
          timestamp: Type.String({ format: 'date-time' })
        })
      }
    }
  }, async (request, reply) => {
    // Add your readiness checks here (database, external services, etc.)
    return {
      ready: true,
      timestamp: new Date().toISOString()
    };
  });

  // Liveness probe
  fastify.get('/live', {
    schema: {
      description: 'Liveness probe for container orchestration',
      tags: ['health'],
      response: {
        200: Type.Object({
          alive: Type.Boolean(),
          timestamp: Type.String({ format: 'date-time' })
        })
      }
    }
  }, async (request, reply) => {
    return {
      alive: true,
      timestamp: new Date().toISOString()
    };
  });
}
`,
    'src/routes/auth.ts': `import { FastifyInstance } from 'fastify';
import { Type } from '@sinclair/typebox';

// In-memory user storage (replace with database)
const users: Array<{
  id: string;
  email: string;
  password: string;
  role: string;
  createdAt: Date;
}> = [];

const RegisterRequest = Type.Object({
  email: Type.String({ format: 'email' }),
  password: Type.String({ minLength: 8 }),
  role: Type.Optional(Type.Union([Type.Literal('user'), Type.Literal('admin')]))
});

const LoginRequest = Type.Object({
  email: Type.String({ format: 'email' }),
  password: Type.String({ minLength: 1 })
});

const AuthResponse = Type.Object({
  user: Type.Object({
    id: Type.String(),
    email: Type.String(),
    role: Type.String(),
    createdAt: Type.Optional(Type.String({ format: 'date-time' }))
  }),
  token: Type.String()
});

export async function authRoutes(fastify: FastifyInstance) {
  // Register endpoint
  fastify.post('/register', {
    schema: {
      description: 'Register a new user',
      tags: ['auth'],
      body: RegisterRequest,
      response: {
        201: AuthResponse,
        409: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        })
      }
    }
  }, async (request, reply) => {
    const { email, password, role = 'user' } = request.body as any;

    // Check if user already exists
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
      return reply.conflict('User already exists');
    }

    // Hash password
    const hashedPassword = await fastify.bcrypt.hash(password);

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
    const token = fastify.jwt.sign(
      {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role
      },
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    reply.code(201);
    return {
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
        createdAt: newUser.createdAt.toISOString()
      },
      token
    };
  });

  // Login endpoint
  fastify.post('/login', {
    schema: {
      description: 'Login user',
      tags: ['auth'],
      body: LoginRequest,
      response: {
        200: AuthResponse,
        401: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        })
      }
    }
  }, async (request, reply) => {
    const { email, password } = request.body as any;

    // Find user
    const user = users.find(user => user.email === email);
    if (!user) {
      return reply.unauthorized('Invalid credentials');
    }

    // Verify password
    const isPasswordValid = await fastify.bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return reply.unauthorized('Invalid credentials');
    }

    // Generate JWT token
    const token = fastify.jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      },
      token
    };
  });

  // Refresh token endpoint
  fastify.post('/refresh', {
    schema: {
      description: 'Refresh JWT token',
      tags: ['auth'],
      security: [{ bearerAuth: [] }],
      response: {
        200: Type.Object({
          token: Type.String()
        }),
        401: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        })
      }
    },
    preHandler: fastify.authenticate
  }, async (request, reply) => {
    const user = request.user!;

    // Generate new token
    const token = fastify.jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    return { token };
  });
}
`,
    'src/routes/users.ts': `import { FastifyInstance } from 'fastify';
import { Type } from '@sinclair/typebox';

const UserResponse = Type.Object({
  id: Type.String(),
  email: Type.String(),
  role: Type.String(),
  createdAt: Type.Optional(Type.String({ format: 'date-time' }))
});

const UsersListResponse = Type.Object({
  users: Type.Array(UserResponse),
  total: Type.Number(),
  page: Type.Optional(Type.Number()),
  limit: Type.Optional(Type.Number())
});

export async function userRoutes(fastify: FastifyInstance) {
  // Get current user profile
  fastify.get('/profile', {
    schema: {
      description: 'Get current user profile',
      tags: ['users'],
      security: [{ bearerAuth: [] }],
      response: {
        200: UserResponse,
        401: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        })
      }
    },
    preHandler: fastify.authenticate
  }, async (request, reply) => {
    const user = request.user!;
    return {
      id: user.id,
      email: user.email,
      role: user.role
    };
  });

  // Get all users (admin only)
  fastify.get('/', {
    schema: {
      description: 'Get all users (admin only)',
      tags: ['users'],
      security: [{ bearerAuth: [] }],
      querystring: Type.Object({
        page: Type.Optional(Type.Number({ minimum: 1, default: 1 })),
        limit: Type.Optional(Type.Number({ minimum: 1, maximum: 100, default: 10 })),
        role: Type.Optional(Type.Union([Type.Literal('user'), Type.Literal('admin')]))
      }),
      response: {
        200: UsersListResponse,
        401: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        }),
        403: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        })
      }
    },
    preHandler: [
      fastify.authenticate,
      fastify.authorize(['admin'])
    ]
  }, async (request, reply) => {
    const { page = 1, limit = 10, role } = request.query as any;

    // Mock users data (replace with database query)
    let mockUsers = [
      { id: '1', email: 'admin@example.com', role: 'admin', createdAt: new Date().toISOString() },
      { id: '2', email: 'user@example.com', role: 'user', createdAt: new Date().toISOString() },
      { id: '3', email: 'user2@example.com', role: 'user', createdAt: new Date().toISOString() }
    ];

    // Filter by role if specified
    if (role) {
      mockUsers = mockUsers.filter(user => user.role === role);
    }

    // Pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedUsers = mockUsers.slice(startIndex, endIndex);

    return {
      users: paginatedUsers,
      total: mockUsers.length,
      page,
      limit
    };
  });

  // Get user by ID (admin only)
  fastify.get('/:id', {
    schema: {
      description: 'Get user by ID (admin only)',
      tags: ['users'],
      security: [{ bearerAuth: [] }],
      params: Type.Object({
        id: Type.String()
      }),
      response: {
        200: UserResponse,
        401: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        }),
        403: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        }),
        404: Type.Object({
          error: Type.String(),
          message: Type.String(),
          statusCode: Type.Number()
        })
      }
    },
    preHandler: [
      fastify.authenticate,
      fastify.authorize(['admin'])
    ]
  }, async (request, reply) => {
    const { id } = request.params as any;

    // Mock user lookup (replace with database query)
    const mockUser = { id, email: \`user\${id}@example.com\`, role: 'user', createdAt: new Date().toISOString() };

    if (!mockUser) {
      return reply.notFound('User not found');
    }

    return mockUser;
  });
}
`,
    'src/schemas/index.ts': `import { Type } from '@sinclair/typebox';

// Common schemas
export const ErrorSchema = Type.Object({
  error: Type.String(),
  message: Type.String(),
  statusCode: Type.Number(),
  timestamp: Type.Optional(Type.String({ format: 'date-time' }))
});

export const PaginationSchema = Type.Object({
  page: Type.Number({ minimum: 1 }),
  limit: Type.Number({ minimum: 1, maximum: 100 }),
  total: Type.Number({ minimum: 0 }),
  totalPages: Type.Number({ minimum: 0 })
});

// User schemas
export const UserSchema = Type.Object({
  id: Type.String(),
  email: Type.String({ format: 'email' }),
  role: Type.Union([Type.Literal('user'), Type.Literal('admin')]),
  createdAt: Type.String({ format: 'date-time' }),
  updatedAt: Type.Optional(Type.String({ format: 'date-time' }))
});

export const CreateUserSchema = Type.Object({
  email: Type.String({ format: 'email' }),
  password: Type.String({ minLength: 8, maxLength: 128 }),
  role: Type.Optional(Type.Union([Type.Literal('user'), Type.Literal('admin')]))
});

export const UpdateUserSchema = Type.Object({
  email: Type.Optional(Type.String({ format: 'email' })),
  role: Type.Optional(Type.Union([Type.Literal('user'), Type.Literal('admin')]))
});

// Auth schemas
export const LoginSchema = Type.Object({
  email: Type.String({ format: 'email' }),
  password: Type.String({ minLength: 1 })
});

export const AuthResponseSchema = Type.Object({
  user: UserSchema,
  token: Type.String(),
  refreshToken: Type.Optional(Type.String())
});

// Health schemas
export const HealthSchema = Type.Object({
  status: Type.String(),
  uptime: Type.Number(),
  timestamp: Type.String({ format: 'date-time' }),
  environment: Type.String(),
  version: Type.String(),
  memory: Type.Optional(Type.Object({
    rss: Type.String(),
    heapTotal: Type.String(),
    heapUsed: Type.String(),
    external: Type.String()
  })),
  cpu: Type.Optional(Type.Object({
    user: Type.Number(),
    system: Type.Number()
  }))
});
`,
    '.env.example': `# Server Configuration
NODE_ENV=development
PORT=3000
HOST=0.0.0.0

# Logging Configuration
LOG_LEVEL=info

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=7d

# Bcrypt Configuration
BCRYPT_ROUNDS=12

# Rate Limiting Configuration
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=900000

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Cookie Configuration
COOKIE_SECRET=your-super-secret-cookie-key

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
.nyc_output/
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

# Tap test output
.tap/
`,
    'README.md': `# {{projectName}}

A high-performance Fastify API server with TypeScript, schema validation, plugins, and async/await support.

## Features

- 🚀 **Fastify Framework** - High-performance web framework with low overhead
- 📊 **Schema Validation** - Built-in JSON schema validation with TypeBox
- 🔌 **Plugin Architecture** - Modular plugin system with auto-loading
- 🔐 **JWT Authentication** - Secure token-based authentication
- 🛡️ **Security First** - Helmet, CORS, rate limiting out of the box
- 📝 **Auto Documentation** - Swagger/OpenAPI documentation generation
- ⚡ **Async/Await** - Modern asynchronous programming patterns
- 🧪 **Testing Ready** - TAP testing framework with TypeScript support
- 🔧 **Developer Experience** - Hot reload, linting, formatting
- 📊 **Health Checks** - Kubernetes-ready health endpoints

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

3. **Start development server:**
   \`\`\`bash
   npm run dev
   \`\`\`

4. **Visit the API documentation:**
   Open [http://localhost:3000/docs](http://localhost:3000/docs)

5. **Build for production:**
   \`\`\`bash
   npm run build
   npm start
   \`\`\`

## API Endpoints

### Health Checks
- \`GET /api/health\` - Basic health check
- \`GET /api/health/detailed\` - Detailed system information
- \`GET /api/health/ready\` - Readiness probe
- \`GET /api/health/live\` - Liveness probe

### Authentication
- \`POST /api/auth/register\` - Register new user
- \`POST /api/auth/login\` - Login user
- \`POST /api/auth/refresh\` - Refresh JWT token

### Users
- \`GET /api/users/profile\` - Get current user profile (requires auth)
- \`GET /api/users\` - Get all users with pagination (admin only)
- \`GET /api/users/:id\` - Get user by ID (admin only)

### Documentation
- \`GET /docs\` - Swagger UI documentation
- \`GET /docs/json\` - OpenAPI JSON specification

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`NODE_ENV\` | Environment | \`development\` |
| \`PORT\` | Server port | \`3000\` |
| \`HOST\` | Server host | \`0.0.0.0\` |
| \`LOG_LEVEL\` | Logging level | \`info\` |
| \`JWT_SECRET\` | JWT secret key | Required |
| \`JWT_EXPIRES_IN\` | JWT expiration | \`7d\` |
| \`BCRYPT_ROUNDS\` | Bcrypt rounds | \`12\` |
| \`RATE_LIMIT_MAX\` | Rate limit max requests | \`100\` |
| \`RATE_LIMIT_WINDOW\` | Rate limit window (ms) | \`900000\` |
| \`ALLOWED_ORIGINS\` | CORS allowed origins | \`*\` |

## Scripts

- \`npm run dev\` - Start development server with hot reload
- \`npm run build\` - Build for production
- \`npm start\` - Start production server
- \`npm test\` - Run tests
- \`npm run test:watch\` - Run tests in watch mode
- \`npm run test:coverage\` - Run tests with coverage
- \`npm run lint\` - Run ESLint
- \`npm run lint:fix\` - Fix ESLint issues
- \`npm run format\` - Format code with Prettier
- \`npm run type-check\` - Type check without emit

## Project Structure

\`\`\`
src/
├── config/          # Configuration files
│   └── environment.ts   # Environment validation
├── plugins/         # Fastify plugins
│   ├── index.ts     # Plugin registration
│   └── auth/        # Authentication plugin
├── routes/          # API routes
│   ├── index.ts     # Route registration
│   ├── health.ts    # Health check routes
│   ├── auth.ts      # Authentication routes
│   └── users.ts     # User routes
├── schemas/         # JSON schemas
│   └── index.ts     # Schema definitions
└── server.ts        # Application entry point
\`\`\`

## Schema Validation

Fastify uses JSON Schema for validation. This template uses TypeBox for type-safe schema definitions:

\`\`\`typescript
import { Type } from '@sinclair/typebox';

const UserSchema = Type.Object({
  email: Type.String({ format: 'email' }),
  password: Type.String({ minLength: 8 })
});

fastify.post('/users', {
  schema: {
    body: UserSchema,
    response: {
      201: UserResponseSchema
    }
  }
}, async (request, reply) => {
  // request.body is automatically validated and typed
});
\`\`\`

## Plugin System

Fastify's plugin system allows for modular architecture:

\`\`\`typescript
// plugins/my-plugin.ts
import fp from 'fastify-plugin';

async function myPlugin(fastify: FastifyInstance, options: any) {
  fastify.decorate('myUtility', () => {
    return 'Hello from plugin!';
  });
}

export default fp(myPlugin);
\`\`\`

## Testing

The template uses TAP for testing with TypeScript support:

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
import { test } from 'tap';
import { build } from '../src/server';

test('health check', async (t) => {
  const app = build();
  
  const response = await app.inject({
    method: 'GET',
    url: '/api/health'
  });
  
  t.equal(response.statusCode, 200);
  t.match(response.json(), { status: 'OK' });
});
\`\`\`

## Performance Features

- **Fast Boot Time** - Optimized for quick startup
- **Low Memory Footprint** - Efficient resource usage
- **High Throughput** - Handles thousands of requests per second
- **Schema Caching** - Compiled JSON schemas for validation
- **Connection Pooling** - Efficient database connections

## Security Features

- **Helmet.js** - Security headers
- **CORS** - Cross-origin resource sharing
- **Rate Limiting** - Request throttling
- **JWT Authentication** - Secure token-based auth
- **Input Validation** - Schema-based validation
- **Password Hashing** - bcrypt with configurable rounds
- **Security Plugins** - Modular security enhancements

## Production Deployment

1. Set \`NODE_ENV=production\`
2. Use a strong \`JWT_SECRET\`
3. Configure proper CORS origins
4. Set up proper logging
5. Use a process manager (PM2, Docker)
6. Configure reverse proxy (nginx)
7. Set up SSL/TLS certificates
8. Monitor with health checks

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
    'test/health.test.ts': `import { test } from 'tap';
import fastify from 'fastify';
import { healthRoutes } from '../src/routes/health';

test('Health routes', async (t) => {
  const app = fastify();
  
  await app.register(healthRoutes, { prefix: '/api/health' });

  t.test('GET /api/health', async (t) => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/health'
    });

    t.equal(response.statusCode, 200);
    
    const body = response.json();
    t.equal(body.status, 'OK');
    t.type(body.uptime, 'number');
    t.type(body.timestamp, 'string');
    t.equal(body.environment, 'test');
    t.type(body.version, 'string');
  });

  t.test('GET /api/health/detailed', async (t) => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/health/detailed'
    });

    t.equal(response.statusCode, 200);
    
    const body = response.json();
    t.equal(body.status, 'OK');
    t.type(body.memory, 'object');
    t.type(body.cpu, 'object');
    t.type(body.memory.rss, 'string');
    t.type(body.cpu.user, 'number');
  });

  t.test('GET /api/health/ready', async (t) => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/health/ready'
    });

    t.equal(response.statusCode, 200);
    
    const body = response.json();
    t.equal(body.ready, true);
    t.type(body.timestamp, 'string');
  });

  t.test('GET /api/health/live', async (t) => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/health/live'
    });

    t.equal(response.statusCode, 200);
    
    const body = response.json();
    t.equal(body.alive, true);
    t.type(body.timestamp, 'string');
  });
});
`,
    'test/auth.test.ts': `import { test } from 'tap';
import fastify from 'fastify';
import { authRoutes } from '../src/routes/auth';

test('Auth routes', async (t) => {
  const app = fastify();
  
  // Register required plugins for auth
  await app.register(import('@fastify/jwt'), {
    secret: 'test-secret'
  });
  
  await app.register(import('@fastify/bcrypt'), {
    saltWorkFactor: 8
  });

  await app.register(authRoutes, { prefix: '/api/auth' });

  let userToken: string;

  t.test('POST /api/auth/register', async (t) => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'password123',
        role: 'user'
      }
    });

    t.equal(response.statusCode, 201);
    
    const body = response.json();
    t.type(body.user, 'object');
    t.type(body.token, 'string');
    t.equal(body.user.email, 'test@example.com');
    t.equal(body.user.role, 'user');
    
    userToken = body.token;
  });

  t.test('POST /api/auth/register - duplicate email', async (t) => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        email: 'test@example.com',
        password: 'password123'
      }
    });

    t.equal(response.statusCode, 409);
  });

  t.test('POST /api/auth/login', async (t) => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: {
        email: 'test@example.com',
        password: 'password123'
      }
    });

    t.equal(response.statusCode, 200);
    
    const body = response.json();
    t.type(body.user, 'object');
    t.type(body.token, 'string');
    t.equal(body.user.email, 'test@example.com');
  });

  t.test('POST /api/auth/login - invalid credentials', async (t) => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: {
        email: 'test@example.com',
        password: 'wrongpassword'
      }
    });

    t.equal(response.statusCode, 401);
  });

  t.test('POST /api/auth/refresh', async (t) => {
    // Register auth plugin first
    app.decorate('authenticate', async function(request: any) {
      const decoded = app.jwt.verify(userToken);
      request.user = decoded;
    });

    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/refresh',
      headers: {
        authorization: \`Bearer \${userToken}\`
      }
    });

    t.equal(response.statusCode, 200);
    
    const body = response.json();
    t.type(body.token, 'string');
  });
});
`,
    '.eslintrc.json': {
      env: {
        node: true,
        es2022: true
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
    'Dockerfile': `# Multi-stage build for Fastify TypeScript application
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

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
    adduser -S fastify -u 1001

# Copy built application from builder stage
COPY --from=builder --chown=fastify:nodejs /app/dist ./dist
COPY --from=builder --chown=fastify:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=fastify:nodejs /app/package*.json ./

# Switch to non-root user
USER fastify

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD node -e "require('http').get('http://localhost:3000/api/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "dist/server.js"]
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
      - LOG_LEVEL=info
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    depends_on:
      - redis
    networks:
      - app-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
    networks:
      - app-network

volumes:
  redis-data:

networks:
  app-network:
    driver: bridge
`
  },
  prompts: [
    {
      type: 'input',
      name: 'projectName',
      message: 'What is your project name?',
      default: 'fastify-api'
    },
    {
      type: 'input',
      name: 'author',
      message: 'Who is the author?',
      default: 'Your Name'
    },
    {
      type: 'confirm',
      name: 'includeDatabase',
      message: 'Include database integration (Prisma)?',
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
    },
    {
      type: 'confirm',
      name: 'includeSwagger',
      message: 'Include Swagger/OpenAPI documentation?',
      default: true
    }
  ],
  postInstall: [
    'npm install',
    'cp .env.example .env',
    'echo "✅ Fastify TypeScript template created successfully!"',
    'echo "📝 Don\'t forget to:"',
    'echo "   1. Update .env with your configuration"',
    'echo "   2. Run \'npm run dev\' to start development"',
    'echo "   3. Visit http://localhost:3000/docs for API documentation"',
    'echo "   4. Visit http://localhost:3000/api/health for health check"'
      'npx prisma generate',
    'echo "📋 Database setup:"',
    'echo "1. Set DATABASE_URL in .env"',
    'echo "2. Run: npm run db:push"',
    'echo "3. Run: npm run db:seed"',]
};