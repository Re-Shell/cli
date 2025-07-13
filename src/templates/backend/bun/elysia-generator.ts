/**
 * Elysia Framework Template Generator
 * Fast and friendly Bun web framework with end-to-end type safety
 */

import { BunBackendGenerator } from './bun-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class ElysiaGenerator extends BunBackendGenerator {
  constructor() {
    super('Elysia');
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Update package.json with Elysia dependencies
    await this.updatePackageJson(projectPath);

    // Generate main application
    await this.generateMainApp(projectPath, options);

    // Generate app setup
    await this.generateApp(projectPath);

    // Generate plugins
    await this.generatePlugins(projectPath);

    // Generate routes
    await this.generateRoutes(projectPath);

    // Generate controllers
    await this.generateControllers(projectPath);

    // Generate services
    await this.generateServices(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate middleware
    await this.generateMiddleware(projectPath);

    // Generate utilities
    await this.generateUtilities(projectPath);

    // Generate types
    await this.generateTypes(projectPath);

    // Generate configuration
    await this.generateConfig(projectPath, options);

    // Generate validation schemas
    await this.generateValidation(projectPath);
  }

  private async updatePackageJson(projectPath: string): Promise<void> {
    const packageJsonPath = path.join(projectPath, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf-8'));

    packageJson.dependencies = {
      ...packageJson.dependencies,
      "elysia": "^0.8.17",
      "@elysiajs/bearer": "^0.8.0",
      "@elysiajs/cors": "^0.8.0",
      "@elysiajs/html": "^0.8.0",
      "@elysiajs/jwt": "^0.8.0",
      "@elysiajs/static": "^0.8.1",
      "@elysiajs/swagger": "^0.8.5",
      "@elysiajs/eden": "^0.8.1",
      "@sinclair/typebox": "^0.32.14",
      "bcryptjs": "^2.4.3",
      "@prisma/client": "^5.13.0"
    };

    packageJson.devDependencies = {
      ...packageJson.devDependencies,
      "prisma": "^5.13.0",
      "@types/bcryptjs": "^2.4.6"
    };

    await fs.writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2));
  }

  private async generateMainApp(projectPath: string, options: any): Promise<void> {
    const mainContent = `import { Elysia } from 'elysia';
import { cors } from '@elysiajs/cors';
import { swagger } from '@elysiajs/swagger';
import { jwt } from '@elysiajs/jwt';
import { staticPlugin } from '@elysiajs/static';
import { config } from './config';
import { logger } from './utils/logger';
import { errorHandler } from './middleware/error-handler';
import { rateLimiter } from './middleware/rate-limiter';
import { authPlugin } from './plugins/auth';
import { databasePlugin } from './plugins/database';
import { healthRoutes } from './routes/health';
import { authRoutes } from './routes/auth';
import { userRoutes } from './routes/users';
import { apiRoutes } from './routes/api';

const app = new Elysia()
  // Global plugins
  .use(
    cors({
      origin: config.CORS_ORIGIN,
      credentials: true
    })
  )
  .use(
    swagger({
      documentation: {
        info: {
          title: '${options.name} API',
          description: 'API documentation for ${options.name}',
          version: '1.0.0'
        },
        tags: [
          { name: 'Health', description: 'Health check endpoints' },
          { name: 'Auth', description: 'Authentication endpoints' },
          { name: 'Users', description: 'User management endpoints' }
        ]
      }
    })
  )
  .use(
    jwt({
      name: 'jwt',
      secret: config.JWT_SECRET,
      exp: '7d'
    })
  )
  .use(staticPlugin())
  
  // Custom plugins
  .use(logger)
  .use(errorHandler)
  .use(rateLimiter)
  .use(authPlugin)
  .use(databasePlugin)
  
  // Routes
  .use(healthRoutes)
  .use(authRoutes)
  .use(userRoutes)
  .use(apiRoutes)
  
  // 404 handler
  .onError(({ code, error, set }) => {
    if (code === 'NOT_FOUND') {
      set.status = 404;
      return {
        error: 'Not Found',
        message: 'The requested resource was not found',
        statusCode: 404
      };
    }
  })
  
  // Start server
  .listen(config.PORT, () => {
    console.log(
      \`🦊 Elysia is running at http://\${config.HOST}:\${config.PORT}\`
    );
    console.log(
      \`📚 Swagger documentation at http://\${config.HOST}:\${config.PORT}/swagger\`
    );
  });

// Type export for Eden client
export type App = typeof app;

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\\n🛑 Shutting down gracefully...');
  await app.stop();
  process.exit(0);
});
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'index.ts'),
      mainContent
    );
  }

  private async generateApp(projectPath: string): Promise<void> {
    const appContent = `import { Elysia } from 'elysia';
import { t } from 'elysia';

// Create a new Elysia instance with shared configuration
export function createApp() {
  return new Elysia({
    name: 'app',
    seed: 'app'
  })
    .state('version', '1.0.0')
    .decorate('startTime', Date.now())
    .model({
      'error.validation': t.Object({
        error: t.String(),
        message: t.String(),
        statusCode: t.Number()
      }),
      'error.unauthorized': t.Object({
        error: t.Literal('Unauthorized'),
        message: t.String(),
        statusCode: t.Literal(401)
      }),
      'error.forbidden': t.Object({
        error: t.Literal('Forbidden'),
        message: t.String(),
        statusCode: t.Literal(403)
      })
    });
}

// Global app instance
export const app = createApp();
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'app.ts'),
      appContent
    );
  }

  private async generatePlugins(projectPath: string): Promise<void> {
    const pluginsDir = path.join(projectPath, 'src', 'plugins');
    await fs.mkdir(pluginsDir, { recursive: true });

    // Auth plugin
    const authPluginContent = `import { Elysia, t } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import { bearer } from '@elysiajs/bearer';
import { UnauthorizedError } from '../utils/errors';

export const authPlugin = new Elysia({ name: 'auth' })
  .use(bearer())
  .use(
    jwt({
      name: 'jwt',
      secret: process.env.JWT_SECRET!
    })
  )
  .derive(async ({ jwt, bearer, set }) => {
    if (!bearer) {
      return { user: null };
    }

    try {
      const payload = await jwt.verify(bearer);
      if (!payload) {
        return { user: null };
      }

      // In production, fetch user from database
      const user = {
        id: payload.sub as string,
        email: payload.email as string,
        role: payload.role as string
      };

      return { user };
    } catch (error) {
      return { user: null };
    }
  })
  .macro(({ onBeforeHandle }) => ({
    isAuthenticated(value: boolean = true) {
      if (!value) return;

      onBeforeHandle(({ user, set }) => {
        if (!user) {
          set.status = 401;
          throw new UnauthorizedError('Authentication required');
        }
      });
    },
    hasRole(role: string | string[]) {
      const roles = Array.isArray(role) ? role : [role];

      onBeforeHandle(({ user, set }) => {
        if (!user) {
          set.status = 401;
          throw new UnauthorizedError('Authentication required');
        }

        if (!roles.includes(user.role)) {
          set.status = 403;
          throw new Error('Insufficient permissions');
        }
      });
    }
  }));
`;

    await fs.writeFile(
      path.join(pluginsDir, 'auth.ts'),
      authPluginContent
    );

    // Database plugin
    const dbPluginContent = `import { Elysia } from 'elysia';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error']
});

export const databasePlugin = new Elysia({ name: 'database' })
  .decorate('db', prisma)
  .onStop(async () => {
    await prisma.$disconnect();
  });

// Type helper for database
export type Database = typeof prisma;
`;

    await fs.writeFile(
      path.join(pluginsDir, 'database.ts'),
      dbPluginContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    const routesDir = path.join(projectPath, 'src', 'routes');
    await fs.mkdir(routesDir, { recursive: true });

    // Health routes
    const healthRoutesContent = `import { Elysia, t } from 'elysia';

export const healthRoutes = new Elysia({ prefix: '/health' })
  .get('/', () => ({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    uptime: process.uptime()
  }), {
    detail: {
      summary: 'Health check',
      tags: ['Health']
    }
  })
  .get('/ready', async ({ db }) => {
    try {
      // Check database connection
      await db.$queryRaw\`SELECT 1\`;
      
      return {
        status: 'ready',
        checks: {
          database: 'ok',
          cache: 'ok'
        }
      };
    } catch (error) {
      return {
        status: 'not ready',
        checks: {
          database: 'error',
          cache: 'ok'
        }
      };
    }
  }, {
    detail: {
      summary: 'Readiness check',
      tags: ['Health']
    }
  });
`;

    await fs.writeFile(
      path.join(routesDir, 'health.ts'),
      healthRoutesContent
    );

    // Auth routes
    const authRoutesContent = `import { Elysia, t } from 'elysia';
import { authController } from '../controllers/auth';

const authSchema = {
  login: t.Object({
    email: t.String({ format: 'email' }),
    password: t.String({ minLength: 6 })
  }),
  register: t.Object({
    email: t.String({ format: 'email' }),
    password: t.String({ minLength: 6 }),
    name: t.String({ minLength: 1 })
  })
};

export const authRoutes = new Elysia({ prefix: '/api/v1/auth' })
  .post('/register', authController.register, {
    body: authSchema.register,
    detail: {
      summary: 'Register a new user',
      tags: ['Auth']
    }
  })
  .post('/login', authController.login, {
    body: authSchema.login,
    detail: {
      summary: 'Login with email and password',
      tags: ['Auth']
    }
  })
  .post('/refresh', authController.refresh, {
    isAuthenticated: true,
    detail: {
      summary: 'Refresh access token',
      tags: ['Auth']
    }
  })
  .post('/logout', authController.logout, {
    isAuthenticated: true,
    detail: {
      summary: 'Logout and invalidate token',
      tags: ['Auth']
    }
  });
`;

    await fs.writeFile(
      path.join(routesDir, 'auth.ts'),
      authRoutesContent
    );

    // User routes
    const userRoutesContent = `import { Elysia, t } from 'elysia';
import { userController } from '../controllers/users';

const userSchema = {
  update: t.Object({
    name: t.Optional(t.String({ minLength: 1 })),
    email: t.Optional(t.String({ format: 'email' }))
  }),
  params: t.Object({
    id: t.String()
  }),
  query: t.Object({
    page: t.Optional(t.Numeric({ minimum: 1 })),
    limit: t.Optional(t.Numeric({ minimum: 1, maximum: 100 })),
    search: t.Optional(t.String())
  })
};

export const userRoutes = new Elysia({ prefix: '/api/v1/users' })
  .get('/', userController.list, {
    isAuthenticated: true,
    hasRole: 'admin',
    query: userSchema.query,
    detail: {
      summary: 'List all users',
      tags: ['Users']
    }
  })
  .get('/me', userController.getCurrentUser, {
    isAuthenticated: true,
    detail: {
      summary: 'Get current user',
      tags: ['Users']
    }
  })
  .get('/:id', userController.getById, {
    isAuthenticated: true,
    params: userSchema.params,
    detail: {
      summary: 'Get user by ID',
      tags: ['Users']
    }
  })
  .put('/:id', userController.update, {
    isAuthenticated: true,
    params: userSchema.params,
    body: userSchema.update,
    detail: {
      summary: 'Update user',
      tags: ['Users']
    }
  })
  .delete('/:id', userController.delete, {
    isAuthenticated: true,
    hasRole: 'admin',
    params: userSchema.params,
    detail: {
      summary: 'Delete user',
      tags: ['Users']
    }
  });
`;

    await fs.writeFile(
      path.join(routesDir, 'users.ts'),
      userRoutesContent
    );

    // API routes aggregator
    const apiRoutesContent = `import { Elysia } from 'elysia';
// Import all your API routes here

export const apiRoutes = new Elysia({ prefix: '/api' })
  .get('/', () => ({
    message: 'Welcome to Elysia API',
    version: 'v1',
    documentation: '/swagger'
  }));
`;

    await fs.writeFile(
      path.join(routesDir, 'api.ts'),
      apiRoutesContent
    );
  }

  private async generateControllers(projectPath: string): Promise<void> {
    const controllersDir = path.join(projectPath, 'src', 'controllers');

    // Auth controller
    const authControllerContent = `import { Context } from 'elysia';
import bcrypt from 'bcryptjs';
import { authService } from '../services/auth';
import { ValidationError, UnauthorizedError } from '../utils/errors';

export const authController = {
  async register({ body, jwt, set }: Context) {
    const { email, password, name } = body;

    // Check if user exists
    const existingUser = await authService.findByEmail(email);
    if (existingUser) {
      throw new ValidationError('Email already registered');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await authService.createUser({
      email,
      password: hashedPassword,
      name
    });

    // Generate token
    const token = await jwt.sign({
      sub: user.id,
      email: user.email,
      role: user.role
    });

    set.status = 201;
    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      },
      token
    };
  },

  async login({ body, jwt, set }: Context) {
    const { email, password } = body;

    // Find user
    const user = await authService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedError('Invalid credentials');
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      throw new UnauthorizedError('Invalid credentials');
    }

    // Generate token
    const token = await jwt.sign({
      sub: user.id,
      email: user.email,
      role: user.role
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      },
      token
    };
  },

  async refresh({ user, jwt }: Context) {
    if (!user) {
      throw new UnauthorizedError('Invalid token');
    }

    const token = await jwt.sign({
      sub: user.id,
      email: user.email,
      role: user.role
    });

    return { token };
  },

  async logout({ user }: Context) {
    // In production, you might want to blacklist the token
    return { message: 'Logged out successfully' };
  }
};
`;

    await fs.writeFile(
      path.join(controllersDir, 'auth.ts'),
      authControllerContent
    );

    // Users controller
    const usersControllerContent = `import { Context } from 'elysia';
import { userService } from '../services/users';
import { NotFoundError, ForbiddenError } from '../utils/errors';

export const userController = {
  async list({ query }: Context) {
    const { page = 1, limit = 10, search } = query;
    
    const users = await userService.findMany({
      page: Number(page),
      limit: Number(limit),
      search: search as string
    });

    return users;
  },

  async getCurrentUser({ user }: Context) {
    if (!user) {
      throw new UnauthorizedError('Not authenticated');
    }

    const currentUser = await userService.findById(user.id);
    if (!currentUser) {
      throw new NotFoundError('User not found');
    }

    return {
      id: currentUser.id,
      email: currentUser.email,
      name: currentUser.name,
      role: currentUser.role,
      createdAt: currentUser.createdAt,
      updatedAt: currentUser.updatedAt
    };
  },

  async getById({ params, user: currentUser }: Context) {
    const { id } = params;

    // Check permissions
    if (currentUser.id !== id && currentUser.role !== 'admin') {
      throw new ForbiddenError('Access denied');
    }

    const user = await userService.findById(id);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  },

  async update({ params, body, user: currentUser, set }: Context) {
    const { id } = params;

    // Check permissions
    if (currentUser.id !== id && currentUser.role !== 'admin') {
      throw new ForbiddenError('Access denied');
    }

    const user = await userService.update(id, body);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      updatedAt: user.updatedAt
    };
  },

  async delete({ params, user: currentUser, set }: Context) {
    const { id } = params;

    // Prevent self-deletion
    if (currentUser.id === id) {
      throw new ForbiddenError('Cannot delete your own account');
    }

    const deleted = await userService.delete(id);
    if (!deleted) {
      throw new NotFoundError('User not found');
    }

    set.status = 204;
    return null;
  }
};
`;

    await fs.writeFile(
      path.join(controllersDir, 'users.ts'),
      usersControllerContent
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    const servicesDir = path.join(projectPath, 'src', 'services');

    // Auth service
    const authServiceContent = `import { db } from '../plugins/database';

export const authService = {
  async findByEmail(email: string) {
    // In production, use real database
    return {
      id: '1',
      email,
      password: '$2a$10$...',
      name: 'Test User',
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    };
  },

  async createUser(data: {
    email: string;
    password: string;
    name: string;
  }) {
    // In production, use real database
    return {
      id: crypto.randomUUID(),
      ...data,
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    };
  }
};
`;

    await fs.writeFile(
      path.join(servicesDir, 'auth.ts'),
      authServiceContent
    );

    // Users service
    const usersServiceContent = `import { db } from '../plugins/database';

interface FindManyOptions {
  page: number;
  limit: number;
  search?: string;
}

export const userService = {
  async findMany({ page, limit, search }: FindManyOptions) {
    // In production, use real database with pagination
    const users = [
      {
        id: '1',
        email: 'user1@example.com',
        name: 'User One',
        role: 'user',
        createdAt: new Date(),
        updatedAt: new Date()
      },
      {
        id: '2',
        email: 'user2@example.com',
        name: 'User Two',
        role: 'admin',
        createdAt: new Date(),
        updatedAt: new Date()
      }
    ];

    const filtered = search
      ? users.filter(u => 
          u.name.toLowerCase().includes(search.toLowerCase()) ||
          u.email.toLowerCase().includes(search.toLowerCase())
        )
      : users;

    const start = (page - 1) * limit;
    const end = start + limit;

    return {
      data: filtered.slice(start, end),
      meta: {
        page,
        limit,
        total: filtered.length,
        totalPages: Math.ceil(filtered.length / limit)
      }
    };
  },

  async findById(id: string) {
    // In production, use real database
    if (id === '1') {
      return {
        id: '1',
        email: 'user@example.com',
        name: 'Test User',
        role: 'user',
        createdAt: new Date(),
        updatedAt: new Date()
      };
    }
    return null;
  },

  async update(id: string, data: Partial<{ name: string; email: string }>) {
    // In production, use real database
    const user = await this.findById(id);
    if (!user) return null;

    return {
      ...user,
      ...data,
      updatedAt: new Date()
    };
  },

  async delete(id: string) {
    // In production, use real database
    const user = await this.findById(id);
    return !!user;
  }
};
`;

    await fs.writeFile(
      path.join(servicesDir, 'users.ts'),
      usersServiceContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    const modelsDir = path.join(projectPath, 'src', 'models');

    // User model
    const userModelContent = `import { t } from 'elysia';

// User schema for validation
export const UserSchema = t.Object({
  id: t.String(),
  email: t.String({ format: 'email' }),
  name: t.String(),
  role: t.Union([t.Literal('user'), t.Literal('admin')]),
  createdAt: t.Date(),
  updatedAt: t.Date()
});

// User input schema
export const CreateUserSchema = t.Object({
  email: t.String({ format: 'email' }),
  password: t.String({ minLength: 6 }),
  name: t.String({ minLength: 1 })
});

export const UpdateUserSchema = t.Partial(
  t.Object({
    email: t.String({ format: 'email' }),
    name: t.String({ minLength: 1 })
  })
);

// TypeScript types
export type User = typeof UserSchema.static;
export type CreateUser = typeof CreateUserSchema.static;
export type UpdateUser = typeof UpdateUserSchema.static;
`;

    await fs.writeFile(
      path.join(modelsDir, 'user.ts'),
      userModelContent
    );

    // Prisma schema
    const prismaDir = path.join(projectPath, 'prisma');
    await fs.mkdir(prismaDir, { recursive: true });

    const prismaSchemaContent = `// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "sqlite"
  url      = "file:../data/app.db"
}

model User {
  id        String   @id @default(cuid())
  email     String   @unique
  password  String
  name      String
  role      String   @default("user")
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  sessions  Session[]
}

model Session {
  id        String   @id @default(cuid())
  userId    String
  token     String   @unique
  expiresAt DateTime
  createdAt DateTime @default(now())
  
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
}
`;

    await fs.writeFile(
      path.join(prismaDir, 'schema.prisma'),
      prismaSchemaContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    const middlewareDir = path.join(projectPath, 'src', 'middleware');

    // Error handler
    const errorHandlerContent = `import { Elysia } from 'elysia';
import { ValidationError, UnauthorizedError, ForbiddenError, NotFoundError } from '../utils/errors';

export const errorHandler = new Elysia({ name: 'error-handler' })
  .onError(({ code, error, set }) => {
    // Handle validation errors from Elysia
    if (code === 'VALIDATION') {
      set.status = 400;
      return {
        error: 'Validation Error',
        message: error.message,
        statusCode: 400
      };
    }

    // Handle custom errors
    if (error instanceof ValidationError) {
      set.status = 400;
      return {
        error: 'Validation Error',
        message: error.message,
        statusCode: 400
      };
    }

    if (error instanceof UnauthorizedError) {
      set.status = 401;
      return {
        error: 'Unauthorized',
        message: error.message,
        statusCode: 401
      };
    }

    if (error instanceof ForbiddenError) {
      set.status = 403;
      return {
        error: 'Forbidden',
        message: error.message,
        statusCode: 403
      };
    }

    if (error instanceof NotFoundError) {
      set.status = 404;
      return {
        error: 'Not Found',
        message: error.message,
        statusCode: 404
      };
    }

    // Handle parsing errors
    if (code === 'PARSE') {
      set.status = 400;
      return {
        error: 'Bad Request',
        message: 'Invalid request body',
        statusCode: 400
      };
    }

    // Default error
    console.error('Unhandled error:', error);
    set.status = 500;
    return {
      error: 'Internal Server Error',
      message: 'An unexpected error occurred',
      statusCode: 500
    };
  });
`;

    await fs.writeFile(
      path.join(middlewareDir, 'error-handler.ts'),
      errorHandlerContent
    );

    // Rate limiter
    const rateLimiterContent = `import { Elysia } from 'elysia';

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

const store: RateLimitStore = {};

export const rateLimiter = new Elysia({ name: 'rate-limiter' })
  .derive(({ request, set }) => {
    const ip = request.headers.get('x-forwarded-for') || 'unknown';
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute
    const maxRequests = 100;

    if (!store[ip] || store[ip].resetTime < now) {
      store[ip] = {
        count: 1,
        resetTime: now + windowMs
      };
    } else {
      store[ip].count++;
    }

    if (store[ip].count > maxRequests) {
      set.status = 429;
      throw new Error('Too many requests');
    }

    return {};
  });

// Cleanup old entries periodically
setInterval(() => {
  const now = Date.now();
  for (const ip in store) {
    if (store[ip].resetTime < now) {
      delete store[ip];
    }
  }
}, 60 * 1000);
`;

    await fs.writeFile(
      path.join(middlewareDir, 'rate-limiter.ts'),
      rateLimiterContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    const utilsDir = path.join(projectPath, 'src', 'utils');

    // Logger
    const loggerContent = `import { Elysia } from 'elysia';

const colors = {
  reset: '\\x1b[0m',
  red: '\\x1b[31m',
  green: '\\x1b[32m',
  yellow: '\\x1b[33m',
  blue: '\\x1b[34m',
  magenta: '\\x1b[35m',
  cyan: '\\x1b[36m'
};

const methodColors: Record<string, string> = {
  GET: colors.green,
  POST: colors.blue,
  PUT: colors.yellow,
  DELETE: colors.red,
  PATCH: colors.magenta
};

export const logger = new Elysia({ name: 'logger' })
  .onRequest(({ request }) => {
    const method = request.method;
    const url = new URL(request.url);
    const path = url.pathname;
    const color = methodColors[method] || colors.reset;
    
    console.log(
      \`\${color}\${method}\${colors.reset} \${path} - \${new Date().toISOString()}\`
    );
  })
  .onResponse(({ request, set }) => {
    const method = request.method;
    const url = new URL(request.url);
    const path = url.pathname;
    const status = set.status || 200;
    const color = status >= 400 ? colors.red : colors.green;
    
    console.log(
      \`\${methodColors[method] || colors.reset}\${method}\${colors.reset} \${path} - \${color}\${status}\${colors.reset}\`
    );
  });
`;

    await fs.writeFile(
      path.join(utilsDir, 'logger.ts'),
      loggerContent
    );

    // Errors
    const errorsContent = `export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class UnauthorizedError extends Error {
  constructor(message: string = 'Unauthorized') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends Error {
  constructor(message: string = 'Forbidden') {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string = 'Not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConflictError';
  }
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'errors.ts'),
      errorsContent
    );

    // Validation
    const validationContent = `export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
  return emailRegex.test(email);
}

export function isValidPassword(password: string): boolean {
  // At least 6 characters
  return password.length >= 6;
}

export function sanitizeInput(input: string): string {
  return input.trim().replace(/<[^>]*>?/gm, '');
}

export function paginate(page: number, limit: number) {
  const offset = (page - 1) * limit;
  return { offset, limit };
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'validation.ts'),
      validationContent
    );
  }

  private async generateTypes(projectPath: string): Promise<void> {
    const typesDir = path.join(projectPath, 'src', 'types');

    // Global types
    const indexTypesContent = `import { Elysia } from 'elysia';

// Context type with authentication
export type AuthContext = {
  user: {
    id: string;
    email: string;
    role: string;
  } | null;
};

// Generic API response
export interface ApiResponse<T = any> {
  data?: T;
  error?: {
    message: string;
    code?: string;
    details?: any;
  };
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
    totalPages?: number;
  };
}

// Pagination
export interface PaginationQuery {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

// Re-export common types
export type Context = Elysia.Context;
`;

    await fs.writeFile(
      path.join(typesDir, 'index.ts'),
      indexTypesContent
    );

    // Environment types
    const envTypesContent = `declare global {
  namespace NodeJS {
    interface ProcessEnv {
      NODE_ENV: 'development' | 'production' | 'test';
      PORT: string;
      HOST: string;
      DATABASE_URL: string;
      JWT_SECRET: string;
      CORS_ORIGIN: string;
      LOG_LEVEL: 'debug' | 'info' | 'warn' | 'error';
    }
  }
}

export {};
`;

    await fs.writeFile(
      path.join(typesDir, 'env.d.ts'),
      envTypesContent
    );
  }

  private async generateConfig(projectPath: string, options: any): Promise<void> {
    const configDir = path.join(projectPath, 'src', 'config');

    // Main config
    const configContent = `import { z } from 'zod';

const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('${options.port || 3000}'),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().default('file:../data/app.db'),
  JWT_SECRET: z.string().min(32),
  CORS_ORIGIN: z.string().default('*'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info')
});

// Load and validate environment variables
const env = configSchema.parse(process.env);

export const config = {
  ...env,
  isDevelopment: env.NODE_ENV === 'development',
  isProduction: env.NODE_ENV === 'production',
  isTest: env.NODE_ENV === 'test'
};

export type Config = typeof config;
`;

    await fs.writeFile(
      path.join(configDir, 'index.ts'),
      configContent
    );
  }

  private async generateValidation(projectPath: string): Promise<void> {
    const schemasDir = path.join(projectPath, 'src', 'schemas');
    await fs.mkdir(schemasDir, { recursive: true });

    // Common schemas
    const commonSchemasContent = `import { t } from 'elysia';

// Common field schemas
export const emailSchema = t.String({ 
  format: 'email',
  error: 'Invalid email format'
});

export const passwordSchema = t.String({ 
  minLength: 6,
  error: 'Password must be at least 6 characters'
});

export const uuidSchema = t.String({
  pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
  error: 'Invalid UUID format'
});

export const dateSchema = t.String({
  format: 'date-time',
  error: 'Invalid date format'
});

// Pagination schema
export const paginationSchema = t.Object({
  page: t.Optional(t.Numeric({ minimum: 1, default: 1 })),
  limit: t.Optional(t.Numeric({ minimum: 1, maximum: 100, default: 10 })),
  sort: t.Optional(t.String()),
  order: t.Optional(t.Union([t.Literal('asc'), t.Literal('desc')]))
});

// Response schemas
export const errorResponseSchema = t.Object({
  error: t.String(),
  message: t.String(),
  statusCode: t.Number(),
  details: t.Optional(t.Any())
});

export const successResponseSchema = <T extends t.TSchema>(dataSchema: T) =>
  t.Object({
    data: dataSchema,
    meta: t.Optional(t.Object({
      page: t.Number(),
      limit: t.Number(),
      total: t.Number(),
      totalPages: t.Number()
    }))
  });
`;

    await fs.writeFile(
      path.join(schemasDir, 'common.ts'),
      commonSchemasContent
    );
  }
}