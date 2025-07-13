/**
 * Hono Framework Template Generator
 * Small, simple, and ultrafast web framework for Bun
 */

import { BunBackendGenerator } from './bun-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class HonoGenerator extends BunBackendGenerator {
  constructor() {
    super('Hono');
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Update package.json with Hono dependencies
    await this.updatePackageJson(projectPath);

    // Generate main application
    await this.generateMainApp(projectPath, options);

    // Generate app factory
    await this.generateApp(projectPath);

    // Generate routes
    await this.generateRoutes(projectPath);

    // Generate controllers
    await this.generateControllers(projectPath);

    // Generate middleware
    await this.generateMiddleware(projectPath);

    // Generate services
    await this.generateServices(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate utilities
    await this.generateUtilities(projectPath);

    // Generate types
    await this.generateTypes(projectPath);

    // Generate configuration
    await this.generateConfig(projectPath, options);

    // Generate validation
    await this.generateValidation(projectPath);
  }

  private async updatePackageJson(projectPath: string): Promise<void> {
    const packageJsonPath = path.join(projectPath, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf-8'));

    packageJson.dependencies = {
      ...packageJson.dependencies,
      "hono": "^4.0.1",
      "@hono/zod-validator": "^0.2.1",
      "@hono/swagger-ui": "^0.2.1",
      "@hono/cors": "^0.2.1",
      "@hono/jwt": "^0.2.1",
      "@hono/logger": "^0.2.1",
      "@hono/timing": "^0.2.1",
      "@hono/etag": "^0.2.1",
      "@hono/compress": "^0.2.1",
      "@hono/pretty-json": "^0.2.1",
      "bcryptjs": "^2.4.3",
      "@prisma/client": "^5.13.0",
      "zod": "^3.22.4",
      "ioredis": "^5.3.2"
    };

    packageJson.devDependencies = {
      ...packageJson.devDependencies,
      "prisma": "^5.13.0",
      "@types/bcryptjs": "^2.4.6"
    };

    await fs.writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2));
  }

  private async generateMainApp(projectPath: string, options: any): Promise<void> {
    const mainContent = `import { Hono } from 'hono';
import { serve } from 'bun';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { timing } from 'hono/timing';
import { etag } from 'hono/etag';
import { compress } from 'hono/compress';
import { prettyJSON } from 'hono/pretty-json';
import { swaggerUI } from '@hono/swagger-ui';
import { config } from './config';
import { errorHandler } from './middleware/error-handler';
import { rateLimiter } from './middleware/rate-limiter';
import { authMiddleware } from './middleware/auth';
import { healthRoutes } from './routes/health';
import { authRoutes } from './routes/auth';
import { userRoutes } from './routes/users';
import { apiRoutes } from './routes/api';
import { connectDatabase } from './utils/database';
import { generateOpenAPISpec } from './utils/openapi';

// Create Hono app
const app = new Hono();

// Global middleware
app.use('*', timing());
app.use('*', logger());
app.use('*', etag());
app.use('*', compress());
app.use('*', prettyJSON());
app.use('*', cors({
  origin: config.CORS_ORIGIN.split(','),
  credentials: true
}));

// Rate limiting
app.use('*', rateLimiter());

// Error handling
app.onError(errorHandler);

// API Documentation
app.get('/swagger', swaggerUI({ url: '/doc' }));
app.get('/doc', (c) => c.json(generateOpenAPISpec()));

// Routes
app.route('/health', healthRoutes);
app.route('/api/v1/auth', authRoutes);
app.route('/api/v1/users', userRoutes);
app.route('/api', apiRoutes);

// 404 handler
app.notFound((c) => {
  return c.json({
    error: 'Not Found',
    message: 'The requested resource was not found',
    statusCode: 404
  }, 404);
});

// Initialize database
await connectDatabase();

// Start server
const server = serve({
  fetch: app.fetch,
  port: config.PORT,
  hostname: config.HOST
});

console.log(\`🔥 Hono is running at http://\${config.HOST}:\${config.PORT}\`);
console.log(\`📚 Swagger UI available at http://\${config.HOST}:\${config.PORT}/swagger\`);

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\\n🛑 Shutting down gracefully...');
  server.stop();
  process.exit(0);
});

// Export app for testing
export default app;
export type AppType = typeof app;
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'index.ts'),
      mainContent
    );
  }

  private async generateApp(projectPath: string): Promise<void> {
    const appContent = `import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { User } from './types';

// Custom app context
export type AppBindings = {
  Variables: {
    user: User | null;
    startTime: number;
  };
};

// Create app factory
export function createApp() {
  const app = new Hono<AppBindings>();
  
  // Add global variables
  app.use('*', async (c, next) => {
    c.set('startTime', Date.now());
    await next();
  });

  return app;
}

// Custom error classes
export class ValidationError extends HTTPException {
  constructor(message: string, details?: any) {
    super(400, { message, details });
  }
}

export class UnauthorizedError extends HTTPException {
  constructor(message: string = 'Unauthorized') {
    super(401, { message });
  }
}

export class ForbiddenError extends HTTPException {
  constructor(message: string = 'Forbidden') {
    super(403, { message });
  }
}

export class NotFoundError extends HTTPException {
  constructor(message: string = 'Not found') {
    super(404, { message });
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'app.ts'),
      appContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    const routesDir = path.join(projectPath, 'src', 'routes');

    // Health routes
    const healthRoutesContent = `import { Hono } from 'hono';
import { db } from '../utils/database';

export const healthRoutes = new Hono()
  .get('/', (c) => {
    return c.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      uptime: process.uptime(),
      memory: process.memoryUsage()
    });
  })
  .get('/ready', async (c) => {
    try {
      // Check database connection
      await db.$queryRaw\`SELECT 1\`;
      
      return c.json({
        status: 'ready',
        checks: {
          database: 'ok',
          cache: 'ok'
        }
      });
    } catch (error) {
      return c.json({
        status: 'not ready',
        checks: {
          database: 'error',
          cache: 'ok'
        }
      }, 503);
    }
  });
`;

    await fs.writeFile(
      path.join(routesDir, 'health.ts'),
      healthRoutesContent
    );

    // Auth routes
    const authRoutesContent = `import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { authController } from '../controllers/auth';
import { loginSchema, registerSchema } from '../schemas/auth';
import { authMiddleware } from '../middleware/auth';

export const authRoutes = new Hono()
  .post('/register',
    zValidator('json', registerSchema),
    authController.register
  )
  .post('/login',
    zValidator('json', loginSchema),
    authController.login
  )
  .post('/refresh',
    authMiddleware,
    authController.refresh
  )
  .post('/logout',
    authMiddleware,
    authController.logout
  );
`;

    await fs.writeFile(
      path.join(routesDir, 'auth.ts'),
      authRoutesContent
    );

    // User routes
    const userRoutesContent = `import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { userController } from '../controllers/users';
import { updateUserSchema, userQuerySchema } from '../schemas/user';
import { authMiddleware } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';

export const userRoutes = new Hono()
  // All routes require authentication
  .use('*', authMiddleware)
  
  .get('/',
    requireRole('admin'),
    zValidator('query', userQuerySchema),
    userController.list
  )
  .get('/me',
    userController.getCurrentUser
  )
  .get('/:id',
    userController.getById
  )
  .put('/:id',
    zValidator('json', updateUserSchema),
    userController.update
  )
  .delete('/:id',
    requireRole('admin'),
    userController.delete
  );
`;

    await fs.writeFile(
      path.join(routesDir, 'users.ts'),
      userRoutesContent
    );

    // API routes aggregator
    const apiRoutesContent = `import { Hono } from 'hono';
import { AppBindings } from '../app';

export const apiRoutes = new Hono<AppBindings>()
  .get('/', (c) => {
    return c.json({
      message: 'Welcome to Hono API',
      version: 'v1',
      documentation: '/swagger'
    });
  })
  .get('/stats', async (c) => {
    const user = c.get('user');
    
    return c.json({
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      authenticated: !!user,
      timestamp: new Date().toISOString()
    });
  });
`;

    await fs.writeFile(
      path.join(routesDir, 'api.ts'),
      apiRoutesContent
    );
  }

  private async generateControllers(projectPath: string): Promise<void> {
    const controllersDir = path.join(projectPath, 'src', 'controllers');

    // Auth controller
    const authControllerContent = `import { Context } from 'hono';
import bcrypt from 'bcryptjs';
import { authService } from '../services/auth';
import { generateToken, verifyToken } from '../utils/jwt';
import { ValidationError, UnauthorizedError } from '../app';

export const authController = {
  async register(c: Context) {
    const { email, password, name } = c.req.valid('json' as never);

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
    const token = await generateToken({
      sub: user.id,
      email: user.email,
      role: user.role
    });

    return c.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      },
      token
    }, 201);
  },

  async login(c: Context) {
    const { email, password } = c.req.valid('json' as never);

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
    const token = await generateToken({
      sub: user.id,
      email: user.email,
      role: user.role
    });

    return c.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      },
      token
    });
  },

  async refresh(c: Context) {
    const user = c.get('user');
    if (!user) {
      throw new UnauthorizedError('Invalid token');
    }

    const token = await generateToken({
      sub: user.id,
      email: user.email,
      role: user.role
    });

    return c.json({ token });
  },

  async logout(c: Context) {
    // In production, you might want to blacklist the token
    return c.json({ message: 'Logged out successfully' });
  }
};
`;

    await fs.writeFile(
      path.join(controllersDir, 'auth.ts'),
      authControllerContent
    );

    // Users controller
    const usersControllerContent = `import { Context } from 'hono';
import { userService } from '../services/users';
import { NotFoundError, ForbiddenError } from '../app';

export const userController = {
  async list(c: Context) {
    const query = c.req.valid('query' as never);
    const { page = 1, limit = 10, search } = query || {};
    
    const users = await userService.findMany({
      page: Number(page),
      limit: Number(limit),
      search: search as string
    });

    return c.json(users);
  },

  async getCurrentUser(c: Context) {
    const user = c.get('user');
    if (!user) {
      throw new UnauthorizedError('Not authenticated');
    }

    const currentUser = await userService.findById(user.id);
    if (!currentUser) {
      throw new NotFoundError('User not found');
    }

    return c.json({
      id: currentUser.id,
      email: currentUser.email,
      name: currentUser.name,
      role: currentUser.role,
      createdAt: currentUser.createdAt,
      updatedAt: currentUser.updatedAt
    });
  },

  async getById(c: Context) {
    const id = c.req.param('id');
    const currentUser = c.get('user');

    // Check permissions
    if (currentUser?.id !== id && currentUser?.role !== 'admin') {
      throw new ForbiddenError('Access denied');
    }

    const user = await userService.findById(id);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    return c.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    });
  },

  async update(c: Context) {
    const id = c.req.param('id');
    const body = c.req.valid('json' as never);
    const currentUser = c.get('user');

    // Check permissions
    if (currentUser?.id !== id && currentUser?.role !== 'admin') {
      throw new ForbiddenError('Access denied');
    }

    const user = await userService.update(id, body);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    return c.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      updatedAt: user.updatedAt
    });
  },

  async delete(c: Context) {
    const id = c.req.param('id');
    const currentUser = c.get('user');

    // Prevent self-deletion
    if (currentUser?.id === id) {
      throw new ForbiddenError('Cannot delete your own account');
    }

    const deleted = await userService.delete(id);
    if (!deleted) {
      throw new NotFoundError('User not found');
    }

    c.status(204);
    return c.body(null);
  }
};
`;

    await fs.writeFile(
      path.join(controllersDir, 'users.ts'),
      usersControllerContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    const middlewareDir = path.join(projectPath, 'src', 'middleware');

    // Error handler
    const errorHandlerContent = `import { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { ZodError } from 'zod';

export async function errorHandler(err: Error, c: Context) {
  // Handle Zod validation errors
  if (err instanceof ZodError) {
    return c.json({
      error: 'Validation Error',
      message: 'Invalid request data',
      details: err.errors,
      statusCode: 400
    }, 400);
  }

  // Handle HTTP exceptions
  if (err instanceof HTTPException) {
    const status = err.status;
    return c.json({
      error: err.message,
      statusCode: status
    }, status);
  }

  // Log unexpected errors
  console.error('Unhandled error:', err);

  // Default error response
  return c.json({
    error: 'Internal Server Error',
    message: 'An unexpected error occurred',
    statusCode: 500
  }, 500);
}
`;

    await fs.writeFile(
      path.join(middlewareDir, 'error-handler.ts'),
      errorHandlerContent
    );

    // Auth middleware
    const authMiddlewareContent = `import { Context, Next } from 'hono';
import { verifyToken } from '../utils/jwt';
import { UnauthorizedError } from '../app';

export async function authMiddleware(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    c.set('user', null);
    throw new UnauthorizedError('Missing authorization header');
  }

  const token = authHeader.substring(7);

  try {
    const payload = await verifyToken(token);
    
    // In production, fetch full user from database
    const user = {
      id: payload.sub as string,
      email: payload.email as string,
      role: payload.role as string
    };

    c.set('user', user);
    await next();
  } catch (error) {
    c.set('user', null);
    throw new UnauthorizedError('Invalid token');
  }
}

// Optional auth middleware - doesn't throw if no token
export async function optionalAuth(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    c.set('user', null);
    await next();
    return;
  }

  const token = authHeader.substring(7);

  try {
    const payload = await verifyToken(token);
    const user = {
      id: payload.sub as string,
      email: payload.email as string,
      role: payload.role as string
    };
    c.set('user', user);
  } catch {
    c.set('user', null);
  }

  await next();
}
`;

    await fs.writeFile(
      path.join(middlewareDir, 'auth.ts'),
      authMiddlewareContent
    );

    // RBAC middleware
    const rbacMiddlewareContent = `import { Context, Next } from 'hono';
import { ForbiddenError } from '../app';

export function requireRole(...roles: string[]) {
  return async (c: Context, next: Next) => {
    const user = c.get('user');
    
    if (!user) {
      throw new ForbiddenError('Authentication required');
    }

    if (!roles.includes(user.role)) {
      throw new ForbiddenError('Insufficient permissions');
    }

    await next();
  };
}

export function requireOwnership(userIdParam = 'id') {
  return async (c: Context, next: Next) => {
    const user = c.get('user');
    const resourceUserId = c.req.param(userIdParam);
    
    if (!user) {
      throw new ForbiddenError('Authentication required');
    }

    if (user.id !== resourceUserId && user.role !== 'admin') {
      throw new ForbiddenError('Access denied');
    }

    await next();
  };
}
`;

    await fs.writeFile(
      path.join(middlewareDir, 'rbac.ts'),
      rbacMiddlewareContent
    );

    // Rate limiter
    const rateLimiterContent = `import { Context, Next } from 'hono';

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

const store: RateLimitStore = {};

export function rateLimiter(options = {
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 100
}) {
  return async (c: Context, next: Next) => {
    const ip = c.req.header('x-forwarded-for') || 
                c.req.header('x-real-ip') || 
                'unknown';
    
    const now = Date.now();
    const key = \`\${ip}:\${c.req.path}\`;

    if (!store[key] || store[key].resetTime < now) {
      store[key] = {
        count: 1,
        resetTime: now + options.windowMs
      };
    } else {
      store[key].count++;
    }

    if (store[key].count > options.maxRequests) {
      return c.json({
        error: 'Too Many Requests',
        message: 'Rate limit exceeded',
        statusCode: 429
      }, 429);
    }

    // Add rate limit headers
    c.header('X-RateLimit-Limit', options.maxRequests.toString());
    c.header('X-RateLimit-Remaining', (options.maxRequests - store[key].count).toString());
    c.header('X-RateLimit-Reset', new Date(store[key].resetTime).toISOString());

    await next();
  };
}

// Cleanup old entries periodically
setInterval(() => {
  const now = Date.now();
  for (const key in store) {
    if (store[key].resetTime < now) {
      delete store[key];
    }
  }
}, 60 * 1000);
`;

    await fs.writeFile(
      path.join(middlewareDir, 'rate-limiter.ts'),
      rateLimiterContent
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    const servicesDir = path.join(projectPath, 'src', 'services');

    // Auth service
    const authServiceContent = `import { db } from '../utils/database';
import type { User } from '@prisma/client';

export const authService = {
  async findByEmail(email: string): Promise<User | null> {
    return db.user.findUnique({
      where: { email }
    });
  },

  async createUser(data: {
    email: string;
    password: string;
    name: string;
  }): Promise<User> {
    return db.user.create({
      data: {
        ...data,
        role: 'user'
      }
    });
  }
};
`;

    await fs.writeFile(
      path.join(servicesDir, 'auth.ts'),
      authServiceContent
    );

    // Users service
    const usersServiceContent = `import { db } from '../utils/database';
import type { User } from '@prisma/client';

interface FindManyOptions {
  page: number;
  limit: number;
  search?: string;
}

export const userService = {
  async findMany({ page, limit, search }: FindManyOptions) {
    const where = search
      ? {
          OR: [
            { name: { contains: search, mode: 'insensitive' } },
            { email: { contains: search, mode: 'insensitive' } }
          ]
        }
      : {};

    const [users, total] = await Promise.all([
      db.user.findMany({
        where,
        skip: (page - 1) * limit,
        take: limit,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
          updatedAt: true
        }
      }),
      db.user.count({ where })
    ]);

    return {
      data: users,
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    };
  },

  async findById(id: string): Promise<User | null> {
    return db.user.findUnique({
      where: { id }
    });
  },

  async update(id: string, data: Partial<{ name: string; email: string }>): Promise<User | null> {
    try {
      return await db.user.update({
        where: { id },
        data
      });
    } catch (error) {
      return null;
    }
  },

  async delete(id: string): Promise<boolean> {
    try {
      await db.user.delete({
        where: { id }
      });
      return true;
    } catch (error) {
      return false;
    }
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
    const userModelContent = `import { z } from 'zod';

// User schemas
export const userSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  name: z.string(),
  role: z.enum(['user', 'admin']),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const createUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().min(1)
});

export const updateUserSchema = z.object({
  email: z.string().email().optional(),
  name: z.string().min(1).optional()
});

// Types
export type User = z.infer<typeof userSchema>;
export type CreateUser = z.infer<typeof createUserSchema>;
export type UpdateUser = z.infer<typeof updateUserSchema>;
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

  private async generateUtilities(projectPath: string): Promise<void> {
    const utilsDir = path.join(projectPath, 'src', 'utils');

    // Database utility
    const databaseContent = `import { PrismaClient } from '@prisma/client';

const globalForPrisma = global as unknown as {
  prisma: PrismaClient | undefined;
};

export const db = globalForPrisma.prisma ?? new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error']
});

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = db;
}

export async function connectDatabase() {
  try {
    await db.$connect();
    console.log('✅ Database connected');
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    process.exit(1);
  }
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'database.ts'),
      databaseContent
    );

    // JWT utility
    const jwtContent = `import { SignJWT, jwtVerify } from 'jose';
import { config } from '../config';

const secret = new TextEncoder().encode(config.JWT_SECRET);

export async function generateToken(payload: any) {
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(secret);

  return jwt;
}

export async function verifyToken(token: string) {
  try {
    const { payload } = await jwtVerify(token, secret);
    return payload;
  } catch (error) {
    throw new Error('Invalid token');
  }
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'jwt.ts'),
      jwtContent
    );

    // OpenAPI utility
    const openapiContent = `export function generateOpenAPISpec() {
  return {
    openapi: '3.0.0',
    info: {
      title: 'Hono API',
      version: '1.0.0',
      description: 'API documentation for Hono application'
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ],
    paths: {
      '/health': {
        get: {
          summary: 'Health check',
          tags: ['Health'],
          responses: {
            '200': {
              description: 'Service is healthy',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      status: { type: 'string' },
                      timestamp: { type: 'string' },
                      version: { type: 'string' }
                    }
                  }
                }
              }
            }
          }
        }
      },
      '/api/v1/auth/register': {
        post: {
          summary: 'Register a new user',
          tags: ['Auth'],
          security: [],
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'password', 'name'],
                  properties: {
                    email: { type: 'string', format: 'email' },
                    password: { type: 'string', minLength: 6 },
                    name: { type: 'string', minLength: 1 }
                  }
                }
              }
            }
          },
          responses: {
            '201': {
              description: 'User created successfully'
            },
            '400': {
              description: 'Validation error'
            }
          }
        }
      },
      '/api/v1/auth/login': {
        post: {
          summary: 'Login',
          tags: ['Auth'],
          security: [],
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'password'],
                  properties: {
                    email: { type: 'string', format: 'email' },
                    password: { type: 'string' }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Login successful'
            },
            '401': {
              description: 'Invalid credentials'
            }
          }
        }
      }
    }
  };
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'openapi.ts'),
      openapiContent
    );

    // Validation utility
    const validationContent = `export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
  return emailRegex.test(email);
}

export function isValidPassword(password: string): boolean {
  return password.length >= 6;
}

export function sanitizeInput(input: string): string {
  return input.trim().replace(/<[^>]*>?/gm, '');
}

export function paginate(page: number, limit: number) {
  const offset = (page - 1) * limit;
  return { offset, limit };
}

export function generateSlug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
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
    const indexTypesContent = `import type { Context as HonoContext } from 'hono';

// User type
export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  createdAt?: Date;
  updatedAt?: Date;
}

// Context with user
export type Context = HonoContext<{
  Variables: {
    user: User | null;
  };
}>;

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
      REDIS_URL?: string;
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
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('${options.port || 3000}'),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().default('file:../data/app.db'),
  JWT_SECRET: z.string().min(32),
  CORS_ORIGIN: z.string().default('*'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  REDIS_URL: z.string().optional()
});

// Validate and parse environment variables
export const config = (() => {
  try {
    const parsed = configSchema.parse(process.env);
    return {
      ...parsed,
      isDevelopment: parsed.NODE_ENV === 'development',
      isProduction: parsed.NODE_ENV === 'production',
      isTest: parsed.NODE_ENV === 'test'
    };
  } catch (error) {
    console.error('❌ Configuration validation failed:');
    if (error instanceof z.ZodError) {
      console.error(error.errors);
    }
    process.exit(1);
  }
})();

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

    // Auth schemas
    const authSchemasContent = `import { z } from 'zod';

export const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required')
});

export const registerSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  name: z.string().min(1, 'Name is required').max(100, 'Name is too long')
});

export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;
`;

    await fs.writeFile(
      path.join(schemasDir, 'auth.ts'),
      authSchemasContent
    );

    // User schemas
    const userSchemasContent = `import { z } from 'zod';

export const updateUserSchema = z.object({
  email: z.string().email('Invalid email format').optional(),
  name: z.string().min(1, 'Name is required').max(100, 'Name is too long').optional()
});

export const userQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(10),
  search: z.string().optional(),
  sort: z.enum(['createdAt', 'updatedAt', 'name', 'email']).optional(),
  order: z.enum(['asc', 'desc']).default('desc')
});

export type UpdateUserInput = z.infer<typeof updateUserSchema>;
export type UserQuery = z.infer<typeof userQuerySchema>;
`;

    await fs.writeFile(
      path.join(schemasDir, 'user.ts'),
      userSchemasContent
    );

    // Common schemas
    const commonSchemasContent = `import { z } from 'zod';

// UUID schema
export const uuidSchema = z.string().uuid('Invalid UUID format');

// Date schema
export const dateSchema = z.string().datetime('Invalid date format');

// Pagination schema
export const paginationSchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(10)
});

// Response schemas
export const errorResponseSchema = z.object({
  error: z.string(),
  message: z.string(),
  statusCode: z.number(),
  details: z.any().optional()
});

export const successResponseSchema = <T extends z.ZodTypeAny>(dataSchema: T) =>
  z.object({
    data: dataSchema,
    meta: z.object({
      page: z.number(),
      limit: z.number(),
      total: z.number(),
      totalPages: z.number()
    }).optional()
  });
`;

    await fs.writeFile(
      path.join(schemasDir, 'common.ts'),
      commonSchemasContent
    );
  }
}