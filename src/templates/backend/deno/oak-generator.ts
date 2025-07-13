/**
 * Oak Framework Template Generator
 * A middleware framework for Deno's native HTTP server
 */

import { DenoBackendGenerator } from './deno-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class OakGenerator extends DenoBackendGenerator {
  constructor() {
    super('Oak');
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application
    await this.generateMainApp(projectPath, options);

    // Generate app setup
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

    // Generate database
    await this.generateDatabase(projectPath);

    // Generate config
    await this.generateConfig(projectPath, options);

    // Generate utilities
    await this.generateUtilities(projectPath);

    // Generate types
    await this.generateTypes(projectPath);

    // Update deps.ts with Oak specific imports
    await this.updateDeps(projectPath);
  }

  private async generateMainApp(projectPath: string, options: any): Promise<void> {
    const mainContent = `import { Application } from "https://deno.land/x/oak@v12.6.2/mod.ts";
import { config } from "https://deno.land/x/dotenv@v3.2.2/mod.ts";
import { log } from "./src/utils/logger.ts";
import { errorHandler } from "./src/middleware/error.ts";
import { corsMiddleware } from "./src/middleware/cors.ts";
import { loggerMiddleware } from "./src/middleware/logger.ts";
import { rateLimitMiddleware } from "./src/middleware/rateLimit.ts";
import { router } from "./src/routes/index.ts";
import { connectDB, closeDB } from "./src/config/database.ts";
import { connectRedis } from "./src/config/redis.ts";

// Load environment variables
const env = config();

// Create Oak application
const app = new Application();

// Get port from environment
const PORT = parseInt(Deno.env.get("PORT") || "8000");
const HOST = Deno.env.get("HOST") || "0.0.0.0";

// Apply global error handler
app.use(errorHandler);

// Apply middleware
app.use(corsMiddleware);
app.use(loggerMiddleware);
app.use(rateLimitMiddleware);

// Apply routes
app.use(router.routes());
app.use(router.allowedMethods());

// Handle 404
app.use((ctx) => {
  ctx.response.status = 404;
  ctx.response.body = {
    error: {
      code: "NOT_FOUND",
      message: "The requested resource was not found",
    },
  };
});

// Database connection
let dbClient;
let redisClient;

// Startup
app.addEventListener("listen", ({ hostname, port, secure }) => {
  log.info(
    \`Server listening on \${secure ? "https://" : "http://"}\${hostname ?? "localhost"}:\${port}\`
  );
});

// Graceful shutdown
const abortController = new AbortController();

Deno.addSignalListener("SIGINT", async () => {
  log.info("Shutting down server...");
  abortController.abort();
  
  // Close database connections
  if (dbClient) {
    await closeDB(dbClient);
  }
  if (redisClient) {
    redisClient.close();
  }
  
  Deno.exit(0);
});

// Initialize connections and start server
async function start() {
  try {
    // Connect to database
    dbClient = await connectDB();
    log.info("Database connected successfully");

    // Connect to Redis
    redisClient = await connectRedis();
    log.info("Redis connected successfully");

    // Start server
    await app.listen({ 
      hostname: HOST, 
      port: PORT,
      signal: abortController.signal 
    });
  } catch (error) {
    log.error("Failed to start server:", error);
    Deno.exit(1);
  }
}

// Start the application
if (import.meta.main) {
  start();
}

export { app };
`;

    await fs.writeFile(
      path.join(projectPath, 'main.ts'),
      mainContent
    );
  }

  private async generateApp(projectPath: string): Promise<void> {
    const appContent = `import { Application, Context, State } from "https://deno.land/x/oak@v12.6.2/mod.ts";
import { Pool } from "https://deno.land/x/postgres@v0.19.3/mod.ts";
import { Redis } from "https://deno.land/x/redis@v0.32.1/mod.ts";

// Extended state interface
export interface AppState extends State {
  db: Pool;
  redis: Redis;
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

// Extended context
export type AppContext = Context<AppState>;

// Helper to create typed middleware
export type AppMiddleware = (
  ctx: AppContext,
  next: () => Promise<unknown>
) => Promise<unknown> | unknown;

// Create application instance
export function createApp(): Application<AppState> {
  return new Application<AppState>();
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'app.ts'),
      appContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'routes'), { recursive: true });

    // Main router
    const indexRouterContent = `import { Router } from "https://deno.land/x/oak@v12.6.2/mod.ts";
import { AppState } from "../app.ts";
import authRouter from "./auth.ts";
import userRouter from "./users.ts";
import healthRouter from "./health.ts";

const router = new Router<AppState>();

// Mount sub-routers
router.use("/health", healthRouter.routes());
router.use("/api/v1/auth", authRouter.routes());
router.use("/api/v1/users", userRouter.routes());

// Root route
router.get("/", (ctx) => {
  ctx.response.body = {
    message: "Welcome to ${this.config.framework} API",
    version: "1.0.0",
    endpoints: {
      health: "/health",
      auth: "/api/v1/auth",
      users: "/api/v1/users",
    },
  };
});

export { router };
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'routes', 'index.ts'),
      indexRouterContent
    );

    // Health router
    const healthRouterContent = `import { Router } from "https://deno.land/x/oak@v12.6.2/mod.ts";
import { AppState } from "../app.ts";
import * as healthController from "../controllers/health.ts";

const router = new Router<AppState>();

router.get("/", healthController.checkHealth);
router.get("/ready", healthController.checkReadiness);
router.get("/live", healthController.checkLiveness);

export default router;
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'routes', 'health.ts'),
      healthRouterContent
    );

    // Auth router
    const authRouterContent = `import { Router } from "https://deno.land/x/oak@v12.6.2/mod.ts";
import { AppState } from "../app.ts";
import * as authController from "../controllers/auth.ts";
import { validateRequest } from "../middleware/validation.ts";
import { registerSchema, loginSchema } from "../models/auth.ts";

const router = new Router<AppState>();

router.post("/register", validateRequest(registerSchema), authController.register);
router.post("/login", validateRequest(loginSchema), authController.login);
router.post("/refresh", authController.refreshToken);
router.post("/logout", authController.logout);

export default router;
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'routes', 'auth.ts'),
      authRouterContent
    );

    // User router
    const userRouterContent = `import { Router } from "https://deno.land/x/oak@v12.6.2/mod.ts";
import { AppState } from "../app.ts";
import * as userController from "../controllers/users.ts";
import { authenticate } from "../middleware/auth.ts";
import { authorize } from "../middleware/authorize.ts";
import { validateRequest } from "../middleware/validation.ts";
import { updateUserSchema } from "../models/user.ts";

const router = new Router<AppState>();

// Protected routes
router.use(authenticate);

router.get("/me", userController.getCurrentUser);
router.put("/me", validateRequest(updateUserSchema), userController.updateCurrentUser);
router.get("/", authorize(["admin"]), userController.listUsers);
router.get("/:id", userController.getUser);
router.put("/:id", authorize(["admin"]), validateRequest(updateUserSchema), userController.updateUser);
router.delete("/:id", authorize(["admin"]), userController.deleteUser);

export default router;
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'routes', 'users.ts'),
      userRouterContent
    );
  }

  private async generateControllers(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'controllers'), { recursive: true });

    // Health controller
    const healthControllerContent = `import { AppContext } from "../app.ts";

export async function checkHealth(ctx: AppContext) {
  ctx.response.body = {
    status: "healthy",
    timestamp: new Date().toISOString(),
    service: "oak-api",
    version: "1.0.0",
  };
}

export async function checkReadiness(ctx: AppContext) {
  const checks: Record<string, string> = {};

  // Check database
  try {
    await ctx.state.db.connect();
    checks.database = "ready";
  } catch {
    checks.database = "not ready";
  }

  // Check Redis
  try {
    await ctx.state.redis.ping();
    checks.redis = "ready";
  } catch {
    checks.redis = "not ready";
  }

  const allReady = Object.values(checks).every((status) => status === "ready");

  ctx.response.status = allReady ? 200 : 503;
  ctx.response.body = {
    status: allReady ? "ready" : "not ready",
    checks,
  };
}

export async function checkLiveness(ctx: AppContext) {
  ctx.response.body = {
    status: "alive",
    timestamp: new Date().toISOString(),
  };
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'controllers', 'health.ts'),
      healthControllerContent
    );

    // Auth controller
    const authControllerContent = `import { AppContext } from "../app.ts";
import * as authService from "../services/auth.ts";
import { CreateUserDto, LoginDto } from "../models/auth.ts";
import { log } from "../utils/logger.ts";

export async function register(ctx: AppContext) {
  try {
    const body = await ctx.request.body({ type: "json" }).value as CreateUserDto;
    const result = await authService.register(body, ctx.state.db);

    ctx.response.status = 201;
    ctx.response.body = {
      message: "User registered successfully",
      data: result,
    };
  } catch (error) {
    log.error("Registration error:", error);
    if (error.message.includes("already exists")) {
      ctx.response.status = 409;
      ctx.response.body = {
        error: {
          code: "USER_EXISTS",
          message: "User with this email already exists",
        },
      };
    } else {
      throw error;
    }
  }
}

export async function login(ctx: AppContext) {
  try {
    const body = await ctx.request.body({ type: "json" }).value as LoginDto;
    const result = await authService.login(body, ctx.state.db);

    ctx.response.body = {
      message: "Login successful",
      data: result,
    };
  } catch (error) {
    log.error("Login error:", error);
    ctx.response.status = 401;
    ctx.response.body = {
      error: {
        code: "INVALID_CREDENTIALS",
        message: "Invalid email or password",
      },
    };
  }
}

export async function refreshToken(ctx: AppContext) {
  try {
    const { refreshToken } = await ctx.request.body({ type: "json" }).value;
    const result = await authService.refreshToken(refreshToken);

    ctx.response.body = {
      message: "Token refreshed successfully",
      data: result,
    };
  } catch (error) {
    log.error("Token refresh error:", error);
    ctx.response.status = 401;
    ctx.response.body = {
      error: {
        code: "INVALID_TOKEN",
        message: "Invalid or expired refresh token",
      },
    };
  }
}

export async function logout(ctx: AppContext) {
  // In a real app, you might want to blacklist the token
  ctx.response.body = {
    message: "Logged out successfully",
  };
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'controllers', 'auth.ts'),
      authControllerContent
    );

    // User controller
    const userControllerContent = `import { AppContext } from "../app.ts";
import * as userService from "../services/user.ts";
import { UpdateUserDto } from "../models/user.ts";
import { log } from "../utils/logger.ts";

export async function getCurrentUser(ctx: AppContext) {
  const userId = ctx.state.user!.id;
  const user = await userService.getUserById(userId, ctx.state.db);

  ctx.response.body = {
    data: user,
  };
}

export async function updateCurrentUser(ctx: AppContext) {
  const userId = ctx.state.user!.id;
  const body = await ctx.request.body({ type: "json" }).value as UpdateUserDto;
  
  const updatedUser = await userService.updateUser(userId, body, ctx.state.db);

  ctx.response.body = {
    message: "User updated successfully",
    data: updatedUser,
  };
}

export async function listUsers(ctx: AppContext) {
  const page = parseInt(ctx.request.url.searchParams.get("page") || "1");
  const limit = parseInt(ctx.request.url.searchParams.get("limit") || "10");
  const search = ctx.request.url.searchParams.get("search") || undefined;

  const result = await userService.listUsers({ page, limit, search }, ctx.state.db);

  ctx.response.body = {
    data: result.users,
    pagination: {
      page,
      limit,
      total: result.total,
      pages: Math.ceil(result.total / limit),
    },
  };
}

export async function getUser(ctx: AppContext) {
  const userId = ctx.params.id;
  const user = await userService.getUserById(userId, ctx.state.db);

  if (!user) {
    ctx.response.status = 404;
    ctx.response.body = {
      error: {
        code: "USER_NOT_FOUND",
        message: "User not found",
      },
    };
    return;
  }

  ctx.response.body = {
    data: user,
  };
}

export async function updateUser(ctx: AppContext) {
  const userId = ctx.params.id;
  const body = await ctx.request.body({ type: "json" }).value as UpdateUserDto;
  
  const updatedUser = await userService.updateUser(userId, body, ctx.state.db);

  if (!updatedUser) {
    ctx.response.status = 404;
    ctx.response.body = {
      error: {
        code: "USER_NOT_FOUND",
        message: "User not found",
      },
    };
    return;
  }

  ctx.response.body = {
    message: "User updated successfully",
    data: updatedUser,
  };
}

export async function deleteUser(ctx: AppContext) {
  const userId = ctx.params.id;
  const deleted = await userService.deleteUser(userId, ctx.state.db);

  if (!deleted) {
    ctx.response.status = 404;
    ctx.response.body = {
      error: {
        code: "USER_NOT_FOUND",
        message: "User not found",
      },
    };
    return;
  }

  ctx.response.status = 204;
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'controllers', 'users.ts'),
      userControllerContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'middleware'), { recursive: true });

    // Error handling middleware
    const errorMiddlewareContent = `import { AppContext } from "../app.ts";
import { log } from "../utils/logger.ts";

export async function errorHandler(ctx: AppContext, next: () => Promise<unknown>) {
  try {
    await next();
  } catch (error) {
    log.error("Unhandled error:", error);

    const status = error.status || 500;
    const message = error.message || "Internal server error";

    ctx.response.status = status;
    ctx.response.body = {
      error: {
        code: "INTERNAL_ERROR",
        message,
        ...(Deno.env.get("ENV") === "development" && { stack: error.stack }),
      },
    };
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'middleware', 'error.ts'),
      errorMiddlewareContent
    );

    // CORS middleware
    const corsMiddlewareContent = `import { AppContext } from "../app.ts";

export async function corsMiddleware(ctx: AppContext, next: () => Promise<unknown>) {
  const origin = ctx.request.headers.get("Origin") || "*";
  const allowedOrigins = Deno.env.get("CORS_ORIGIN")?.split(",") || ["*"];

  if (allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
    ctx.response.headers.set("Access-Control-Allow-Origin", origin);
  }

  ctx.response.headers.set(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );
  ctx.response.headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  ctx.response.headers.set("Access-Control-Allow-Credentials", "true");

  if (ctx.request.method === "OPTIONS") {
    ctx.response.status = 204;
    return;
  }

  await next();
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'middleware', 'cors.ts'),
      corsMiddlewareContent
    );

    // Logger middleware
    const loggerMiddlewareContent = `import { AppContext } from "../app.ts";
import { log } from "../utils/logger.ts";

export async function loggerMiddleware(ctx: AppContext, next: () => Promise<unknown>) {
  const start = Date.now();
  const { method, url } = ctx.request;

  await next();

  const ms = Date.now() - start;
  const status = ctx.response.status;

  log.info(\`\${method} \${url.pathname} - \${status} - \${ms}ms\`);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'middleware', 'logger.ts'),
      loggerMiddlewareContent
    );

    // Rate limit middleware
    const rateLimitMiddlewareContent = `import { AppContext } from "../app.ts";

const requests = new Map<string, { count: number; resetTime: number }>();

export async function rateLimitMiddleware(ctx: AppContext, next: () => Promise<unknown>) {
  const ip = ctx.request.ip;
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute
  const maxRequests = 100;

  const userRequests = requests.get(ip);

  if (!userRequests || now > userRequests.resetTime) {
    requests.set(ip, {
      count: 1,
      resetTime: now + windowMs,
    });
  } else {
    userRequests.count++;

    if (userRequests.count > maxRequests) {
      ctx.response.status = 429;
      ctx.response.body = {
        error: {
          code: "RATE_LIMIT_EXCEEDED",
          message: "Too many requests, please try again later",
        },
      };
      return;
    }
  }

  await next();
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'middleware', 'rateLimit.ts'),
      rateLimitMiddlewareContent
    );

    // Auth middleware
    const authMiddlewareContent = `import { AppContext } from "../app.ts";
import { verifyJWT } from "../utils/jwt.ts";
import { log } from "../utils/logger.ts";

export async function authenticate(ctx: AppContext, next: () => Promise<unknown>) {
  const authorization = ctx.request.headers.get("Authorization");

  if (!authorization || !authorization.startsWith("Bearer ")) {
    ctx.response.status = 401;
    ctx.response.body = {
      error: {
        code: "UNAUTHORIZED",
        message: "Missing or invalid authorization header",
      },
    };
    return;
  }

  const token = authorization.substring(7);

  try {
    const payload = await verifyJWT(token);
    ctx.state.user = {
      id: payload.sub as string,
      email: payload.email as string,
      role: payload.role as string,
    };
    await next();
  } catch (error) {
    log.error("Authentication error:", error);
    ctx.response.status = 401;
    ctx.response.body = {
      error: {
        code: "INVALID_TOKEN",
        message: "Invalid or expired token",
      },
    };
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'middleware', 'auth.ts'),
      authMiddlewareContent
    );

    // Authorization middleware
    const authorizeMiddlewareContent = `import { AppContext } from "../app.ts";

export function authorize(roles: string[]) {
  return async (ctx: AppContext, next: () => Promise<unknown>) => {
    const userRole = ctx.state.user?.role;

    if (!userRole || !roles.includes(userRole)) {
      ctx.response.status = 403;
      ctx.response.body = {
        error: {
          code: "FORBIDDEN",
          message: "Insufficient permissions",
        },
      };
      return;
    }

    await next();
  };
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'middleware', 'authorize.ts'),
      authorizeMiddlewareContent
    );

    // Validation middleware
    const validationMiddlewareContent = `import { AppContext } from "../app.ts";
import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";

export function validateRequest<T extends z.ZodSchema>(
  schema: T
) {
  return async (ctx: AppContext, next: () => Promise<unknown>) => {
    try {
      const body = await ctx.request.body({ type: "json" }).value;
      const validated = schema.parse(body);
      ctx.request.body = () => ({ type: "json", value: Promise.resolve(validated) });
      await next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        ctx.response.status = 400;
        ctx.response.body = {
          error: {
            code: "VALIDATION_ERROR",
            message: "Invalid request data",
            details: error.errors,
          },
        };
      } else {
        throw error;
      }
    }
  };
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'middleware', 'validation.ts'),
      validationMiddlewareContent
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'services'), { recursive: true });

    // Auth service
    const authServiceContent = `import { Pool } from "https://deno.land/x/postgres@v0.19.3/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";
import { CreateUserDto, LoginDto } from "../models/auth.ts";
import { User } from "../models/user.ts";
import { generateJWT, generateRefreshToken } from "../utils/jwt.ts";
import { createUser, getUserByEmail } from "./user.ts";

export async function register(data: CreateUserDto, db: Pool) {
  // Check if user exists
  const existingUser = await getUserByEmail(data.email, db);
  if (existingUser) {
    throw new Error("User already exists");
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(data.password);

  // Create user
  const user = await createUser(
    {
      ...data,
      password: hashedPassword,
    },
    db
  );

  // Generate tokens
  const accessToken = await generateJWT(user);
  const refreshToken = await generateRefreshToken(user);

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt,
    },
    tokens: {
      accessToken,
      refreshToken,
    },
  };
}

export async function login(data: LoginDto, db: Pool) {
  // Get user
  const user = await getUserByEmail(data.email, db);
  if (!user) {
    throw new Error("Invalid credentials");
  }

  // Verify password
  const validPassword = await bcrypt.compare(data.password, user.password);
  if (!validPassword) {
    throw new Error("Invalid credentials");
  }

  // Generate tokens
  const accessToken = await generateJWT(user);
  const refreshToken = await generateRefreshToken(user);

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt,
    },
    tokens: {
      accessToken,
      refreshToken,
    },
  };
}

export async function refreshToken(refreshToken: string) {
  // Verify refresh token and get new access token
  // Implementation depends on your token strategy
  throw new Error("Not implemented");
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'services', 'auth.ts'),
      authServiceContent
    );

    // User service
    const userServiceContent = `import { Pool } from "https://deno.land/x/postgres@v0.19.3/mod.ts";
import { User, UpdateUserDto } from "../models/user.ts";
import { v4 as uuid } from "https://deno.land/std@0.212.0/uuid/mod.ts";

export async function createUser(
  data: { email: string; password: string; name: string },
  db: Pool
): Promise<User> {
  const client = await db.connect();
  try {
    const result = await client.queryObject<User>(
      \`INSERT INTO users (id, email, password, name, role, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, email, name, role, created_at, updated_at\`,
      [
        uuid.generate(),
        data.email,
        data.password,
        data.name,
        "user",
        new Date(),
        new Date(),
      ]
    );
    return result.rows[0];
  } finally {
    client.release();
  }
}

export async function getUserById(id: string, db: Pool): Promise<User | null> {
  const client = await db.connect();
  try {
    const result = await client.queryObject<User>(
      "SELECT id, email, name, role, created_at, updated_at FROM users WHERE id = $1",
      [id]
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

export async function getUserByEmail(email: string, db: Pool): Promise<User | null> {
  const client = await db.connect();
  try {
    const result = await client.queryObject<User>(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

export async function updateUser(
  id: string,
  data: UpdateUserDto,
  db: Pool
): Promise<User | null> {
  const client = await db.connect();
  try {
    const updates: string[] = [];
    const values: any[] = [];
    let paramCount = 1;

    if (data.name !== undefined) {
      updates.push(\`name = $\${paramCount++}\`);
      values.push(data.name);
    }

    if (data.email !== undefined) {
      updates.push(\`email = $\${paramCount++}\`);
      values.push(data.email);
    }

    updates.push(\`updated_at = $\${paramCount++}\`);
    values.push(new Date());
    values.push(id);

    const result = await client.queryObject<User>(
      \`UPDATE users SET \${updates.join(", ")} WHERE id = $\${paramCount}
       RETURNING id, email, name, role, created_at, updated_at\`,
      values
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

export async function deleteUser(id: string, db: Pool): Promise<boolean> {
  const client = await db.connect();
  try {
    const result = await client.queryObject(
      "DELETE FROM users WHERE id = $1",
      [id]
    );
    return result.rowCount > 0;
  } finally {
    client.release();
  }
}

export async function listUsers(
  params: { page: number; limit: number; search?: string },
  db: Pool
): Promise<{ users: User[]; total: number }> {
  const client = await db.connect();
  try {
    const offset = (params.page - 1) * params.limit;
    let query = "SELECT id, email, name, role, created_at, updated_at FROM users";
    let countQuery = "SELECT COUNT(*) FROM users";
    const queryParams: any[] = [];
    const countParams: any[] = [];

    if (params.search) {
      query += " WHERE name ILIKE $1 OR email ILIKE $1";
      countQuery += " WHERE name ILIKE $1 OR email ILIKE $1";
      queryParams.push(\`%\${params.search}%\`);
      countParams.push(\`%\${params.search}%\`);
    }

    query += \` ORDER BY created_at DESC LIMIT \${params.limit} OFFSET \${offset}\`;

    const [users, count] = await Promise.all([
      client.queryObject<User>(query, queryParams),
      client.queryObject<{ count: number }>(countQuery, countParams),
    ]);

    return {
      users: users.rows,
      total: parseInt(count.rows[0].count.toString()),
    };
  } finally {
    client.release();
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'services', 'user.ts'),
      userServiceContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'models'), { recursive: true });

    // User model
    const userModelContent = `import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";

export interface User {
  id: string;
  email: string;
  password: string;
  name: string;
  role: string;
  createdAt: Date;
  updatedAt: Date;
}

export const updateUserSchema = z.object({
  email: z.string().email().optional(),
  name: z.string().min(1).max(100).optional(),
});

export type UpdateUserDto = z.infer<typeof updateUserSchema>;
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'models', 'user.ts'),
      userModelContent
    );

    // Auth model
    const authModelContent = `import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(100),
  name: z.string().min(1).max(100),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export type CreateUserDto = z.infer<typeof registerSchema>;
export type LoginDto = z.infer<typeof loginSchema>;
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'models', 'auth.ts'),
      authModelContent
    );
  }

  private async generateDatabase(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'config'), { recursive: true });

    // Database config
    const databaseContent = `import { Pool } from "https://deno.land/x/postgres@v0.19.3/mod.ts";
import { log } from "../utils/logger.ts";

let pool: Pool | null = null;

export async function connectDB(): Promise<Pool> {
  if (pool) {
    return pool;
  }

  const databaseUrl = Deno.env.get("DATABASE_URL");
  
  if (!databaseUrl) {
    throw new Error("DATABASE_URL environment variable is not set");
  }

  // Parse database URL
  const url = new URL(databaseUrl);
  
  pool = new Pool({
    user: url.username,
    password: url.password,
    database: url.pathname.slice(1),
    hostname: url.hostname,
    port: url.port ? parseInt(url.port) : 5432,
  }, 10); // Max 10 connections

  // Test connection
  try {
    const client = await pool.connect();
    await client.queryArray("SELECT 1");
    client.release();
    log.info("Database connected successfully");
  } catch (error) {
    log.error("Failed to connect to database:", error);
    throw error;
  }

  return pool;
}

export async function closeDB(pool: Pool): Promise<void> {
  await pool.end();
  log.info("Database connection closed");
}

// Database migrations
export async function runMigrations(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    // Create users table
    await client.queryArray(\`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(100) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    \`);

    // Create indexes
    await client.queryArray(\`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    \`);

    log.info("Database migrations completed");
  } finally {
    client.release();
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'config', 'database.ts'),
      databaseContent
    );

    // Redis config
    const redisContent = `import { connect } from "https://deno.land/x/redis@v0.32.1/mod.ts";
import { log } from "../utils/logger.ts";

export async function connectRedis() {
  const redisUrl = Deno.env.get("REDIS_URL") || "redis://localhost:6379";
  
  try {
    const redis = await connect({
      hostname: new URL(redisUrl).hostname,
      port: parseInt(new URL(redisUrl).port || "6379"),
    });
    
    // Test connection
    await redis.ping();
    log.info("Redis connected successfully");
    
    return redis;
  } catch (error) {
    log.error("Failed to connect to Redis:", error);
    throw error;
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'config', 'redis.ts'),
      redisContent
    );
  }

  private async generateConfig(projectPath: string, options: any): Promise<void> {
    // Environment config is handled by deps.ts and dotenv
    const envExampleContent = `# Server
PORT=8000
HOST=0.0.0.0
ENV=development

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/${options.name}_db

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=15m
REFRESH_TOKEN_EXPIRES_IN=7d

# CORS
CORS_ORIGIN=*

# Logging
LOG_LEVEL=info
`;

    await fs.writeFile(
      path.join(projectPath, '.env.example'),
      envExampleContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'utils'), { recursive: true });

    // Logger utility
    const loggerContent = `import * as log from "https://deno.land/std@0.212.0/log/mod.ts";

const logLevel = Deno.env.get("LOG_LEVEL") || "INFO";

await log.setup({
  handlers: {
    console: new log.handlers.ConsoleHandler(logLevel as log.LevelName, {
      formatter: (logRecord) => {
        const timestamp = new Date().toISOString();
        return \`[\${timestamp}] [\${logRecord.levelName}] \${logRecord.msg}\`;
      },
    }),
  },
  loggers: {
    default: {
      level: logLevel as log.LevelName,
      handlers: ["console"],
    },
  },
});

export { log };
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'logger.ts'),
      loggerContent
    );

    // JWT utility
    const jwtContent = `import { create, verify, getNumericDate } from "https://deno.land/x/djwt@v3.0.1/mod.ts";
import { User } from "../models/user.ts";

const JWT_SECRET = Deno.env.get("JWT_SECRET") || "your-secret-key";
const key = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(JWT_SECRET),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign", "verify"]
);

export async function generateJWT(user: User): Promise<string> {
  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    exp: getNumericDate(15 * 60), // 15 minutes
  };

  return await create({ alg: "HS256", typ: "JWT" }, payload, key);
}

export async function generateRefreshToken(user: User): Promise<string> {
  const payload = {
    sub: user.id,
    type: "refresh",
    exp: getNumericDate(7 * 24 * 60 * 60), // 7 days
  };

  return await create({ alg: "HS256", typ: "JWT" }, payload, key);
}

export async function verifyJWT(token: string) {
  return await verify(token, key);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'jwt.ts'),
      jwtContent
    );

    // Validation utility
    const validationContent = `import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";

export const paginationSchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(10),
  search: z.string().optional(),
});

export const idSchema = z.string().uuid();

export const emailSchema = z.string().email();

export const passwordSchema = z
  .string()
  .min(8)
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[0-9]/, "Password must contain at least one number");
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'validation.ts'),
      validationContent
    );
  }

  private async generateTypes(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'types'), { recursive: true });

    // Global types
    const typesContent = `// Global type definitions

export interface ApiResponse<T = any> {
  message?: string;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
}

export interface PaginationParams {
  page: number;
  limit: number;
  search?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'types', 'index.ts'),
      typesContent
    );
  }

  private async updateDeps(projectPath: string): Promise<void> {
    const depsContent = await fs.readFile(path.join(projectPath, 'deps.ts'), 'utf-8');
    const oakDeps = `
// Oak framework
export {
  Application,
  Router,
  Context,
  State,
  helpers,
  Status,
} from "https://deno.land/x/oak@v12.6.2/mod.ts";
export type { Middleware, Next } from "https://deno.land/x/oak@v12.6.2/mod.ts";
`;

    await fs.writeFile(
      path.join(projectPath, 'deps.ts'),
      depsContent + oakDeps
    );
  }
}