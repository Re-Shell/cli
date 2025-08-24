import { NodeBackendGenerator } from './node-base-generator';

export class ExpressGenerator extends NodeBackendGenerator {
  
  constructor() {
    super('Express.js');
  }
  
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'express': '^4.19.2',
      'express-async-handler': '^1.2.0',
      'express-rate-limit': '^7.2.0',
      'express-validator': '^7.0.1',
      'helmet': '^7.1.0',
      'cors': '^2.8.5',
      'compression': '^1.7.4',
      'morgan': '^1.10.0',
      'winston': '^3.13.0',
      'dotenv': '^16.4.5',
      'bcryptjs': '^2.4.3',
      'jsonwebtoken': '^9.0.2',
      'prisma': '^5.13.0',
      '@prisma/client': '^5.13.0',
      'redis': '^4.6.13',
      'ioredis': '^5.3.2',
      'swagger-ui-express': '^5.0.0',
      'swagger-jsdoc': '^6.2.8',
      'express-ws': '^5.0.2',
      'socket.io': '^4.7.5',
      'multer': '^1.4.5-lts.1',
      'express-session': '^1.18.0',
      'connect-redis': '^7.1.1',
      'passport': '^0.7.0',
      'passport-jwt': '^4.0.1',
      'passport-local': '^1.0.0',
      'express-mongo-sanitize': '^2.2.0',
      'express-fileupload': '^1.5.0',
      'rate-limit-redis': '^4.2.0'
    };
  }
  
  protected getFrameworkDevDependencies(): Record<string, string> {
    return {
      '@types/express': '^4.17.21',
      '@types/node': '^20.12.7',
      '@types/cors': '^2.8.17',
      '@types/compression': '^1.7.5',
      '@types/morgan': '^1.9.9',
      '@types/bcryptjs': '^2.4.6',
      '@types/jsonwebtoken': '^9.0.6',
      '@types/swagger-ui-express': '^4.1.6',
      '@types/swagger-jsdoc': '^6.0.4',
      '@types/express-ws': '^3.0.4',
      '@types/multer': '^1.4.11',
      '@types/express-session': '^1.17.10',
      '@types/passport': '^1.0.16',
      '@types/passport-jwt': '^4.0.1',
      '@types/passport-local': '^1.0.38',
      '@typescript-eslint/eslint-plugin': '^7.7.1',
      '@typescript-eslint/parser': '^7.7.1',
      'eslint': '^8.57.0',
      'eslint-config-prettier': '^9.1.0',
      'prettier': '^3.2.5',
      'typescript': '^5.4.5',
      'tsx': '^4.7.2',
      'jest': '^29.7.0',
      'ts-jest': '^29.1.2',
      '@types/jest': '^29.5.12',
      'supertest': '^7.0.0',
      '@types/supertest': '^6.0.2',
      'nodemon': '^3.1.0'
    };
  }
  
  protected generateMainFile(): string {
    return `import express, { Express } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { errorHandler } from './middlewares/error.middleware';
import { notFoundHandler } from './middlewares/notFound.middleware';
import { rateLimiter } from './middlewares/rateLimit.middleware';
import { logger } from './utils/logger';
import { connectDatabase } from './config/database';
import { redisClient } from './config/redis';
import routes from './routes';
import { swaggerDocs } from './config/swagger';
import { initializeWebSocket } from './config/websocket';

// Load environment variables
dotenv.config();

const app: Express = express();
const PORT = process.env.PORT || 3000;

// Create HTTP server
const httpServer = createServer(app);

// Initialize Socket.IO
const io = new Server(httpServer, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
  }
});

// Initialize WebSocket handlers
initializeWebSocket(io);

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN?.split(',') || '*',
  credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression middleware
app.use(compression());

// Logging middleware
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));

// Rate limiting
app.use('/api', rateLimiter);

// API Documentation
swaggerDocs(app);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API routes
app.use('/api/v1', routes);

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  httpServer.close(() => {
    logger.info('HTTP server closed');
  });
  
  // Close database connections
  await redisClient.quit();
  process.exit(0);
});

// Start server
const startServer = async () => {
  try {
    // Connect to database
    await connectDatabase();
    
    // Connect to Redis
    await redisClient.connect();
    
    httpServer.listen(PORT, () => {
      logger.info(\`🚀 Server is running on port \${PORT}\`);
      logger.info(\`📚 API Documentation: http://localhost:\${PORT}/api-docs\`);
      logger.info(\`🔧 Environment: \${process.env.NODE_ENV || 'development'}\`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

export { app, io };`;
  }
  
  protected generateRoutingFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/routes/index.ts',
        content: `import { Router } from 'express';
import authRoutes from './auth.routes';
import userRoutes from './user.routes';
import todoRoutes from './todo.routes';

const router = Router();

// Mount routes
router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/todos', todoRoutes);

// API info endpoint
router.get('/', (req, res) => {
  res.json({
    message: '${this.options.name} API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/v1/auth',
      users: '/api/v1/users',
      todos: '/api/v1/todos',
      docs: '/api-docs',
      health: '/health'
    }
  });
});

export default router;`
      },
      {
        path: 'src/routes/auth.routes.ts',
        content: `import { Router } from 'express';
import { body } from 'express-validator';
import { validate } from '../middlewares/validate.middleware';
import { AuthController } from '../controllers/auth.controller';
import { authenticate } from '../middlewares/auth.middleware';

const router = Router();
const authController = new AuthController();

// Register
router.post(
  '/register',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('name').trim().notEmpty().withMessage('Name is required'),
    validate
  ],
  authController.register
);

// Login
router.post(
  '/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
    validate
  ],
  authController.login
);

// Refresh token
router.post('/refresh', authController.refreshToken);

// Logout
router.post('/logout', authenticate, authController.logout);

// Verify email
router.get('/verify/:token', authController.verifyEmail);

// Forgot password
router.post(
  '/forgot-password',
  [
    body('email').isEmail().normalizeEmail(),
    validate
  ],
  authController.forgotPassword
);

// Reset password
router.post(
  '/reset-password/:token',
  [
    body('password').isLength({ min: 8 }),
    validate
  ],
  authController.resetPassword
);

export default router;`
      },
      {
        path: 'src/routes/user.routes.ts',
        content: `import { Router } from 'express';
import { body, param } from 'express-validator';
import { validate } from '../middlewares/validate.middleware';
import { authenticate, authorize } from '../middlewares/auth.middleware';
import { UserController } from '../controllers/user.controller';

const router = Router();
const userController = new UserController();

// Get all users (admin only)
router.get('/', authenticate, authorize('admin'), userController.getAllUsers);

// Get current user
router.get('/me', authenticate, userController.getCurrentUser);

// Get user by ID
router.get(
  '/:id',
  [
    param('id').isMongoId(),
    validate
  ],
  authenticate,
  userController.getUserById
);

// Update user
router.put(
  '/:id',
  [
    param('id').isMongoId(),
    body('email').optional().isEmail().normalizeEmail(),
    body('name').optional().trim().notEmpty(),
    validate
  ],
  authenticate,
  userController.updateUser
);

// Delete user
router.delete(
  '/:id',
  [
    param('id').isMongoId(),
    validate
  ],
  authenticate,
  authorize('admin'),
  userController.deleteUser
);

// Change password
router.post(
  '/change-password',
  [
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 8 }),
    validate
  ],
  authenticate,
  userController.changePassword
);

// Upload avatar
router.post(
  '/avatar',
  authenticate,
  userController.uploadAvatar
);

export default router;`
      },
      {
        path: 'src/routes/todo.routes.ts',
        content: `import { Router } from 'express';
import { body, param, query } from 'express-validator';
import { validate } from '../middlewares/validate.middleware';
import { authenticate } from '../middlewares/auth.middleware';
import { TodoController } from '../controllers/todo.controller';

const router = Router();
const todoController = new TodoController();

// All routes require authentication
router.use(authenticate);

// Get all todos with pagination and filtering
router.get(
  '/',
  [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('status').optional().isIn(['pending', 'in_progress', 'completed']),
    query('priority').optional().isIn(['low', 'medium', 'high']),
    validate
  ],
  todoController.getAllTodos
);

// Get todo by ID
router.get(
  '/:id',
  [
    param('id').isMongoId(),
    validate
  ],
  todoController.getTodoById
);

// Create todo
router.post(
  '/',
  [
    body('title').trim().notEmpty().withMessage('Title is required'),
    body('description').optional().trim(),
    body('priority').optional().isIn(['low', 'medium', 'high']),
    body('dueDate').optional().isISO8601(),
    validate
  ],
  todoController.createTodo
);

// Update todo
router.put(
  '/:id',
  [
    param('id').isMongoId(),
    body('title').optional().trim().notEmpty(),
    body('description').optional().trim(),
    body('status').optional().isIn(['pending', 'in_progress', 'completed']),
    body('priority').optional().isIn(['low', 'medium', 'high']),
    body('dueDate').optional().isISO8601(),
    validate
  ],
  todoController.updateTodo
);

// Delete todo
router.delete(
  '/:id',
  [
    param('id').isMongoId(),
    validate
  ],
  todoController.deleteTodo
);

// Bulk operations
router.post('/bulk/delete', todoController.bulkDelete);
router.post('/bulk/update', todoController.bulkUpdate);

export default router;`
      }
    ];
  }
  
  protected generateControllerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/controllers/auth.controller.ts',
        content: `import { Request, Response, NextFunction } from 'express';
import asyncHandler from 'express-async-handler';
import { AuthService } from '../services/auth.service';
import { EmailService } from '../services/email.service';
import { logger } from '../utils/logger';

export class AuthController {
  private authService: AuthService;
  private emailService: EmailService;

  constructor() {
    this.authService = new AuthService();
    this.emailService = new EmailService();
  }

  register = asyncHandler(async (req: Request, res: Response) => {
    const { email, password, name } = req.body;

    const result = await this.authService.register({ email, password, name });

    // Send verification email
    await this.emailService.sendVerificationEmail(email, result.verificationToken);

    res.status(201).json({
      success: true,
      message: 'Registration successful. Please check your email to verify your account.',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken
      }
    });
  });

  login = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    const result = await this.authService.login(email, password);

    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: result.user,
        accessToken: result.accessToken
      }
    });
  });

  refreshToken = asyncHandler(async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!refreshToken) {
      res.status(401);
      throw new Error('Refresh token not provided');
    }

    const result = await this.authService.refreshToken(refreshToken);

    res.json({
      success: true,
      data: {
        accessToken: result.accessToken
      }
    });
  });

  logout = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;

    if (userId) {
      await this.authService.logout(userId);
    }

    res.clearCookie('refreshToken');

    res.json({
      success: true,
      message: 'Logout successful'
    });
  });

  verifyEmail = asyncHandler(async (req: Request, res: Response) => {
    const { token } = req.params;

    await this.authService.verifyEmail(token);

    res.json({
      success: true,
      message: 'Email verified successfully'
    });
  });

  forgotPassword = asyncHandler(async (req: Request, res: Response) => {
    const { email } = req.body;

    const resetToken = await this.authService.forgotPassword(email);

    // Send reset email
    await this.emailService.sendPasswordResetEmail(email, resetToken);

    res.json({
      success: true,
      message: 'Password reset email sent'
    });
  });

  resetPassword = asyncHandler(async (req: Request, res: Response) => {
    const { token } = req.params;
    const { password } = req.body;

    await this.authService.resetPassword(token, password);

    res.json({
      success: true,
      message: 'Password reset successful'
    });
  });
}`
      },
      {
        path: 'src/controllers/user.controller.ts',
        content: `import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { UserService } from '../services/user.service';
import { uploadSingle } from '../utils/upload';

export class UserController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
  }

  getAllUsers = asyncHandler(async (req: Request, res: Response) => {
    const { page = 1, limit = 10, search } = req.query;

    const result = await this.userService.getAllUsers({
      page: Number(page),
      limit: Number(limit),
      search: search as string
    });

    res.json({
      success: true,
      data: result
    });
  });

  getCurrentUser = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;

    const user = await this.userService.getUserById(userId);

    res.json({
      success: true,
      data: user
    });
  });

  getUserById = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;

    const user = await this.userService.getUserById(id);

    res.json({
      success: true,
      data: user
    });
  });

  updateUser = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const updates = req.body;

    // Ensure users can only update their own profile unless admin
    if (req.user!.id !== id && req.user!.role !== 'admin') {
      res.status(403);
      throw new Error('Forbidden');
    }

    const user = await this.userService.updateUser(id, updates);

    res.json({
      success: true,
      message: 'User updated successfully',
      data: user
    });
  });

  deleteUser = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;

    await this.userService.deleteUser(id);

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  });

  changePassword = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const { currentPassword, newPassword } = req.body;

    await this.userService.changePassword(userId, currentPassword, newPassword);

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  });

  uploadAvatar = [
    uploadSingle('avatar'),
    asyncHandler(async (req: Request, res: Response) => {
      const userId = req.user!.id;

      if (!req.file) {
        res.status(400);
        throw new Error('No file uploaded');
      }

      const avatarUrl = await this.userService.updateAvatar(userId, req.file);

      res.json({
        success: true,
        message: 'Avatar uploaded successfully',
        data: { avatarUrl }
      });
    })
  ];
}`
      },
      {
        path: 'src/controllers/todo.controller.ts',
        content: `import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { TodoService } from '../services/todo.service';

export class TodoController {
  private todoService: TodoService;

  constructor() {
    this.todoService = new TodoService();
  }

  getAllTodos = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const { page = 1, limit = 10, status, priority } = req.query;

    const result = await this.todoService.getAllTodos({
      userId,
      page: Number(page),
      limit: Number(limit),
      status: status as string,
      priority: priority as string
    });

    res.json({
      success: true,
      data: result
    });
  });

  getTodoById = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const userId = req.user!.id;

    const todo = await this.todoService.getTodoById(id, userId);

    res.json({
      success: true,
      data: todo
    });
  });

  createTodo = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const todoData = { ...req.body, userId };

    const todo = await this.todoService.createTodo(todoData);

    res.status(201).json({
      success: true,
      message: 'Todo created successfully',
      data: todo
    });
  });

  updateTodo = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const userId = req.user!.id;
    const updates = req.body;

    const todo = await this.todoService.updateTodo(id, userId, updates);

    res.json({
      success: true,
      message: 'Todo updated successfully',
      data: todo
    });
  });

  deleteTodo = asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const userId = req.user!.id;

    await this.todoService.deleteTodo(id, userId);

    res.json({
      success: true,
      message: 'Todo deleted successfully'
    });
  });

  bulkDelete = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      res.status(400);
      throw new Error('Invalid todo IDs');
    }

    const count = await this.todoService.bulkDelete(ids, userId);

    res.json({
      success: true,
      message: \`\${count} todos deleted successfully\`
    });
  });

  bulkUpdate = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const { ids, updates } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      res.status(400);
      throw new Error('Invalid todo IDs');
    }

    const count = await this.todoService.bulkUpdate(ids, userId, updates);

    res.json({
      success: true,
      message: \`\${count} todos updated successfully\`
    });
  });
}`
      }
    ];
  }
  
  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/services/auth.service.ts',
        content: `import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { prisma } from '../config/database';
import { redisClient } from '../config/redis';

interface RegisterData {
  email: string;
  password: string;
  name: string;
}

export class AuthService {
  async register(data: RegisterData) {
    const { email, password, name } = data;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      throw new Error('User already exists with this email');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        verificationToken
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isEmailVerified: true,
        createdAt: true
      }
    });

    // Generate tokens
    const accessToken = this.generateAccessToken(user);
    const refreshToken = this.generateRefreshToken();

    // Store refresh token
    await this.storeRefreshToken(user.id, refreshToken);

    return {
      user,
      accessToken,
      refreshToken,
      verificationToken
    };
  }

  async login(email: string, password: string) {
    // Find user
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      throw new Error('Invalid credentials');
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw new Error('Invalid credentials');
    }

    // Generate tokens
    const accessToken = this.generateAccessToken(user);
    const refreshToken = this.generateRefreshToken();

    // Store refresh token
    await this.storeRefreshToken(user.id, refreshToken);

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isEmailVerified: user.isEmailVerified
      },
      accessToken,
      refreshToken
    };
  }

  async refreshToken(refreshToken: string) {
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!) as any;
      
      // Check if refresh token exists in Redis
      const storedToken = await redisClient.get(\`refresh_token:\${decoded.id}\`);
      if (!storedToken || storedToken !== refreshToken) {
        throw new Error('Invalid refresh token');
      }

      // Get user
      const user = await prisma.user.findUnique({
        where: { id: decoded.id }
      });

      if (!user) {
        throw new Error('User not found');
      }

      // Generate new access token
      const accessToken = this.generateAccessToken(user);

      return { accessToken };
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  async logout(userId: string) {
    // Remove refresh token from Redis
    await redisClient.del(\`refresh_token:\${userId}\`);
  }

  async verifyEmail(token: string) {
    const user = await prisma.user.findFirst({
      where: { verificationToken: token }
    });

    if (!user) {
      throw new Error('Invalid verification token');
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        isEmailVerified: true,
        verificationToken: null
      }
    });
  }

  async forgotPassword(email: string) {
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      throw new Error('User not found');
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetToken,
        resetTokenExpiry
      }
    });

    return resetToken;
  }

  async resetPassword(token: string, newPassword: string) {
    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiry: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      throw new Error('Invalid or expired reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null
      }
    });
  }

  private generateAccessToken(user: any): string {
    return jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET!,
      { expiresIn: process.env.JWT_EXPIRE || '15m' }
    );
  }

  private generateRefreshToken(): string {
    return jwt.sign(
      { type: 'refresh' },
      process.env.JWT_REFRESH_SECRET!,
      { expiresIn: '7d' }
    );
  }

  private async storeRefreshToken(userId: string, refreshToken: string) {
    await redisClient.setex(\`refresh_token:\${userId}\`, 7 * 24 * 60 * 60, refreshToken); // 7 days
  }
}`
      },
      {
        path: 'src/services/user.service.ts',
        content: `import bcrypt from 'bcryptjs';
import { prisma } from '../config/database';

export class UserService {
  async getAllUsers(options: { page: number; limit: number; search?: string }) {
    const { page, limit, search } = options;
    const skip = (page - 1) * limit;

    const where = search
      ? {
          OR: [
            { name: { contains: search, mode: 'insensitive' as const } },
            { email: { contains: search, mode: 'insensitive' as const } }
          ]
        }
      : {};

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: limit,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          isEmailVerified: true,
          avatar: true,
          createdAt: true,
          updatedAt: true
        },
        orderBy: { createdAt: 'desc' }
      }),
      prisma.user.count({ where })
    ]);

    return {
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  }

  async getUserById(id: string) {
    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isEmailVerified: true,
        avatar: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (!user) {
      throw new Error('User not found');
    }

    return user;
  }

  async updateUser(id: string, updates: any) {
    const user = await prisma.user.update({
      where: { id },
      data: updates,
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isEmailVerified: true,
        avatar: true,
        updatedAt: true
      }
    });

    return user;
  }

  async deleteUser(id: string) {
    await prisma.user.delete({
      where: { id }
    });
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      throw new Error('User not found');
    }

    const isValidPassword = await bcrypt.compare(currentPassword, user.password);
    if (!isValidPassword) {
      throw new Error('Current password is incorrect');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword }
    });
  }

  async updateAvatar(userId: string, file: any) {
    // In a real application, you would upload the file to a cloud storage service
    // For this example, we'll just store the filename
    const avatarUrl = \`/uploads/avatars/\${file.filename}\`;

    await prisma.user.update({
      where: { id: userId },
      data: { avatar: avatarUrl }
    });

    return avatarUrl;
  }
}`
      },
      {
        path: 'src/services/todo.service.ts',
        content: `import { prisma } from '../config/database';

export class TodoService {
  async getAllTodos(options: {
    userId: string;
    page: number;
    limit: number;
    status?: string;
    priority?: string;
  }) {
    const { userId, page, limit, status, priority } = options;
    const skip = (page - 1) * limit;

    const where: any = { userId };

    if (status) {
      where.status = status.toUpperCase();
    }

    if (priority) {
      where.priority = priority.toUpperCase();
    }

    const [todos, total] = await Promise.all([
      prisma.todo.findMany({
        where,
        skip,
        take: limit,
        orderBy: [
          { priority: 'desc' },
          { createdAt: 'desc' }
        ]
      }),
      prisma.todo.count({ where })
    ]);

    return {
      todos,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  }

  async getTodoById(id: string, userId: string) {
    const todo = await prisma.todo.findFirst({
      where: { id, userId }
    });

    if (!todo) {
      throw new Error('Todo not found');
    }

    return todo;
  }

  async createTodo(data: any) {
    const todo = await prisma.todo.create({
      data: {
        ...data,
        status: data.status?.toUpperCase() || 'PENDING',
        priority: data.priority?.toUpperCase() || 'MEDIUM'
      }
    });

    return todo;
  }

  async updateTodo(id: string, userId: string, updates: any) {
    // Check if todo exists and belongs to user
    const existingTodo = await this.getTodoById(id, userId);

    const todo = await prisma.todo.update({
      where: { id },
      data: {
        ...updates,
        status: updates.status?.toUpperCase(),
        priority: updates.priority?.toUpperCase()
      }
    });

    return todo;
  }

  async deleteTodo(id: string, userId: string) {
    // Check if todo exists and belongs to user
    await this.getTodoById(id, userId);

    await prisma.todo.delete({
      where: { id }
    });
  }

  async bulkDelete(ids: string[], userId: string) {
    const result = await prisma.todo.deleteMany({
      where: {
        id: { in: ids },
        userId
      }
    });

    return result.count;
  }

  async bulkUpdate(ids: string[], userId: string, updates: any) {
    const result = await prisma.todo.updateMany({
      where: {
        id: { in: ids },
        userId
      },
      data: {
        ...updates,
        status: updates.status?.toUpperCase(),
        priority: updates.priority?.toUpperCase()
      }
    });

    return result.count;
  }
}`
      },
      {
        path: 'src/services/email.service.ts',
        content: `export class EmailService {
  async sendVerificationEmail(email: string, token: string) {
    // Implement email sending logic here
    // This is a placeholder implementation
    console.log(\`Sending verification email to \${email} with token: \${token}\`);
  }

  async sendPasswordResetEmail(email: string, token: string) {
    // Implement email sending logic here
    // This is a placeholder implementation
    console.log(\`Sending password reset email to \${email} with token: \${token}\`);
  }
}`
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middlewares/auth.middleware.ts',
        content: `import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import { UserService } from '../services/user.service';

interface JwtPayload {
  id: string;
  email: string;
  role: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

const userService = new UserService();

export const authenticate = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  let token: string | undefined;

  // Check for token in Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    res.status(401);
    throw new Error('Not authorized, no token');
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;

    // Check if user still exists
    const user = await userService.getUserById(decoded.id);
    if (!user) {
      res.status(401);
      throw new Error('User no longer exists');
    }

    // Attach user to request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role
    };

    next();
  } catch (error) {
    res.status(401);
    throw new Error('Not authorized, token failed');
  }
});

export const authorize = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401);
      throw new Error('Not authenticated');
    }

    if (!roles.includes(req.user.role)) {
      res.status(403);
      throw new Error('Not authorized for this resource');
    }

    next();
  };
};`
      },
      {
        path: 'src/middlewares/error.middleware.ts',
        content: `import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

interface ErrorWithStatus extends Error {
  status?: number;
  code?: string;
}

export const errorHandler = (
  err: ErrorWithStatus,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let status = err.status || res.statusCode || 500;
  let message = err.message || 'Internal Server Error';

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    status = 400;
    message = 'Validation Error';
  }

  // Mongoose duplicate key error
  if (err.code === '11000') {
    status = 400;
    message = 'Duplicate field value';
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    status = 401;
    message = 'Invalid token';
  }

  if (err.name === 'TokenExpiredError') {
    status = 401;
    message = 'Token expired';
  }

  // Log error
  logger.error({
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    status
  });

  res.status(status).json({
    success: false,
    error: {
      message,
      status,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
};`
      },
      {
        path: 'src/middlewares/notFound.middleware.ts',
        content: `import { Request, Response } from 'express';

export const notFoundHandler = (req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: {
      message: 'Resource not found',
      status: 404,
      path: req.originalUrl
    }
  });
};`
      },
      {
        path: 'src/middlewares/validate.middleware.ts',
        content: `import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';

export const validate = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        status: 400,
        details: errors.array()
      }
    });
  }

  next();
};`
      },
      {
        path: 'src/middlewares/rateLimit.middleware.ts',
        content: `import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { redisClient } from '../config/redis';

// General API rate limit
export const rateLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rate_limit:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict rate limit for auth endpoints
export const authRateLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'auth_limit:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true,
});

// File upload rate limit
export const uploadRateLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'upload_limit:'
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 uploads per hour
  message: 'Upload limit exceeded, please try again later.',
});`
      }
    ];
  }
  
  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/config/database.ts',
        content: `import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';

const prisma = new PrismaClient({
  log: [
    { emit: 'event', level: 'query' },
    { emit: 'event', level: 'error' },
    { emit: 'event', level: 'info' },
    { emit: 'event', level: 'warn' },
  ],
});

// Log database queries in development
if (process.env.NODE_ENV === 'development') {
  prisma.$on('query', (e) => {
    logger.debug(\`Query: \${e.query}\`);
    logger.debug(\`Duration: \${e.duration}ms\`);
  });
}

prisma.$on('error', (e) => {
  logger.error(\`Database error: \${e.message}\`);
});

export const connectDatabase = async () => {
  try {
    await prisma.$connect();
    logger.info('Database connected successfully');
  } catch (error) {
    logger.error('Database connection failed:', error);
    throw error;
  }
};

export { prisma };`
      },
      {
        path: 'src/config/redis.ts',
        content: `import { createClient } from 'redis';
import { logger } from '../utils/logger';

const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

export const redisClient = createClient({
  url: redisUrl,
  socket: {
    reconnectStrategy: (retries) => {
      if (retries > 10) {
        logger.error('Redis: Maximum reconnection attempts reached');
        return new Error('Maximum reconnection attempts reached');
      }
      const delay = Math.min(retries * 100, 3000);
      logger.info(\`Redis: Reconnecting in \${delay}ms...\`);
      return delay;
    }
  }
});

redisClient.on('error', (err) => {
  logger.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
  logger.info('Redis Client Connected');
});

redisClient.on('ready', () => {
  logger.info('Redis Client Ready');
});

redisClient.on('reconnecting', () => {
  logger.warn('Redis Client Reconnecting');
});`
      },
      {
        path: 'src/config/websocket.ts',
        content: `import { Server, Socket } from 'socket.io';
import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger';

interface SocketWithAuth extends Socket {
  userId?: string;
}

export const initializeWebSocket = (io: Server) => {
  // Authentication middleware
  io.use(async (socket: SocketWithAuth, next) => {
    try {
      const token = socket.handshake.auth.token;
      
      if (!token) {
        return next(new Error('Authentication error'));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
      socket.userId = decoded.id;
      
      next();
    } catch (err) {
      next(new Error('Authentication error'));
    }
  });

  io.on('connection', (socket: SocketWithAuth) => {
    logger.info(\`User \${socket.userId} connected via WebSocket\`);

    // Join user's personal room
    if (socket.userId) {
      socket.join(\`user:\${socket.userId}\`);
    }

    // Handle real-time events
    socket.on('join-room', (roomId: string) => {
      socket.join(roomId);
      logger.info(\`User \${socket.userId} joined room \${roomId}\`);
    });

    socket.on('leave-room', (roomId: string) => {
      socket.leave(roomId);
      logger.info(\`User \${socket.userId} left room \${roomId}\`);
    });

    socket.on('todo-update', (data) => {
      // Broadcast to all users in the room
      socket.to(\`user:\${socket.userId}\`).emit('todo-updated', data);
    });

    socket.on('disconnect', () => {
      logger.info(\`User \${socket.userId} disconnected\`);
    });
  });
};

export const emitToUser = (io: Server, userId: string, event: string, data: any) => {
  io.to(\`user:\${userId}\`).emit(event, data);
};`
      },
      {
        path: 'src/config/swagger.ts',
        content: `import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { Express } from 'express';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: '${this.options.name} API',
      version: '1.0.0',
      description: 'Express.js API with TypeScript',
      license: {
        name: 'MIT',
        url: 'https://spdx.org/licenses/MIT.html',
      },
      contact: {
        name: 'API Support',
        email: 'support@example.com',
      },
    },
    servers: [
      {
        url: 'http://localhost:3000/api/v1',
        description: 'Development server',
      },
      {
        url: process.env.API_URL || 'https://api.example.com/v1',
        description: 'Production server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: ['./src/routes/*.ts', './src/models/*.ts'],
};

const swaggerSpec = swaggerJsdoc(options);

export const swaggerDocs = (app: Express) => {
  // Swagger page
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

  // Docs in JSON format
  app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  });
};`
      }
    ];
  }
  
  protected generateUtilFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/utils/logger.ts',
        content: `import winston from 'winston';
import path from 'path';

const logDir = process.env.LOG_DIR || 'logs';

const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const level = () => {
  const env = process.env.NODE_ENV || 'development';
  const isDevelopment = env === 'development';
  return isDevelopment ? 'debug' : 'warn';
};

const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

winston.addColors(colors);

const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => \`\${info.timestamp} \${info.level}: \${info.message}\`
  ),
);

const transports = [
  new winston.transports.Console(),
  new winston.transports.File({
    filename: path.join(logDir, 'error.log'),
    level: 'error',
  }),
  new winston.transports.File({
    filename: path.join(logDir, 'all.log')
  }),
];

export const logger = winston.createLogger({
  level: level(),
  levels,
  format,
  transports,
});`
      },
      {
        path: 'src/utils/upload.ts',
        content: `import multer from 'multer';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, process.env.UPLOAD_DIR || 'uploads');
  },
  filename: (req, file, cb) => {
    const uniqueId = uuidv4();
    const extension = path.extname(file.originalname);
    cb(null, \`\${uniqueId}\${extension}\`);
  }
});

const fileFilter = (req: any, file: any, cb: any) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE || '10485760') // 10MB default
  }
});

export const uploadSingle = (fieldName: string) => upload.single(fieldName);
export const uploadMultiple = (fieldName: string, maxCount: number) => upload.array(fieldName, maxCount);`
      }
    ];
  }
  
}