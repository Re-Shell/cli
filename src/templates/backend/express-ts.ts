import { BackendTemplate } from '../types';

export const expressTypeScriptTemplate: BackendTemplate = {
  id: 'express-ts',
  name: 'Express.js + TypeScript',
  description: 'Modern Express.js API server with TypeScript, JWT authentication, and choice of Prisma or TypeORM',
  framework: 'express',
  language: 'typescript',
  version: '1.0.0',
  tags: ['express', 'typescript', 'jwt', 'middleware', 'rest-api', 'prisma', 'typeorm', 'database'],
  dependencies: {
    express: '^4.18.2',
    cors: '^2.8.5',
    helmet: '^7.1.0',
    compression: '^1.7.4',
    'express-rate-limit': '^7.1.5',
    jsonwebtoken: '^9.0.2',
    bcryptjs: '^2.4.3',
    dotenv: '^16.3.1',
    winston: '^3.11.0',
    'express-validator': '^7.0.1',
    'express-async-errors': '^3.1.1',
    '@types/express': '^4.17.21',
    '@types/cors': '^2.8.17',
    '@types/compression': '^1.7.5',
    '@types/jsonwebtoken': '^9.0.5',
    '@types/bcryptjs': '^2.4.6',
    typescript: '^5.3.3',
    'ts-node': '^10.9.1',
    nodemon: '^3.0.2',
    // Prisma ORM
    '@prisma/client': '^5.8.1',
    bcrypt: '^5.1.1',
    uuid: '^9.0.1',
    // TypeORM integration
    typeorm: '^0.3.17',
    'class-validator': '^0.14.0',
    'class-transformer': '^0.5.1',
    reflect-metadata: '^0.1.13',
    pg: '^8.11.3',
    mysql2: '^3.6.5',
    sqlite3: '^5.1.6'
  },
  devDependencies: {
    '@types/node': '^20.10.5',
    '@types/jest': '^29.5.8',
    jest: '^29.7.0',
    'ts-jest': '^29.1.1',
    supertest: '^6.3.3',
    '@types/supertest': '^6.0.0',
    eslint: '^8.56.0',
    '@typescript-eslint/parser': '^6.15.0',
    '@typescript-eslint/eslint-plugin': '^6.15.0',
    prettier: '^3.1.1',
    // Prisma ORM
    prisma: '^5.8.1',
    '@types/bcrypt': '^5.0.2',
    '@types/uuid': '^9.0.7',
    // TypeORM types
    '@types/pg': '^8.10.9'
  },
  files: {
    'package.json': {
      name: '{{projectName}}',
      version: '1.0.0',
      description: 'Express.js TypeScript API server',
      main: 'dist/index.js',
      scripts: {
        start: 'node dist/index.js',
        dev: 'nodemon src/index.ts',
        build: 'tsc',
        test: 'jest',
        'test:watch': 'jest --watch',
        'test:coverage': 'jest --coverage',
        lint: 'eslint src --ext .ts',
        'lint:fix': 'eslint src --ext .ts --fix',
        format: 'prettier --write "src/**/*.ts"',
        // Prisma scripts
        'db:generate': 'prisma generate',
        'db:push': 'prisma db push',
        'db:migrate': 'prisma migrate dev',
        'db:studio': 'prisma studio',
        'db:seed': 'ts-node prisma/seed.ts',
        // TypeORM scripts
        'typeorm': 'typeorm-ts-node-commonjs',
        'typeorm:migration:generate': 'npm run typeorm -- migration:generate src/migrations/Migration -d src/config/typeorm.config.ts',
        'typeorm:migration:run': 'npm run typeorm -- migration:run -d src/config/typeorm.config.ts',
        'typeorm:migration:revert': 'npm run typeorm -- migration:revert -d src/config/typeorm.config.ts',
        'typeorm:schema:sync': 'npm run typeorm -- schema:sync -d src/config/typeorm.config.ts',
        'typeorm:schema:drop': 'npm run typeorm -- schema:drop -d src/config/typeorm.config.ts',
        'typeorm:seed': 'ts-node src/seeds/seed.ts'
      },
      keywords: ['express', 'typescript', 'api', 'server'],
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
        resolveJsonModule: true
      },
      include: ['src/**/*'],
      exclude: ['node_modules', 'dist', '**/*.test.ts']
    },
    'src/index.ts': `import 'reflect-metadata'; // Required for TypeORM decorators
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import 'express-async-errors';

import { logger } from './config/logger';
import { errorHandler } from './middleware/errorHandler';
import { notFoundHandler } from './middleware/notFoundHandler';
import { authRoutes } from './routes/auth';
import { userRoutes } from './routes/users';
import { healthRoutes } from './routes/health';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Body parsing and compression
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Logging middleware
app.use((req, res, next) => {
  logger.info(\`\${req.method} \${req.url}\`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  next();
});

// Routes
app.use('/api/health', healthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Error handling
app.use(notFoundHandler);
app.use(errorHandler);

// Graceful shutdown
const server = app.listen(PORT, () => {
  logger.info(\`Server running on port \${PORT}\`);
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

export default app;
`,
    'src/config/logger.ts': `import winston from 'winston';

const logLevel = process.env.LOG_LEVEL || 'info';

export const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: '{{projectName}}' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}
`,
    'src/config/auth.ts': `import jwt from 'jsonwebtoken';

export const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
export const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
export const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '30d';

export interface JWTPayload {
  userId: string;
  email: string;
  role?: string;
}

export const generateToken = (payload: JWTPayload): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

export const generateRefreshToken = (payload: JWTPayload): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });
};

export const verifyToken = (token: string): JWTPayload => {
  return jwt.verify(token, JWT_SECRET) as JWTPayload;
};
`,
    'src/middleware/auth.ts': `import { Request, Response, NextFunction } from 'express';
import { verifyToken, JWTPayload } from '../config/auth';
import { AppError } from '../utils/AppError';

export interface AuthenticatedRequest extends Request {
  user?: JWTPayload;
}

export const authenticateToken = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    throw new AppError('Access token required', 401);
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    throw new AppError('Invalid or expired token', 401);
  }
};

export const authorizeRoles = (...roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      throw new AppError('Authentication required', 401);
    }

    if (req.user.role && !roles.includes(req.user.role)) {
      throw new AppError('Insufficient permissions', 403);
    }

    next();
  };
};
`,
    'src/middleware/errorHandler.ts': `import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';
import { AppError } from '../utils/AppError';

export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let statusCode = 500;
  let message = 'Internal Server Error';

  if (error instanceof AppError) {
    statusCode = error.statusCode;
    message = error.message;
  }

  // Log error
  logger.error(error.message, {
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Send error response
  res.status(statusCode).json({
    success: false,
    error: {
      message,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    }
  });
};
`,
    'src/middleware/notFoundHandler.ts': `import { Request, Response } from 'express';

export const notFoundHandler = (req: Request, res: Response): void => {
  res.status(404).json({
    success: false,
    error: {
      message: \`Route \${req.method} \${req.url} not found\`
    }
  });
};
`,
    'src/middleware/validation.ts': `import { Request, Response, NextFunction } from 'express';
import { validationResult, ValidationChain } from 'express-validator';
import { AppError } from '../utils/AppError';

export const validate = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Run all validations
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    const errorMessages = errors.array().map(error => ({
      field: error.param,
      message: error.msg
    }));

    throw new AppError('Validation failed', 400, errorMessages);
  };
};
`,
    'src/utils/AppError.ts': `export class AppError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly data?: any;

  constructor(message: string, statusCode: number = 500, data?: any) {
    super(message);
    
    this.statusCode = statusCode;
    this.isOperational = true;
    this.data = data;

    Error.captureStackTrace(this, this.constructor);
  }
}
`,
    'src/utils/asyncWrapper.ts': `import { Request, Response, NextFunction } from 'express';

type AsyncFunction = (req: Request, res: Response, next: NextFunction) => Promise<any>;

export const asyncWrapper = (fn: AsyncFunction) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res, next).catch(next);
  };
};
`,
    'src/utils/passwordUtils.ts': `import bcrypt from 'bcryptjs';

export const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
};

export const comparePassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};
`,
    'src/routes/health.ts': `import { Router, Request, Response } from 'express';
import { asyncWrapper } from '../utils/asyncWrapper';

const router = Router();

router.get('/', asyncWrapper(async (req: Request, res: Response) => {
  const healthCheck = {
    uptime: process.uptime(),
    message: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0'
  };

  res.status(200).json({
    success: true,
    data: healthCheck
  });
}));

router.get('/detailed', asyncWrapper(async (req: Request, res: Response) => {
  const memoryUsage = process.memoryUsage();
  
  const detailedHealth = {
    uptime: process.uptime(),
    message: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0',
    memory: {
      rss: Math.round(memoryUsage.rss / 1024 / 1024) + ' MB',
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB',
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB',
      external: Math.round(memoryUsage.external / 1024 / 1024) + ' MB'
    },
    cpu: process.cpuUsage()
  };

  res.status(200).json({
    success: true,
    data: detailedHealth
  });
}));

export { router as healthRoutes };
`,
    'src/routes/auth.ts': `import { Router, Request, Response } from 'express';
import { body } from 'express-validator';
import { validate } from '../middleware/validation';
import { asyncWrapper } from '../utils/asyncWrapper';
import { hashPassword, comparePassword } from '../utils/passwordUtils';
import { generateToken, generateRefreshToken } from '../config/auth';
import { AppError } from '../utils/AppError';

const router = Router();

// Mock user storage (replace with database)
const users: Array<{
  id: string;
  email: string;
  password: string;
  role: string;
  createdAt: Date;
}> = [];

// Register endpoint
router.post('/register',
  validate([
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('role').optional().isIn(['user', 'admin']).withMessage('Invalid role')
  ]),
  asyncWrapper(async (req: Request, res: Response) => {
    const { email, password, role = 'user' } = req.body;

    // Check if user already exists
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
      throw new AppError('User already exists', 409);
    }

    // Hash password and create user
    const hashedPassword = await hashPassword(password);
    const newUser = {
      id: Date.now().toString(),
      email,
      password: hashedPassword,
      role,
      createdAt: new Date()
    };

    users.push(newUser);

    // Generate tokens
    const token = generateToken({ userId: newUser.id, email: newUser.email, role: newUser.role });
    const refreshToken = generateRefreshToken({ userId: newUser.id, email: newUser.email, role: newUser.role });

    res.status(201).json({
      success: true,
      data: {
        user: {
          id: newUser.id,
          email: newUser.email,
          role: newUser.role,
          createdAt: newUser.createdAt
        },
        token,
        refreshToken
      }
    });
  })
);

// Login endpoint
router.post('/login',
  validate([
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required')
  ]),
  asyncWrapper(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    // Find user
    const user = users.find(user => user.email === email);
    if (!user) {
      throw new AppError('Invalid credentials', 401);
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      throw new AppError('Invalid credentials', 401);
    }

    // Generate tokens
    const token = generateToken({ userId: user.id, email: user.email, role: user.role });
    const refreshToken = generateRefreshToken({ userId: user.id, email: user.email, role: user.role });

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        },
        token,
        refreshToken
      }
    });
  })
);

export { router as authRoutes };
`,
    'src/routes/users.ts': `import { Router, Response } from 'express';
import { authenticateToken, authorizeRoles, AuthenticatedRequest } from '../middleware/auth';
import { asyncWrapper } from '../utils/asyncWrapper';

const router = Router();

// Get current user profile
router.get('/profile',
  authenticateToken,
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    res.json({
      success: true,
      data: {
        user: req.user
      }
    });
  })
);

// Get all users (admin only)
router.get('/',
  authenticateToken,
  authorizeRoles('admin'),
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    // Mock users data (replace with database query)
    const users = [
      { id: '1', email: 'admin@example.com', role: 'admin' },
      { id: '2', email: 'user@example.com', role: 'user' }
    ];

    res.json({
      success: true,
      data: {
        users,
        total: users.length
      }
    });
  })
);

export { router as userRoutes };
`,
    // TypeORM Configuration Files
    'src/config/typeorm.config.ts': `import { DataSource } from 'typeorm';
import { User } from '../entities/User';
import { Profile } from '../entities/Profile';
import { Post } from '../entities/Post';
import dotenv from 'dotenv';

dotenv.config();

export const AppDataSource = new DataSource({
  type: (process.env.TYPEORM_CONNECTION as any) || 'postgres',
  host: process.env.TYPEORM_HOST || 'localhost',
  port: parseInt(process.env.TYPEORM_PORT || '5432'),
  username: process.env.TYPEORM_USERNAME || 'postgres',
  password: process.env.TYPEORM_PASSWORD || 'password',
  database: process.env.TYPEORM_DATABASE || 'database',
  url: process.env.TYPEORM_URL || process.env.DATABASE_URL,
  synchronize: process.env.TYPEORM_SYNCHRONIZE === 'true' || process.env.NODE_ENV === 'development',
  logging: process.env.TYPEORM_LOGGING === 'true' || process.env.NODE_ENV === 'development',
  entities: [User, Profile, Post],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: ['src/subscribers/**/*.ts'],
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});
`,
    'src/entities/User.ts': `import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToOne,
  OneToMany,
  Index,
  BeforeInsert,
  BeforeUpdate
} from 'typeorm';
import { IsEmail, IsNotEmpty, MinLength, IsOptional, IsEnum } from 'class-validator';
import { Exclude, Transform } from 'class-transformer';
import bcrypt from 'bcryptjs';
import { Profile } from './Profile';
import { Post } from './Post';

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
  MODERATOR = 'moderator'
}

@Entity('users')
@Index(['email'], { unique: true })
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }) => value?.toLowerCase())
  email: string;

  @Column()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Exclude({ toPlainOnly: true })
  password: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER
  })
  @IsOptional()
  @IsEnum(UserRole, { message: 'Role must be user, admin, or moderator' })
  role: UserRole;

  @Column({ nullable: true })
  @IsOptional()
  firstName?: string;

  @Column({ nullable: true })
  @IsOptional()
  lastName?: string;

  @Column({ default: true })
  isActive: boolean;

  @Column({ default: false })
  isEmailVerified: boolean;

  @Column({ nullable: true })
  emailVerificationToken?: string;

  @Column({ nullable: true })
  passwordResetToken?: string;

  @Column({ type: 'timestamp', nullable: true })
  passwordResetExpires?: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt?: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relations
  @OneToOne(() => Profile, profile => profile.user, { cascade: true })
  profile?: Profile;

  @OneToMany(() => Post, post => post.author)
  posts: Post[];

  // Hooks
  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword(): Promise<void> {
    if (this.password && !this.password.startsWith('$2a$')) {
      this.password = await bcrypt.hash(this.password, 12);
    }
  }

  // Methods
  async comparePassword(candidatePassword: string): Promise<boolean> {
    return bcrypt.compare(candidatePassword, this.password);
  }

  get fullName(): string {
    return [this.firstName, this.lastName].filter(Boolean).join(' ');
  }

  toJSON(): Partial<User> {
    const { password, emailVerificationToken, passwordResetToken, ...user } = this;
    return user;
  }
}
`,
    'src/entities/Profile.ts': `import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToOne,
  JoinColumn
} from 'typeorm';
import { IsOptional, IsUrl, IsDateString, IsString, MaxLength } from 'class-validator';
import { User } from './User';

@Entity('profiles')
export class Profile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: true })
  @IsOptional()
  @IsUrl({}, { message: 'Avatar must be a valid URL' })
  avatar?: string;

  @Column({ type: 'text', nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(500, { message: 'Bio cannot exceed 500 characters' })
  bio?: string;

  @Column({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(100, { message: 'Location cannot exceed 100 characters' })
  location?: string;

  @Column({ nullable: true })
  @IsOptional()
  @IsUrl({}, { message: 'Website must be a valid URL' })
  website?: string;

  @Column({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50, { message: 'Phone cannot exceed 50 characters' })
  phone?: string;

  @Column({ type: 'date', nullable: true })
  @IsOptional()
  @IsDateString({}, { message: 'Birth date must be a valid date' })
  birthDate?: Date;

  @Column({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(50, { message: 'Company cannot exceed 50 characters' })
  company?: string;

  @Column({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(100, { message: 'Job title cannot exceed 100 characters' })
  jobTitle?: string;

  @Column({ type: 'json', nullable: true })
  socialLinks?: {
    twitter?: string;
    linkedin?: string;
    github?: string;
    instagram?: string;
    facebook?: string;
  };

  @Column({ type: 'json', nullable: true })
  preferences?: {
    theme: 'light' | 'dark';
    language: string;
    timezone: string;
    emailNotifications: boolean;
    pushNotifications: boolean;
  };

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relations
  @OneToOne(() => User, user => user.profile, { onDelete: 'CASCADE' })
  @JoinColumn()
  user: User;

  @Column()
  userId: string;
}
`,
    'src/entities/Post.ts': `import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index
} from 'typeorm';
import { IsNotEmpty, IsOptional, IsString, MaxLength, IsEnum, IsBoolean, IsArray } from 'class-validator';
import { User } from './User';

export enum PostStatus {
  DRAFT = 'draft',
  PUBLISHED = 'published',
  ARCHIVED = 'archived'
}

export enum PostCategory {
  TECHNOLOGY = 'technology',
  LIFESTYLE = 'lifestyle',
  BUSINESS = 'business',
  EDUCATION = 'education',
  ENTERTAINMENT = 'entertainment',
  OTHER = 'other'
}

@Entity('posts')
@Index(['status', 'publishedAt'])
@Index(['authorId', 'status'])
@Index(['category', 'status'])
export class Post {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  @IsNotEmpty({ message: 'Title is required' })
  @IsString()
  @MaxLength(200, { message: 'Title cannot exceed 200 characters' })
  title: string;

  @Column({ nullable: true })
  @IsOptional()
  @IsString()
  @MaxLength(300, { message: 'Excerpt cannot exceed 300 characters' })
  excerpt?: string;

  @Column({ type: 'text' })
  @IsNotEmpty({ message: 'Content is required' })
  @IsString()
  content: string;

  @Column({ nullable: true })
  @IsOptional()
  @IsString()
  slug?: string;

  @Column({
    type: 'enum',
    enum: PostStatus,
    default: PostStatus.DRAFT
  })
  @IsOptional()
  @IsEnum(PostStatus, { message: 'Status must be draft, published, or archived' })
  status: PostStatus;

  @Column({
    type: 'enum',
    enum: PostCategory,
    default: PostCategory.OTHER
  })
  @IsOptional()
  @IsEnum(PostCategory, { message: 'Invalid category' })
  category: PostCategory;

  @Column({ type: 'simple-array', nullable: true })
  @IsOptional()
  @IsArray()
  tags?: string[];

  @Column({ nullable: true })
  @IsOptional()
  @IsString()
  featuredImage?: string;

  @Column({ default: false })
  @IsOptional()
  @IsBoolean()
  isFeatured: boolean;

  @Column({ default: true })
  @IsOptional()
  @IsBoolean()
  allowComments: boolean;

  @Column({ type: 'int', default: 0 })
  viewCount: number;

  @Column({ type: 'int', default: 0 })
  likeCount: number;

  @Column({ type: 'int', default: 0 })
  commentCount: number;

  @Column({ type: 'json', nullable: true })
  metadata?: {
    readingTime?: number;
    wordCount?: number;
    seoTitle?: string;
    seoDescription?: string;
    customFields?: Record<string, any>;
  };

  @Column({ type: 'timestamp', nullable: true })
  publishedAt?: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relations
  @ManyToOne(() => User, user => user.posts, { eager: true, onDelete: 'CASCADE' })
  @JoinColumn()
  author: User;

  @Column()
  authorId: string;

  // Methods
  generateSlug(): void {
    this.slug = this.title
      .toLowerCase()
      .replace(/[^a-z0-9 -]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim();
  }

  updateMetadata(): void {
    if (!this.metadata) {
      this.metadata = {};
    }
    
    // Calculate word count and reading time
    const wordCount = this.content.split(/\s+/).length;
    const readingTime = Math.ceil(wordCount / 200); // Assume 200 words per minute

    this.metadata.wordCount = wordCount;
    this.metadata.readingTime = readingTime;
  }

  publish(): void {
    this.status = PostStatus.PUBLISHED;
    this.publishedAt = new Date();
    if (!this.slug) {
      this.generateSlug();
    }
    this.updateMetadata();
  }
}
`,
    'src/services/UserService.typeorm.ts': `import { AppDataSource } from '../config/typeorm.config';
import { User, UserRole } from '../entities/User';
import { Profile } from '../entities/Profile';
import { Repository } from 'typeorm';
import { AppError } from '../utils/AppError';
import { validate } from 'class-validator';

export class UserService {
  private userRepository: Repository<User>;
  private profileRepository: Repository<Profile>;

  constructor() {
    this.userRepository = AppDataSource.getRepository(User);
    this.profileRepository = AppDataSource.getRepository(Profile);
  }

  async createUser(userData: {
    email: string;
    password: string;
    role?: UserRole;
    firstName?: string;
    lastName?: string;
  }): Promise<User> {
    // Create user instance
    const user = this.userRepository.create(userData);

    // Validate user data
    const errors = await validate(user);
    if (errors.length > 0) {
      const errorMessages = errors.map(error => 
        Object.values(error.constraints || {}).join(', ')
      ).join('; ');
      throw new AppError(\`Validation failed: \${errorMessages}\`, 400);
    }

    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
      where: { email: userData.email }
    });

    if (existingUser) {
      throw new AppError('User with this email already exists', 409);
    }

    // Save user
    const savedUser = await this.userRepository.save(user);

    // Create default profile
    const profile = this.profileRepository.create({
      userId: savedUser.id,
      preferences: {
        theme: 'light',
        language: 'en',
        timezone: 'UTC',
        emailNotifications: true,
        pushNotifications: false
      }
    });

    await this.profileRepository.save(profile);

    return savedUser;
  }

  async findUserById(id: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { id },
      relations: ['profile', 'posts']
    });
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { email: email.toLowerCase() },
      relations: ['profile']
    });
  }

  async updateUser(id: string, updateData: Partial<User>): Promise<User> {
    const user = await this.findUserById(id);
    if (!user) {
      throw new AppError('User not found', 404);
    }

    // Remove sensitive fields from update
    const { password, emailVerificationToken, passwordResetToken, ...safeUpdateData } = updateData;

    Object.assign(user, safeUpdateData);

    // Validate updated user
    const errors = await validate(user);
    if (errors.length > 0) {
      const errorMessages = errors.map(error => 
        Object.values(error.constraints || {}).join(', ')
      ).join('; ');
      throw new AppError(\`Validation failed: \${errorMessages}\`, 400);
    }

    return this.userRepository.save(user);
  }

  async updateUserPassword(id: string, newPassword: string): Promise<void> {
    const user = await this.findUserById(id);
    if (!user) {
      throw new AppError('User not found', 404);
    }

    user.password = newPassword; // Will be hashed by the @BeforeUpdate hook
    await this.userRepository.save(user);
  }

  async deleteUser(id: string): Promise<void> {
    const result = await this.userRepository.delete(id);
    if (result.affected === 0) {
      throw new AppError('User not found', 404);
    }
  }

  async findAllUsers(options: {
    page?: number;
    limit?: number;
    role?: UserRole;
    isActive?: boolean;
  } = {}): Promise<{ users: User[]; total: number; page: number; totalPages: number }> {
    const { page = 1, limit = 10, role, isActive } = options;
    const skip = (page - 1) * limit;

    const queryBuilder = this.userRepository.createQueryBuilder('user')
      .leftJoinAndSelect('user.profile', 'profile')
      .skip(skip)
      .take(limit)
      .orderBy('user.createdAt', 'DESC');

    if (role) {
      queryBuilder.andWhere('user.role = :role', { role });
    }

    if (isActive !== undefined) {
      queryBuilder.andWhere('user.isActive = :isActive', { isActive });
    }

    const [users, total] = await queryBuilder.getManyAndCount();
    const totalPages = Math.ceil(total / limit);

    return {
      users,
      total,
      page,
      totalPages
    };
  }

  async updateLastLogin(id: string): Promise<void> {
    await this.userRepository.update(id, {
      lastLoginAt: new Date()
    });
  }

  async searchUsers(query: string, limit: number = 10): Promise<User[]> {
    return this.userRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.profile', 'profile')
      .where('user.email ILIKE :query', { query: \`%\${query}%\` })
      .orWhere('user.firstName ILIKE :query', { query: \`%\${query}%\` })
      .orWhere('user.lastName ILIKE :query', { query: \`%\${query}%\` })
      .take(limit)
      .getMany();
  }

  async getUserStats(): Promise<{
    totalUsers: number;
    activeUsers: number;
    newUsersThisMonth: number;
  }> {
    const totalUsers = await this.userRepository.count();
    const activeUsers = await this.userRepository.count({
      where: { isActive: true }
    });

    const thisMonth = new Date();
    thisMonth.setDate(1);
    thisMonth.setHours(0, 0, 0, 0);

    const newUsersThisMonth = await this.userRepository.count({
      where: {
        createdAt: { $gte: thisMonth } as any
      }
    });

    return {
      totalUsers,
      activeUsers,
      newUsersThisMonth
    };
  }
}
`,
    'src/seeds/seed.ts': `import 'reflect-metadata';
import { AppDataSource } from '../config/typeorm.config';
import { User, UserRole } from '../entities/User';
import { Profile } from '../entities/Profile';
import { Post, PostStatus, PostCategory } from '../entities/Post';
import { logger } from '../config/logger';

async function seed(): Promise<void> {
  try {
    // Initialize data source
    await AppDataSource.initialize();
    logger.info('Database connected for seeding');

    // Clear existing data (be careful in production!)
    if (process.env.NODE_ENV === 'development') {
      await AppDataSource.query('DELETE FROM posts');
      await AppDataSource.query('DELETE FROM profiles');
      await AppDataSource.query('DELETE FROM users');
      logger.info('Cleared existing data');
    }

    const userRepository = AppDataSource.getRepository(User);
    const profileRepository = AppDataSource.getRepository(Profile);
    const postRepository = AppDataSource.getRepository(Post);

    // Create admin user
    const adminUser = userRepository.create({
      email: 'admin@example.com',
      password: 'AdminPassword123!',
      role: UserRole.ADMIN,
      firstName: 'Admin',
      lastName: 'User',
      isActive: true,
      isEmailVerified: true
    });
    await userRepository.save(adminUser);

    // Create admin profile
    const adminProfile = profileRepository.create({
      userId: adminUser.id,
      bio: 'System administrator with full access rights.',
      location: 'San Francisco, CA',
      company: 'Tech Corp',
      jobTitle: 'System Administrator',
      preferences: {
        theme: 'dark',
        language: 'en',
        timezone: 'America/Los_Angeles',
        emailNotifications: true,
        pushNotifications: true
      },
      socialLinks: {
        linkedin: 'https://linkedin.com/in/admin',
        github: 'https://github.com/admin'
      }
    });
    await profileRepository.save(adminProfile);

    // Create regular users
    const users = [];
    for (let i = 1; i <= 5; i++) {
      const user = userRepository.create({
        email: \`user\${i}@example.com\`,
        password: 'UserPassword123!',
        role: UserRole.USER,
        firstName: \`User\`,
        lastName: \`\${i}\`,
        isActive: true,
        isEmailVerified: i % 2 === 0 // Every other user is verified
      });
      const savedUser = await userRepository.save(user);
      users.push(savedUser);

      // Create profile for each user
      const profile = profileRepository.create({
        userId: savedUser.id,
        bio: \`This is user \${i}'s bio. I'm passionate about technology and innovation.\`,
        location: ['New York, NY', 'Los Angeles, CA', 'Chicago, IL', 'Houston, TX', 'Phoenix, AZ'][i - 1],
        preferences: {
          theme: i % 2 === 0 ? 'dark' : 'light',
          language: 'en',
          timezone: 'America/New_York',
          emailNotifications: true,
          pushNotifications: i % 2 === 0
        }
      });
      await profileRepository.save(profile);
    }

    // Create sample posts
    const categories = Object.values(PostCategory);
    const sampleTitles = [
      'Getting Started with TypeORM',
      'Building RESTful APIs with Express',
      'Modern JavaScript Best Practices',
      'Database Design Principles',
      'Authentication and Security',
      'Testing Strategies for Node.js',
      'Docker for Development',
      'GraphQL vs REST',
      'Microservices Architecture',
      'Performance Optimization Tips'
    ];

    const allUsers = [adminUser, ...users];

    for (let i = 0; i < 15; i++) {
      const randomUser = allUsers[Math.floor(Math.random() * allUsers.length)];
      const randomTitle = sampleTitles[Math.floor(Math.random() * sampleTitles.length)];
      
      const post = postRepository.create({
        title: \`\${randomTitle} - Part \${i + 1}\`,
        excerpt: \`This is an excerpt for the post about \${randomTitle.toLowerCase()}. Learn the fundamentals and advanced concepts.\`,
        content: \`
# \${randomTitle}

This is a comprehensive guide about \${randomTitle.toLowerCase()}. In this post, we'll explore:

## Introduction

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.

## Key Concepts

- Point 1: Understanding the basics
- Point 2: Advanced techniques
- Point 3: Best practices
- Point 4: Common pitfalls to avoid

## Implementation

Here's a code example:

\\\`\\\`\\\`typescript
const example = () => {
  console.log('Hello, world!');
  return { success: true };
};
\\\`\\\`\\\`

## Conclusion

This wraps up our discussion on \${randomTitle.toLowerCase()}. Remember to always follow best practices!
        \`.trim(),
        status: i % 3 === 0 ? PostStatus.DRAFT : PostStatus.PUBLISHED,
        category: categories[Math.floor(Math.random() * categories.length)],
        tags: ['tutorial', 'beginner', 'javascript', 'typescript'].slice(0, Math.floor(Math.random() * 3) + 1),
        authorId: randomUser.id,
        isFeatured: i % 5 === 0,
        viewCount: Math.floor(Math.random() * 1000),
        likeCount: Math.floor(Math.random() * 50),
        publishedAt: i % 3 !== 0 ? new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000) : undefined
      });

      post.generateSlug();
      post.updateMetadata();
      
      await postRepository.save(post);
    }

    logger.info('Database seeded successfully!');
    logger.info(\`Created:
      - 1 admin user (admin@example.com / AdminPassword123!)
      - 5 regular users (user1@example.com to user5@example.com / UserPassword123!)
      - 6 user profiles
      - 15 sample posts\`);

  } catch (error) {
    logger.error('Error seeding database:', error);
    throw error;
  } finally {
    await AppDataSource.destroy();
  }
}

// Run the seed if this file is executed directly
if (require.main === module) {
  seed().catch(error => {
    console.error('Seeding failed:', error);
    process.exit(1);
  });
}

export { seed };
`,
    'ormconfig.ts': `import { DataSource } from 'typeorm';

// TypeORM CLI configuration file
// This file is used by TypeORM CLI commands
const dataSource = new DataSource({
  type: (process.env.TYPEORM_CONNECTION as any) || 'postgres',
  host: process.env.TYPEORM_HOST || 'localhost',
  port: parseInt(process.env.TYPEORM_PORT || '5432'),
  username: process.env.TYPEORM_USERNAME || 'postgres',
  password: process.env.TYPEORM_PASSWORD || 'password',
  database: process.env.TYPEORM_DATABASE || 'database',
  url: process.env.TYPEORM_URL || process.env.DATABASE_URL,
  synchronize: false, // Never use true in production
  logging: process.env.TYPEORM_LOGGING === 'true',
  entities: ['src/entities/**/*.ts'],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: ['src/subscribers/**/*.ts'],
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

export default dataSource;
`,
    'typeorm.config.ts': `import { DataSource } from 'typeorm';
import { config } from 'dotenv';

config();

// Alternative TypeORM configuration for CLI
export default new DataSource({
  type: (process.env.TYPEORM_CONNECTION as any) || 'postgres',
  host: process.env.TYPEORM_HOST || 'localhost',
  port: parseInt(process.env.TYPEORM_PORT || '5432'),
  username: process.env.TYPEORM_USERNAME || 'postgres',
  password: process.env.TYPEORM_PASSWORD || 'password',
  database: process.env.TYPEORM_DATABASE || 'database',
  url: process.env.TYPEORM_URL || process.env.DATABASE_URL,
  synchronize: process.env.NODE_ENV === 'development',
  logging: process.env.TYPEORM_LOGGING === 'true',
  entities: ['src/entities/**/*.ts'],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: ['src/subscribers/**/*.ts'],
});
`,
    // TypeORM Routes with Database Integration
    'src/routes/auth.typeorm.ts': `import { Router, Request, Response } from 'express';
import { body } from 'express-validator';
import { validate } from '../middleware/validation';
import { asyncWrapper } from '../utils/asyncWrapper';
import { generateToken, generateRefreshToken } from '../config/auth';
import { AppError } from '../utils/AppError';
import { UserService } from '../services/UserService.typeorm';
import { AppDataSource } from '../config/typeorm.config';

const router = Router();
const userService = new UserService();

// Initialize TypeORM connection
const initializeDatabase = async (): Promise<void> => {
  if (!AppDataSource.isInitialized) {
    await AppDataSource.initialize();
  }
};

// Register endpoint
router.post('/register',
  validate([
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('firstName').optional().isLength({ min: 1 }).withMessage('First name cannot be empty'),
    body('lastName').optional().isLength({ min: 1 }).withMessage('Last name cannot be empty'),
    body('role').optional().isIn(['user', 'admin', 'moderator']).withMessage('Invalid role')
  ]),
  asyncWrapper(async (req: Request, res: Response) => {
    await initializeDatabase();
    
    const { email, password, firstName, lastName, role } = req.body;

    // Create user using TypeORM service
    const user = await userService.createUser({
      email,
      password,
      firstName,
      lastName,
      role
    });

    // Generate tokens
    const token = generateToken({ 
      userId: user.id, 
      email: user.email, 
      role: user.role 
    });
    const refreshToken = generateRefreshToken({ 
      userId: user.id, 
      email: user.email, 
      role: user.role 
    });

    res.status(201).json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isActive: user.isActive,
          createdAt: user.createdAt
        },
        token,
        refreshToken
      }
    });
  })
);

// Login endpoint
router.post('/login',
  validate([
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required')
  ]),
  asyncWrapper(async (req: Request, res: Response) => {
    await initializeDatabase();
    
    const { email, password } = req.body;

    // Find user by email
    const user = await userService.findUserByEmail(email);
    if (!user) {
      throw new AppError('Invalid credentials', 401);
    }

    // Verify password using the User entity method
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      throw new AppError('Invalid credentials', 401);
    }

    // Update last login
    await userService.updateLastLogin(user.id);

    // Generate tokens
    const token = generateToken({ 
      userId: user.id, 
      email: user.email, 
      role: user.role 
    });
    const refreshToken = generateRefreshToken({ 
      userId: user.id, 
      email: user.email, 
      role: user.role 
    });

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          fullName: user.fullName,
          role: user.role,
          isActive: user.isActive,
          lastLoginAt: user.lastLoginAt
        },
        token,
        refreshToken
      }
    });
  })
);

// Password reset request
router.post('/forgot-password',
  validate([
    body('email').isEmail().normalizeEmail()
  ]),
  asyncWrapper(async (req: Request, res: Response) => {
    await initializeDatabase();
    
    const { email } = req.body;
    const user = await userService.findUserByEmail(email);
    
    if (!user) {
      // Don't reveal if user exists or not
      res.json({
        success: true,
        message: 'If a user with this email exists, a password reset link has been sent.'
      });
      return;
    }

    // In a real application, you would:
    // 1. Generate a secure password reset token
    // 2. Save it to the user record with an expiration time
    // 3. Send an email with the reset link
    
    // For demo purposes, we'll just return success
    res.json({
      success: true,
      message: 'Password reset instructions have been sent to your email.'
    });
  })
);

export { router as authTypeOrmRoutes };
`,
    'src/routes/users.typeorm.ts': `import { Router, Response } from 'express';
import { query, param, body } from 'express-validator';
import { authenticateToken, authorizeRoles, AuthenticatedRequest } from '../middleware/auth';
import { validate } from '../middleware/validation';
import { asyncWrapper } from '../utils/asyncWrapper';
import { UserService } from '../services/UserService.typeorm';
import { AppDataSource } from '../config/typeorm.config';
import { UserRole } from '../entities/User';

const router = Router();
const userService = new UserService();

// Initialize TypeORM connection
const initializeDatabase = async (): Promise<void> => {
  if (!AppDataSource.isInitialized) {
    await AppDataSource.initialize();
  }
};

// Get current user profile
router.get('/profile',
  authenticateToken,
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    await initializeDatabase();
    
    const user = await userService.findUserById(req.user!.userId);
    if (!user) {
      res.status(404).json({
        success: false,
        error: { message: 'User not found' }
      });
      return;
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          fullName: user.fullName,
          role: user.role,
          isActive: user.isActive,
          isEmailVerified: user.isEmailVerified,
          createdAt: user.createdAt,
          profile: user.profile
        }
      }
    });
  })
);

// Update current user profile
router.put('/profile',
  authenticateToken,
  validate([
    body('firstName').optional().isLength({ min: 1 }).withMessage('First name cannot be empty'),
    body('lastName').optional().isLength({ min: 1 }).withMessage('Last name cannot be empty'),
    body('email').optional().isEmail().normalizeEmail()
  ]),
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    await initializeDatabase();
    
    const { firstName, lastName, email } = req.body;
    const userId = req.user!.userId;

    const updatedUser = await userService.updateUser(userId, {
      firstName,
      lastName,
      email
    });

    res.json({
      success: true,
      data: {
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          fullName: updatedUser.fullName,
          role: updatedUser.role,
          updatedAt: updatedUser.updatedAt
        }
      }
    });
  })
);

// Get all users (admin only) with pagination and filtering
router.get('/',
  authenticateToken,
  authorizeRoles('admin'),
  validate([
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('role').optional().isIn(Object.values(UserRole)).withMessage('Invalid role'),
    query('isActive').optional().isBoolean().withMessage('isActive must be a boolean'),
    query('search').optional().isLength({ min: 1 }).withMessage('Search query cannot be empty')
  ]),
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    await initializeDatabase();
    
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const role = req.query.role as UserRole;
    const isActive = req.query.isActive === 'true' ? true : 
                    req.query.isActive === 'false' ? false : undefined;
    const search = req.query.search as string;

    let result;
    
    if (search) {
      // Use search functionality
      const users = await userService.searchUsers(search, limit);
      result = {
        users,
        total: users.length,
        page: 1,
        totalPages: 1
      };
    } else {
      // Use pagination with filters
      result = await userService.findAllUsers({
        page,
        limit,
        role,
        isActive
      });
    }

    res.json({
      success: true,
      data: {
        users: result.users.map(user => ({
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          fullName: user.fullName,
          role: user.role,
          isActive: user.isActive,
          isEmailVerified: user.isEmailVerified,
          lastLoginAt: user.lastLoginAt,
          createdAt: user.createdAt
        })),
        pagination: {
          page: result.page,
          limit,
          total: result.total,
          totalPages: result.totalPages
        }
      }
    });
  })
);

// Get user by ID (admin only)
router.get('/:id',
  authenticateToken,
  authorizeRoles('admin'),
  validate([
    param('id').isUUID().withMessage('Invalid user ID format')
  ]),
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    await initializeDatabase();
    
    const { id } = req.params;
    const user = await userService.findUserById(id);

    if (!user) {
      res.status(404).json({
        success: false,
        error: { message: 'User not found' }
      });
      return;
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          fullName: user.fullName,
          role: user.role,
          isActive: user.isActive,
          isEmailVerified: user.isEmailVerified,
          lastLoginAt: user.lastLoginAt,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          profile: user.profile,
          posts: user.posts?.map(post => ({
            id: post.id,
            title: post.title,
            slug: post.slug,
            status: post.status,
            category: post.category,
            publishedAt: post.publishedAt,
            createdAt: post.createdAt
          }))
        }
      }
    });
  })
);

// Update user (admin only)
router.put('/:id',
  authenticateToken,
  authorizeRoles('admin'),
  validate([
    param('id').isUUID().withMessage('Invalid user ID format'),
    body('firstName').optional().isLength({ min: 1 }).withMessage('First name cannot be empty'),
    body('lastName').optional().isLength({ min: 1 }).withMessage('Last name cannot be empty'),
    body('email').optional().isEmail().normalizeEmail(),
    body('role').optional().isIn(Object.values(UserRole)).withMessage('Invalid role'),
    body('isActive').optional().isBoolean().withMessage('isActive must be a boolean')
  ]),
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    await initializeDatabase();
    
    const { id } = req.params;
    const updateData = req.body;

    const updatedUser = await userService.updateUser(id, updateData);

    res.json({
      success: true,
      data: {
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          fullName: updatedUser.fullName,
          role: updatedUser.role,
          isActive: updatedUser.isActive,
          updatedAt: updatedUser.updatedAt
        }
      }
    });
  })
);

// Delete user (admin only)
router.delete('/:id',
  authenticateToken,
  authorizeRoles('admin'),
  validate([
    param('id').isUUID().withMessage('Invalid user ID format')
  ]),
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    await initializeDatabase();
    
    const { id } = req.params;
    
    // Prevent admin from deleting themselves
    if (id === req.user!.userId) {
      res.status(400).json({
        success: false,
        error: { message: 'You cannot delete your own account' }
      });
      return;
    }

    await userService.deleteUser(id);

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  })
);

// Get user statistics (admin only)
router.get('/admin/stats',
  authenticateToken,
  authorizeRoles('admin'),
  asyncWrapper(async (req: AuthenticatedRequest, res: Response) => {
    await initializeDatabase();
    
    const stats = await userService.getUserStats();

    res.json({
      success: true,
      data: {
        stats
      }
    });
  })
);

export { router as userTypeOrmRoutes };
`,
    // Prisma Integration Files (for comparison)
    'prisma/schema.prisma': `// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id                    String    @id @default(cuid())
  email                 String    @unique
  password              String
  firstName             String?
  lastName              String?
  role                  Role      @default(USER)
  isActive              Boolean   @default(true)
  isEmailVerified       Boolean   @default(false)
  emailVerificationToken String?
  passwordResetToken     String?
  passwordResetExpires   DateTime?
  lastLoginAt           DateTime?
  createdAt             DateTime  @default(now())
  updatedAt             DateTime  @updatedAt

  profile Profile?
  posts   Post[]

  @@map("users")
}

model Profile {
  id            String   @id @default(cuid())
  avatar        String?
  bio           String?  @db.Text
  location      String?
  website       String?
  phone         String?
  birthDate     DateTime?
  company       String?
  jobTitle      String?
  socialLinks   Json?
  preferences   Json?
  createdAt     DateTime @default(now())
  updatedAt     DateTime @updatedAt

  user   User   @relation(fields: [userId], references: [id], onDelete: Cascade)
  userId String @unique

  @@map("profiles")
}

model Post {
  id           String      @id @default(cuid())
  title        String
  excerpt      String?
  content      String      @db.Text
  slug         String?     @unique
  status       PostStatus  @default(DRAFT)
  category     PostCategory @default(OTHER)
  tags         String[]
  featuredImage String?
  isFeatured   Boolean     @default(false)
  allowComments Boolean    @default(true)
  viewCount    Int         @default(0)
  likeCount    Int         @default(0)
  commentCount Int         @default(0)
  metadata     Json?
  publishedAt  DateTime?
  createdAt    DateTime    @default(now())
  updatedAt    DateTime    @updatedAt

  author   User   @relation(fields: [authorId], references: [id], onDelete: Cascade)
  authorId String

  @@index([status, publishedAt])
  @@index([authorId, status])
  @@index([category, status])
  @@map("posts")
}

enum Role {
  USER
  ADMIN
  MODERATOR
}

enum PostStatus {
  DRAFT
  PUBLISHED
  ARCHIVED
}

enum PostCategory {
  TECHNOLOGY
  LIFESTYLE
  BUSINESS
  EDUCATION
  ENTERTAINMENT
  OTHER
}
`,
    'prisma/seed.ts': `import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Clear existing data (be careful in production!)
  if (process.env.NODE_ENV === 'development') {
    await prisma.post.deleteMany();
    await prisma.profile.deleteMany();
    await prisma.user.deleteMany();
    console.log('🧹 Cleared existing data');
  }

  // Hash passwords
  const adminPassword = await bcrypt.hash('AdminPassword123!', 12);
  const userPassword = await bcrypt.hash('UserPassword123!', 12);

  // Create admin user
  const adminUser = await prisma.user.create({
    data: {
      email: 'admin@example.com',
      password: adminPassword,
      firstName: 'Admin',
      lastName: 'User',
      role: 'ADMIN',
      isActive: true,
      isEmailVerified: true,
      profile: {
        create: {
          bio: 'System administrator with full access rights.',
          location: 'San Francisco, CA',
          company: 'Tech Corp',
          jobTitle: 'System Administrator',
          preferences: {
            theme: 'dark',
            language: 'en',
            timezone: 'America/Los_Angeles',
            emailNotifications: true,
            pushNotifications: true
          },
          socialLinks: {
            linkedin: 'https://linkedin.com/in/admin',
            github: 'https://github.com/admin'
          }
        }
      }
    }
  });

  // Create regular users
  const users = [];
  for (let i = 1; i <= 5; i++) {
    const user = await prisma.user.create({
      data: {
        email: \`user\${i}@example.com\`,
        password: userPassword,
        firstName: 'User',
        lastName: \`\${i}\`,
        role: 'USER',
        isActive: true,
        isEmailVerified: i % 2 === 0,
        profile: {
          create: {
            bio: \`This is user \${i}'s bio. I'm passionate about technology and innovation.\`,
            location: ['New York, NY', 'Los Angeles, CA', 'Chicago, IL', 'Houston, TX', 'Phoenix, AZ'][i - 1],
            preferences: {
              theme: i % 2 === 0 ? 'dark' : 'light',
              language: 'en',
              timezone: 'America/New_York',
              emailNotifications: true,
              pushNotifications: i % 2 === 0
            }
          }
        }
      }
    });
    users.push(user);
  }

  // Create sample posts
  const categories = ['TECHNOLOGY', 'LIFESTYLE', 'BUSINESS', 'EDUCATION', 'ENTERTAINMENT', 'OTHER'];
  const sampleTitles = [
    'Getting Started with Prisma',
    'Building RESTful APIs with Express',
    'Modern JavaScript Best Practices',
    'Database Design Principles',
    'Authentication and Security'
  ];

  const allUsers = [adminUser, ...users];

  for (let i = 0; i < 10; i++) {
    const randomUser = allUsers[Math.floor(Math.random() * allUsers.length)];
    const randomTitle = sampleTitles[Math.floor(Math.random() * sampleTitles.length)];
    
    await prisma.post.create({
      data: {
        title: \`\${randomTitle} - Part \${i + 1}\`,
        excerpt: \`This is an excerpt for the post about \${randomTitle.toLowerCase()}.\`,
        content: \`This is the full content for \${randomTitle}...\`,
        slug: \`\${randomTitle.toLowerCase().replace(/\s+/g, '-')}-part-\${i + 1}\`,
        status: i % 3 === 0 ? 'DRAFT' : 'PUBLISHED',
        category: categories[Math.floor(Math.random() * categories.length)] as any,
        tags: ['tutorial', 'beginner'],
        authorId: randomUser.id,
        publishedAt: i % 3 !== 0 ? new Date() : null,
        viewCount: Math.floor(Math.random() * 1000),
        likeCount: Math.floor(Math.random() * 50)
      }
    });
  }

  console.log('✅ Database seeded successfully!');
  console.log(\`Created:
    - 1 admin user (admin@example.com / AdminPassword123!)
    - 5 regular users (user1@example.com to user5@example.com / UserPassword123!)
    - 6 user profiles
    - 10 sample posts\`);
}

main()
  .catch((e) => {
    console.error('❌ Error seeding database:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
`,
    '.env.example': `# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=7d
REFRESH_TOKEN_EXPIRES_IN=30d

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Logging Configuration
LOG_LEVEL=info

# Database Configuration
# Choose one ORM and configure accordingly:

# Prisma Database URL
DATABASE_URL=postgresql://username:password@localhost:5432/database_name

# TypeORM Database Configuration
TYPEORM_CONNECTION=postgres
TYPEORM_HOST=localhost
TYPEORM_PORT=5432
TYPEORM_USERNAME=username
TYPEORM_PASSWORD=password
TYPEORM_DATABASE=database_name
TYPEORM_SYNCHRONIZE=false
TYPEORM_LOGGING=true
TYPEORM_ENTITIES=src/entities/**/*.ts
TYPEORM_MIGRATIONS=src/migrations/**/*.ts
TYPEORM_SUBSCRIBERS=src/subscribers/**/*.ts

# Alternative: Use DATABASE_URL for TypeORM as well
# TYPEORM_URL=postgresql://username:password@localhost:5432/database_name
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
    'README.md': `# {{projectName}}

A modern Express.js API server with TypeScript, JWT authentication, and comprehensive middleware.

## Features

- 🚀 **Express.js + TypeScript** - Modern web framework with type safety
- 🔐 **JWT Authentication** - Secure token-based authentication
- 🛡️ **Security Middleware** - Helmet, CORS, rate limiting
- 📝 **Logging** - Winston logger with file rotation
- ✅ **Validation** - Express-validator for input validation
- 🧪 **Testing** - Jest with TypeScript support
- 📦 **Hot Reload** - Nodemon for development
- 🔧 **Code Quality** - ESLint, Prettier, TypeScript strict mode

- **🗄️ Database Integration**: Choose between Prisma ORM or TypeORM with PostgreSQL, MySQL, SQLite support
- **🎯 Flexible ORM Options**: Complete implementations for both Prisma and TypeORM with entity relationships

## ORM Options

This template provides complete implementations for both popular Node.js ORMs:

### Prisma ORM
- **Schema-first approach** with `prisma/schema.prisma`
- **Type-safe client** with auto-generated types
- **Migrations** with `prisma migrate`
- **Database introspection** and visual studio
- **Files**: `prisma/schema.prisma`, `prisma/seed.ts`

### TypeORM
- **Entity-first approach** with decorators
- **Class-based entities** with validation
- **Advanced querying** with QueryBuilder
- **Automatic migrations** and schema sync
- **Files**: `src/entities/*.ts`, `src/config/typeorm.config.ts`, `src/services/UserService.typeorm.ts`

Choose the ORM that best fits your project needs. Both implementations include:
- User authentication and authorization
- Entity relationships (User ↔ Profile ↔ Posts)
- Input validation and error handling
- Comprehensive CRUD operations
- Database seeding with sample data

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

3. **Choose and set up your ORM:**

   **Option A: Using Prisma (Recommended for beginners)**
   \`\`\`bash
   # Generate Prisma client
   npm run db:generate
   
   # Create and run initial migration
   npm run db:migrate
   
   # Seed the database
   npm run db:seed
   \`\`\`

   **Option B: Using TypeORM**
   \`\`\`bash
   # Update src/index.ts to import TypeORM routes
   # Replace auth and user routes with TypeORM versions
   
   # Run database synchronization (development only)
   npm run typeorm:schema:sync
   
   # Seed the database
   npm run typeorm:seed
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

### Health Check
- \`GET /api/health\` - Basic health check
- \`GET /api/health/detailed\` - Detailed system information

### Authentication
- \`POST /api/auth/register\` - Register new user
- \`POST /api/auth/login\` - Login user

### Users
- \`GET /api/users/profile\` - Get current user profile (requires auth)
- \`GET /api/users\` - Get all users (admin only)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`PORT\` | Server port | \`3000\` |
| \`NODE_ENV\` | Environment | \`development\` |
| \`JWT_SECRET\` | JWT secret key | \`your-super-secret-jwt-key\` |
| \`JWT_EXPIRES_IN\` | JWT expiration | \`7d\` |
| \`REFRESH_TOKEN_EXPIRES_IN\` | Refresh token expiration | \`30d\` |
| \`ALLOWED_ORIGINS\` | CORS allowed origins | \`*\` |
| \`LOG_LEVEL\` | Logging level | \`info\` |

## Database Setup

### Environment Variables

Update your `.env` file with the appropriate database configuration:

\`\`\`env
# For PostgreSQL
DATABASE_URL="postgresql://username:password@localhost:5432/mydb"
TYPEORM_CONNECTION=postgres
TYPEORM_HOST=localhost
TYPEORM_PORT=5432
TYPEORM_USERNAME=username
TYPEORM_PASSWORD=password
TYPEORM_DATABASE=mydb

# For MySQL
DATABASE_URL="mysql://username:password@localhost:3306/mydb"
TYPEORM_CONNECTION=mysql

# For SQLite
DATABASE_URL="file:./dev.db"
TYPEORM_CONNECTION=sqlite
TYPEORM_DATABASE=./dev.db
\`\`\`

### Using Prisma

1. **Setup database:**
   \`\`\`bash
   npm run db:generate    # Generate Prisma client
   npm run db:push        # Push schema to database
   npm run db:migrate     # Create migration files
   npm run db:seed        # Seed with sample data
   npm run db:studio      # Open Prisma Studio
   \`\`\`

2. **Update schema:** Edit \`prisma/schema.prisma\` and run migrations

### Using TypeORM

1. **Setup database:**
   \`\`\`bash
   npm run typeorm:schema:sync    # Sync schema (dev only)
   npm run typeorm:seed           # Seed with sample data
   \`\`\`

2. **Migrations:**
   \`\`\`bash
   npm run typeorm:migration:generate  # Generate migration
   npm run typeorm:migration:run       # Run migrations
   npm run typeorm:migration:revert    # Revert last migration
   \`\`\`

3. **Update entities:** Edit files in \`src/entities/\` and run migrations

### Switching Between ORMs

To switch from default Prisma routes to TypeORM routes, update \`src/index.ts\`:

\`\`\`typescript
// Replace these imports:
import { authRoutes } from './routes/auth';
import { userRoutes } from './routes/users';

// With these:
import { authTypeOrmRoutes as authRoutes } from './routes/auth.typeorm';
import { userTypeOrmRoutes as userRoutes } from './routes/users.typeorm';
\`\`\`

## Scripts

### General Scripts
- \`npm run dev\` - Start development server with hot reload
- \`npm run build\` - Build for production
- \`npm start\` - Start production server
- \`npm test\` - Run tests
- \`npm run test:watch\` - Run tests in watch mode
- \`npm run test:coverage\` - Run tests with coverage
- \`npm run lint\` - Run ESLint
- \`npm run lint:fix\` - Fix ESLint issues
- \`npm run format\` - Format code with Prettier

### Database Scripts (Prisma)
- \`npm run db:generate\` - Generate Prisma client
- \`npm run db:push\` - Push schema changes to database
- \`npm run db:migrate\` - Create and run migration
- \`npm run db:studio\` - Open Prisma Studio
- \`npm run db:seed\` - Seed database with sample data

### Database Scripts (TypeORM)
- \`npm run typeorm:migration:generate\` - Generate migration
- \`npm run typeorm:migration:run\` - Run pending migrations
- \`npm run typeorm:migration:revert\` - Revert last migration
- \`npm run typeorm:schema:sync\` - Sync schema (development only)
- \`npm run typeorm:schema:drop\` - Drop all tables
- \`npm run typeorm:seed\` - Seed database with sample data

## Project Structure

\`\`\`
src/
├── config/          # Configuration files
│   ├── auth.ts      # JWT configuration
│   ├── logger.ts    # Winston logger setup
│   └── typeorm.config.ts  # TypeORM configuration
├── entities/        # TypeORM entities
│   ├── User.ts      # User entity with relations
│   ├── Profile.ts   # Profile entity
│   └── Post.ts      # Post entity
├── middleware/      # Express middleware
│   ├── auth.ts      # Authentication middleware
│   ├── errorHandler.ts
│   ├── notFoundHandler.ts
│   └── validation.ts
├── routes/          # API routes
│   ├── auth.ts      # Prisma authentication routes
│   ├── auth.typeorm.ts    # TypeORM authentication routes
│   ├── health.ts    # Health check routes
│   ├── users.ts     # Prisma user routes
│   └── users.typeorm.ts   # TypeORM user routes
├── services/        # Business logic services
│   └── UserService.typeorm.ts  # TypeORM user service
├── seeds/           # Database seeding
│   └── seed.ts      # TypeORM seed script
├── migrations/      # TypeORM migrations (auto-generated)
├── utils/           # Utility functions
│   ├── AppError.ts  # Custom error class
│   ├── asyncWrapper.ts
│   └── passwordUtils.ts
└── index.ts         # Application entry point

prisma/              # Prisma ORM files
├── schema.prisma    # Prisma schema definition
├── seed.ts          # Prisma seed script
└── migrations/      # Prisma migrations (auto-generated)
\`\`\`

## Security Features

- **Helmet.js** - Sets various HTTP headers
- **CORS** - Cross-Origin Resource Sharing
- **Rate Limiting** - Prevents abuse
- **JWT Authentication** - Secure token-based auth
- **Password Hashing** - bcrypt with salt rounds
- **Input Validation** - express-validator
- **Error Handling** - Centralized error management

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

## Development

### Adding New Routes

1. Create route file in \`src/routes/\`
2. Import and use in \`src/index.ts\`
3. Add authentication/authorization as needed

### Adding Middleware

1. Create middleware in \`src/middleware/\`
2. Export and use in routes or globally

### Environment Setup

1. Copy \`.env.example\` to \`.env\`
2. Update variables for your environment
3. Never commit \`.env\` files

## Production Deployment

1. Set \`NODE_ENV=production\`
2. Use a strong \`JWT_SECRET\`
3. Configure proper CORS origins
4. Set up log rotation
5. Use a process manager like PM2
6. Configure reverse proxy (nginx)
7. Set up SSL/TLS certificates

## License

MIT
`,
    'Dockerfile': `# Multi-stage build for Express.js TypeScript application
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
    adduser -S express -u 1001

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder --chown=express:nodejs /app/dist ./dist

# Create logs directory
RUN mkdir -p logs && chown express:nodejs logs

# Switch to non-root user
USER express

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
      - JWT_SECRET=your-production-jwt-secret
      - LOG_LEVEL=info
    volumes:
      - ./logs:/app/logs
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

volumes:
  redis-data:

networks:
  app-network:
    driver: bridge
`,
    'jest.config.js': `module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
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
};
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
        '@typescript-eslint/explicit-function-return-type': 'warn',
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
    'nodemon.json': {
      watch: ['src'],
      ext: 'ts',
      ignore: ['src/**/*.test.ts'],
      exec: 'ts-node src/index.ts'
    }
  },
  prompts: [
    {
      type: 'input',
      name: 'projectName',
      message: 'What is your project name?',
      default: 'express-api'
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
      message: 'Include database integration?',
      default: true
    },
    {
      type: 'list',
      name: 'orm',
      message: 'Which ORM would you like to use?',
      choices: [
        { name: 'Prisma (Recommended for beginners)', value: 'prisma' },
        { name: 'TypeORM (Advanced features)', value: 'typeorm' },
        { name: 'Both (Full comparison)', value: 'both' }
      ],
      when: (answers) => answers.includeDatabase,
      default: 'prisma'
    },
    {
      type: 'list',
      name: 'database',
      message: 'Which database would you like to use?',
      choices: ['PostgreSQL', 'MySQL', 'SQLite'],
      when: (answers) => answers.includeDatabase,
      default: 'PostgreSQL'
    }
  ],
  postInstall: [
    'npm install',
    'mkdir -p logs',
    'cp .env.example .env',
    'echo "✅ Express.js TypeScript template created successfully!"',
    'echo ""',
    'echo "🗄️  DATABASE SETUP - Choose one ORM:"',
    'echo ""',
    'echo "📋 Option A: Prisma ORM (Recommended for beginners)"',
    'echo "1. Set DATABASE_URL in .env"',
    'echo "2. Run: npm run db:generate"',
    'echo "3. Run: npm run db:push"',
    'echo "4. Run: npm run db:seed"',
    'echo ""',
    'echo "📋 Option B: TypeORM (Advanced users)"',
    'echo "1. Set TYPEORM_* variables in .env"',
    'echo "2. Update src/index.ts to use TypeORM routes"',
    'echo "3. Run: npm run typeorm:schema:sync"',
    'echo "4. Run: npm run typeorm:seed"',
    'echo ""',
    'echo "📝 Next steps:"',
    'echo "   1. Update .env with your database configuration"',
    'echo "   2. Choose and set up your preferred ORM (see above)"',
    'echo "   3. Run \'npm run dev\' to start development"',
    'echo "   4. Visit http://localhost:3000/api/health"',
    'echo ""',
    'echo "📚 View README.md for detailed setup instructions"'
  ]
};