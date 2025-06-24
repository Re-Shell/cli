import { BackendTemplate } from '../types';

export const expressTypeScriptTemplate: BackendTemplate = {
  id: 'express-ts',
  name: 'Express.js + TypeScript',
  description: 'Modern Express.js API server with TypeScript, middleware, error handling, and JWT authentication',
  framework: 'express',
  language: 'typescript',
  version: '1.0.0',
  tags: ['express', 'typescript', 'jwt', 'middleware', 'rest-api'],
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
    nodemon: '^3.0.2'
      '@prisma/client': '^5.8.1',
      'bcrypt': '^5.1.1',
      'uuid': '^9.0.1',
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
    prettier: '^3.1.1'
      'prisma': '^5.8.1',
      '@types/bcrypt': '^5.0.2',
      '@types/uuid': '^9.0.7',
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
        format: 'prettier --write "src/**/*.ts"'
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
    'src/index.ts': `import express from 'express';
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

4. **Build for production:**
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

## Project Structure

\`\`\`
src/
├── config/          # Configuration files
│   ├── auth.ts      # JWT configuration
│   └── logger.ts    # Winston logger setup
├── middleware/      # Express middleware
│   ├── auth.ts      # Authentication middleware
│   ├── errorHandler.ts
│   ├── notFoundHandler.ts
│   └── validation.ts
├── routes/          # API routes
│   ├── auth.ts      # Authentication routes
│   ├── health.ts    # Health check routes
│   └── users.ts     # User routes
├── utils/           # Utility functions
│   ├── AppError.ts  # Custom error class
│   ├── asyncWrapper.ts
│   └── passwordUtils.ts
└── index.ts         # Application entry point
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
    }
  ],
  postInstall: [
    'npm install',
    'mkdir -p logs',
    'cp .env.example .env',
    'echo "✅ Express.js TypeScript template created successfully!"',
    'echo "📝 Don\'t forget to:"',
    'echo "   1. Update .env with your configuration"',
    'echo "   2. Run \'npm run dev\' to start development"',
    'echo "   3. Visit http://localhost:3000/api/health"'
      'npx prisma generate',
    'echo "📋 Database setup:"',
    'echo "1. Set DATABASE_URL in .env"',
    'echo "2. Run: npm run db:push"',
    'echo "3. Run: npm run db:seed"',]
};