import { BackendTemplateGenerator, BackendTemplateConfig, DockerConfig } from '../shared/backend-template-generator';
import * as path from 'path';
import { promises as fs } from 'fs';

export abstract class NodeBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Node.js',
      framework: framework,
      packageManager: 'npm',
      buildTool: 'npm',
      testFramework: 'jest',
      features: [
        'JWT Authentication',
        'TypeScript Support',
        'PostgreSQL Database',
        'Redis Cache',
        'Docker Support',
        'API Documentation',
        'Real-time WebSocket',
        'File Upload Support',
        'Email Service',
        'Rate Limiting',
        'Comprehensive Testing'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        dev: 'tsx watch src/index.ts',
        build: 'tsc',
        start: 'node dist/index.js',
        test: 'jest',
        lint: 'eslint src --ext .ts'
      },
      dockerConfig: {
        baseImage: 'node:20-alpine',
        workDir: '/app',
        exposedPorts: [3000],
        buildSteps: ['npm ci', 'npm run build'],
        runCommand: 'node dist/index.js',
        multistage: true
      }
    };
    super(config);
  }
  
  // Framework-specific abstract methods
  protected abstract getFrameworkDependencies(): Record<string, string>;
  protected abstract getFrameworkDevDependencies(): Record<string, string>;
  protected abstract generateMainFile(): string;
  protected abstract generateRoutingFiles(): { path: string; content: string }[];
  protected abstract generateControllerFiles(): { path: string; content: string }[];
  protected abstract generateServiceFiles(): { path: string; content: string }[];
  protected abstract generateMiddlewareFiles(): { path: string; content: string }[];
  protected abstract generateConfigFiles(): { path: string; content: string }[];
  protected abstract generateUtilFiles(): { path: string; content: string }[];
  
  // Implementation of required abstract methods from BackendTemplateGenerator
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    this.options = options;
    
    // Generate package.json
    await this.writeFile(path.join(projectPath, 'package.json'), this.generatePackageJson());
    
    // Generate TypeScript configuration
    await this.writeFile(path.join(projectPath, 'tsconfig.json'), this.generateTsConfig());
    
    // Generate environment file
    await this.writeFile(path.join(projectPath, '.env.example'), this.generateEnvironmentFile());
    
    // Generate Jest configuration
    await this.writeFile(path.join(projectPath, 'jest.config.js'), this.generateJestConfig());
    
    // Generate Prisma schema
    await this.writeFile(path.join(projectPath, 'prisma/schema.prisma'), this.generatePrismaSchema());
  }
  
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application file
    await this.writeFile(path.join(projectPath, 'src/index.ts'), this.generateMainFile());
    
    // Generate routing files
    const routingFiles = this.generateRoutingFiles();
    for (const file of routingFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate controller files
    const controllerFiles = this.generateControllerFiles();
    for (const file of controllerFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate service files
    const serviceFiles = this.generateServiceFiles();
    for (const file of serviceFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate middleware files
    const middlewareFiles = this.generateMiddlewareFiles();
    for (const file of middlewareFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate config files
    const configFiles = this.generateConfigFiles();
    for (const file of configFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate utility files
    const utilFiles = this.generateUtilFiles();
    for (const file of utilFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
  }
  
  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Create test directories
    await fs.mkdir(path.join(projectPath, 'src/__tests__'), { recursive: true });
    
    // Generate test setup file
    await this.writeFile(
      path.join(projectPath, 'src/__tests__/setup.ts'),
      this.generateTestSetup()
    );
    
    // Generate example test file
    await this.writeFile(
      path.join(projectPath, 'src/__tests__/auth.test.ts'),
      this.generateAuthTest()
    );
  }
  
  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is included in the main index.ts file
    // No separate file needed for Node.js/Express
  }
  
  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs configuration is included in config files
    // No separate generation needed as it's handled in generateConfigFiles
  }
  
  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    await this.writeFile(path.join(projectPath, 'Dockerfile'), this.generateDockerfile());
    await this.writeFile(path.join(projectPath, 'docker-compose.yml'), this.generateDockerCompose());
  }
  
  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    await this.writeFile(path.join(projectPath, 'README.md'), this.generateReadmeContent());
  }
  
  // Helper method implementations
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      'node_modules/',
      'dist/',
      'build/',
      '*.log',
      '.env',
      'coverage/',
      '.nyc_output/',
      '.cache/',
      'uploads/',
      'logs/'
    ];
  }
  
  protected getLanguagePrerequisites(): string {
    return 'Node.js 20+ and npm';
  }
  
  protected getInstallCommand(): string {
    return 'npm install';
  }
  
  protected getDevCommand(): string {
    return 'npm run dev';
  }
  
  protected getProdCommand(): string {
    return 'npm start';
  }
  
  protected getTestCommand(): string {
    return 'npm test';
  }
  
  protected getCoverageCommand(): string {
    return 'npm run test:coverage';
  }
  
  protected getLintCommand(): string {
    return 'npm run lint';
  }
  
  protected getBuildCommand(): string {
    return 'npm run build';
  }
  
  protected getSetupAction(): string {
    return 'npm install && npm run build';
  }
  
  protected generatePackageJson(): string {
    const dependencies = this.getFrameworkDependencies();
    const devDependencies = this.getFrameworkDevDependencies();
    
    const deps = Object.entries(dependencies)
      .map(([name, version]) => `    "${name}": "${version}"`)
      .join(',\n');
      
    const devDeps = Object.entries(devDependencies)
      .map(([name, version]) => `    "${name}": "${version}"`)
      .join(',\n');

    return `{
  "name": "${this.options.name}",
  "version": "1.0.0",
  "description": "${this.config.framework} API server with TypeScript",
  "main": "dist/index.js",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "lint": "eslint src --ext .ts",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "typecheck": "tsc --noEmit",
    "format": "prettier --write .",
    "docker:build": "docker build -t ${this.options.name} .",
    "docker:run": "docker run -p 3000:3000 ${this.options.name}"
  },
  "dependencies": {
${deps}
  },
  "devDependencies": {
${devDeps}
  }
}`;
  }
  
  protected generateTsConfig(): string {
    return `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": true,
    "noEmitOnError": true,
    "allowSyntheticDefaultImports": true,
    "moduleResolution": "node",
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@config/*": ["src/config/*"],
      "@controllers/*": ["src/controllers/*"],
      "@middlewares/*": ["src/middlewares/*"],
      "@models/*": ["src/models/*"],
      "@routes/*": ["src/routes/*"],
      "@services/*": ["src/services/*"],
      "@utils/*": ["src/utils/*"],
      "@types/*": ["src/types/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "coverage"]
}`;
  }
  
  protected generateEnvironmentFile(): string {
    return `# Application
NODE_ENV=development
PORT=3000
API_URL=http://localhost:3000

# Database
DATABASE_URL="postgresql://user:password@localhost:5432/dbname"

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRE=7d

# CORS
CORS_ORIGIN=http://localhost:3000,http://localhost:5173

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
EMAIL_FROM=noreply@example.com

# File Upload
UPLOAD_DIR=uploads
MAX_FILE_SIZE=10485760

# Logging
LOG_DIR=logs
LOG_LEVEL=debug

# Client
CLIENT_URL=http://localhost:3000`;
  }
  
  protected generateDockerfile(): string {
    return `# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src
COPY prisma ./prisma

# Generate Prisma client
RUN npx prisma generate

# Build application
RUN npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

# Install dumb-init
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && npm cache clean --force

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

# Copy Prisma schema
COPY prisma ./prisma

# Change ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD node -e "require('http').get('http://localhost:3000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1); })"

# Start application
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]`;
  }
  
  protected generatePrismaSchema(): string {
    return `generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id                String    @id @default(cuid())
  email             String    @unique
  password          String
  name              String
  role              Role      @default(USER)
  avatar            String?
  isEmailVerified   Boolean   @default(false)
  verificationToken String?
  resetToken        String?
  resetTokenExpiry  DateTime?
  refreshTokens     String[]
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt
  
  todos             Todo[]
  
  @@index([email])
}

model Todo {
  id          String       @id @default(cuid())
  title       String
  description String?
  status      TodoStatus   @default(PENDING)
  priority    TodoPriority @default(MEDIUM)
  dueDate     DateTime?
  userId      String
  user        User         @relation(fields: [userId], references: [id], onDelete: Cascade)
  createdAt   DateTime     @default(now())
  updatedAt   DateTime     @updatedAt
  
  @@index([userId])
  @@index([status])
  @@index([priority])
}

enum Role {
  USER
  ADMIN
}

enum TodoStatus {
  PENDING
  IN_PROGRESS
  COMPLETED
}

enum TodoPriority {
  LOW
  MEDIUM
  HIGH
}`;
  }
  
  protected generateJestConfig(): string {
    return `module.exports = {
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
    '!src/**/*.spec.ts',
    '!src/**/*.test.ts',
    '!src/__tests__/**',
    '!src/index.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@config/(.*)$': '<rootDir>/src/config/$1',
    '^@controllers/(.*)$': '<rootDir>/src/controllers/$1',
    '^@middlewares/(.*)$': '<rootDir>/src/middlewares/$1',
    '^@models/(.*)$': '<rootDir>/src/models/$1',
    '^@routes/(.*)$': '<rootDir>/src/routes/$1',
    '^@services/(.*)$': '<rootDir>/src/services/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@types/(.*)$': '<rootDir>/src/types/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup.ts'],
  testTimeout: 10000,
};`;
  }
  
  protected generateReadmeContent(): string {
    return `# ${this.options.name}

${this.config.framework} API server built with TypeScript, featuring authentication, real-time updates, and comprehensive testing.

## Features

- 🚀 **${this.config.framework}** with TypeScript
- 🔐 **JWT Authentication** with refresh tokens
- 🗄️ **PostgreSQL** database with Prisma ORM
- 🚦 **Redis** for caching and rate limiting
- 🔄 **Real-time updates** with Socket.IO
- 📚 **API Documentation** with Swagger/OpenAPI
- 🧪 **Testing** with Jest and Supertest
- 🐳 **Docker** support with multi-stage builds
- 📊 **Logging** with Winston
- 🛡️ **Security** with Helmet, CORS, and rate limiting
- 📤 **File uploads** with Multer
- ✉️ **Email** support
- 🔄 **Hot reload** in development

## Getting Started

### Prerequisites

- Node.js 20+
- PostgreSQL
- Redis
- Docker (optional)

### Installation

1. Clone the repository
2. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

3. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   \`\`\`

4. Set up the database:
   \`\`\`bash
   npx prisma migrate dev
   \`\`\`

5. Start the development server:
   \`\`\`bash
   npm run dev
   \`\`\`

### Running with Docker

\`\`\`bash
docker-compose up
\`\`\`

## API Documentation

Once the server is running, visit:
- Swagger UI: http://localhost:3000/api-docs
- OpenAPI JSON: http://localhost:3000/api-docs.json

## Testing

\`\`\`bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
\`\`\`

## Scripts

- \`npm run dev\` - Start development server with hot reload
- \`npm run build\` - Build for production
- \`npm start\` - Start production server
- \`npm run lint\` - Run ESLint
- \`npm test\` - Run tests
- \`npm run typecheck\` - Type check without building

## Project Structure

\`\`\`
src/
├── config/         # Configuration files
├── controllers/    # Route controllers
├── middlewares/    # Express middlewares
├── models/         # Data models
├── routes/         # API routes
├── services/       # Business logic
├── types/          # TypeScript types
├── utils/          # Utility functions
└── index.ts        # Application entry point
\`\`\`

## License

MIT`;
  }
  
  protected generateDockerCompose(): string {
    return `version: '3.8'

services:
  app:
    build: .
    container_name: ${this.options.name}-api
    ports:
      - "\${PORT:-3000}:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://\${DB_USER}:\${DB_PASSWORD}@postgres:5432/\${DB_NAME}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    networks:
      - app-network

  postgres:
    image: postgres:16-alpine
    container_name: ${this.options.name}-db
    environment:
      - POSTGRES_USER=\${DB_USER:-user}
      - POSTGRES_PASSWORD=\${DB_PASSWORD:-password}
      - POSTGRES_DB=\${DB_NAME:-${this.options.name}}
    ports:
      - "\${DB_PORT:-5432}:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped
    networks:
      - app-network

  redis:
    image: redis:7-alpine
    container_name: ${this.options.name}-redis
    command: redis-server --appendonly yes
    ports:
      - "\${REDIS_PORT:-6379}:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
    networks:
      - app-network

volumes:
  postgres-data:
  redis-data:

networks:
  app-network:
    driver: bridge`;
  }
  
  protected generateTestSetup(): string {
    return `import { prisma } from '../config/database';

beforeAll(async () => {
  // Connect to test database
  await prisma.$connect();
});

afterAll(async () => {
  // Clean up and disconnect
  await prisma.$disconnect();
});

afterEach(async () => {
  // Clean up test data after each test
  const tablenames = await prisma.$queryRaw\`
    SELECT tablename FROM pg_tables WHERE schemaname='public';
  \` as Array<{ tablename: string }>;

  for (const { tablename } of tablenames) {
    if (tablename !== '_prisma_migrations') {
      try {
        await prisma.$executeRawUnsafe(\`TRUNCATE TABLE "\${tablename}" CASCADE;\`);
      } catch (error) {
        console.log({ error });
      }
    }
  }
});`;
  }
  
  protected generateAuthTest(): string {
    return `import request from 'supertest';
import { app } from '../index';
import { prisma } from '../config/database';

describe('Authentication', () => {
  describe('POST /api/v1/auth/register', () => {
    it('should register a new user', async () => {
      const userData = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(userData.email);
      expect(response.body.data.accessToken).toBeDefined();
    });

    it('should not register user with invalid email', async () => {
      const userData = {
        name: 'Test User',
        email: 'invalid-email',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/v1/auth/login', () => {
    beforeEach(async () => {
      // Create a test user
      await request(app)
        .post('/api/v1/auth/register')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password: 'password123'
        });
    });

    it('should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123'
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
    });

    it('should not login with invalid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword'
        })
        .expect(500);

      expect(response.body.success).toBe(false);
    });
  });
});`;
  }
  
  protected async writeFile(filePath: string, content: string): Promise<void> {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, 'utf-8');
  }
}