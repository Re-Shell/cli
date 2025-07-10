import { BackendTemplate } from '../types';

export const moleculerTemplate: BackendTemplate = {
  id: 'moleculer',
  name: 'Moleculer',
  displayName: 'Moleculer',
  description: 'Fast & powerful microservices framework with built-in service discovery, load balancing, and fault tolerance',
  language: 'typescript',
  framework: 'moleculer',
  version: '0.14.0',
  tags: ['microservices', 'distributed', 'fault-tolerant'],
  port: 3000,
  dependencies: {},
  features: ['microservices', 'service-discovery', 'load-balancing', 'fault-tolerance'],
  
  files: {
    'package.json': `{
  "name": "moleculer-microservices",
  "version": "1.0.0",
  "description": "Moleculer-based microservices with TypeScript",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc",
    "dev": "ts-node-dev --respawn --transpile-only src/index.ts",
    "start": "node dist/index.js",
    "start:services": "concurrently \\"npm run service:api\\" \\"npm run service:greeter\\" \\"npm run service:db\\"",
    "service:api": "nodemon --exec ts-node src/services/api.service.ts",
    "service:greeter": "nodemon --exec ts-node src/services/greeter.service.ts",
    "service:db": "nodemon --exec ts-node src/services/db.service.ts",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/**/*.ts",
    "docker:build": "docker-compose build",
    "docker:up": "docker-compose up -d",
    "docker:down": "docker-compose down"
  },
  "dependencies": {
    "moleculer": "^0.14.32",
    "moleculer-web": "^0.10.6",
    "moleculer-db": "^0.8.23",
    "moleculer-db-adapter-mongo": "^0.4.17",
    "moleculer-db-adapter-sequelize": "^0.2.17",
    "moleculer-repl": "^0.7.4",
    "nats": "^2.18.0",
    "ioredis": "^5.3.2",
    "jaeger-client": "^3.19.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "dotenv": "^16.3.1",
    "sequelize": "^6.35.2",
    "pg": "^8.11.3",
    "mongodb": "^6.3.0"
  },
  "devDependencies": {
    "@types/node": "^20.10.5",
    "@types/jest": "^29.5.11",
    "@types/bcryptjs": "^2.4.6",
    "@types/jsonwebtoken": "^9.0.5",
    "typescript": "^5.3.3",
    "ts-node": "^10.9.2",
    "ts-node-dev": "^2.0.0",
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "ts-jest": "^29.1.1",
    "@typescript-eslint/eslint-plugin": "^6.15.0",
    "@typescript-eslint/parser": "^6.15.0",
    "eslint": "^8.56.0",
    "concurrently": "^8.2.2"
  }
}`,
    'tsconfig.json': `{
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
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "**/*.test.ts"]
}`,
    '.env.example': `# Node environment
NODE_ENV=development

# Service configuration
SERVICEDIR=dist/services
TRANSPORTER=nats://localhost:4222
CACHER=redis://localhost:6379

# API Gateway
API_PORT=3000
API_HOST=0.0.0.0

# Database
MONGO_URI=mongodb://localhost:27017/moleculer-db
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=moleculer
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# NATS
NATS_URL=nats://localhost:4222

# Authentication
JWT_SECRET=your-secret-key-here
JWT_EXPIRY=7d

# Tracing
JAEGER_AGENT_HOST=localhost
JAEGER_AGENT_PORT=6832

# Metrics
METRICS_ENABLED=true
METRICS_PORT=3030`,
    'moleculer.config.ts': `import { BrokerOptions, Errors } from 'moleculer';
import { config } from 'dotenv';

config();

const brokerConfig: BrokerOptions = {
  namespace: 'microservices',
  nodeID: \`node-\${process.pid}\`,
  
  // Logger configuration
  logger: {
    type: 'Console',
    options: {
      colors: true,
      moduleColors: true,
      formatter: 'full',
      objectPrinter: null,
      autoPadding: false
    }
  },
  logLevel: 'info',
  
  // Transporter configuration
  transporter: process.env.TRANSPORTER || 'TCP',
  
  // Cacher configuration
  cacher: {
    type: 'Redis',
    options: {
      redis: process.env.REDIS_HOST ? {
        host: process.env.REDIS_HOST,
        port: parseInt(process.env.REDIS_PORT || '6379')
      } : 'redis://localhost:6379'
    }
  },
  
  // Serializer configuration
  serializer: 'JSON',
  
  // Request timeout
  requestTimeout: 10 * 1000,
  
  // Retry policy
  retryPolicy: {
    enabled: true,
    retries: 5,
    delay: 100,
    maxDelay: 1000,
    factor: 2,
    check: (err: Errors.MoleculerError) => err && !!err.retryable
  },
  
  // Circuit breaker
  circuitBreaker: {
    enabled: true,
    threshold: 0.5,
    minRequestCount: 20,
    windowTime: 60,
    halfOpenTime: 10 * 1000,
    check: (err: Errors.MoleculerError) => err && err.code >= 500
  },
  
  // Bulkhead
  bulkhead: {
    enabled: true,
    concurrency: 10,
    maxQueueSize: 100
  },
  
  // Service registry
  registry: {
    strategy: 'RoundRobin',
    preferLocal: true
  },
  
  // Metrics
  metrics: {
    enabled: process.env.METRICS_ENABLED === 'true',
    reporter: {
      type: 'Prometheus',
      options: {
        port: parseInt(process.env.METRICS_PORT || '3030'),
        path: '/metrics',
        defaultLabels: registry => ({
          namespace: registry.broker.namespace,
          nodeID: registry.broker.nodeID
        })
      }
    }
  },
  
  // Tracing
  tracing: {
    enabled: true,
    exporter: {
      type: 'Jaeger',
      options: {
        endpoint: null,
        host: process.env.JAEGER_AGENT_HOST || 'localhost',
        port: parseInt(process.env.JAEGER_AGENT_PORT || '6832'),
        sampler: {
          type: 'Const',
          options: {}
        },
        tracerOptions: {},
        defaultTags: null
      }
    }
  },
  
  // Middleware
  middlewares: [],
  
  // Service created lifecycle event handler
  created(broker) {
    broker.logger.info('Broker created!');
  },
  
  // Service started lifecycle event handler
  started(broker) {
    broker.logger.info('Broker started!');
  },
  
  // Service stopped lifecycle event handler
  stopped(broker) {
    broker.logger.info('Broker stopped!');
  }
};

export default brokerConfig;`,
    'src/index.ts': `import { ServiceBroker } from 'moleculer';
import brokerConfig from '../moleculer.config';
import { resolve } from 'path';

async function startBroker() {
  const broker = new ServiceBroker(brokerConfig);
  
  // Load services
  broker.loadServices(resolve(__dirname, 'services'), '**/*.service.ts');
  
  // Start broker
  await broker.start();
  
  // Start REPL for development
  if (process.env.NODE_ENV === 'development') {
    broker.repl();
  }
}

startBroker().catch(err => {
  console.error('Failed to start broker:', err);
  process.exit(1);
});`,
    'src/services/api.service.ts': `import { Service, ServiceBroker, Context } from 'moleculer';
import ApiGateway from 'moleculer-web';
import { IncomingMessage, ServerResponse } from 'http';
import jwt from 'jsonwebtoken';

interface Meta {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

export default class ApiService extends Service {
  public constructor(broker: ServiceBroker) {
    super(broker);
    
    this.parseServiceSchema({
      name: 'api',
      
      mixins: [ApiGateway],
      
      settings: {
        port: process.env.API_PORT || 3000,
        host: process.env.API_HOST || '0.0.0.0',
        
        // Global CORS settings
        cors: {
          origin: '*',
          methods: ['GET', 'OPTIONS', 'POST', 'PUT', 'DELETE'],
          allowedHeaders: ['Content-Type', 'Authorization'],
          exposedHeaders: ['X-Total-Count'],
          credentials: true,
          maxAge: 3600
        },
        
        // Rate limiter
        rateLimit: {
          window: 10 * 1000,
          limit: 10,
          headers: true,
          key: (req: IncomingMessage) => {
            return req.headers['x-forwarded-for'] || 
                   req.connection.remoteAddress || 
                   req.socket.remoteAddress || 
                   'unknown';
          }
        },
        
        routes: [
          {
            path: '/api',
            
            authorization: true,
            
            aliases: {
              // Authentication
              'POST /auth/login': 'auth.login',
              'POST /auth/register': 'auth.register',
              'POST /auth/refresh': 'auth.refresh',
              'GET /auth/me': 'auth.me',
              
              // Greeter service
              'GET /hello': 'greeter.hello',
              'GET /welcome/:name': 'greeter.welcome',
              
              // Database service
              'REST /users': 'users',
              
              // Health check
              'GET /health': 'api.health',
              'GET /ready': 'api.ready'
            },
            
            // Route-level middlewares
            onBeforeCall(ctx: Context<any, Meta>, route: any, req: IncomingMessage, res: ServerResponse) {
              ctx.meta.requestTime = Date.now();
            },
            
            onAfterCall(ctx: Context<any, Meta>, route: any, req: IncomingMessage, res: ServerResponse, data: any) {
              const duration = Date.now() - (ctx.meta.requestTime || 0);
              res.setHeader('X-Response-Time', duration + 'ms');
              return data;
            },
            
            // Error handler
            onError(req: IncomingMessage, res: ServerResponse, err: any) {
              res.setHeader('Content-Type', 'application/json; charset=utf-8');
              res.writeHead(err.code || 500);
              res.end(JSON.stringify({
                error: {
                  message: err.message,
                  code: err.code || 500,
                  type: err.type || 'UNKNOWN_ERROR'
                }
              }));
            }
          }
        ],
        
        // Do not log client side errors (like 404)
        log4XXResponses: false,
        
        // Logging request parameters and response data
        logRequestParams: 'info',
        logResponseData: 'info',
        
        // Serve assets
        assets: {
          folder: 'public',
          options: {}
        }
      },
      
      methods: {
        /**
         * Authenticate the request
         */
        async authenticate(ctx: Context, route: any, req: IncomingMessage): Promise<any> {
          const auth = req.headers.authorization;
          
          if (auth && auth.startsWith('Bearer ')) {
            const token = auth.slice(7);
            
            try {
              const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret') as any;
              
              if (decoded.id) {
                const user = await ctx.call('users.get', { id: decoded.id });
                if (user) {
                  return { id: user.id, email: user.email, role: user.role };
                }
              }
            } catch (err) {
              throw new Error('Invalid token');
            }
          }
          
          throw new Error('No token provided');
        },
        
        /**
         * Authorize the request
         */
        async authorize(ctx: Context<any, Meta>, route: any, req: IncomingMessage): Promise<any> {
          const user = ctx.meta.user;
          
          if (!user) {
            throw new Error('Unauthorized');
          }
          
          // Add role-based authorization logic here
          return ctx;
        }
      },
      
      actions: {
        health: {
          rest: 'GET /health',
          handler(ctx: Context) {
            return {
              status: 'ok',
              timestamp: new Date().toISOString(),
              uptime: process.uptime(),
              memory: process.memoryUsage(),
              nodeID: this.broker.nodeID
            };
          }
        },
        
        ready: {
          rest: 'GET /ready',
          async handler(ctx: Context) {
            const services = await ctx.call('$node.services');
            
            return {
              status: 'ready',
              services: services.length,
              timestamp: new Date().toISOString()
            };
          }
        }
      }
    });
  }
}`,
    'src/services/greeter.service.ts': `import { Service, ServiceBroker, Context } from 'moleculer';

interface HelloParams {
  name?: string;
}

interface WelcomeParams {
  name: string;
}

export default class GreeterService extends Service {
  public constructor(broker: ServiceBroker) {
    super(broker);
    
    this.parseServiceSchema({
      name: 'greeter',
      
      settings: {
        upperCase: true
      },
      
      dependencies: [],
      
      actions: {
        /**
         * Say hello
         */
        hello: {
          rest: 'GET /hello',
          cache: {
            keys: ['name'],
            ttl: 30
          },
          params: {
            name: { type: 'string', optional: true }
          },
          async handler(ctx: Context<HelloParams>) {
            const response = await this.sayHello(ctx.params.name);
            
            // Emit event
            ctx.emit('greeter.hello.called', { name: ctx.params.name });
            
            return response;
          }
        },
        
        /**
         * Welcome a user
         */
        welcome: {
          rest: 'GET /welcome/:name',
          params: {
            name: 'string'
          },
          async handler(ctx: Context<WelcomeParams>) {
            const user = await ctx.call('users.find', { 
              query: { email: ctx.params.name } 
            });
            
            if (user && user.length > 0) {
              return this.welcomeUser(user[0]);
            }
            
            return this.welcomeGuest(ctx.params.name);
          }
        }
      },
      
      events: {
        'user.created': {
          async handler(ctx: Context<{ user: any }>) {
            this.logger.info('New user created:', ctx.params.user.email);
            
            // Send welcome email
            await ctx.call('mail.send', {
              to: ctx.params.user.email,
              subject: 'Welcome!',
              template: 'welcome',
              data: {
                name: ctx.params.user.name
              }
            });
          }
        }
      },
      
      methods: {
        sayHello(name?: string) {
          const greeting = \`Hello \${name || 'Anonymous'}!\`;
          
          if (this.settings.upperCase) {
            return greeting.toUpperCase();
          }
          
          return greeting;
        },
        
        welcomeUser(user: any) {
          return {
            message: \`Welcome back, \${user.name}!\`,
            lastLogin: user.lastLogin,
            role: user.role
          };
        },
        
        welcomeGuest(name: string) {
          return {
            message: \`Welcome, \${name}! Please register for full access.\`,
            guest: true
          };
        }
      },
      
      created() {
        this.logger.info('Greeter service created');
      },
      
      started() {
        this.logger.info('Greeter service started');
      },
      
      stopped() {
        this.logger.info('Greeter service stopped');
      }
    });
  }
}`,
    'src/services/users.service.ts': `import { Service, ServiceBroker } from 'moleculer';
import DbService from 'moleculer-db';
import MongoAdapter from 'moleculer-db-adapter-mongo';
import { Context } from 'moleculer';
import bcrypt from 'bcryptjs';

interface User {
  _id?: string;
  name: string;
  email: string;
  password: string;
  role: string;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastLogin?: Date;
}

export default class UsersService extends Service {
  public constructor(broker: ServiceBroker) {
    super(broker);
    
    this.parseServiceSchema({
      name: 'users',
      
      mixins: [DbService],
      
      adapter: new MongoAdapter(process.env.MONGO_URI || 'mongodb://localhost:27017/moleculer-db'),
      collection: 'users',
      
      settings: {
        fields: ['_id', 'name', 'email', 'role', 'active', 'createdAt', 'updatedAt', 'lastLogin'],
        
        entityValidator: {
          name: 'string|min:3',
          email: 'email',
          password: 'string|min:6',
          role: { type: 'enum', values: ['user', 'admin'], default: 'user' },
          active: { type: 'boolean', default: true }
        }
      },
      
      hooks: {
        before: {
          create: [
            async function(ctx: Context<{ params: User }>) {
              const user = ctx.params;
              
              // Check if email already exists
              const found = await this.adapter.findOne({ email: user.email });
              if (found) {
                throw new Error('Email already exists');
              }
              
              // Hash password
              user.password = await bcrypt.hash(user.password, 10);
              user.createdAt = new Date();
              user.updatedAt = new Date();
            }
          ],
          
          update: [
            async function(ctx: Context<{ params: User }>) {
              const user = ctx.params;
              
              // Hash password if changed
              if (user.password) {
                user.password = await bcrypt.hash(user.password, 10);
              }
              
              user.updatedAt = new Date();
            }
          ]
        },
        
        after: {
          create: [
            async function(ctx: Context<{ params: User }, { user: User }>) {
              const user = ctx.result;
              
              // Emit user created event
              await ctx.emit('user.created', { user });
              
              // Remove password from response
              delete user.password;
              
              return user;
            }
          ],
          
          find: [
            async function(ctx: Context<any, { rows: User[] }>) {
              // Remove passwords from response
              ctx.result.forEach((user: User) => delete user.password);
              return ctx.result;
            }
          ],
          
          get: [
            async function(ctx: Context<any, { user: User }>) {
              // Remove password from response
              if (ctx.result) {
                delete ctx.result.password;
              }
              return ctx.result;
            }
          ]
        }
      },
      
      actions: {
        /**
         * Get current user
         */
        me: {
          auth: true,
          cache: {
            keys: ['#user.id'],
            ttl: 60
          },
          async handler(ctx: Context<any, { user: { id: string } }>) {
            const user = await this.getById(ctx.meta.user.id);
            
            if (!user) {
              throw new Error('User not found');
            }
            
            delete user.password;
            return user;
          }
        },
        
        /**
         * Update user profile
         */
        updateProfile: {
          auth: true,
          params: {
            name: { type: 'string', optional: true },
            email: { type: 'email', optional: true }
          },
          async handler(ctx: Context<{ name?: string; email?: string }, { user: { id: string } }>) {
            const updates: any = {};
            
            if (ctx.params.name) updates.name = ctx.params.name;
            if (ctx.params.email) updates.email = ctx.params.email;
            
            updates.updatedAt = new Date();
            
            const user = await this.adapter.updateById(ctx.meta.user.id, { $set: updates });
            
            delete user.password;
            return user;
          }
        },
        
        /**
         * Verify user credentials
         */
        verifyCredentials: {
          params: {
            email: 'email',
            password: 'string'
          },
          async handler(ctx: Context<{ email: string; password: string }>) {
            const user = await this.adapter.findOne({ email: ctx.params.email });
            
            if (!user || !user.active) {
              throw new Error('Invalid credentials');
            }
            
            const valid = await bcrypt.compare(ctx.params.password, user.password);
            
            if (!valid) {
              throw new Error('Invalid credentials');
            }
            
            // Update last login
            await this.adapter.updateById(user._id, {
              $set: { lastLogin: new Date() }
            });
            
            delete user.password;
            return user;
          }
        }
      },
      
      methods: {
        async seedDB() {
          const count = await this.adapter.count();
          
          if (count === 0) {
            this.logger.info('Seeding users database...');
            
            await this.adapter.insertMany([
              {
                name: 'Admin User',
                email: 'admin@example.com',
                password: await bcrypt.hash('admin123', 10),
                role: 'admin',
                active: true,
                createdAt: new Date(),
                updatedAt: new Date()
              },
              {
                name: 'Test User',
                email: 'user@example.com',
                password: await bcrypt.hash('user123', 10),
                role: 'user',
                active: true,
                createdAt: new Date(),
                updatedAt: new Date()
              }
            ]);
            
            this.logger.info('Database seeded!');
          }
        }
      },
      
      async afterConnected() {
        // Create indexes
        await this.adapter.collection.createIndex({ email: 1 }, { unique: true });
        
        // Seed database
        await this.seedDB();
      }
    });
  }
}`,
    'src/services/auth.service.ts': `import { Service, ServiceBroker, Context, Errors } from 'moleculer';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const { MoleculerError } = Errors;

interface LoginParams {
  email: string;
  password: string;
}

interface RegisterParams {
  name: string;
  email: string;
  password: string;
}

interface RefreshParams {
  refreshToken: string;
}

export default class AuthService extends Service {
  public constructor(broker: ServiceBroker) {
    super(broker);
    
    this.parseServiceSchema({
      name: 'auth',
      
      settings: {
        jwt: {
          secret: process.env.JWT_SECRET || 'moleculer-secret',
          expiresIn: process.env.JWT_EXPIRY || '7d'
        },
        
        refreshToken: {
          secret: process.env.REFRESH_SECRET || 'moleculer-refresh-secret',
          expiresIn: '30d'
        }
      },
      
      actions: {
        /**
         * Login with email and password
         */
        login: {
          rest: 'POST /login',
          params: {
            email: 'email',
            password: 'string'
          },
          async handler(ctx: Context<LoginParams>) {
            const { email, password } = ctx.params;
            
            // Verify credentials
            const user = await ctx.call('users.verifyCredentials', { email, password });
            
            if (!user) {
              throw new MoleculerError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
            }
            
            // Generate tokens
            const tokens = this.generateTokens(user);
            
            // Log login event
            await ctx.emit('user.logged-in', { user, timestamp: new Date() });
            
            return {
              user,
              ...tokens
            };
          }
        },
        
        /**
         * Register new user
         */
        register: {
          rest: 'POST /register',
          params: {
            name: 'string|min:3',
            email: 'email',
            password: 'string|min:6'
          },
          async handler(ctx: Context<RegisterParams>) {
            const { name, email, password } = ctx.params;
            
            // Create user
            const user = await ctx.call('users.create', {
              name,
              email,
              password,
              role: 'user',
              active: true
            });
            
            // Generate tokens
            const tokens = this.generateTokens(user);
            
            // Log registration event
            await ctx.emit('user.registered', { user, timestamp: new Date() });
            
            return {
              user,
              ...tokens
            };
          }
        },
        
        /**
         * Refresh access token
         */
        refresh: {
          rest: 'POST /refresh',
          params: {
            refreshToken: 'string'
          },
          async handler(ctx: Context<RefreshParams>) {
            const { refreshToken } = ctx.params;
            
            try {
              // Verify refresh token
              const decoded = jwt.verify(
                refreshToken, 
                this.settings.refreshToken.secret
              ) as any;
              
              // Get user
              const user = await ctx.call('users.get', { id: decoded.id });
              
              if (!user) {
                throw new Error('User not found');
              }
              
              // Generate new tokens
              const tokens = this.generateTokens(user);
              
              return tokens;
            } catch (err) {
              throw new MoleculerError('Invalid refresh token', 401, 'INVALID_TOKEN');
            }
          }
        },
        
        /**
         * Get current user info
         */
        me: {
          auth: true,
          async handler(ctx: Context<any, { user: { id: string } }>) {
            const user = await ctx.call('users.get', { id: ctx.meta.user.id });
            
            if (!user) {
              throw new MoleculerError('User not found', 404, 'USER_NOT_FOUND');
            }
            
            return user;
          }
        },
        
        /**
         * Verify JWT token
         */
        verify: {
          params: {
            token: 'string'
          },
          async handler(ctx: Context<{ token: string }>) {
            try {
              const decoded = jwt.verify(ctx.params.token, this.settings.jwt.secret) as any;
              
              const user = await ctx.call('users.get', { id: decoded.id });
              
              if (!user) {
                throw new Error('User not found');
              }
              
              return {
                valid: true,
                user
              };
            } catch (err) {
              return {
                valid: false,
                error: err.message
              };
            }
          }
        },
        
        /**
         * Logout (invalidate tokens)
         */
        logout: {
          auth: true,
          async handler(ctx: Context<any, { user: { id: string } }>) {
            // In a real application, you would invalidate the token here
            // For example, by adding it to a blacklist in Redis
            
            await ctx.emit('user.logged-out', { 
              userId: ctx.meta.user.id, 
              timestamp: new Date() 
            });
            
            return { success: true };
          }
        }
      },
      
      methods: {
        /**
         * Generate JWT and refresh tokens
         */
        generateTokens(user: any) {
          const payload = {
            id: user._id || user.id,
            email: user.email,
            role: user.role
          };
          
          const accessToken = jwt.sign(
            payload,
            this.settings.jwt.secret,
            { expiresIn: this.settings.jwt.expiresIn }
          );
          
          const refreshToken = jwt.sign(
            payload,
            this.settings.refreshToken.secret,
            { expiresIn: this.settings.refreshToken.expiresIn }
          );
          
          return {
            accessToken,
            refreshToken,
            expiresIn: this.settings.jwt.expiresIn
          };
        }
      }
    });
  }
}`,
    'src/services/db.service.ts': `import { Service, ServiceBroker } from 'moleculer';
import DbService from 'moleculer-db';
import SequelizeAdapter from 'moleculer-db-adapter-sequelize';
import { Sequelize, DataTypes } from 'sequelize';

export default class DatabaseService extends Service {
  public constructor(broker: ServiceBroker) {
    super(broker);
    
    const sequelize = new Sequelize({
      dialect: 'postgres',
      host: process.env.POSTGRES_HOST || 'localhost',
      port: parseInt(process.env.POSTGRES_PORT || '5432'),
      database: process.env.POSTGRES_DB || 'moleculer',
      username: process.env.POSTGRES_USER || 'postgres',
      password: process.env.POSTGRES_PASSWORD || 'postgres',
      logging: false
    });
    
    this.parseServiceSchema({
      name: 'products',
      
      mixins: [DbService],
      
      adapter: new SequelizeAdapter(sequelize),
      
      model: {
        name: 'product',
        define: {
          id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true
          },
          name: {
            type: DataTypes.STRING,
            allowNull: false
          },
          description: {
            type: DataTypes.TEXT,
            allowNull: true
          },
          price: {
            type: DataTypes.DECIMAL(10, 2),
            allowNull: false
          },
          stock: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
          },
          category: {
            type: DataTypes.STRING,
            allowNull: false
          },
          active: {
            type: DataTypes.BOOLEAN,
            defaultValue: true
          }
        },
        options: {
          timestamps: true
        }
      },
      
      settings: {
        fields: ['id', 'name', 'description', 'price', 'stock', 'category', 'active', 'createdAt', 'updatedAt'],
        
        entityValidator: {
          name: 'string|min:3',
          description: { type: 'string', optional: true },
          price: 'number|positive',
          stock: 'number|integer|min:0',
          category: 'string',
          active: { type: 'boolean', optional: true }
        }
      },
      
      actions: {
        /**
         * Get products by category
         */
        byCategory: {
          cache: {
            keys: ['category'],
            ttl: 300
          },
          params: {
            category: 'string'
          },
          async handler(ctx) {
            return this.adapter.find({
              where: {
                category: ctx.params.category,
                active: true
              },
              order: [['name', 'ASC']]
            });
          }
        },
        
        /**
         * Search products
         */
        search: {
          params: {
            query: 'string',
            limit: { type: 'number', optional: true, default: 10 }
          },
          async handler(ctx) {
            const { Op } = this.adapter.db.Sequelize;
            
            return this.adapter.find({
              where: {
                [Op.or]: [
                  { name: { [Op.iLike]: \`%\${ctx.params.query}%\` } },
                  { description: { [Op.iLike]: \`%\${ctx.params.query}%\` } }
                ],
                active: true
              },
              limit: ctx.params.limit,
              order: [['name', 'ASC']]
            });
          }
        },
        
        /**
         * Update stock
         */
        updateStock: {
          params: {
            id: 'string',
            quantity: 'number|integer'
          },
          async handler(ctx) {
            const product = await this.adapter.findById(ctx.params.id);
            
            if (!product) {
              throw new Error('Product not found');
            }
            
            const newStock = product.stock + ctx.params.quantity;
            
            if (newStock < 0) {
              throw new Error('Insufficient stock');
            }
            
            await this.adapter.updateById(ctx.params.id, {
              stock: newStock
            });
            
            // Emit stock update event
            await ctx.emit('product.stock-updated', {
              productId: ctx.params.id,
              oldStock: product.stock,
              newStock,
              change: ctx.params.quantity
            });
            
            return this.adapter.findById(ctx.params.id);
          }
        }
      },
      
      methods: {
        async seedDB() {
          const count = await this.adapter.count();
          
          if (count === 0) {
            this.logger.info('Seeding products database...');
            
            const products = [
              {
                name: 'Laptop Pro',
                description: 'High-performance laptop for professionals',
                price: 1299.99,
                stock: 50,
                category: 'Electronics'
              },
              {
                name: 'Wireless Mouse',
                description: 'Ergonomic wireless mouse with precision tracking',
                price: 49.99,
                stock: 200,
                category: 'Electronics'
              },
              {
                name: 'USB-C Hub',
                description: 'Multi-port USB-C hub with HDMI and ethernet',
                price: 79.99,
                stock: 150,
                category: 'Accessories'
              },
              {
                name: 'Mechanical Keyboard',
                description: 'RGB mechanical keyboard with custom switches',
                price: 149.99,
                stock: 75,
                category: 'Electronics'
              },
              {
                name: 'Monitor Stand',
                description: 'Adjustable monitor stand with cable management',
                price: 89.99,
                stock: 100,
                category: 'Accessories'
              }
            ];
            
            await this.adapter.insertMany(products);
            
            this.logger.info('Products database seeded!');
          }
        }
      },
      
      async afterConnected() {
        // Sync database
        await this.adapter.db.sync();
        
        // Seed database
        await this.seedDB();
      }
    });
  }
}`,
    'src/middlewares/metrics.middleware.ts': `import { Middleware } from 'moleculer';

const MetricsMiddleware: Middleware = {
  name: 'MetricsMiddleware',
  
  // Wrap local action handlers
  localAction(handler, action) {
    return async function metricsHandler(ctx) {
      const startTime = Date.now();
      
      try {
        const result = await handler(ctx);
        
        // Record success metric
        ctx.broker.metrics.increment('moleculer.request.total', {
          action: action.name,
          service: ctx.service?.name,
          status: 'success'
        });
        
        // Record duration
        const duration = Date.now() - startTime;
        ctx.broker.metrics.histogram('moleculer.request.duration', duration, {
          action: action.name,
          service: ctx.service?.name
        });
        
        return result;
      } catch (err) {
        // Record error metric
        ctx.broker.metrics.increment('moleculer.request.total', {
          action: action.name,
          service: ctx.service?.name,
          status: 'error',
          error: err.name
        });
        
        throw err;
      }
    };
  },
  
  // Wrap broker.call method
  call(handler) {
    return async function metricsCall(actionName, params, opts) {
      const startTime = Date.now();
      
      try {
        const result = await handler(actionName, params, opts);
        
        // Record duration
        const duration = Date.now() - startTime;
        this.metrics.histogram('moleculer.call.duration', duration, {
          action: actionName
        });
        
        return result;
      } catch (err) {
        // Record error
        this.metrics.increment('moleculer.call.error.total', {
          action: actionName,
          error: err.name
        });
        
        throw err;
      }
    };
  }
};

export default MetricsMiddleware;`,
    'docker-compose.yml': `version: '3.8'

services:
  # API Gateway
  api:
    build: .
    image: moleculer-microservices
    environment:
      NODE_ENV: production
      SERVICES: api
      PORT: 3000
    depends_on:
      - nats
      - redis
      - mongo
      - postgres
    ports:
      - "3000:3000"
    networks:
      - moleculer-net
    restart: unless-stopped

  # Greeter service
  greeter:
    build: .
    image: moleculer-microservices
    environment:
      NODE_ENV: production
      SERVICES: greeter
    depends_on:
      - nats
      - redis
    networks:
      - moleculer-net
    restart: unless-stopped

  # Users service
  users:
    build: .
    image: moleculer-microservices
    environment:
      NODE_ENV: production
      SERVICES: users
    depends_on:
      - nats
      - redis
      - mongo
    networks:
      - moleculer-net
    restart: unless-stopped

  # Auth service
  auth:
    build: .
    image: moleculer-microservices
    environment:
      NODE_ENV: production
      SERVICES: auth
    depends_on:
      - nats
      - redis
    networks:
      - moleculer-net
    restart: unless-stopped

  # Products service
  products:
    build: .
    image: moleculer-microservices
    environment:
      NODE_ENV: production
      SERVICES: products
    depends_on:
      - nats
      - redis
      - postgres
    networks:
      - moleculer-net
    restart: unless-stopped

  # NATS
  nats:
    image: nats:2.10-alpine
    ports:
      - "4222:4222"
      - "8222:8222"
    networks:
      - moleculer-net
    restart: unless-stopped

  # Redis
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - moleculer-net
    restart: unless-stopped

  # MongoDB
  mongo:
    image: mongo:7
    environment:
      MONGO_INITDB_DATABASE: moleculer-db
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
    networks:
      - moleculer-net
    restart: unless-stopped

  # PostgreSQL
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: moleculer
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - moleculer-net
    restart: unless-stopped

  # Jaeger
  jaeger:
    image: jaegertracing/all-in-one:1.52
    environment:
      COLLECTOR_ZIPKIN_HOST_PORT: ":9411"
    ports:
      - "5775:5775/udp"
      - "6831:6831/udp"
      - "6832:6832/udp"
      - "5778:5778"
      - "16686:16686"
      - "14268:14268"
      - "14250:14250"
      - "9411:9411"
    networks:
      - moleculer-net
    restart: unless-stopped

  # Prometheus
  prometheus:
    image: prom/prometheus:v2.48.1
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    ports:
      - "9090:9090"
    networks:
      - moleculer-net
    restart: unless-stopped

  # Grafana
  grafana:
    image: grafana/grafana:10.2.3
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    ports:
      - "3001:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - moleculer-net
    restart: unless-stopped

networks:
  moleculer-net:
    driver: bridge

volumes:
  mongo-data:
  postgres-data:
  prometheus-data:
  grafana-data:`,
    'Dockerfile': `FROM node:20-alpine

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY src ./src

# Build TypeScript
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

USER nodejs

# Start the service
CMD ["node", "dist/index.js"]`,
    'prometheus.yml': `global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'moleculer'
    static_configs:
      - targets: 
          - 'api:3030'
          - 'greeter:3030'
          - 'users:3030'
          - 'auth:3030'
          - 'products:3030'
    metrics_path: '/metrics'`,
    'jest.config.js': `module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.interface.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};`,
    'test/unit/greeter.spec.ts': `import { ServiceBroker } from 'moleculer';
import GreeterService from '../../src/services/greeter.service';

describe('Test Greeter service', () => {
  let broker: ServiceBroker;
  let service: any;

  beforeAll(() => {
    broker = new ServiceBroker({ logger: false });
    service = broker.createService(GreeterService);
    return broker.start();
  });

  afterAll(() => broker.stop());

  describe('Test greeter.hello action', () => {
    it('should return with Hello Anonymous', async () => {
      const result = await broker.call('greeter.hello');
      expect(result).toBe('HELLO ANONYMOUS!');
    });

    it('should return with Hello John', async () => {
      const result = await broker.call('greeter.hello', { name: 'John' });
      expect(result).toBe('HELLO JOHN!');
    });
  });

  describe('Test greeter.welcome action', () => {
    it('should welcome a guest', async () => {
      const result = await broker.call('greeter.welcome', { name: 'John' });
      expect(result).toHaveProperty('message');
      expect(result).toHaveProperty('guest', true);
      expect(result.message).toContain('Welcome, John!');
    });
  });
});`,
    'test/integration/api.spec.ts': `import { ServiceBroker } from 'moleculer';
import ApiService from '../../src/services/api.service';
import request from 'supertest';

describe('Test API Gateway', () => {
  let broker: ServiceBroker;
  let server: any;

  beforeAll(async () => {
    broker = new ServiceBroker({ 
      logger: false,
      transporter: null 
    });
    
    broker.createService(ApiService);
    
    await broker.start();
    server = (broker.getLocalService('api') as any).server;
  });

  afterAll(() => broker.stop());

  describe('Test health endpoints', () => {
    it('GET /api/health should return health status', async () => {
      const res = await request(server)
        .get('/api/health')
        .expect(200);

      expect(res.body).toHaveProperty('status', 'ok');
      expect(res.body).toHaveProperty('timestamp');
      expect(res.body).toHaveProperty('uptime');
      expect(res.body).toHaveProperty('memory');
    });

    it('GET /api/ready should return ready status', async () => {
      const res = await request(server)
        .get('/api/ready')
        .expect(200);

      expect(res.body).toHaveProperty('status', 'ready');
      expect(res.body).toHaveProperty('services');
      expect(res.body).toHaveProperty('timestamp');
    });
  });

  describe('Test CORS', () => {
    it('should have CORS headers', async () => {
      const res = await request(server)
        .get('/api/health')
        .expect(200);

      expect(res.headers).toHaveProperty('access-control-allow-origin', '*');
    });
  });
});`,
    '.eslintrc.js': `module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    project: './tsconfig.json'
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended'
  ],
  env: {
    node: true,
    jest: true
  },
  rules: {
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    'no-console': ['warn', { allow: ['warn', 'error'] }]
  }
};`,
    'kubernetes/namespace.yaml': `apiVersion: v1
kind: Namespace
metadata:
  name: moleculer-microservices
  labels:
    name: moleculer-microservices`,
    'kubernetes/api-deployment.yaml': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: moleculer-microservices
  labels:
    app: api-gateway
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: api
        image: moleculer-microservices:latest
        imagePullPolicy: IfNotPresent
        env:
        - name: NODE_ENV
          value: "production"
        - name: SERVICES
          value: "api"
        - name: TRANSPORTER
          value: "nats://nats:4222"
        - name: CACHER
          value: "redis://redis:6379"
        ports:
        - containerPort: 3000
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
  namespace: moleculer-microservices
spec:
  selector:
    app: api-gateway
  ports:
  - port: 3000
    targetPort: 3000
  type: LoadBalancer`,
    'README.md': `# Moleculer Microservices

A production-ready microservices architecture built with Moleculer framework, featuring TypeScript support, service discovery, and comprehensive monitoring.

## Features

- **Service-Oriented Architecture**: Built-in service broker with automatic service discovery
- **Multiple Transport Layers**: NATS, Redis, TCP, and more
- **Fault Tolerance**: Circuit breaker, retry logic, timeout, and bulkhead patterns
- **Caching**: Redis-based caching with automatic cache invalidation
- **Load Balancing**: Multiple strategies (RoundRobin, Random, CPU usage-based)
- **Authentication & Authorization**: JWT-based auth with role-based access control
- **Database Integration**: MongoDB and PostgreSQL with ORM support
- **API Gateway**: RESTful endpoints with rate limiting and CORS
- **Monitoring**: Prometheus metrics and Jaeger distributed tracing
- **Hot Reload**: Development mode with automatic service reloading
- **Testing**: Comprehensive unit and integration tests with Jest
- **Docker & Kubernetes**: Production-ready containerization

## Quick Start

1. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

2. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   \`\`\`

3. Start infrastructure services:
   \`\`\`bash
   docker-compose up -d nats redis mongo postgres jaeger
   \`\`\`

4. Run in development mode:
   \`\`\`bash
   npm run dev
   \`\`\`

5. Or run specific services:
   \`\`\`bash
   npm run start:services
   \`\`\`

## Architecture

### Services

- **API Gateway**: REST API endpoints, authentication, rate limiting
- **Auth Service**: JWT authentication and authorization
- **Users Service**: User management with MongoDB
- **Products Service**: Product catalog with PostgreSQL
- **Greeter Service**: Example service demonstrating patterns

### Infrastructure

- **NATS**: Message broker for inter-service communication
- **Redis**: Caching and session storage
- **MongoDB**: Document database for users
- **PostgreSQL**: Relational database for products
- **Jaeger**: Distributed tracing
- **Prometheus**: Metrics collection
- **Grafana**: Metrics visualization

## API Endpoints

### Authentication
- \`POST /api/auth/login\` - User login
- \`POST /api/auth/register\` - User registration
- \`POST /api/auth/refresh\` - Refresh access token
- \`GET /api/auth/me\` - Get current user

### Users
- \`GET /api/users\` - List users (admin only)
- \`GET /api/users/:id\` - Get user by ID
- \`PUT /api/users/:id\` - Update user
- \`DELETE /api/users/:id\` - Delete user

### Products
- \`GET /api/products\` - List products
- \`POST /api/products\` - Create product
- \`GET /api/products/:id\` - Get product
- \`PUT /api/products/:id\` - Update product
- \`DELETE /api/products/:id\` - Delete product

### Health
- \`GET /api/health\` - Health check
- \`GET /api/ready\` - Readiness check

## Development

### Running Tests
\`\`\`bash
npm test                 # Run all tests
npm run test:watch      # Run tests in watch mode
npm run test:coverage   # Run tests with coverage
\`\`\`

### Building for Production
\`\`\`bash
npm run build
\`\`\`

### Docker Deployment
\`\`\`bash
docker-compose up -d    # Start all services
docker-compose logs -f  # View logs
docker-compose down     # Stop all services
\`\`\`

### Kubernetes Deployment
\`\`\`bash
kubectl apply -f kubernetes/
kubectl get pods -n moleculer-microservices
kubectl port-forward -n moleculer-microservices svc/api-gateway 3000:3000
\`\`\`

## Monitoring

- **Metrics**: http://localhost:9090 (Prometheus)
- **Tracing**: http://localhost:16686 (Jaeger)
- **Dashboards**: http://localhost:3001 (Grafana, admin/admin)

## Best Practices

1. **Service Design**: Keep services small and focused on a single domain
2. **Error Handling**: Use proper error types and retry strategies
3. **Caching**: Cache expensive operations with appropriate TTL
4. **Security**: Always validate inputs and use authentication where needed
5. **Monitoring**: Add custom metrics and traces for critical operations
6. **Testing**: Write unit tests for services and integration tests for workflows

## License

MIT`
  }
};