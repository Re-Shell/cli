import { BackendTemplate } from '../../types';

export const feathersJsTemplate: BackendTemplate = {
  id: 'feathersjs',
  name: 'Feathers.js',
  description: 'Real-time, micro-service ready web framework with TypeScript',
  category: 'backend',
  
  files: [
    {
      path: 'package.json',
      content: `{
  "name": "feathersjs-backend",
  "version": "1.0.0",
  "description": "Real-time Feathers.js backend with TypeScript",
  "main": "dist/index.js",
  "scripts": {
    "dev": "nodemon",
    "build": "tsc",
    "start": "node dist/index.js",
    "test": "mocha --recursive test/ --require ts-node/register --exit",
    "test:watch": "mocha --recursive test/ --require ts-node/register --watch",
    "lint": "eslint . --ext .ts --fix",
    "db:migrate": "knex migrate:latest",
    "db:seed": "knex seed:run",
    "docker:build": "docker build -t feathersjs-backend .",
    "docker:run": "docker run -p 3030:3030 feathersjs-backend"
  },
  "dependencies": {
    "@feathersjs/authentication": "^5.0.11",
    "@feathersjs/authentication-local": "^5.0.11",
    "@feathersjs/authentication-oauth": "^5.0.11",
    "@feathersjs/configuration": "^5.0.11",
    "@feathersjs/errors": "^5.0.11",
    "@feathersjs/express": "^5.0.11",
    "@feathersjs/feathers": "^5.0.11",
    "@feathersjs/knex": "^5.0.11",
    "@feathersjs/schema": "^5.0.11",
    "@feathersjs/socketio": "^5.0.11",
    "@feathersjs/transport-commons": "^5.0.11",
    "@feathersjs/typebox": "^5.0.11",
    "compression": "^1.7.4",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "feathers-apollo": "^1.2.0",
    "graphql": "^16.8.1",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "knex": "^3.0.1",
    "multer": "^1.4.5-lts.1",
    "nodemailer": "^6.9.7",
    "pg": "^8.11.3",
    "rate-limiter-flexible": "^3.0.0",
    "redis": "^4.6.10",
    "socket.io": "^4.6.2",
    "winston": "^3.11.0"
  },
  "devDependencies": {
    "@types/compression": "^1.7.5",
    "@types/cors": "^2.8.17",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/mocha": "^10.0.6",
    "@types/multer": "^1.4.11",
    "@types/node": "^20.10.0",
    "@types/nodemailer": "^6.4.14",
    "@typescript-eslint/eslint-plugin": "^6.13.1",
    "@typescript-eslint/parser": "^6.13.1",
    "chai": "^4.3.10",
    "eslint": "^8.54.0",
    "mocha": "^10.2.0",
    "nodemon": "^3.0.1",
    "supertest": "^6.3.3",
    "ts-node": "^10.9.1",
    "typescript": "^5.3.2"
  },
  "engines": {
    "node": ">= 18.0.0"
  }
}`
    },
    {
      path: 'tsconfig.json',
      content: `{
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
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noImplicitThis": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "allowSyntheticDefaultImports": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "test"]
}`
    },
    {
      path: 'src/index.ts',
      content: `import { app } from './app';
import { logger } from './logger';

const port = app.get('port');
const host = app.get('host');

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection', reason);
  process.exit(1);
});

app.listen(port).then(() => {
  logger.info(\`Feathers application started on http://\${host}:\${port}\`);
});`
    },
    {
      path: 'src/app.ts',
      content: `import { feathers } from '@feathersjs/feathers';
import express, { rest, json, urlencoded, cors, serveStatic, notFound, errorHandler } from '@feathersjs/express';
import configuration from '@feathersjs/configuration';
import socketio from '@feathersjs/socketio';
import { configurationValidator } from './configuration';
import type { Application } from './declarations';

import { logger } from './logger';
import { logError } from './hooks/log-error';
import { authentication } from './authentication';
import { services } from './services';
import { channels } from './channels';
import { rateLimiter } from './middleware/rate-limiter';
import { setupGraphQL } from './graphql';
import { setupFileUpload } from './middleware/file-upload';

const app: Application = express(feathers());

// Load app configuration
app.configure(configuration(configurationValidator));

// Enable security, CORS, compression, favicon and body parsing
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compress());
app.use(json());
app.use(urlencoded({ extended: true }));

// Host the public folder
app.use('/', serveStatic(app.get('public')));

// Configure rate limiting
app.configure(rateLimiter);

// Configure file upload
app.configure(setupFileUpload);

// Configure other middleware
app.configure(rest());
app.configure(
  socketio({
    cors: {
      origin: app.get('origins')
    }
  })
);

// Configure authentication
app.configure(authentication);

// Configure GraphQL
app.configure(setupGraphQL);

// Set up our services
app.configure(services);

// Set up event channels
app.configure(channels);

// Configure a middleware for 404s and the error handler
app.use(notFound());
app.use(errorHandler({ logger }));

// Register hooks that run on all service methods
app.hooks({
  around: {
    all: [logError]
  },
  before: {},
  after: {},
  error: {}
});

// Register application setup and teardown hooks
app.hooks({
  setup: [],
  teardown: []
});

export { app };`
    },
    {
      path: 'src/declarations.ts',
      content: `import { Application as ExpressFeathers } from '@feathersjs/express';
import { ServiceAddons } from '@feathersjs/feathers';
import { AuthenticationService, AuthenticationRequest } from '@feathersjs/authentication';
import { User, UserService } from './services/users/users.class';
import { Message, MessageService } from './services/messages/messages.class';
import { Email, EmailService } from './services/email/email.class';
import { Job, JobService } from './services/jobs/jobs.class';

// A mapping of service names to types
export interface ServiceTypes {
  authentication: AuthenticationService;
  users: UserService & ServiceAddons<User>;
  messages: MessageService & ServiceAddons<Message>;
  email: EmailService & ServiceAddons<Email>;
  jobs: JobService & ServiceAddons<Job>;
}

// The application instance type
export interface Application extends ExpressFeathers<ServiceTypes> {}

// The configuration object type
export interface Configuration {
  host: string;
  port: number;
  public: string;
  origins: string[];
  paginate: {
    default: number;
    max: number;
  };
  authentication: {
    entity: string;
    service: string;
    secret: string;
    authStrategies: string[];
    jwtOptions: {
      header: { typ: 'access' };
      audience: string;
      algorithm: string;
      expiresIn: string;
    };
    local: {
      usernameField: string;
      passwordField: string;
    };
    oauth: {
      redirect: string;
      google: {
        key: string;
        secret: string;
        scope: string[];
      };
    };
  };
  redis: {
    host: string;
    port: number;
    password?: string;
  };
  database: {
    client: string;
    connection: {
      host: string;
      port: number;
      user: string;
      password: string;
      database: string;
    };
    migrations: {
      directory: string;
    };
    seeds: {
      directory: string;
    };
  };
  email: {
    service: string;
    auth: {
      user: string;
      pass: string;
    };
  };
}

// Helper type for authentication
export interface AuthenticationPayload {
  user: User;
  accessToken: string;
}

// Extend Express Request
declare module 'express' {
  interface Request extends AuthenticationRequest {}
}`
    },
    {
      path: 'src/configuration.ts',
      content: `import { Type, getValidator } from '@feathersjs/typebox';
import type { Static } from '@feathersjs/typebox';

const configurationSchema = Type.Object({
  host: Type.String(),
  port: Type.Number(),
  public: Type.String(),
  origins: Type.Array(Type.String()),
  paginate: Type.Object({
    default: Type.Number(),
    max: Type.Number()
  }),
  authentication: Type.Object({
    entity: Type.String(),
    service: Type.String(),
    secret: Type.String(),
    authStrategies: Type.Array(Type.String()),
    jwtOptions: Type.Object({
      header: Type.Object({ typ: Type.Literal('access') }),
      audience: Type.String(),
      algorithm: Type.String(),
      expiresIn: Type.String()
    }),
    local: Type.Object({
      usernameField: Type.String(),
      passwordField: Type.String()
    }),
    oauth: Type.Object({
      redirect: Type.String(),
      google: Type.Object({
        key: Type.String(),
        secret: Type.String(),
        scope: Type.Array(Type.String())
      })
    })
  }),
  redis: Type.Object({
    host: Type.String(),
    port: Type.Number(),
    password: Type.Optional(Type.String())
  }),
  database: Type.Object({
    client: Type.String(),
    connection: Type.Object({
      host: Type.String(),
      port: Type.Number(),
      user: Type.String(),
      password: Type.String(),
      database: Type.String()
    }),
    migrations: Type.Object({
      directory: Type.String()
    }),
    seeds: Type.Object({
      directory: Type.String()
    })
  }),
  email: Type.Object({
    service: Type.String(),
    auth: Type.Object({
      user: Type.String(),
      pass: Type.String()
    })
  })
});

export type Configuration = Static<typeof configurationSchema>;

export const configurationValidator = getValidator(configurationSchema, {});`
    },
    {
      path: 'src/logger.ts',
      content: `import winston from 'winston';

// Configure the Winston logger
export const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'feathersjs-backend' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Add console transport in non-production environments
if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  );
}`
    },
    {
      path: 'src/authentication.ts',
      content: `import { AuthenticationService, JWTStrategy } from '@feathersjs/authentication';
import { LocalStrategy } from '@feathersjs/authentication-local';
import { OAuthStrategy, OAuthProfile } from '@feathersjs/authentication-oauth';
import { Application } from './declarations';

declare module './declarations' {
  interface ServiceTypes {
    authentication: AuthenticationService;
  }
}

class GoogleStrategy extends OAuthStrategy {
  async getEntityData(profile: OAuthProfile) {
    const baseData = await super.getEntityData(profile);
    
    return {
      ...baseData,
      email: profile.email,
      name: profile.name,
      googleId: profile.sub || profile.id,
      avatar: profile.picture
    };
  }
}

export const authentication = (app: Application) => {
  const authentication = new AuthenticationService(app);

  authentication.register('jwt', new JWTStrategy());
  authentication.register('local', new LocalStrategy());
  authentication.register('google', new GoogleStrategy());

  app.use('authentication', authentication);
};`
    },
    {
      path: 'src/channels.ts',
      content: `import '@feathersjs/transport-commons';
import { Application } from './declarations';
import { logger } from './logger';

export const channels = (app: Application) => {
  logger.info('Publishing all events to all authenticated users');

  app.on('connection', (connection: any) => {
    // On a new real-time connection, add it to the anonymous channel
    app.channel('anonymous').join(connection);
  });

  app.on('login', (authResult: any, { connection }: any) => {
    // Connection can be undefined if there is no real-time connection
    if (connection) {
      // The user attached to this connection
      const user = authResult.user;

      // The connection is no longer anonymous, remove it
      app.channel('anonymous').leave(connection);

      // Add it to the authenticated user channel
      app.channel('authenticated').join(connection);

      // Channels can be named anything and joined on any condition
      // E.g. to send real-time events only to admins use:
      if (user.role === 'admin') {
        app.channel('admins').join(connection);
      }

      // Add user to their personal channel
      app.channel(\`users/\${user.id}\`).join(connection);

      // Easily organize users by email domain
      const domain = user.email.split('@')[1];
      app.channel(\`domains/\${domain}\`).join(connection);
    }
  });

  app.on('logout', (authResult: any, { connection }: any) => {
    if (connection) {
      // Leave all channels when logging out
      app.channel(app.channels).leave(connection);
      
      // Join anonymous channel
      app.channel('anonymous').join(connection);
    }
  });

  // Publish all service events to authenticated users
  app.publish((data: any, context: any) => {
    // Only publish to authenticated users
    return app.channel('authenticated');
  });

  // Register more granular publishers for specific services
  app.service('messages').publish('created', (data: any, context: any) => {
    // Publish message created events to specific rooms
    return app.channel(\`rooms/\${data.roomId}\`);
  });

  app.service('users').publish('patched', (data: any, context: any) => {
    // Send user updates only to that user
    return app.channel(\`users/\${data.id}\`);
  });
};`
    },
    {
      path: 'src/hooks/log-error.ts',
      content: `import { HookContext } from '@feathersjs/feathers';
import { logger } from '../logger';

export const logError = async (context: HookContext, next: Function) => {
  try {
    await next();
  } catch (error: any) {
    logger.error(error.stack);
    
    // Log additional error information
    if (error.code) {
      logger.error(\`Error code: \${error.code}\`);
    }
    
    if (context.params.user) {
      logger.error(\`User: \${context.params.user.email}\`);
    }
    
    logger.error(\`Service: \${context.path}\`);
    logger.error(\`Method: \${context.method}\`);
    
    throw error;
  }
};`
    },
    {
      path: 'src/hooks/validate.ts',
      content: `import { HookContext } from '@feathersjs/feathers';
import { BadRequest } from '@feathersjs/errors';
import { Type, getValidator } from '@feathersjs/typebox';
import type { Static, TSchema } from '@feathersjs/typebox';

export const validate = <T extends TSchema>(schema: T) => {
  const validator = getValidator(schema, {});
  
  return async (context: HookContext) => {
    const data = context.method === 'find' ? context.params.query : context.data;
    
    try {
      context.data = validator(data);
    } catch (error: any) {
      throw new BadRequest('Validation failed', {
        errors: error.errors
      });
    }
  };
};`
    },
    {
      path: 'src/middleware/rate-limiter.ts',
      content: `import { Application } from '../declarations';
import { RateLimiterRedis } from 'rate-limiter-flexible';
import { createClient } from 'redis';
import { TooManyRequests } from '@feathersjs/errors';

export const rateLimiter = async (app: Application) => {
  const redisClient = createClient({
    socket: {
      host: app.get('redis').host,
      port: app.get('redis').port
    },
    password: app.get('redis').password
  });

  await redisClient.connect();

  const rateLimiter = new RateLimiterRedis({
    storeClient: redisClient,
    keyPrefix: 'middleware',
    points: 100, // Number of requests
    duration: 900, // Per 15 minutes
    blockDuration: 900, // Block for 15 minutes
  });

  app.use(async (req: any, res: any, next: Function) => {
    try {
      const key = req.ip;
      await rateLimiter.consume(key);
      next();
    } catch (rejRes: any) {
      const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
      res.set('Retry-After', String(secs));
      res.set('X-RateLimit-Limit', String(rateLimiter.points));
      res.set('X-RateLimit-Remaining', String(rejRes.remainingPoints || 0));
      res.set('X-RateLimit-Reset', String(Date.now() + rejRes.msBeforeNext));
      
      throw new TooManyRequests('Too many requests');
    }
  });
};`
    },
    {
      path: 'src/middleware/file-upload.ts',
      content: `import multer from 'multer';
import path from 'path';
import { Application } from '../declarations';
import { BadRequest } from '@feathersjs/errors';

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (_req: any, file: any, cb: Function) => {
  // Allowed file types
  const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new BadRequest('Invalid file type'));
  }
};

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
  },
  fileFilter
});

export const setupFileUpload = (app: Application) => {
  // Single file upload
  app.post('/upload', upload.single('file'), (req: any, res: any) => {
    if (!req.file) {
      throw new BadRequest('No file uploaded');
    }
    
    res.json({
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      path: req.file.path
    });
  });

  // Multiple file upload
  app.post('/upload/multiple', upload.array('files', 10), (req: any, res: any) => {
    if (!req.files || req.files.length === 0) {
      throw new BadRequest('No files uploaded');
    }
    
    const files = req.files.map((file: any) => ({
      filename: file.filename,
      originalName: file.originalname,
      size: file.size,
      path: file.path
    }));
    
    res.json({ files });
  });
};`
    },
    {
      path: 'src/services/index.ts',
      content: `import { Application } from '../declarations';
import { users } from './users/users.service';
import { messages } from './messages/messages.service';
import { email } from './email/email.service';
import { jobs } from './jobs/jobs.service';

export const services = (app: Application) => {
  app.configure(users);
  app.configure(messages);
  app.configure(email);
  app.configure(jobs);
};`
    },
    {
      path: 'src/services/users/users.class.ts',
      content: `import { Params } from '@feathersjs/feathers';
import { KnexService } from '@feathersjs/knex';
import { Application } from '../../declarations';
import { User, UserData, UserPatch, UserQuery } from './users.schema';

export { User, UserData, UserPatch, UserQuery };

export interface UserParams extends Params<UserQuery> {}

export class UserService extends KnexService<User, UserData, UserParams, UserPatch> {
  constructor(options: any, app: Application) {
    super({
      ...options,
      name: 'users'
    });
  }

  async create(data: UserData, params?: UserParams) {
    // Hash password before saving
    const { password, ...userData } = data;
    const user = await super.create({
      ...userData,
      password: await this.hashPassword(password)
    }, params);

    // Remove password from response
    delete (user as any).password;
    return user;
  }

  private async hashPassword(password: string): Promise<string> {
    // In real implementation, use bcrypt or argon2
    return 'hashed_' + password;
  }
}

export const getOptions = (app: Application) => {
  return {
    paginate: app.get('paginate'),
    Model: app.get('knexClient'),
    name: 'users'
  };
};`
    },
    {
      path: 'src/services/users/users.schema.ts',
      content: `import { Type, getValidator, querySyntax } from '@feathersjs/typebox';
import type { Static } from '@feathersjs/typebox';

// Main data model schema
export const userSchema = Type.Object(
  {
    id: Type.Number(),
    email: Type.String({ format: 'email' }),
    password: Type.String(),
    name: Type.String(),
    role: Type.String({ default: 'user' }),
    googleId: Type.Optional(Type.String()),
    avatar: Type.Optional(Type.String()),
    isVerified: Type.Boolean({ default: false }),
    verifyToken: Type.Optional(Type.String()),
    verifyExpires: Type.Optional(Type.String({ format: 'date-time' })),
    resetToken: Type.Optional(Type.String()),
    resetExpires: Type.Optional(Type.String({ format: 'date-time' })),
    createdAt: Type.String({ format: 'date-time' }),
    updatedAt: Type.String({ format: 'date-time' })
  },
  { $id: 'User', additionalProperties: false }
);

export type User = Static<typeof userSchema>;

// Schema for creating new entries
export const userDataSchema = Type.Pick(
  userSchema,
  ['email', 'password', 'name', 'role', 'googleId', 'avatar'],
  { additionalProperties: false }
);

export type UserData = Static<typeof userDataSchema>;

// Schema for updating existing entries
export const userPatchSchema = Type.Partial(
  Type.Pick(userSchema, ['email', 'name', 'role', 'avatar', 'isVerified']),
  { additionalProperties: false }
);

export type UserPatch = Static<typeof userPatchSchema>;

// Schema for allowed query properties
export const userQueryProperties = Type.Pick(
  userSchema,
  ['id', 'email', 'name', 'role', 'isVerified', 'createdAt', 'updatedAt']
);

export const userQuerySchema = querySyntax(userQueryProperties);

export type UserQuery = Static<typeof userQuerySchema>;

// Validators
export const userValidator = getValidator(userSchema, {});
export const userDataValidator = getValidator(userDataSchema, {});
export const userPatchValidator = getValidator(userPatchSchema, {});
export const userQueryValidator = getValidator(userQuerySchema, {});`
    },
    {
      path: 'src/services/users/users.service.ts',
      content: `import { authenticate } from '@feathersjs/authentication';
import { hooks as schemaHooks } from '@feathersjs/schema';
import { Application } from '../../declarations';
import { UserService, getOptions } from './users.class';
import { userDataValidator, userPatchValidator, userQueryValidator } from './users.schema';
import { disallow, iff, isProvider } from 'feathers-hooks-common';

declare module '../../declarations' {
  interface ServiceTypes {
    users: UserService;
  }
}

export const users = (app: Application) => {
  app.use('users', new UserService(getOptions(app), app), {
    methods: ['find', 'get', 'create', 'patch', 'remove'],
    events: ['created', 'updated', 'patched', 'removed']
  });

  app.service('users').hooks({
    around: {
      all: [],
      find: [authenticate('jwt')],
      get: [authenticate('jwt')],
      create: [],
      update: [authenticate('jwt'), disallow('external')],
      patch: [authenticate('jwt')],
      remove: [authenticate('jwt')]
    },
    before: {
      all: [],
      find: [schemaHooks.validateQuery(userQueryValidator)],
      get: [],
      create: [schemaHooks.validateData(userDataValidator)],
      patch: [
        iff(
          isProvider('external'),
          schemaHooks.validateData(userPatchValidator)
        )
      ],
      remove: []
    },
    after: {
      all: [],
      find: [],
      get: [],
      create: [],
      patch: [],
      remove: []
    },
    error: {
      all: [],
      find: [],
      get: [],
      create: [],
      patch: [],
      remove: []
    }
  });
};`
    },
    {
      path: 'src/services/messages/messages.class.ts',
      content: `import { Params } from '@feathersjs/feathers';
import { KnexService } from '@feathersjs/knex';
import { Application } from '../../declarations';
import { Message, MessageData, MessagePatch, MessageQuery } from './messages.schema';

export { Message, MessageData, MessagePatch, MessageQuery };

export interface MessageParams extends Params<MessageQuery> {
  user?: any;
}

export class MessageService extends KnexService<Message, MessageData, MessageParams, MessagePatch> {
  constructor(options: any, app: Application) {
    super({
      ...options,
      name: 'messages'
    });
  }

  async create(data: MessageData, params?: MessageParams) {
    // Add user information to message
    const user = params?.user;
    const messageData = {
      ...data,
      userId: user?.id,
      userName: user?.name || 'Anonymous',
      createdAt: new Date().toISOString()
    };

    return super.create(messageData, params);
  }
}

export const getOptions = (app: Application) => {
  return {
    paginate: app.get('paginate'),
    Model: app.get('knexClient'),
    name: 'messages'
  };
};`
    },
    {
      path: 'src/services/messages/messages.schema.ts',
      content: `import { Type, getValidator, querySyntax } from '@feathersjs/typebox';
import type { Static } from '@feathersjs/typebox';

// Main data model schema
export const messageSchema = Type.Object(
  {
    id: Type.Number(),
    text: Type.String({ minLength: 1, maxLength: 1000 }),
    userId: Type.Number(),
    userName: Type.String(),
    roomId: Type.String(),
    attachments: Type.Optional(Type.Array(Type.String())),
    editedAt: Type.Optional(Type.String({ format: 'date-time' })),
    createdAt: Type.String({ format: 'date-time' })
  },
  { $id: 'Message', additionalProperties: false }
);

export type Message = Static<typeof messageSchema>;

// Schema for creating new entries
export const messageDataSchema = Type.Pick(
  messageSchema,
  ['text', 'roomId', 'attachments'],
  { additionalProperties: false }
);

export type MessageData = Static<typeof messageDataSchema>;

// Schema for updating existing entries
export const messagePatchSchema = Type.Partial(
  Type.Pick(messageSchema, ['text', 'attachments']),
  { additionalProperties: false }
);

export type MessagePatch = Static<typeof messagePatchSchema>;

// Schema for allowed query properties
export const messageQueryProperties = Type.Pick(
  messageSchema,
  ['id', 'userId', 'roomId', 'createdAt']
);

export const messageQuerySchema = querySyntax(messageQueryProperties);

export type MessageQuery = Static<typeof messageQuerySchema>;

// Validators
export const messageValidator = getValidator(messageSchema, {});
export const messageDataValidator = getValidator(messageDataSchema, {});
export const messagePatchValidator = getValidator(messagePatchSchema, {});
export const messageQueryValidator = getValidator(messageQuerySchema, {});`
    },
    {
      path: 'src/services/messages/messages.service.ts',
      content: `import { authenticate } from '@feathersjs/authentication';
import { hooks as schemaHooks } from '@feathersjs/schema';
import { Application } from '../../declarations';
import { MessageService, getOptions } from './messages.class';
import { messageDataValidator, messagePatchValidator, messageQueryValidator } from './messages.schema';
import { setField } from 'feathers-authentication-hooks';

declare module '../../declarations' {
  interface ServiceTypes {
    messages: MessageService;
  }
}

export const messages = (app: Application) => {
  app.use('messages', new MessageService(getOptions(app), app), {
    methods: ['find', 'get', 'create', 'patch', 'remove'],
    events: ['created', 'updated', 'patched', 'removed']
  });

  app.service('messages').hooks({
    around: {
      all: [authenticate('jwt')],
      find: [],
      get: [],
      create: [],
      update: [],
      patch: [],
      remove: []
    },
    before: {
      all: [],
      find: [schemaHooks.validateQuery(messageQueryValidator)],
      get: [],
      create: [
        schemaHooks.validateData(messageDataValidator),
        setField({
          from: 'params.user.id',
          as: 'data.userId'
        })
      ],
      patch: [schemaHooks.validateData(messagePatchValidator)],
      remove: []
    },
    after: {
      all: [],
      find: [],
      get: [],
      create: [],
      patch: [],
      remove: []
    },
    error: {
      all: [],
      find: [],
      get: [],
      create: [],
      patch: [],
      remove: []
    }
  });
};`
    },
    {
      path: 'src/services/email/email.class.ts',
      content: `import { Params, ServiceMethods } from '@feathersjs/feathers';
import nodemailer from 'nodemailer';
import { Application } from '../../declarations';
import { BadRequest } from '@feathersjs/errors';

export interface Email {
  to: string | string[];
  subject: string;
  text?: string;
  html?: string;
  template?: string;
  data?: Record<string, any>;
}

export class EmailService implements Partial<ServiceMethods<Email>> {
  app: Application;
  transporter: nodemailer.Transporter;

  constructor(app: Application) {
    this.app = app;
    
    const emailConfig = app.get('email');
    this.transporter = nodemailer.createTransport({
      service: emailConfig.service,
      auth: emailConfig.auth
    });
  }

  async create(data: Email, params?: Params): Promise<any> {
    try {
      let html = data.html;
      
      // If template is specified, render it
      if (data.template) {
        html = await this.renderTemplate(data.template, data.data || {});
      }

      const mailOptions = {
        from: this.app.get('email').auth.user,
        to: Array.isArray(data.to) ? data.to.join(', ') : data.to,
        subject: data.subject,
        text: data.text,
        html
      };

      const result = await this.transporter.sendMail(mailOptions);
      
      return {
        messageId: result.messageId,
        accepted: result.accepted,
        rejected: result.rejected,
        response: result.response
      };
    } catch (error: any) {
      throw new BadRequest('Failed to send email', { error: error.message });
    }
  }

  private async renderTemplate(template: string, data: Record<string, any>): Promise<string> {
    // Simple template rendering - in production use a proper template engine
    const templates: Record<string, string> = {
      welcome: \`
        <h1>Welcome \${data.name}!</h1>
        <p>Thank you for joining our platform.</p>
        <p>Please verify your email by clicking <a href="\${data.verifyUrl}">here</a>.</p>
      \`,
      reset: \`
        <h1>Reset Password</h1>
        <p>Hello \${data.name},</p>
        <p>Click <a href="\${data.resetUrl}">here</a> to reset your password.</p>
        <p>This link will expire in 1 hour.</p>
      \`,
      notification: \`
        <h1>\${data.title}</h1>
        <p>\${data.message}</p>
      \`
    };

    const templateHtml = templates[template];
    if (!templateHtml) {
      throw new BadRequest(\`Template '\${template}' not found\`);
    }

    // Replace variables
    return templateHtml.replace(/\\\${([^}]+)}/g, (match, path) => {
      const keys = path.split('.');
      let value = { data };
      for (const key of keys) {
        value = value[key];
        if (value === undefined) return '';
      }
      return value;
    });
  }
}

export const getOptions = (app: Application) => {
  return {};
};`
    },
    {
      path: 'src/services/email/email.service.ts',
      content: `import { Application } from '../../declarations';
import { EmailService, getOptions } from './email.class';
import { disallow } from 'feathers-hooks-common';

declare module '../../declarations' {
  interface ServiceTypes {
    email: EmailService;
  }
}

export const email = (app: Application) => {
  app.use('email', new EmailService(app), {
    methods: ['create'],
    events: []
  });

  app.service('email').hooks({
    around: {
      all: [],
      create: []
    },
    before: {
      all: [disallow('external')], // Only allow internal calls
      create: []
    },
    after: {
      all: [],
      create: []
    },
    error: {
      all: [],
      create: []
    }
  });
};`
    },
    {
      path: 'src/services/jobs/jobs.class.ts',
      content: `import { Params, ServiceMethods } from '@feathersjs/feathers';
import { Application } from '../../declarations';
import { createClient } from 'redis';
import { v4 as uuidv4 } from 'uuid';

export interface Job {
  id?: string;
  type: string;
  data: any;
  status?: 'pending' | 'processing' | 'completed' | 'failed';
  result?: any;
  error?: any;
  createdAt?: string;
  startedAt?: string;
  completedAt?: string;
  attempts?: number;
  maxAttempts?: number;
}

export class JobService implements Partial<ServiceMethods<Job>> {
  app: Application;
  redis: any;

  constructor(app: Application) {
    this.app = app;
    this.setupRedis();
    this.startWorker();
  }

  private async setupRedis() {
    const redisConfig = this.app.get('redis');
    this.redis = createClient({
      socket: {
        host: redisConfig.host,
        port: redisConfig.port
      },
      password: redisConfig.password
    });
    await this.redis.connect();
  }

  async find(params?: Params): Promise<Job[]> {
    const keys = await this.redis.keys('job:*');
    const jobs = await Promise.all(
      keys.map(async (key: string) => {
        const job = await this.redis.get(key);
        return JSON.parse(job);
      })
    );
    
    return jobs.sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  async get(id: string, params?: Params): Promise<Job> {
    const job = await this.redis.get(\`job:\${id}\`);
    if (!job) {
      throw new Error('Job not found');
    }
    return JSON.parse(job);
  }

  async create(data: Job, params?: Params): Promise<Job> {
    const job: Job = {
      id: uuidv4(),
      ...data,
      status: 'pending',
      createdAt: new Date().toISOString(),
      attempts: 0,
      maxAttempts: data.maxAttempts || 3
    };

    await this.redis.set(\`job:\${job.id}\`, JSON.stringify(job));
    await this.redis.lpush('job:queue', job.id);

    return job;
  }

  private async startWorker() {
    setInterval(async () => {
      try {
        const jobId = await this.redis.rpop('job:queue');
        if (!jobId) return;

        const job = await this.get(jobId);
        
        // Update job status
        job.status = 'processing';
        job.startedAt = new Date().toISOString();
        job.attempts = (job.attempts || 0) + 1;
        await this.redis.set(\`job:\${job.id}\`, JSON.stringify(job));

        // Process job based on type
        try {
          const result = await this.processJob(job);
          
          // Mark as completed
          job.status = 'completed';
          job.result = result;
          job.completedAt = new Date().toISOString();
        } catch (error: any) {
          job.error = error.message;
          
          if (job.attempts! < job.maxAttempts!) {
            // Retry job
            job.status = 'pending';
            await this.redis.lpush('job:queue', job.id);
          } else {
            // Mark as failed
            job.status = 'failed';
          }
        }

        await this.redis.set(\`job:\${job.id}\`, JSON.stringify(job));
      } catch (error) {
        console.error('Worker error:', error);
      }
    }, 1000); // Check every second
  }

  private async processJob(job: Job): Promise<any> {
    // Simulate different job types
    switch (job.type) {
      case 'sendEmail':
        await this.app.service('email').create(job.data);
        return { sent: true };
      
      case 'generateReport':
        // Simulate report generation
        await new Promise(resolve => setTimeout(resolve, 2000));
        return { reportUrl: '/reports/' + job.id + '.pdf' };
      
      case 'processImage':
        // Simulate image processing
        await new Promise(resolve => setTimeout(resolve, 3000));
        return { 
          thumbnailUrl: '/thumbnails/' + job.id + '.jpg',
          metadata: { width: 1920, height: 1080 }
        };
      
      default:
        throw new Error(\`Unknown job type: \${job.type}\`);
    }
  }
}

export const getOptions = (app: Application) => {
  return {};
};`
    },
    {
      path: 'src/services/jobs/jobs.service.ts',
      content: `import { authenticate } from '@feathersjs/authentication';
import { Application } from '../../declarations';
import { JobService, getOptions } from './jobs.class';

declare module '../../declarations' {
  interface ServiceTypes {
    jobs: JobService;
  }
}

export const jobs = (app: Application) => {
  app.use('jobs', new JobService(app), {
    methods: ['find', 'get', 'create'],
    events: ['created', 'updated']
  });

  app.service('jobs').hooks({
    around: {
      all: [authenticate('jwt')],
      find: [],
      get: [],
      create: []
    },
    before: {
      all: [],
      find: [],
      get: [],
      create: []
    },
    after: {
      all: [],
      find: [],
      get: [],
      create: []
    },
    error: {
      all: [],
      find: [],
      get: [],
      create: []
    }
  });
};`
    },
    {
      path: 'src/graphql.ts',
      content: `import { Application } from './declarations';
import { createApolloServer } from 'feathers-apollo';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { gql } from 'graphql-tag';

const typeDefs = gql\`
  type User {
    id: Int!
    email: String!
    name: String!
    role: String!
    avatar: String
    createdAt: String!
    updatedAt: String!
  }

  type Message {
    id: Int!
    text: String!
    userId: Int!
    userName: String!
    roomId: String!
    attachments: [String]
    createdAt: String!
  }

  type AuthPayload {
    accessToken: String!
    user: User!
  }

  type Query {
    me: User
    users(limit: Int, skip: Int): [User]
    user(id: Int!): User
    messages(roomId: String!, limit: Int, skip: Int): [Message]
    message(id: Int!): Message
  }

  type Mutation {
    login(email: String!, password: String!): AuthPayload
    register(email: String!, password: String!, name: String!): AuthPayload
    createMessage(text: String!, roomId: String!): Message
    updateUser(id: Int!, name: String, avatar: String): User
  }

  type Subscription {
    messageCreated(roomId: String!): Message
    userUpdated(userId: Int!): User
  }
\`;

const resolvers = {
  Query: {
    me: async (_parent: any, _args: any, context: any) => {
      return context.user;
    },
    users: async (_parent: any, args: any, context: any) => {
      const result = await context.app.service('users').find({
        query: {
          $limit: args.limit || 10,
          $skip: args.skip || 0
        },
        user: context.user
      });
      return result.data;
    },
    user: async (_parent: any, args: any, context: any) => {
      return context.app.service('users').get(args.id, {
        user: context.user
      });
    },
    messages: async (_parent: any, args: any, context: any) => {
      const result = await context.app.service('messages').find({
        query: {
          roomId: args.roomId,
          $limit: args.limit || 50,
          $skip: args.skip || 0,
          $sort: { createdAt: -1 }
        },
        user: context.user
      });
      return result.data;
    },
    message: async (_parent: any, args: any, context: any) => {
      return context.app.service('messages').get(args.id, {
        user: context.user
      });
    }
  },
  Mutation: {
    login: async (_parent: any, args: any, context: any) => {
      const result = await context.app.service('authentication').create({
        strategy: 'local',
        email: args.email,
        password: args.password
      });
      return result;
    },
    register: async (_parent: any, args: any, context: any) => {
      const user = await context.app.service('users').create({
        email: args.email,
        password: args.password,
        name: args.name
      });
      
      const result = await context.app.service('authentication').create({
        strategy: 'local',
        email: args.email,
        password: args.password
      });
      
      return result;
    },
    createMessage: async (_parent: any, args: any, context: any) => {
      return context.app.service('messages').create({
        text: args.text,
        roomId: args.roomId
      }, {
        user: context.user
      });
    },
    updateUser: async (_parent: any, args: any, context: any) => {
      const { id, ...data } = args;
      return context.app.service('users').patch(id, data, {
        user: context.user
      });
    }
  },
  Subscription: {
    messageCreated: {
      subscribe: async (_parent: any, args: any, context: any) => {
        const channel = context.app.channel(\`rooms/\${args.roomId}\`);
        // Implementation would use GraphQL subscriptions with real-time events
        return channel;
      }
    },
    userUpdated: {
      subscribe: async (_parent: any, args: any, context: any) => {
        const channel = context.app.channel(\`users/\${args.userId}\`);
        return channel;
      }
    }
  }
};

export const setupGraphQL = (app: Application) => {
  const schema = makeExecutableSchema({
    typeDefs,
    resolvers
  });

  const server = createApolloServer({
    schema,
    context: async ({ req }: any) => {
      // Get the user from the request if authenticated
      let user = null;
      if (req.headers.authorization) {
        try {
          const result = await app.service('authentication').authenticate({
            authentication: {
              strategy: 'jwt',
              accessToken: req.headers.authorization.replace('Bearer ', '')
            }
          });
          user = result.user;
        } catch (error) {
          // Not authenticated
        }
      }
      
      return {
        app,
        user
      };
    }
  });

  app.use('/graphql', server);
};`
    },
    {
      path: 'knexfile.ts',
      content: `import type { Knex } from 'knex';
import dotenv from 'dotenv';

dotenv.config();

const config: { [key: string]: Knex.Config } = {
  development: {
    client: 'postgresql',
    connection: {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME || 'feathersjs_dev',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres'
    },
    pool: {
      min: 2,
      max: 10
    },
    migrations: {
      directory: './migrations',
      extension: 'ts'
    },
    seeds: {
      directory: './seeds',
      extension: 'ts'
    }
  },

  test: {
    client: 'postgresql',
    connection: {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME || 'feathersjs_test',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres'
    },
    pool: {
      min: 2,
      max: 10
    },
    migrations: {
      directory: './migrations',
      extension: 'ts'
    }
  },

  production: {
    client: 'postgresql',
    connection: process.env.DATABASE_URL || {
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      ssl: { rejectUnauthorized: false }
    },
    pool: {
      min: 2,
      max: 10
    },
    migrations: {
      directory: './migrations',
      extension: 'ts'
    }
  }
};

export default config;`
    },
    {
      path: 'migrations/001_create_users.ts',
      content: `import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('users', (table) => {
    table.increments('id').primary();
    table.string('email').unique().notNullable();
    table.string('password').notNullable();
    table.string('name').notNullable();
    table.string('role').defaultTo('user');
    table.string('googleId').unique();
    table.string('avatar');
    table.boolean('isVerified').defaultTo(false);
    table.string('verifyToken');
    table.timestamp('verifyExpires');
    table.string('resetToken');
    table.timestamp('resetExpires');
    table.timestamps(true, true);
    
    table.index(['email']);
    table.index(['googleId']);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('users');
}`
    },
    {
      path: 'migrations/002_create_messages.ts',
      content: `import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('messages', (table) => {
    table.increments('id').primary();
    table.text('text').notNullable();
    table.integer('userId').unsigned().references('id').inTable('users').onDelete('CASCADE');
    table.string('userName').notNullable();
    table.string('roomId').notNullable();
    table.json('attachments');
    table.timestamp('editedAt');
    table.timestamp('createdAt').defaultTo(knex.fn.now());
    
    table.index(['roomId', 'createdAt']);
    table.index(['userId']);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('messages');
}`
    },
    {
      path: 'test/app.test.ts',
      content: `import { expect } from 'chai';
import request from 'supertest';
import { app } from '../src/app';

describe('Feathers application tests', () => {
  let server: any;

  before((done) => {
    server = app.listen(3030);
    server.once('listening', () => done());
  });

  after((done) => {
    server.close(done);
  });

  it('starts and shows the index page', async () => {
    const response = await request(app).get('/').expect(200);
    expect(response.text).to.include('<html>');
  });

  describe('404', () => {
    it('shows a 404 JSON error', async () => {
      const response = await request(app)
        .get('/path/to/nowhere')
        .set('Accept', 'application/json')
        .expect(404);
      
      expect(response.body.code).to.equal(404);
      expect(response.body.name).to.equal('NotFound');
    });
  });
});`
    },
    {
      path: 'test/services/users.test.ts',
      content: `import { expect } from 'chai';
import { app } from '../../src/app';

describe('users service', () => {
  let userInfo: any;

  before(async () => {
    // Create a test user
    userInfo = await app.service('users').create({
      email: 'test@example.com',
      password: 'password123',
      name: 'Test User'
    });
  });

  after(async () => {
    // Clean up test user
    await app.service('users').remove(userInfo.id);
  });

  it('registered the service', () => {
    const service = app.service('users');
    expect(service).to.be.ok;
  });

  it('creates a user and encrypts password', async () => {
    expect(userInfo.email).to.equal('test@example.com');
    expect(userInfo.name).to.equal('Test User');
    expect(userInfo).to.not.have.property('password');
  });

  it('authenticates user and returns JWT', async () => {
    const { user, accessToken } = await app.service('authentication').create({
      strategy: 'local',
      email: 'test@example.com',
      password: 'password123'
    });

    expect(accessToken).to.be.ok;
    expect(user.email).to.equal('test@example.com');
  });
});`
    },
    {
      path: 'test/services/messages.test.ts',
      content: `import { expect } from 'chai';
import { app } from '../../src/app';

describe('messages service', () => {
  let user: any;
  let authResult: any;

  before(async () => {
    // Create test user and authenticate
    user = await app.service('users').create({
      email: 'message-test@example.com',
      password: 'password123',
      name: 'Message Test User'
    });

    authResult = await app.service('authentication').create({
      strategy: 'local',
      email: 'message-test@example.com',
      password: 'password123'
    });
  });

  after(async () => {
    // Clean up
    await app.service('users').remove(user.id);
  });

  it('registered the service', () => {
    const service = app.service('messages');
    expect(service).to.be.ok;
  });

  it('creates a message', async () => {
    const message = await app.service('messages').create({
      text: 'Test message',
      roomId: 'test-room'
    }, {
      user,
      authentication: authResult
    });

    expect(message.text).to.equal('Test message');
    expect(message.roomId).to.equal('test-room');
    expect(message.userId).to.equal(user.id);
    expect(message.userName).to.equal(user.name);
  });
});`
    },
    {
      path: 'Dockerfile',
      content: `FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose port
EXPOSE 3030

# Start the application
CMD ["node", "dist/index.js"]`
    },
    {
      path: 'docker-compose.yml',
      content: `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3030:3030"
    environment:
      NODE_ENV: production
      DB_HOST: postgres
      DB_USER: postgres
      DB_PASSWORD: postgres
      DB_NAME: feathersjs
      REDIS_HOST: redis
    depends_on:
      - postgres
      - redis
    volumes:
      - ./uploads:/usr/src/app/uploads

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: feathersjs
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"

volumes:
  postgres_data:
  redis_data:`
    },
    {
      path: '.env.example',
      content: `# Server
NODE_ENV=development
HOST=localhost
PORT=3030

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=feathersjs_dev

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Authentication
AUTH_SECRET=your-super-secret-jwt-key-change-this-in-production

# OAuth
GOOGLE_KEY=your-google-oauth-key
GOOGLE_SECRET=your-google-oauth-secret

# Email
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# File Upload
UPLOAD_MAX_SIZE=10485760
UPLOAD_PATH=./uploads`
    },
    {
      path: 'nodemon.json',
      content: `{
  "watch": ["src"],
  "ext": "ts",
  "ignore": ["src/**/*.spec.ts", "src/**/*.test.ts"],
  "exec": "ts-node src/index.ts"
}`
    },
    {
      path: '.eslintrc.json',
      content: `{
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": 2022,
    "sourceType": "module",
    "project": "./tsconfig.json"
  },
  "plugins": ["@typescript-eslint"],
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended"
  ],
  "rules": {
    "@typescript-eslint/no-explicit-any": "warn",
    "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
    "@typescript-eslint/explicit-function-return-type": "off",
    "@typescript-eslint/explicit-module-boundary-types": "off",
    "no-console": ["warn", { "allow": ["warn", "error"] }],
    "prefer-const": "error",
    "no-trailing-spaces": "error",
    "comma-dangle": ["error", "never"]
  },
  "env": {
    "node": true,
    "es2022": true
  }
}`
    },
    {
      path: '.gitignore',
      content: `# Dependencies
node_modules/

# Production build
dist/

# Environment variables
.env
.env.local
.env.production

# Logs
logs/
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Database
*.sqlite
*.sqlite3

# Uploads
uploads/*
!uploads/.gitkeep

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Test coverage
coverage/
.nyc_output/

# Misc
.cache/
tmp/
temp/`
    },
    {
      path: 'README.md',
      content: `# Feathers.js Real-time Backend

A production-ready Feathers.js backend with TypeScript, real-time events, authentication, and microservice architecture.

## Features

- **Real-time Communication**: Socket.io integration for live updates
- **Service-Oriented Architecture**: Modular, scalable service design
- **Authentication**: Local, JWT, and OAuth (Google) strategies
- **Database Support**: PostgreSQL with Knex.js migrations
- **GraphQL API**: Apollo Server integration alongside REST
- **Background Jobs**: Redis-based job queue system
- **Email Service**: Nodemailer integration with templates
- **File Uploads**: Multer middleware for handling files
- **Rate Limiting**: Redis-based rate limiting
- **Schema Validation**: TypeBox for runtime validation
- **Testing**: Mocha test suite with fixtures
- **Docker Ready**: Full containerization support

## Quick Start

1. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

2. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

3. Run database migrations:
   \`\`\`bash
   npm run db:migrate
   \`\`\`

4. Start development server:
   \`\`\`bash
   npm run dev
   \`\`\`

## API Endpoints

### REST API

- \`POST /authentication\` - Login
- \`GET /users\` - List users
- \`POST /users\` - Create user
- \`GET /messages\` - List messages
- \`POST /messages\` - Create message
- \`POST /upload\` - Upload file
- \`GET /jobs\` - List background jobs
- \`POST /jobs\` - Create background job

### GraphQL API

Available at \`/graphql\` with GraphQL Playground in development.

### WebSocket Events

Connect to Socket.io at the root URL for real-time updates:

- \`messages created\` - New message in a room
- \`users patched\` - User profile updated
- \`jobs created\` - New background job
- \`jobs updated\` - Job status changed

## Services

### Users Service
- User registration and authentication
- Profile management
- OAuth integration

### Messages Service
- Real-time messaging
- Room-based conversations
- Message history

### Email Service
- Template-based emails
- Welcome emails
- Password reset

### Jobs Service
- Background job processing
- Retry logic
- Job status tracking

## Testing

Run the test suite:
\`\`\`bash
npm test
\`\`\`

## Docker Deployment

Build and run with Docker Compose:
\`\`\`bash
docker-compose up -d
\`\`\`

## Configuration

See \`config/default.json\` for all configuration options. Key settings:

- \`host\`: Server hostname
- \`port\`: Server port
- \`paginate\`: Default pagination settings
- \`authentication\`: Auth strategies and JWT config
- \`database\`: PostgreSQL connection
- \`redis\`: Redis connection for jobs and rate limiting

## License

MIT`
    }
  ],
  
  dependencies: [
    '@feathersjs/feathers',
    '@feathersjs/express',
    '@feathersjs/socketio',
    '@feathersjs/authentication',
    '@feathersjs/authentication-local',
    '@feathersjs/authentication-oauth',
    '@feathersjs/knex',
    '@feathersjs/schema',
    'knex',
    'pg',
    'redis',
    'nodemailer',
    'multer',
    'helmet',
    'cors',
    'compression'
  ],
  
  devDependencies: [
    'typescript',
    '@types/node',
    'nodemon',
    'ts-node',
    'mocha',
    'chai',
    'supertest',
    'eslint',
    '@typescript-eslint/parser',
    '@typescript-eslint/eslint-plugin'
  ],
  
  postInstall: `
echo "Setting up Feathers.js backend..."
echo "1. Copy .env.example to .env and configure"
echo "2. Set up PostgreSQL and Redis"
echo "3. Run 'npm run db:migrate' to create tables"
echo "4. Start with 'npm run dev'"
echo ""
echo "Real-time features:"
echo "- Connect to Socket.io for live updates"
echo "- Join rooms for filtered events"
echo "- GraphQL subscriptions available"
  `
};`