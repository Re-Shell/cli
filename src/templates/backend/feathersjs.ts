import { BackendTemplate } from '../types';

export const feathersjsTemplate: BackendTemplate = {
  id: 'feathersjs',
  name: 'Feathers.js',
  displayName: 'Feathers.js',
  description: 'Real-time, micro-service ready web framework with TypeScript',
  language: 'typescript',
  framework: 'feathersjs',
  version: '5.0.11',
  tags: ['real-time', 'microservices', 'rest', 'websockets', 'typescript'],
  port: 3030,
  dependencies: {
    '@feathersjs/authentication': '^5.0.11',
    '@feathersjs/authentication-local': '^5.0.11',
    '@feathersjs/authentication-oauth': '^5.0.11',
    '@feathersjs/configuration': '^5.0.11',
    '@feathersjs/errors': '^5.0.11',
    '@feathersjs/express': '^5.0.11',
    '@feathersjs/feathers': '^5.0.11',
    '@feathersjs/knex': '^5.0.11',
    '@feathersjs/schema': '^5.0.11',
    '@feathersjs/socketio': '^5.0.11',
    '@feathersjs/transport-commons': '^5.0.11',
    '@feathersjs/typebox': '^5.0.11',
    'compression': '^1.7.4',
    'cors': '^2.8.5',
    'dotenv': '^16.3.1',
    'feathers-apollo': '^1.2.0',
    'graphql': '^16.8.1',
    'helmet': '^7.1.0',
    'jsonwebtoken': '^9.0.2',
    'knex': '^3.0.1',
    'multer': '^1.4.5-lts.1',
    'nodemailer': '^6.9.7',
    'pg': '^8.11.3',
    'rate-limiter-flexible': '^3.0.0',
    'redis': '^4.6.10',
    'socket.io': '^4.6.2',
    'winston': '^3.11.0'
  },
  features: ['authentication', 'real-time', 'rest-api', 'graphql', 'websockets', 'database', 'typescript'],
  files: {
    'package.json': `{
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
}`,
    'src/index.ts': `import { app } from './app';
import { logger } from './logger';

const port = app.get('port');
const host = app.get('host');

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection', reason);
  process.exit(1);
});

app.listen(port).then(() => {
  logger.info(\`Feathers application started on http://\${host}:\${port}\`);
});`,
    'src/app.ts': `import { feathers } from '@feathersjs/feathers';
import express, { rest, json, urlencoded, cors, serveStatic, notFound, errorHandler } from '@feathersjs/express';
import configuration from '@feathersjs/configuration';
import socketio from '@feathersjs/socketio';
import { configurationValidator } from './configuration';
import type { Application } from './declarations';

import { logger } from './logger';
import { services } from './services';
import { channels } from './channels';
import { authentication } from './authentication';
import { logError } from './hooks/log-error';
import { rateLimiter } from './middleware/rate-limiter';
import { setupFileUpload } from './middleware/file-upload';
import { setupGraphQL } from './graphql';

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

// Set up our services (see \`services/index.ts\`)
app.configure(services);

// Set up GraphQL
app.configure(setupGraphQL);

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

export { app };`,
    'src/declarations.ts': `import { Application as ExpressFeathers } from '@feathersjs/express';
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
}`,
    'src/configuration.ts': `import { Type, getValidator } from '@feathersjs/typebox';
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

export const configurationValidator = getValidator(configurationSchema, {});`,
    'src/logger.ts': `import winston from 'winston';

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
  }
};