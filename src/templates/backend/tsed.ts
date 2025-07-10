import { BackendTemplate } from '../types';

export const tsedTemplate: BackendTemplate = {
  id: 'tsed',
  name: 'Ts.ED',
  displayName: 'Ts.ED',
  description: 'TypeScript framework built on Express/Koa with decorators, DI, and enterprise features',
  language: 'typescript',
  framework: 'tsed',
  version: '7.0.0',
  tags: ['typescript', 'decorators', 'di', 'express', 'openapi'],
  features: [
    'TypeScript decorators',
    'Dependency injection',
    'OpenAPI/Swagger',
    'GraphQL support',
    'WebSocket (Socket.io)',
    'Passport.js auth',
    'TypeORM integration',
    'Exception filters',
    'Interceptors (AOP)',
    'Model validation',
    'Testing framework',
    'Docker support'
  ],
  dependencies: {
    '@tsed/common': '^7.0.0',
    '@tsed/core': '^7.0.0',
    '@tsed/di': '^7.0.0',
    '@tsed/exceptions': '^7.0.0',
    '@tsed/json-mapper': '^7.0.0',
    '@tsed/platform-express': '^7.0.0',
    '@tsed/schema': '^7.0.0',
    '@tsed/swagger': '^7.0.0',
    '@tsed/typeorm': '^7.0.0',
    '@tsed/passport': '^7.0.0',
    '@tsed/socketio': '^7.0.0',
    '@tsed/graphql': '^7.0.0',
    '@tsed/apollo': '^7.0.0',
    '@tsed/ajv': '^7.0.0',
    '@tsed/testing': '^7.0.0',
    'express': '^4.18.2',
    'cors': '^2.8.5',
    'helmet': '^7.0.0',
    'compression': '^1.7.4',
    'cookie-parser': '^1.4.6',
    'express-session': '^1.17.3',
    'typeorm': '^0.3.17',
    'reflect-metadata': '^0.1.13',
    'class-transformer': '^0.5.1',
    'class-validator': '^0.14.0',
    'passport': '^0.6.0',
    'passport-local': '^1.0.0',
    'passport-jwt': '^4.0.1',
    'jsonwebtoken': '^9.0.2',
    'bcrypt': '^5.1.1',
    'socket.io': '^4.6.2',
    'graphql': '^16.6.0',
    'apollo-server-express': '^3.12.0',
    'type-graphql': '^2.0.0-beta.1',
    'dotenv': '^16.3.1',
    'winston': '^3.10.0',
    'sqlite3': '^5.1.6'
  },
  devDependencies: {
    '@types/node': '^20.0.0',
    '@types/express': '^4.17.17',
    '@types/cors': '^2.8.13',
    '@types/compression': '^1.7.2',
    '@types/cookie-parser': '^1.4.3',
    '@types/express-session': '^1.17.7',
    '@types/passport': '^1.0.12',
    '@types/passport-local': '^1.0.35',
    '@types/passport-jwt': '^3.0.9',
    '@types/jsonwebtoken': '^9.0.2',
    '@types/bcrypt': '^5.0.0',
    '@types/jest': '^29.5.2',
    '@types/supertest': '^2.0.12',
    'typescript': '^5.0.0',
    'ts-node': '^10.9.1',
    'ts-node-dev': '^2.0.0',
    'jest': '^29.5.0',
    'ts-jest': '^29.1.0',
    'supertest': '^6.3.3',
    '@typescript-eslint/eslint-plugin': '^5.59.0',
    '@typescript-eslint/parser': '^5.59.0',
    'eslint': '^8.38.0',
    'prettier': '^2.8.7'
  },
  scripts: {
    'dev': 'ts-node-dev --respawn --transpile-only --exit-child src/index.ts',
    'build': 'tsc',
    'start': 'node dist/index.js',
    'test': 'jest',
    'test:watch': 'jest --watch',
    'test:coverage': 'jest --coverage',
    'lint': 'eslint "src/**/*.ts"',
    'format': 'prettier --write "src/**/*.ts"',
    'migration:run': 'typeorm migration:run',
    'migration:revert': 'typeorm migration:revert',
    'docker:build': 'docker build -t tsed-app .',
    'docker:run': 'docker run -p 3000:3000 tsed-app'
  },
  files: {
    'src/index.ts': `import { $log } from '@tsed/common';
import { PlatformExpress } from '@tsed/platform-express';
import { Server } from './Server';

async function bootstrap() {
  try {
    const platform = await PlatformExpress.bootstrap(Server, {
      // Platform options
    });
    
    await platform.listen();
    $log.info('Server initialized');
  } catch (error) {
    $log.error({ event: 'SERVER_BOOTSTRAP_ERROR', error });
    process.exit(1);
  }
}

bootstrap();
`,
    'src/Server.ts': `import { Configuration, Inject } from '@tsed/di';
import { PlatformApplication } from '@tsed/common';
import '@tsed/platform-express';
import '@tsed/ajv';
import '@tsed/swagger';
import '@tsed/typeorm';
import '@tsed/passport';
import '@tsed/socketio';
import '@tsed/graphql';
import '@tsed/apollo';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { config } from './config';
import * as rest from './controllers/rest';
import * as socket from './controllers/socket';
import * as pages from './controllers/pages';

@Configuration({
  ...config,
  acceptMimes: ['application/json'],
  httpPort: process.env.PORT || 3000,
  httpsPort: false,
  componentsScan: [
    \`\${__dirname}/protocols/*.ts\`,
    \`\${__dirname}/services/**/*.ts\`,
    \`\${__dirname}/middlewares/**/*.ts\`,
    \`\${__dirname}/filters/**/*.ts\`,
    \`\${__dirname}/decorators/**/*.ts\`,
    \`\${__dirname}/interceptors/**/*.ts\`
  ],
  mount: {
    '/api': [...Object.values(rest)],
    '/ws': [...Object.values(socket)],
    '/': [...Object.values(pages)]
  },
  swagger: [
    {
      path: '/api-docs',
      specVersion: '3.0.1',
      spec: {
        info: {
          title: 'Ts.ED API',
          version: '1.0.0',
          description: 'API documentation for Ts.ED application'
        }
      }
    }
  ],
  typeorm: [
    {
      name: 'default',
      type: 'sqlite',
      database: './db.sqlite',
      synchronize: true,
      logging: false,
      entities: [
        \`\${__dirname}/entities/**/*.ts\`
      ],
      migrations: [
        \`\${__dirname}/migrations/**/*.ts\`
      ],
      subscribers: [
        \`\${__dirname}/subscribers/**/*.ts\`
      ]
    }
  ],
  passport: {
    userInfoModel: 'UserInfo'
  },
  socketIO: {
    cors: {
      origin: '*',
      credentials: true
    }
  },
  graphql: {
    server1: {
      path: '/graphql',
      playground: true,
      schema: \`\${__dirname}/graphql/schema.graphql\`,
      resolvers: [
        \`\${__dirname}/graphql/resolvers/**/*.ts\`
      ]
    }
  },
  logger: {
    level: 'debug',
    logRequest: true,
    requestFields: ['reqId', 'method', 'url', 'headers', 'body', 'query', 'params', 'duration']
  },
  exclude: [
    '**/*.spec.ts'
  ]
})
export class Server {
  @Inject()
  protected app: PlatformApplication;

  @Configuration()
  protected settings: Configuration;

  $beforeRoutesInit() {
    this.app
      .use(helmet())
      .use(cors())
      .use(compression())
      .use(cookieParser())
      .use(session({
        secret: process.env.SESSION_SECRET || 'default-secret',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }
      }));
  }
}
`,
    'src/config/index.ts': `import { readFileSync } from 'fs';
import { envs } from './envs';
import loggerConfig from './logger';
import { resolve } from 'path';

const pkg = JSON.parse(readFileSync('./package.json', { encoding: 'utf8' }));

export const config: Partial<TsED.Configuration> = {
  version: pkg.version,
  envs,
  logger: loggerConfig,
  rootDir: resolve(__dirname, '..'),
  statics: {
    '/': [
      {
        root: \`./public\`,
        maxAge: '1d'
      }
    ]
  }
};
`,
    'src/config/envs/index.ts': `export const envs = {
  production: process.env.NODE_ENV === 'production',
  development: process.env.NODE_ENV === 'development',
  test: process.env.NODE_ENV === 'test'
};
`,
    'src/config/logger/index.ts': `export default {
  disableRoutesSummary: false,
  format: process.env.NODE_ENV === 'production' ? 'json' : 'dev',
  jsonIndentation: process.env.NODE_ENV === 'production' ? 0 : 2,
  level: process.env.LOG_LEVEL || 'debug',
  logRequest: true,
  logStart: true
};
`,
    'src/controllers/rest/index.ts': `export * from './UserController';
export * from './AuthController';
export * from './ProductController';
`,
    'src/controllers/rest/UserController.ts': `import { Controller, Get, Post, Put, Delete, PathParams, BodyParams } from '@tsed/common';
import { Inject } from '@tsed/di';
import { NotFound } from '@tsed/exceptions';
import { Summary, Returns, ReturnsArray, Groups, Required, Description } from '@tsed/schema';
import { Authorize } from '@tsed/passport';
import { UserService } from '../../services/UserService';
import { User } from '../../entities/User';
import { CreateUserDto, UpdateUserDto } from '../../dto/UserDto';

@Controller('/users')
export class UserController {
  @Inject()
  private userService: UserService;

  @Get('/')
  @Summary('Get all users')
  @ReturnsArray(User)
  async getAll(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Get('/:id')
  @Summary('Get user by ID')
  @Returns(User)
  @Returns(404).Description('User not found')
  async getById(@PathParams('id') id: string): Promise<User> {
    const user = await this.userService.findById(id);
    
    if (!user) {
      throw new NotFound('User not found');
    }
    
    return user;
  }

  @Post('/')
  @Summary('Create new user')
  @Returns(201, User)
  @Returns(400).Description('Invalid user data')
  async create(@Required() @BodyParams() @Groups('creation') dto: CreateUserDto): Promise<User> {
    return this.userService.create(dto);
  }

  @Put('/:id')
  @Summary('Update user')
  @Authorize('jwt')
  @Returns(User)
  @Returns(404).Description('User not found')
  async update(
    @PathParams('id') id: string,
    @Required() @BodyParams() @Groups('update') dto: UpdateUserDto
  ): Promise<User> {
    const user = await this.userService.update(id, dto);
    
    if (!user) {
      throw new NotFound('User not found');
    }
    
    return user;
  }

  @Delete('/:id')
  @Summary('Delete user')
  @Authorize('jwt')
  @Returns(204)
  @Returns(404).Description('User not found')
  async delete(@PathParams('id') id: string): Promise<void> {
    const deleted = await this.userService.delete(id);
    
    if (!deleted) {
      throw new NotFound('User not found');
    }
  }
}
`,
    'src/controllers/rest/AuthController.ts': `import { Controller, Post, BodyParams, Req, Res, Get } from '@tsed/common';
import { Inject } from '@tsed/di';
import { Authenticate, Authorize } from '@tsed/passport';
import { Returns, Required, Security } from '@tsed/schema';
import { Unauthorized } from '@tsed/exceptions';
import { AuthService } from '../../services/AuthService';
import { LoginDto, RegisterDto, TokenResponse } from '../../dto/AuthDto';
import { User } from '../../entities/User';

@Controller('/auth')
export class AuthController {
  @Inject()
  private authService: AuthService;

  @Post('/login')
  @Authenticate('local')
  @Returns(200, TokenResponse)
  @Returns(401).Description('Invalid credentials')
  async login(@Req() req: Req, @Required() @BodyParams() credentials: LoginDto): Promise<TokenResponse> {
    const user = req.user as User;
    
    if (!user) {
      throw new Unauthorized('Invalid credentials');
    }
    
    return this.authService.generateToken(user);
  }

  @Post('/register')
  @Returns(201, User)
  @Returns(400).Description('Invalid registration data')
  async register(@Required() @BodyParams() dto: RegisterDto): Promise<User> {
    return this.authService.register(dto);
  }

  @Get('/profile')
  @Authorize('jwt')
  @Security('jwt')
  @Returns(User)
  @Returns(401).Description('Unauthorized')
  async getProfile(@Req() req: Req): Promise<User> {
    return req.user as User;
  }

  @Post('/logout')
  @Authorize('jwt')
  @Returns(204)
  async logout(@Req() req: Req, @Res() res: Res): Promise<void> {
    req.logout(() => {
      res.status(204).send();
    });
  }
}
`,
    'src/controllers/rest/ProductController.ts': `import { Controller, Get, Post, Put, Delete, PathParams, BodyParams, QueryParams } from '@tsed/common';
import { Inject } from '@tsed/di';
import { NotFound } from '@tsed/exceptions';
import { Summary, Returns, ReturnsArray, Required, Min, Max } from '@tsed/schema';
import { UseCache } from '../../decorators/UseCache';
import { ValidateQuery } from '../../decorators/ValidateQuery';
import { ProductService } from '../../services/ProductService';
import { Product } from '../../entities/Product';
import { CreateProductDto, UpdateProductDto, ProductQueryDto } from '../../dto/ProductDto';

@Controller('/products')
export class ProductController {
  @Inject()
  private productService: ProductService;

  @Get('/')
  @Summary('Get products with pagination and filtering')
  @ReturnsArray(Product)
  @UseCache({ ttl: 300 })
  async getProducts(@QueryParams() @ValidateQuery() query: ProductQueryDto): Promise<Product[]> {
    return this.productService.findWithFilters(query);
  }

  @Get('/:id')
  @Summary('Get product by ID')
  @Returns(Product)
  @Returns(404).Description('Product not found')
  @UseCache({ ttl: 600 })
  async getById(@PathParams('id') id: string): Promise<Product> {
    const product = await this.productService.findById(id);
    
    if (!product) {
      throw new NotFound('Product not found');
    }
    
    return product;
  }

  @Post('/')
  @Summary('Create new product')
  @Returns(201, Product)
  @Returns(400).Description('Invalid product data')
  async create(@Required() @BodyParams() dto: CreateProductDto): Promise<Product> {
    return this.productService.create(dto);
  }

  @Put('/:id')
  @Summary('Update product')
  @Returns(Product)
  @Returns(404).Description('Product not found')
  async update(
    @PathParams('id') id: string,
    @Required() @BodyParams() dto: UpdateProductDto
  ): Promise<Product> {
    const product = await this.productService.update(id, dto);
    
    if (!product) {
      throw new NotFound('Product not found');
    }
    
    return product;
  }

  @Delete('/:id')
  @Summary('Delete product')
  @Returns(204)
  @Returns(404).Description('Product not found')
  async delete(@PathParams('id') id: string): Promise<void> {
    const deleted = await this.productService.delete(id);
    
    if (!deleted) {
      throw new NotFound('Product not found');
    }
  }
}
`,
    'src/controllers/socket/index.ts': `export * from './ChatSocketController';
export * from './NotificationSocketController';
`,
    'src/controllers/socket/ChatSocketController.ts': `import { SocketController, Input, Emit, Args, Socket, Nsp } from '@tsed/socketio';
import { Inject } from '@tsed/di';
import { Namespace, Socket as IOSocket } from 'socket.io';
import { ChatService } from '../../services/ChatService';
import { Message, JoinRoomDto, SendMessageDto } from '../../dto/ChatDto';

@SocketController('/chat')
export class ChatSocketController {
  @Inject()
  private chatService: ChatService;

  @Input('join-room')
  @Emit('user-joined')
  async joinRoom(@Args(0) data: JoinRoomDto, @Socket() socket: IOSocket, @Nsp() nsp: Namespace) {
    await socket.join(data.room);
    
    const message = await this.chatService.createSystemMessage({
      room: data.room,
      content: \`\${data.username} joined the room\`
    });
    
    nsp.to(data.room).emit('message', message);
    
    return { room: data.room, username: data.username };
  }

  @Input('send-message')
  @Emit('message')
  async sendMessage(@Args(0) data: SendMessageDto, @Socket() socket: IOSocket, @Nsp() nsp: Namespace): Promise<Message> {
    const message = await this.chatService.createMessage(data);
    
    nsp.to(data.room).emit('message', message);
    
    return message;
  }

  @Input('leave-room')
  @Emit('user-left')
  async leaveRoom(@Args(0) data: JoinRoomDto, @Socket() socket: IOSocket, @Nsp() nsp: Namespace) {
    await socket.leave(data.room);
    
    const message = await this.chatService.createSystemMessage({
      room: data.room,
      content: \`\${data.username} left the room\`
    });
    
    nsp.to(data.room).emit('message', message);
    
    return { room: data.room, username: data.username };
  }

  @Input('typing')
  async userTyping(@Args(0) data: { room: string; username: string; }, @Socket() socket: IOSocket, @Nsp() nsp: Namespace) {
    socket.broadcast.to(data.room).emit('user-typing', {
      username: data.username,
      isTyping: true
    });
  }

  @Input('stop-typing')
  async userStoppedTyping(@Args(0) data: { room: string; username: string; }, @Socket() socket: IOSocket, @Nsp() nsp: Namespace) {
    socket.broadcast.to(data.room).emit('user-typing', {
      username: data.username,
      isTyping: false
    });
  }
}
`,
    'src/controllers/socket/NotificationSocketController.ts': `import { SocketController, Input, Emit, Args, Socket, Nsp, SocketSession } from '@tsed/socketio';
import { Inject } from '@tsed/di';
import { Namespace, Socket as IOSocket } from 'socket.io';
import { NotificationService } from '../../services/NotificationService';
import { Notification, SubscribeDto } from '../../dto/NotificationDto';

@SocketController('/notifications')
export class NotificationSocketController {
  @Inject()
  private notificationService: NotificationService;

  @Input('subscribe')
  async subscribe(@Args(0) data: SubscribeDto, @Socket() socket: IOSocket, @SocketSession() session: any) {
    session.userId = data.userId;
    await socket.join(\`user:\${data.userId}\`);
    
    const unreadNotifications = await this.notificationService.getUnreadForUser(data.userId);
    socket.emit('unread-notifications', unreadNotifications);
  }

  @Input('mark-as-read')
  @Emit('notification-read')
  async markAsRead(@Args(0) notificationId: string, @SocketSession() session: any): Promise<Notification> {
    return this.notificationService.markAsRead(notificationId, session.userId);
  }

  @Input('mark-all-as-read')
  @Emit('all-notifications-read')
  async markAllAsRead(@SocketSession() session: any): Promise<number> {
    return this.notificationService.markAllAsRead(session.userId);
  }

  // Server-side method to send notifications
  async sendNotificationToUser(userId: string, notification: Notification, @Nsp() nsp: Namespace) {
    nsp.to(\`user:\${userId}\`).emit('new-notification', notification);
  }

  @Input('unsubscribe')
  async unsubscribe(@Socket() socket: IOSocket, @SocketSession() session: any) {
    if (session.userId) {
      await socket.leave(\`user:\${session.userId}\`);
      delete session.userId;
    }
  }
}
`,
    'src/controllers/pages/index.ts': `export * from './HomeController';
`,
    'src/controllers/pages/HomeController.ts': `import { Controller, Get, View } from '@tsed/common';

@Controller('/')
export class HomeController {
  @Get('/')
  @View('index.ejs')
  home() {
    return {
      title: 'Ts.ED Application',
      message: 'Welcome to Ts.ED!'
    };
  }

  @Get('/health')
  health() {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString()
    };
  }
}
`,
    'src/entities/User.ts': `import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, BeforeInsert, BeforeUpdate } from 'typeorm';
import { Property, Required, Email, MinLength, Groups, Ignore, Allow } from '@tsed/schema';
import * as bcrypt from 'bcrypt';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  @Property()
  id: string;

  @Column({ unique: true })
  @Required()
  @Email()
  @Groups('!update')
  email: string;

  @Column()
  @Required()
  @MinLength(2)
  username: string;

  @Column()
  @Required()
  @MinLength(8)
  @Groups('creation')
  @Ignore()
  password: string;

  @Column({ default: 'user' })
  @Allow('admin')
  role: string;

  @Column({ default: true })
  @Property()
  isActive: boolean;

  @CreateDateColumn()
  @Property()
  createdAt: Date;

  @UpdateDateColumn()
  @Property()
  updatedAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    if (this.password) {
      this.password = await bcrypt.hash(this.password, 10);
    }
  }

  async validatePassword(password: string): Promise<boolean> {
    return bcrypt.compare(password, this.password);
  }
}
`,
    'src/entities/Product.ts': `import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { Property, Required, Min, Max, Pattern, Default, Example, Description } from '@tsed/schema';

@Entity('products')
export class Product {
  @PrimaryGeneratedColumn('uuid')
  @Property()
  id: string;

  @Column()
  @Required()
  @Property()
  @Description('Product name')
  @Example('Laptop')
  name: string;

  @Column('text')
  @Property()
  @Description('Product description')
  description: string;

  @Column('decimal', { precision: 10, scale: 2 })
  @Required()
  @Min(0)
  @Property()
  @Description('Product price')
  @Example(999.99)
  price: number;

  @Column({ default: 0 })
  @Min(0)
  @Default(0)
  @Property()
  @Description('Available quantity')
  stock: number;

  @Column()
  @Required()
  @Pattern(/^[A-Z]{3}-\d{4}$/)
  @Property()
  @Description('Product SKU')
  @Example('LAP-1234')
  sku: string;

  @Column({ default: true })
  @Default(true)
  @Property()
  isAvailable: boolean;

  @CreateDateColumn()
  @Property()
  createdAt: Date;

  @UpdateDateColumn()
  @Property()
  updatedAt: Date;
}
`,
    'src/dto/UserDto.ts': `import { Property, Required, Email, MinLength, Groups, Optional } from '@tsed/schema';

export class CreateUserDto {
  @Required()
  @Email()
  @Groups('creation')
  email: string;

  @Required()
  @MinLength(2)
  username: string;

  @Required()
  @MinLength(8)
  @Groups('creation')
  password: string;
}

export class UpdateUserDto {
  @Optional()
  @MinLength(2)
  username?: string;

  @Optional()
  @MinLength(8)
  password?: string;

  @Optional()
  isActive?: boolean;
}
`,
    'src/dto/AuthDto.ts': `import { Property, Required, Email, MinLength } from '@tsed/schema';

export class LoginDto {
  @Required()
  @Email()
  email: string;

  @Required()
  password: string;
}

export class RegisterDto {
  @Required()
  @Email()
  email: string;

  @Required()
  @MinLength(2)
  username: string;

  @Required()
  @MinLength(8)
  password: string;
}

export class TokenResponse {
  @Property()
  accessToken: string;

  @Property()
  tokenType: string = 'Bearer';

  @Property()
  expiresIn: number;

  @Property()
  user: {
    id: string;
    email: string;
    username: string;
    role: string;
  };
}
`,
    'src/dto/ProductDto.ts': `import { Property, Required, Min, Max, Pattern, Optional, Integer, Default } from '@tsed/schema';

export class CreateProductDto {
  @Required()
  name: string;

  @Optional()
  description?: string;

  @Required()
  @Min(0)
  price: number;

  @Optional()
  @Min(0)
  @Default(0)
  stock?: number;

  @Required()
  @Pattern(/^[A-Z]{3}-\d{4}$/)
  sku: string;
}

export class UpdateProductDto {
  @Optional()
  name?: string;

  @Optional()
  description?: string;

  @Optional()
  @Min(0)
  price?: number;

  @Optional()
  @Min(0)
  stock?: number;

  @Optional()
  isAvailable?: boolean;
}

export class ProductQueryDto {
  @Optional()
  @Min(1)
  @Integer()
  @Default(1)
  page?: number = 1;

  @Optional()
  @Min(1)
  @Max(100)
  @Integer()
  @Default(20)
  limit?: number = 20;

  @Optional()
  search?: string;

  @Optional()
  @Min(0)
  minPrice?: number;

  @Optional()
  @Min(0)
  maxPrice?: number;

  @Optional()
  isAvailable?: boolean;

  @Optional()
  @Pattern(/^(name|price|createdAt)$/)
  @Default('createdAt')
  sortBy?: string = 'createdAt';

  @Optional()
  @Pattern(/^(asc|desc)$/)
  @Default('desc')
  sortOrder?: 'asc' | 'desc' = 'desc';
}
`,
    'src/dto/ChatDto.ts': `import { Property, Required } from '@tsed/schema';

export class JoinRoomDto {
  @Required()
  room: string;

  @Required()
  username: string;
}

export class SendMessageDto {
  @Required()
  room: string;

  @Required()
  username: string;

  @Required()
  content: string;
}

export class Message {
  @Property()
  id: string;

  @Property()
  room: string;

  @Property()
  username: string;

  @Property()
  content: string;

  @Property()
  timestamp: Date;

  @Property()
  type: 'user' | 'system';
}
`,
    'src/dto/NotificationDto.ts': `import { Property, Required } from '@tsed/schema';

export class SubscribeDto {
  @Required()
  userId: string;
}

export class Notification {
  @Property()
  id: string;

  @Property()
  userId: string;

  @Property()
  title: string;

  @Property()
  message: string;

  @Property()
  type: 'info' | 'warning' | 'error' | 'success';

  @Property()
  isRead: boolean;

  @Property()
  createdAt: Date;

  @Property()
  readAt?: Date;
}
`,
    'src/services/UserService.ts': `import { Injectable } from '@tsed/di';
import { InjectRepository } from '@tsed/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/User';
import { CreateUserDto, UpdateUserDto } from '../dto/UserDto';

@Injectable()
export class UserService {
  @InjectRepository(User)
  private repository: Repository<User>;

  async findAll(): Promise<User[]> {
    return this.repository.find({
      select: ['id', 'email', 'username', 'role', 'isActive', 'createdAt', 'updatedAt']
    });
  }

  async findById(id: string): Promise<User | null> {
    return this.repository.findOne({
      where: { id },
      select: ['id', 'email', 'username', 'role', 'isActive', 'createdAt', 'updatedAt']
    });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.repository.findOne({ where: { email } });
  }

  async create(dto: CreateUserDto): Promise<User> {
    const user = this.repository.create(dto);
    return this.repository.save(user);
  }

  async update(id: string, dto: UpdateUserDto): Promise<User | null> {
    const user = await this.repository.findOne({ where: { id } });
    
    if (!user) {
      return null;
    }

    Object.assign(user, dto);
    return this.repository.save(user);
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.repository.delete(id);
    return result.affected !== 0;
  }
}
`,
    'src/services/AuthService.ts': `import { Injectable } from '@tsed/di';
import { Inject } from '@tsed/di';
import { Forbidden } from '@tsed/exceptions';
import * as jwt from 'jsonwebtoken';
import { UserService } from './UserService';
import { User } from '../entities/User';
import { RegisterDto, TokenResponse } from '../dto/AuthDto';

@Injectable()
export class AuthService {
  @Inject()
  private userService: UserService;

  private readonly jwtSecret = process.env.JWT_SECRET || 'default-secret';
  private readonly jwtExpiresIn = '24h';

  async register(dto: RegisterDto): Promise<User> {
    const existingUser = await this.userService.findByEmail(dto.email);
    
    if (existingUser) {
      throw new Forbidden('Email already registered');
    }

    return this.userService.create(dto);
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userService.findByEmail(email);
    
    if (user && await user.validatePassword(password)) {
      return user;
    }
    
    return null;
  }

  generateToken(user: User): TokenResponse {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role
    };

    const accessToken = jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.jwtExpiresIn
    });

    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn: 86400, // 24 hours in seconds
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role
      }
    };
  }

  async verifyToken(token: string): Promise<any> {
    try {
      return jwt.verify(token, this.jwtSecret);
    } catch (error) {
      return null;
    }
  }
}
`,
    'src/services/ProductService.ts': `import { Injectable } from '@tsed/di';
import { InjectRepository } from '@tsed/typeorm';
import { Repository, Like, Between, FindManyOptions } from 'typeorm';
import { Product } from '../entities/Product';
import { CreateProductDto, UpdateProductDto, ProductQueryDto } from '../dto/ProductDto';

@Injectable()
export class ProductService {
  @InjectRepository(Product)
  private repository: Repository<Product>;

  async findWithFilters(query: ProductQueryDto): Promise<Product[]> {
    const { page = 1, limit = 20, search, minPrice, maxPrice, isAvailable, sortBy = 'createdAt', sortOrder = 'desc' } = query;
    
    const where: any = {};
    
    if (search) {
      where.name = Like(\`%\${search}%\`);
    }
    
    if (minPrice !== undefined && maxPrice !== undefined) {
      where.price = Between(minPrice, maxPrice);
    } else if (minPrice !== undefined) {
      where.price = Between(minPrice, Number.MAX_SAFE_INTEGER);
    } else if (maxPrice !== undefined) {
      where.price = Between(0, maxPrice);
    }
    
    if (isAvailable !== undefined) {
      where.isAvailable = isAvailable;
    }

    const options: FindManyOptions<Product> = {
      where,
      order: { [sortBy]: sortOrder.toUpperCase() },
      skip: (page - 1) * limit,
      take: limit
    };

    return this.repository.find(options);
  }

  async findById(id: string): Promise<Product | null> {
    return this.repository.findOne({ where: { id } });
  }

  async create(dto: CreateProductDto): Promise<Product> {
    const product = this.repository.create(dto);
    return this.repository.save(product);
  }

  async update(id: string, dto: UpdateProductDto): Promise<Product | null> {
    const product = await this.repository.findOne({ where: { id } });
    
    if (!product) {
      return null;
    }

    Object.assign(product, dto);
    return this.repository.save(product);
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.repository.delete(id);
    return result.affected !== 0;
  }
}
`,
    'src/services/ChatService.ts': `import { Injectable } from '@tsed/di';
import { v4 as uuidv4 } from 'uuid';
import { Message, SendMessageDto } from '../dto/ChatDto';

@Injectable()
export class ChatService {
  private messages: Map<string, Message[]> = new Map();

  async createMessage(dto: SendMessageDto): Promise<Message> {
    const message: Message = {
      id: uuidv4(),
      room: dto.room,
      username: dto.username,
      content: dto.content,
      timestamp: new Date(),
      type: 'user'
    };

    this.addMessageToRoom(dto.room, message);
    return message;
  }

  async createSystemMessage(data: { room: string; content: string }): Promise<Message> {
    const message: Message = {
      id: uuidv4(),
      room: data.room,
      username: 'System',
      content: data.content,
      timestamp: new Date(),
      type: 'system'
    };

    this.addMessageToRoom(data.room, message);
    return message;
  }

  async getMessagesForRoom(room: string, limit: number = 50): Promise<Message[]> {
    const messages = this.messages.get(room) || [];
    return messages.slice(-limit);
  }

  private addMessageToRoom(room: string, message: Message): void {
    if (!this.messages.has(room)) {
      this.messages.set(room, []);
    }
    
    const roomMessages = this.messages.get(room)!;
    roomMessages.push(message);
    
    // Keep only last 1000 messages per room
    if (roomMessages.length > 1000) {
      roomMessages.shift();
    }
  }
}
`,
    'src/services/NotificationService.ts': `import { Injectable } from '@tsed/di';
import { v4 as uuidv4 } from 'uuid';
import { Notification } from '../dto/NotificationDto';

@Injectable()
export class NotificationService {
  private notifications: Map<string, Notification[]> = new Map();

  async createNotification(userId: string, data: Partial<Notification>): Promise<Notification> {
    const notification: Notification = {
      id: uuidv4(),
      userId,
      title: data.title || 'New Notification',
      message: data.message || '',
      type: data.type || 'info',
      isRead: false,
      createdAt: new Date()
    };

    if (!this.notifications.has(userId)) {
      this.notifications.set(userId, []);
    }

    this.notifications.get(userId)!.push(notification);
    return notification;
  }

  async getUnreadForUser(userId: string): Promise<Notification[]> {
    const userNotifications = this.notifications.get(userId) || [];
    return userNotifications.filter(n => !n.isRead);
  }

  async markAsRead(notificationId: string, userId: string): Promise<Notification> {
    const userNotifications = this.notifications.get(userId) || [];
    const notification = userNotifications.find(n => n.id === notificationId);
    
    if (notification) {
      notification.isRead = true;
      notification.readAt = new Date();
    }
    
    return notification!;
  }

  async markAllAsRead(userId: string): Promise<number> {
    const userNotifications = this.notifications.get(userId) || [];
    let count = 0;
    
    userNotifications.forEach(notification => {
      if (!notification.isRead) {
        notification.isRead = true;
        notification.readAt = new Date();
        count++;
      }
    });
    
    return count;
  }
}
`,
    'src/protocols/JwtProtocol.ts': `import { Inject } from '@tsed/di';
import { Req } from '@tsed/common';
import { Arg, OnInstall, OnVerify, Protocol } from '@tsed/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { UserService } from '../services/UserService';

@Protocol({
  name: 'jwt',
  useStrategy: Strategy,
  settings: {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET || 'default-secret'
  }
})
export class JwtProtocol implements OnVerify, OnInstall {
  @Inject()
  private userService: UserService;

  async $onVerify(@Req() req: Req, @Arg(0) payload: any) {
    const user = await this.userService.findById(payload.sub);
    
    if (!user || !user.isActive) {
      return false;
    }
    
    return user;
  }

  $onInstall(strategy: Strategy): void {
    // Additional strategy configuration if needed
  }
}
`,
    'src/protocols/LocalProtocol.ts': `import { Inject } from '@tsed/di';
import { Req } from '@tsed/common';
import { BodyParams } from '@tsed/platform-params';
import { OnInstall, OnVerify, Protocol } from '@tsed/passport';
import { IStrategyOptions, Strategy } from 'passport-local';
import { AuthService } from '../services/AuthService';

@Protocol<IStrategyOptions>({
  name: 'local',
  useStrategy: Strategy,
  settings: {
    usernameField: 'email',
    passwordField: 'password'
  }
})
export class LocalProtocol implements OnVerify, OnInstall {
  @Inject()
  private authService: AuthService;

  async $onVerify(@Req() request: Req, @BodyParams() credentials: any) {
    const { email, password } = credentials;
    const user = await this.authService.validateUser(email, password);
    
    if (!user) {
      return false;
    }
    
    return user;
  }

  $onInstall(strategy: Strategy): void {
    // Additional strategy configuration if needed
  }
}
`,
    'src/middlewares/ErrorHandlerMiddleware.ts': `import { Catch, ExceptionFilterMethods, PlatformContext } from '@tsed/common';
import { Exception } from '@tsed/exceptions';

@Catch(Error)
export class ErrorHandlerMiddleware implements ExceptionFilterMethods {
  catch(exception: Exception, ctx: PlatformContext) {
    const { response, logger } = ctx;
    const error = this.mapError(exception);
    const status = exception.status || 500;

    logger.error({
      error: exception,
      stack: exception.stack
    });

    response
      .status(status)
      .json({
        status,
        message: error.message,
        name: error.name,
        errors: error.errors,
        stack: process.env.NODE_ENV === 'development' ? exception.stack : undefined
      });
  }

  private mapError(error: any) {
    return {
      name: error.name || 'InternalServerError',
      message: error.message || 'An error occurred',
      errors: error.errors || []
    };
  }
}
`,
    'src/middlewares/RequestLoggerMiddleware.ts': `import { Middleware, Req, Res, Next } from '@tsed/common';
import { Logger } from '@tsed/logger';

@Middleware()
export class RequestLoggerMiddleware {
  constructor(private logger: Logger) {}

  use(@Req() request: Req, @Res() response: Res, @Next() next: Next) {
    const start = Date.now();
    const { method, url, headers } = request;

    this.logger.info({
      event: 'REQUEST_STARTED',
      method,
      url,
      userAgent: headers['user-agent']
    });

    response.on('finish', () => {
      const duration = Date.now() - start;
      const { statusCode } = response;

      this.logger.info({
        event: 'REQUEST_COMPLETED',
        method,
        url,
        statusCode,
        duration
      });
    });

    next();
  }
}
`,
    'src/decorators/UseCache.ts': `import { UseDecorator, StoreSet } from '@tsed/core';
import { useDecorators } from '@tsed/core';
import { Returns } from '@tsed/schema';

export interface CacheOptions {
  ttl?: number;
  key?: string;
}

export function UseCache(options: CacheOptions = {}): MethodDecorator {
  return useDecorators(
    StoreSet('cache', options),
    UseDecorator((target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
      const originalMethod = descriptor.value;
      const cache = new Map<string, { value: any; expires: number }>();

      descriptor.value = async function (...args: any[]) {
        const cacheKey = options.key || \`\${propertyKey}:\${JSON.stringify(args)}\`;
        const cached = cache.get(cacheKey);
        
        if (cached && cached.expires > Date.now()) {
          return cached.value;
        }

        const result = await originalMethod.apply(this, args);
        
        cache.set(cacheKey, {
          value: result,
          expires: Date.now() + (options.ttl || 300) * 1000
        });

        return result;
      };

      return descriptor;
    })
  );
}
`,
    'src/decorators/ValidateQuery.ts': `import { UseDecorator } from '@tsed/core';
import { BadRequest } from '@tsed/exceptions';
import { validate } from 'class-validator';
import { plainToClass } from 'class-transformer';

export function ValidateQuery(): ParameterDecorator {
  return UseDecorator((target: any, propertyKey: string | symbol, parameterIndex: number) => {
    const types = Reflect.getMetadata('design:paramtypes', target, propertyKey);
    const type = types[parameterIndex];

    const originalMethod = target[propertyKey];
    
    target[propertyKey] = async function (...args: any[]) {
      const query = args[parameterIndex];
      
      if (query && type) {
        const instance = plainToClass(type, query);
        const errors = await validate(instance);
        
        if (errors.length > 0) {
          throw new BadRequest('Invalid query parameters', errors);
        }
        
        args[parameterIndex] = instance;
      }
      
      return originalMethod.apply(this, args);
    };
  });
}
`,
    'src/interceptors/PerformanceInterceptor.ts': `import { Interceptor, InterceptorMethods, InterceptorContext, InterceptorNext } from '@tsed/di';
import { Logger } from '@tsed/logger';

@Interceptor()
export class PerformanceInterceptor implements InterceptorMethods {
  constructor(private logger: Logger) {}

  intercept(context: InterceptorContext<any>, next: InterceptorNext) {
    const start = Date.now();
    const { target, propertyKey, args } = context;

    return next().then((result) => {
      const duration = Date.now() - start;
      
      if (duration > 1000) {
        this.logger.warn({
          event: 'SLOW_METHOD',
          class: target.constructor.name,
          method: propertyKey,
          duration,
          threshold: 1000
        });
      }

      return result;
    });
  }
}
`,
    'src/filters/ValidationFilter.ts': `import { Catch, ExceptionFilterMethods, PlatformContext } from '@tsed/common';
import { ValidationError } from 'class-validator';
import { BadRequest } from '@tsed/exceptions';

@Catch(BadRequest)
export class ValidationFilter implements ExceptionFilterMethods {
  catch(exception: BadRequest, ctx: PlatformContext) {
    const { response } = ctx;
    const errors = exception.origin as ValidationError[];
    
    if (Array.isArray(errors) && errors[0] instanceof ValidationError) {
      const formattedErrors = this.formatValidationErrors(errors);
      
      response.status(400).json({
        status: 400,
        message: 'Validation failed',
        errors: formattedErrors
      });
    } else {
      response.status(400).json({
        status: 400,
        message: exception.message
      });
    }
  }

  private formatValidationErrors(errors: ValidationError[]): any[] {
    return errors.map(error => ({
      property: error.property,
      value: error.value,
      constraints: error.constraints
    }));
  }
}
`,
    'src/graphql/schema.graphql': `type Query {
  users: [User!]!
  user(id: ID!): User
  products(filter: ProductFilter): [Product!]!
  product(id: ID!): Product
}

type Mutation {
  createUser(input: CreateUserInput!): User!
  updateUser(id: ID!, input: UpdateUserInput!): User!
  deleteUser(id: ID!): Boolean!
  
  createProduct(input: CreateProductInput!): Product!
  updateProduct(id: ID!, input: UpdateProductInput!): Product!
  deleteProduct(id: ID!): Boolean!
}

type User {
  id: ID!
  email: String!
  username: String!
  role: String!
  isActive: Boolean!
  createdAt: String!
  updatedAt: String!
}

type Product {
  id: ID!
  name: String!
  description: String
  price: Float!
  stock: Int!
  sku: String!
  isAvailable: Boolean!
  createdAt: String!
  updatedAt: String!
}

input CreateUserInput {
  email: String!
  username: String!
  password: String!
}

input UpdateUserInput {
  username: String
  password: String
  isActive: Boolean
}

input CreateProductInput {
  name: String!
  description: String
  price: Float!
  stock: Int
  sku: String!
}

input UpdateProductInput {
  name: String
  description: String
  price: Float
  stock: Int
  isAvailable: Boolean
}

input ProductFilter {
  search: String
  minPrice: Float
  maxPrice: Float
  isAvailable: Boolean
}
`,
    'src/graphql/resolvers/UserResolver.ts': `import { ResolverService } from '@tsed/graphql';
import { Inject } from '@tsed/di';
import { Query, Mutation, Arg, Args } from 'type-graphql';
import { UserService } from '../../services/UserService';
import { User } from '../../entities/User';
import { CreateUserDto, UpdateUserDto } from '../../dto/UserDto';

@ResolverService(User)
export class UserResolver {
  @Inject()
  private userService: UserService;

  @Query(() => [User])
  async users(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Query(() => User, { nullable: true })
  async user(@Arg('id') id: string): Promise<User | null> {
    return this.userService.findById(id);
  }

  @Mutation(() => User)
  async createUser(@Arg('input') input: CreateUserDto): Promise<User> {
    return this.userService.create(input);
  }

  @Mutation(() => User)
  async updateUser(
    @Arg('id') id: string,
    @Arg('input') input: UpdateUserDto
  ): Promise<User> {
    const user = await this.userService.update(id, input);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }

  @Mutation(() => Boolean)
  async deleteUser(@Arg('id') id: string): Promise<boolean> {
    return this.userService.delete(id);
  }
}
`,
    'src/graphql/resolvers/ProductResolver.ts': `import { ResolverService } from '@tsed/graphql';
import { Inject } from '@tsed/di';
import { Query, Mutation, Arg, Args } from 'type-graphql';
import { ProductService } from '../../services/ProductService';
import { Product } from '../../entities/Product';
import { CreateProductDto, UpdateProductDto, ProductQueryDto } from '../../dto/ProductDto';

@ResolverService(Product)
export class ProductResolver {
  @Inject()
  private productService: ProductService;

  @Query(() => [Product])
  async products(@Arg('filter', { nullable: true }) filter?: ProductQueryDto): Promise<Product[]> {
    return this.productService.findWithFilters(filter || {});
  }

  @Query(() => Product, { nullable: true })
  async product(@Arg('id') id: string): Promise<Product | null> {
    return this.productService.findById(id);
  }

  @Mutation(() => Product)
  async createProduct(@Arg('input') input: CreateProductDto): Promise<Product> {
    return this.productService.create(input);
  }

  @Mutation(() => Product)
  async updateProduct(
    @Arg('id') id: string,
    @Arg('input') input: UpdateProductDto
  ): Promise<Product> {
    const product = await this.productService.update(id, input);
    if (!product) {
      throw new Error('Product not found');
    }
    return product;
  }

  @Mutation(() => Boolean)
  async deleteProduct(@Arg('id') id: string): Promise<boolean> {
    return this.productService.delete(id);
  }
}
`,
    'tests/unit/services/UserService.spec.ts': `import { PlatformTest } from '@tsed/common';
import { UserService } from '../../../src/services/UserService';
import { User } from '../../../src/entities/User';
import { Repository } from 'typeorm';

describe('UserService', () => {
  let service: UserService;
  let repository: Repository<User>;

  beforeEach(async () => {
    const testModule = await PlatformTest.create({
      providers: [
        UserService,
        {
          provide: 'UserRepository',
          useValue: {
            find: jest.fn(),
            findOne: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
            delete: jest.fn()
          }
        }
      ]
    });

    service = testModule.get<UserService>(UserService);
    repository = testModule.get<Repository<User>>('UserRepository');
  });

  afterEach(() => {
    PlatformTest.reset();
  });

  describe('findAll', () => {
    it('should return all users', async () => {
      const users = [
        { id: '1', email: 'user1@test.com', username: 'user1' },
        { id: '2', email: 'user2@test.com', username: 'user2' }
      ];

      jest.spyOn(repository, 'find').mockResolvedValue(users as any);

      const result = await service.findAll();

      expect(result).toEqual(users);
      expect(repository.find).toHaveBeenCalledWith({
        select: ['id', 'email', 'username', 'role', 'isActive', 'createdAt', 'updatedAt']
      });
    });
  });

  describe('create', () => {
    it('should create a new user', async () => {
      const dto = {
        email: 'new@test.com',
        username: 'newuser',
        password: 'password123'
      };

      const createdUser = { id: '1', ...dto };

      jest.spyOn(repository, 'create').mockReturnValue(createdUser as any);
      jest.spyOn(repository, 'save').mockResolvedValue(createdUser as any);

      const result = await service.create(dto);

      expect(result).toEqual(createdUser);
      expect(repository.create).toHaveBeenCalledWith(dto);
      expect(repository.save).toHaveBeenCalledWith(createdUser);
    });
  });
});
`,
    'tests/integration/UserController.spec.ts': `import { PlatformTest } from '@tsed/common';
import SuperTest from 'supertest';
import { Server } from '../../src/Server';

describe('UserController', () => {
  let request: SuperTest.SuperTest<SuperTest.Test>;

  beforeAll(async () => {
    const testServer = await PlatformTest.bootstrap(Server, {
      logger: {
        level: 'off'
      }
    });

    request = SuperTest(testServer.app.raw);
  });

  afterAll(() => PlatformTest.reset());

  describe('GET /api/users', () => {
    it('should return all users', async () => {
      const response = await request
        .get('/api/users')
        .expect(200);

      expect(response.body).toBeInstanceOf(Array);
    });
  });

  describe('POST /api/users', () => {
    it('should create a new user', async () => {
      const newUser = {
        email: 'test@example.com',
        username: 'testuser',
        password: 'password123'
      };

      const response = await request
        .post('/api/users')
        .send(newUser)
        .expect(201);

      expect(response.body).toMatchObject({
        email: newUser.email,
        username: newUser.username
      });
      expect(response.body).toHaveProperty('id');
      expect(response.body).not.toHaveProperty('password');
    });

    it('should return 400 for invalid user data', async () => {
      const invalidUser = {
        email: 'invalid-email',
        username: 'a',
        password: 'short'
      };

      await request
        .post('/api/users')
        .send(invalidUser)
        .expect(400);
    });
  });
});
`,
    'jest.config.js': `module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/*.spec.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts',
    '!src/**/*.spec.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1'
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts']
};
`,
    'tests/setup.ts': `import 'reflect-metadata';
import { config } from 'dotenv';

// Load test environment variables
config({ path: '.env.test' });

// Set test environment
process.env.NODE_ENV = 'test';

// Mock console methods during tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};
`,
    'tsconfig.json': `{
  "compilerOptions": {
    "target": "ES2021",
    "lib": ["ES2021"],
    "module": "commonjs",
    "moduleResolution": "node",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "removeComments": true,
    "preserveConstEnums": true,
    "sourceMap": true,
    "declaration": true,
    "declarationMap": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "strictPropertyInitialization": false,
    "allowSyntheticDefaultImports": true,
    "types": ["node", "jest"],
    "typeRoots": ["node_modules/@types"],
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src/**/*.ts"],
  "exclude": ["node_modules", "dist", "coverage", "tests"]
}
`,
    '.eslintrc.js': `module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  root: true,
  env: {
    node: true,
    jest: true,
  },
  ignorePatterns: ['.eslintrc.js', 'jest.config.js', 'dist'],
  rules: {
    '@typescript-eslint/interface-name-prefix': 'off',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  },
};
`,
    '.prettierrc': `{
  "singleQuote": true,
  "trailingComma": "none",
  "printWidth": 100,
  "tabWidth": 2,
  "semi": true,
  "bracketSpacing": true,
  "arrowParens": "avoid",
  "endOfLine": "lf"
}
`,
    '.gitignore': `node_modules/
dist/
coverage/
.env
.env.local
.env.test
*.log
*.sqlite
.DS_Store
.idea/
.vscode/
*.swp
*.swo
.cache/
`,
    '.env.example': `NODE_ENV=development
PORT=3000

# Database
DB_TYPE=sqlite
DB_DATABASE=./db.sqlite

# JWT
JWT_SECRET=your-jwt-secret-here

# Session
SESSION_SECRET=your-session-secret-here

# Logging
LOG_LEVEL=debug
`,
    'Dockerfile': `FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src

# Build application
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && \
    npm cache clean --force

# Copy built application
COPY --from=builder /app/dist ./dist

# Copy other necessary files
COPY .env.example .env

# Change ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start application
CMD ["node", "dist/index.js"]
`,
    '.dockerignore': `node_modules
dist
coverage
.git
.gitignore
.eslintrc.js
.prettierrc
jest.config.js
tests
*.log
*.md
.env
.env.test
.DS_Store
`,
    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    container_name: tsed-app
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: production
      PORT: 3000
      DB_TYPE: postgres
      DB_HOST: db
      DB_PORT: 5432
      DB_USERNAME: tsed
      DB_PASSWORD: tsed123
      DB_DATABASE: tsed
    depends_on:
      - db
    networks:
      - tsed-network
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    container_name: tsed-db
    environment:
      POSTGRES_USER: tsed
      POSTGRES_PASSWORD: tsed123
      POSTGRES_DB: tsed
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - tsed-network
    restart: unless-stopped

volumes:
  postgres-data:

networks:
  tsed-network:
    driver: bridge
`,
    'README.md': `# Ts.ED Application

A full-featured TypeScript application built with Ts.ED framework.

## Features

- TypeScript with decorators
- Express.js integration
- Dependency injection
- OpenAPI/Swagger documentation
- GraphQL support
- WebSocket support (Socket.io)
- Authentication (Passport.js)
- ORM integration (TypeORM)
- Validation with class-validator
- Exception handling
- Testing with Jest
- Docker support

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

\`\`\`bash
npm install
\`\`\`

### Development

\`\`\`bash
npm run dev
\`\`\`

### Testing

\`\`\`bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
\`\`\`

### Building

\`\`\`bash
npm run build
\`\`\`

### Production

\`\`\`bash
npm start
\`\`\`

### Docker

\`\`\`bash
# Build image
npm run docker:build

# Run container
npm run docker:run

# Or use docker-compose
docker-compose up
\`\`\`

## API Documentation

- REST API: http://localhost:3000/api-docs
- GraphQL Playground: http://localhost:3000/graphql

## Project Structure

\`\`\`
src/
├── config/           # Configuration files
├── controllers/      # REST, WebSocket, and page controllers
├── decorators/       # Custom decorators
├── dto/              # Data transfer objects
├── entities/         # TypeORM entities
├── filters/          # Exception filters
├── graphql/          # GraphQL schema and resolvers
├── interceptors/     # Method interceptors
├── middlewares/      # Express middlewares
├── protocols/        # Passport strategies
├── services/         # Business logic services
├── Server.ts         # Server configuration
└── index.ts          # Application entry point
\`\`\`
`
  }
};