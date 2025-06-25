import { BackendTemplate } from '../types';

export const nestjsTypeScriptTemplate: BackendTemplate = {
  id: 'nestjs-ts',
  name: 'NestJS + TypeScript',
  description: 'Enterprise-grade NestJS API server with dependency injection, modules, guards, interceptors, and decorators',
  framework: 'nestjs',
  language: 'typescript',
  version: '1.0.0',
  tags: ['nestjs', 'typescript', 'dependency-injection', 'decorators', 'modules', 'guards', 'interceptors'],
  port: 3000,
  features: [
    'authentication',
    'authorization',
    'validation',
    'logging',
    'testing',
    'cors',
    'security',
    'rest-api',
    'microservices',
    'docker'
  ],
  dependencies: {
    '@nestjs/common': '^10.3.0',
    '@nestjs/core': '^10.3.0',
    '@nestjs/platform-express': '^10.3.0',
    '@nestjs/config': '^3.1.1',
    '@nestjs/jwt': '^10.2.0',
    '@nestjs/passport': '^10.0.2',
    '@nestjs/swagger': '^7.1.17',
    '@nestjs/throttler': '^5.1.1',
    '@nestjs/typeorm': '^10.0.1',
    'passport': '^0.7.0',
    'passport-jwt': '^4.0.1',
    'passport-local': '^1.0.0',
    'bcrypt': '^5.1.1',
    'class-validator': '^0.14.0',
    'class-transformer': '^0.5.1',
    'helmet': '^7.1.0',
    'compression': '^1.7.4',
    'typeorm': '^0.3.17',
    'reflect-metadata': '^0.1.13',
    'rxjs': '^7.8.1'
      '@prisma/client': '^5.8.1',
      'uuid': '^9.0.1',
  },
  devDependencies: {
    '@nestjs/cli': '^10.2.1',
    '@nestjs/schematics': '^10.0.3',
    '@nestjs/testing': '^10.3.0',
    '@types/express': '^4.17.21',
    '@types/jest': '^29.5.8',
    '@types/node': '^20.10.5',
    '@types/passport-jwt': '^4.0.0',
    '@types/passport-local': '^1.0.38',
    '@types/bcrypt': '^5.0.2',
    '@types/supertest': '^6.0.0',
    '@typescript-eslint/eslint-plugin': '^6.15.0',
    '@typescript-eslint/parser': '^6.15.0',
    'eslint': '^8.56.0',
    'eslint-config-prettier': '^9.1.0',
    'eslint-plugin-prettier': '^5.1.0',
    'jest': '^29.7.0',
    'prettier': '^3.1.1',
    'source-map-support': '^0.5.21',
    'supertest': '^6.3.3',
    'ts-jest': '^29.1.1',
    'ts-loader': '^9.5.1',
    'ts-node': '^10.9.1',
    'tsconfig-paths': '^4.2.0',
    'typescript': '^5.3.3'
      'prisma': '^5.8.1',
      '@types/uuid': '^9.0.7',
  },
  files: {
    'package.json': {
      name: '{{projectName}}',
      version: '0.0.1',
      description: 'NestJS TypeScript API server with enterprise features',
      author: '{{author}}',
      private: true,
      license: 'MIT',
      scripts: {
        build: 'nest build',
        format: 'prettier --write "src/**/*.ts" "test/**/*.ts"',
        start: 'nest start',
        'start:dev': 'nest start --watch',
        'start:debug': 'nest start --debug --watch',
        'start:prod': 'node dist/main',
        lint: 'eslint "{src,apps,libs,test}/**/*.ts" --fix',
        test: 'jest',
        'test:watch': 'jest --watch',
        'test:cov': 'jest --coverage',
        'test:debug': 'node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand',
        'test:e2e': 'jest --config ./test/jest-e2e.json'
      },
      dependencies: {},
      devDependencies: {},
      jest: {
        moduleFileExtensions: ['js', 'json', 'ts'],
        rootDir: 'src',
        testRegex: '.*\\.spec\\.ts$',
        transform: {
          '^.+\\.(t|j)s$': 'ts-jest'
        },
        collectCoverageFrom: ['**/*.(t|j)s'],
        coverageDirectory: '../coverage',
        testEnvironment: 'node'
      }
    },
    'nest-cli.json': {
      '$schema': 'https://json.schemastore.org/nest-cli',
      collection: '@nestjs/schematics',
      sourceRoot: 'src',
      compilerOptions: {
        deleteOutDir: true
      }
    },
    'tsconfig.json': {
      compilerOptions: {
        module: 'commonjs',
        declaration: true,
        removeComments: true,
        emitDecoratorMetadata: true,
        experimentalDecorators: true,
        allowSyntheticDefaultImports: true,
        target: 'ES2022',
        sourceMap: true,
        outDir: './dist',
        baseUrl: './',
        incremental: true,
        skipLibCheck: true,
        strictNullChecks: false,
        noImplicitAny: false,
        strictBindCallApply: false,
        forceConsistentCasingInFileNames: false,
        noFallthroughCasesInSwitch: false
      },
      paths: {
        '@/*': ['src/*'],
        '@app/*': ['src/app/*'],
        '@auth/*': ['src/auth/*'],
        '@common/*': ['src/common/*'],
        '@config/*': ['src/config/*']
      }
    },
    'tsconfig.build.json': {
      extends: './tsconfig.json',
      exclude: ['node_modules', 'test', 'dist', '**/*spec.ts']
    },
    'src/main.ts': `import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import * as compression from 'compression';
import { AppModule } from './app/app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  
  const app = await NestFactory.create(AppModule, {
    logger: ['log', 'error', 'warn', 'debug', 'verbose'],
  });

  const configService = app.get(ConfigService);

  // Security
  app.use(helmet());
  app.use(compression());

  // CORS
  app.enableCors({
    origin: configService.get('ALLOWED_ORIGINS')?.split(',') || '*',
    credentials: true,
  });

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // API prefix
  app.setGlobalPrefix('api/v1');

  // Swagger documentation
  if (configService.get('NODE_ENV') !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('{{projectName}} API')
      .setDescription('NestJS TypeScript API with enterprise features')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document);
  }

  const port = configService.get('PORT') || 3000;
  await app.listen(port);

  logger.log(\`Application is running on: http://localhost:\${port}\`);
  logger.log(\`Swagger documentation: http://localhost:\${port}/docs\`);
}

bootstrap().catch((error) => {
  console.error('Application failed to start:', error);
  process.exit(1);
});
`,
    'src/app/app.module.ts': `import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../users/users.module';
import { HealthModule } from '../health/health.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { configuration } from '../config/configuration';
import { DatabaseConfig } from '../config/database.config';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      envFilePath: ['.env.local', '.env'],
    }),

    // Rate limiting
    ThrottlerModule.forRoot([{
      ttl: 60000, // 1 minute
      limit: 100, // 100 requests per minute
    }]),

    // Database (optional - uncomment when ready to use)
    // TypeOrmModule.forRootAsync({
    //   useClass: DatabaseConfig,
    // }),

    // Feature modules
    HealthModule,
    AuthModule,
    UsersModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
`,
    'src/app/app.controller.ts': `import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';

@ApiTags('app')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({ summary: 'Get application info' })
  @ApiResponse({ status: 200, description: 'Application information' })
  getInfo() {
    return this.appService.getInfo();
  }
}
`,
    'src/app/app.service.ts': `import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService {
  constructor(private configService: ConfigService) {}

  getInfo() {
    return {
      name: '{{projectName}}',
      version: '1.0.0',
      environment: this.configService.get('NODE_ENV', 'development'),
      timestamp: new Date().toISOString(),
    };
  }
}
`,
    'src/config/configuration.ts': `export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },
  database: {
    type: process.env.DB_TYPE || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'nestjs_app',
  },
  bcrypt: {
    rounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
  },
});

export const configuration = () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  allowedOrigins: process.env.ALLOWED_ORIGINS || '*',
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },
  database: {
    type: process.env.DB_TYPE || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'nestjs_app',
  },
  bcrypt: {
    rounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
  },
});
`,
    'src/config/database.config.ts': `import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions, TypeOrmOptionsFactory } from '@nestjs/typeorm';

@Injectable()
export class DatabaseConfig implements TypeOrmOptionsFactory {
  constructor(private configService: ConfigService) {}

  createTypeOrmOptions(): TypeOrmModuleOptions {
    return {
      type: this.configService.get('database.type') as any,
      host: this.configService.get('database.host'),
      port: this.configService.get('database.port'),
      username: this.configService.get('database.username'),
      password: this.configService.get('database.password'),
      database: this.configService.get('database.database'),
      entities: [__dirname + '/../**/*.entity{.ts,.js}'],
      synchronize: this.configService.get('nodeEnv') === 'development',
      logging: this.configService.get('nodeEnv') === 'development',
      migrations: [__dirname + '/../migrations/*{.ts,.js}'],
      migrationsRun: true,
    };
  }
}
`,
    'src/auth/auth.module.ts': `import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from '../users/users.module';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('jwt.secret'),
        signOptions: {
          expiresIn: configService.get<string>('jwt.expiresIn'),
        },
      }),
      inject: [ConfigService],
    }),
    UsersModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
`,
    'src/auth/auth.service.ts': `import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (user && await this.comparePasswords(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.email, loginDto.password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { email: user.email, sub: user.id, role: user.role };
    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  async register(registerDto: RegisterDto) {
    const existingUser = await this.usersService.findByEmail(registerDto.email);
    if (existingUser) {
      throw new UnauthorizedException('User already exists');
    }

    const hashedPassword = await this.hashPassword(registerDto.password);
    const user = await this.usersService.create({
      ...registerDto,
      password: hashedPassword,
    });

    const { password, ...result } = user;
    const payload = { email: result.email, sub: result.id, role: result.role };

    return {
      user: result,
      access_token: this.jwtService.sign(payload),
    };
  }

  private async hashPassword(password: string): Promise<string> {
    const rounds = this.configService.get<number>('bcrypt.rounds');
    return bcrypt.hash(password, rounds);
  }

  private async comparePasswords(password: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }
}
`,
    'src/auth/auth.controller.ts': `import { Controller, Post, Body, UseGuards, Get, Request } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@ApiTags('auth')
@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User successfully registered' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 409, description: 'User already exists' })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({ status: 200, description: 'User successfully logged in' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({ status: 200, description: 'User profile retrieved' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getProfile(@Request() req) {
    return req.user;
  }
}
`,
    'src/auth/dto/login.dto.ts': `import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'password123', minLength: 8 })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;
}
`,
    'src/auth/dto/register.dto.ts': `import { IsEmail, IsNotEmpty, IsString, MinLength, IsOptional, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

export class RegisterDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'password123', minLength: 8 })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;

  @ApiProperty({ example: 'John Doe', required: false })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiProperty({ enum: UserRole, default: UserRole.USER, required: false })
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
}
`,
    'src/auth/strategies/jwt.strategy.ts': `import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from '../../users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('jwt.secret'),
    });
  }

  async validate(payload: any) {
    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException();
    }
    return { id: payload.sub, email: payload.email, role: payload.role };
  }
}
`,
    'src/auth/strategies/local.strategy.ts': `import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
    });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
`,
    'src/auth/guards/jwt-auth.guard.ts': `import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
`,
    'src/auth/guards/local-auth.guard.ts': `import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
`,
    'src/auth/guards/roles.guard.ts': `import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    
    if (!requiredRoles) {
      return true;
    }
    
    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.role?.includes(role));
  }
}
`,
    'src/auth/decorators/roles.decorator.ts': `import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
`,
    'src/users/users.module.ts': `import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
`,
    'src/users/users.service.ts': `import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

// Mock user data (replace with database integration)
interface User {
  id: string;
  email: string;
  password: string;
  name?: string;
  role: string;
  createdAt: Date;
}

@Injectable()
export class UsersService {
  private users: User[] = [
    {
      id: '1',
      email: 'admin@example.com',
      password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewjyxdoBN5kL.xm6', // password
      name: 'Admin User',
      role: 'admin',
      createdAt: new Date(),
    },
  ];

  async create(createUserDto: CreateUserDto): Promise<User> {
    const user: User = {
      id: (this.users.length + 1).toString(),
      ...createUserDto,
      role: createUserDto.role || 'user',
      createdAt: new Date(),
    };
    
    this.users.push(user);
    return user;
  }

  async findAll(): Promise<Omit<User, 'password'>[]> {
    return this.users.map(({ password, ...user }) => user);
  }

  async findById(id: string): Promise<User | undefined> {
    return this.users.find((user) => user.id === id);
  }

  async findByEmail(email: string): Promise<User | undefined> {
    return this.users.find((user) => user.email === email);
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const userIndex = this.users.findIndex((user) => user.id === id);
    if (userIndex === -1) {
      throw new NotFoundException('User not found');
    }

    this.users[userIndex] = { ...this.users[userIndex], ...updateUserDto };
    return this.users[userIndex];
  }

  async remove(id: string): Promise<void> {
    const userIndex = this.users.findIndex((user) => user.id === id);
    if (userIndex === -1) {
      throw new NotFoundException('User not found');
    }

    this.users.splice(userIndex, 1);
  }
}
`,
    'src/users/users.controller.ts': `import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Query,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@ApiTags('users')
@Controller('users')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiOperation({ summary: 'Create a new user (admin only)' })
  @ApiResponse({ status: 201, description: 'User successfully created' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Get()
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiOperation({ summary: 'Get all users (admin only)' })
  @ApiResponse({ status: 200, description: 'List of all users' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  findAll() {
    return this.usersService.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get user by ID' })
  @ApiResponse({ status: 200, description: 'User found' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async findOne(@Param('id') id: string) {
    const user = await this.usersService.findById(id);
    if (!user) {
      throw new Error('User not found');
    }
    const { password, ...result } = user;
    return result;
  }

  @Patch(':id')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiOperation({ summary: 'Update user (admin only)' })
  @ApiResponse({ status: 200, description: 'User successfully updated' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  @ApiResponse({ status: 404, description: 'User not found' })
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  @Delete(':id')
  @UseGuards(RolesGuard)
  @Roles('admin')
  @ApiOperation({ summary: 'Delete user (admin only)' })
  @ApiResponse({ status: 200, description: 'User successfully deleted' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  @ApiResponse({ status: 404, description: 'User not found' })
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}
`,
    'src/users/dto/create-user.dto.ts': `import { IsEmail, IsNotEmpty, IsString, MinLength, IsOptional, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

export class CreateUserDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'password123', minLength: 8 })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;

  @ApiProperty({ example: 'John Doe', required: false })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiProperty({ enum: UserRole, default: UserRole.USER, required: false })
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
}
`,
    'src/users/dto/update-user.dto.ts': `import { PartialType } from '@nestjs/swagger';
import { CreateUserDto } from './create-user.dto';

export class UpdateUserDto extends PartialType(CreateUserDto) {}
`,
    'src/health/health.module.ts': `import { Module } from '@nestjs/common';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';

@Module({
  controllers: [HealthController],
  providers: [HealthService],
})
export class HealthModule {}
`,
    'src/health/health.service.ts': `import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class HealthService {
  constructor(private configService: ConfigService) {}

  getHealthStatus() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: this.configService.get('nodeEnv'),
      version: '1.0.0',
    };
  }

  getDetailedHealth() {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: this.configService.get('nodeEnv'),
      version: '1.0.0',
      memory: {
        rss: Math.round(memoryUsage.rss / 1024 / 1024) + ' MB',
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB',
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB',
        external: Math.round(memoryUsage.external / 1024 / 1024) + ' MB',
      },
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system,
      },
    };
  }

  getReadiness() {
    // Add checks for database, external services, etc.
    return {
      ready: true,
      timestamp: new Date().toISOString(),
      checks: {
        database: 'ok', // Replace with actual database check
        externalServices: 'ok', // Replace with actual service checks
      },
    };
  }

  getLiveness() {
    return {
      alive: true,
      timestamp: new Date().toISOString(),
    };
  }
}
`,
    'src/health/health.controller.ts': `import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { HealthService } from './health.service';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  @ApiOperation({ summary: 'Basic health check' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  getHealth() {
    return this.healthService.getHealthStatus();
  }

  @Get('detailed')
  @ApiOperation({ summary: 'Detailed health check with system metrics' })
  @ApiResponse({ status: 200, description: 'Detailed health information' })
  getDetailedHealth() {
    return this.healthService.getDetailedHealth();
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe for Kubernetes' })
  @ApiResponse({ status: 200, description: 'Service is ready' })
  getReadiness() {
    return this.healthService.getReadiness();
  }

  @Get('live')
  @ApiOperation({ summary: 'Liveness probe for Kubernetes' })
  @ApiResponse({ status: 200, description: 'Service is alive' })
  getLiveness() {
    return this.healthService.getLiveness();
  }
}
`,
    'src/common/interceptors/logging.interceptor.ts': `import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const method = request.method;
    const url = request.url;
    const userAgent = request.get('User-Agent') || '';
    const ip = request.ip;

    const now = Date.now();

    return next.handle().pipe(
      tap(() => {
        const response = context.switchToHttp().getResponse();
        const statusCode = response.statusCode;
        const delay = Date.now() - now;

        this.logger.log(
          \`\${method} \${url} \${statusCode} \${delay}ms - \${userAgent} \${ip}\`,
        );
      }),
    );
  }
}
`,
    'src/common/interceptors/transform.interceptor.ts': `import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Response<T> {
  success: boolean;
  data: T;
  timestamp: string;
  path: string;
}

@Injectable()
export class TransformInterceptor<T>
  implements NestInterceptor<T, Response<T>>
{
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<Response<T>> {
    const request = context.switchToHttp().getRequest();

    return next.handle().pipe(
      map((data) => ({
        success: true,
        data,
        timestamp: new Date().toISOString(),
        path: request.url,
      })),
    );
  }
}
`,
    'src/common/filters/http-exception.filter.ts': `import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();

    const errorResponse = {
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      message: exception.message || null,
    };

    if (status === HttpStatus.INTERNAL_SERVER_ERROR) {
      this.logger.error(
        \`\${request.method} \${request.url}\`,
        exception.stack,
        'ExceptionFilter',
      );
    } else {
      this.logger.warn(
        \`\${request.method} \${request.url} - \${exception.message}\`,
        'ExceptionFilter',
      );
    }

    response.status(status).json(errorResponse);
  }
}
`,
    '.env.example': `# Server Configuration
NODE_ENV=development
PORT=3000

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=7d

# Bcrypt Configuration
BCRYPT_ROUNDS=12

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Database Configuration
DB_TYPE=postgres
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_NAME=nestjs_app

# Logging
LOG_LEVEL=debug


# Database Configuration
DATABASE_URL="postgresql://username:password@localhost:5432/mydb?schema=public"

# Prisma Configuration
PRISMA_SCHEMA_DISABLE_ADVISORY_LOCK="1"`,
    '.gitignore': `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Compiled output
/dist
/tmp
/out-tsc

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Logs
logs
*.log

# Coverage directory used by tools like istanbul
coverage
*.lcov

# nyc test coverage
.nyc_output

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# IDE - VSCode
.vscode/*
!.vscode/settings.json
!.vscode/tasks.json
!.vscode/launch.json
!.vscode/extensions.json

# IDE - IntelliJ
.idea/
*.iml
*.ipr
*.iws

# OS
.DS_Store
Thumbs.db
`,
    '.eslintrc.js': `module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint/eslint-plugin'],
  extends: [
    'eslint:recommended',
    '@typescript-eslint/recommended',
    'prettier',
  ],
  root: true,
  env: {
    node: true,
    jest: true,
  },
  ignorePatterns: ['.eslintrc.js'],
  rules: {
    '@typescript-eslint/interface-name-prefix': 'off',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-unused-vars': 'error',
    'prefer-const': 'error',
  },
};
`,
    '.prettierrc': `{
  "semi": true,
  "trailingComma": "all",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false
}
`,
    'README.md': `# {{projectName}}

An enterprise-grade NestJS API server with TypeScript, dependency injection, modules, guards, interceptors, and comprehensive enterprise features.

## Features

- 🏗️ **NestJS Framework** - Progressive Node.js framework for scalable server-side applications
- 💉 **Dependency Injection** - Powerful IoC container with decorators
- 🏭 **Modular Architecture** - Feature modules with clear separation of concerns
- 🛡️ **Guards & Interceptors** - Route protection and request/response transformation
- 🔐 **JWT Authentication** - Passport-based authentication with multiple strategies
- ✅ **Validation** - Class-validator for DTO validation
- 📊 **Auto Documentation** - Swagger/OpenAPI documentation generation
- 🔄 **Rate Limiting** - Built-in throttling protection
- 🏥 **Health Checks** - Kubernetes-ready health endpoints
- 🧪 **Testing Ready** - Jest testing framework with e2e support
- 🐳 **Production Ready** - Docker configuration and deployment setup

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
   npm run start:dev
   \`\`\`

4. **Visit the API documentation:**
   Open [http://localhost:3000/docs](http://localhost:3000/docs)

5. **Build for production:**
   \`\`\`bash
   npm run build
   npm run start:prod
   \`\`\`

## API Endpoints

### Application
- \`GET /api/v1\` - Application information

### Health Checks
- \`GET /api/v1/health\` - Basic health check
- \`GET /api/v1/health/detailed\` - Detailed system information
- \`GET /api/v1/health/ready\` - Readiness probe (Kubernetes)
- \`GET /api/v1/health/live\` - Liveness probe (Kubernetes)

### Authentication
- \`POST /api/v1/auth/register\` - Register new user
- \`POST /api/v1/auth/login\` - Login user
- \`GET /api/v1/auth/profile\` - Get current user profile (requires auth)

### Users
- \`GET /api/v1/users\` - Get all users (admin only)
- \`GET /api/v1/users/:id\` - Get user by ID (requires auth)
- \`POST /api/v1/users\` - Create user (admin only)
- \`PATCH /api/v1/users/:id\` - Update user (admin only)
- \`DELETE /api/v1/users/:id\` - Delete user (admin only)

### Documentation
- \`GET /docs\` - Swagger UI documentation

## Architecture

### Modules
The application is organized into feature modules:

- **AppModule** - Root module with global configuration
- **AuthModule** - Authentication and authorization
- **UsersModule** - User management
- **HealthModule** - Health check endpoints

### Guards
- **JwtAuthGuard** - JWT token validation
- **LocalAuthGuard** - Local username/password authentication
- **RolesGuard** - Role-based access control

### Interceptors
- **LoggingInterceptor** - Request/response logging
- **TransformInterceptor** - Response transformation

### Strategies
- **JwtStrategy** - JWT token verification
- **LocalStrategy** - Local authentication

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`NODE_ENV\` | Environment | \`development\` |
| \`PORT\` | Server port | \`3000\` |
| \`JWT_SECRET\` | JWT secret key | Required |
| \`JWT_EXPIRES_IN\` | JWT expiration | \`7d\` |
| \`BCRYPT_ROUNDS\` | Bcrypt rounds | \`12\` |
| \`ALLOWED_ORIGINS\` | CORS allowed origins | \`*\` |
| \`DB_TYPE\` | Database type | \`postgres\` |
| \`DB_HOST\` | Database host | \`localhost\` |
| \`DB_PORT\` | Database port | \`5432\` |
| \`DB_USERNAME\` | Database username | \`postgres\` |
| \`DB_PASSWORD\` | Database password | \`postgres\` |
| \`DB_NAME\` | Database name | \`nestjs_app\` |

## Scripts

- \`npm run start\` - Start production server
- \`npm run start:dev\` - Start development server with hot reload
- \`npm run start:debug\` - Start server in debug mode
- \`npm run start:prod\` - Start production server (requires build)
- \`npm run build\` - Build for production
- \`npm run test\` - Run unit tests
- \`npm run test:watch\` - Run tests in watch mode
- \`npm run test:cov\` - Run tests with coverage
- \`npm run test:e2e\` - Run end-to-end tests
- \`npm run lint\` - Run ESLint
- \`npm run format\` - Format code with Prettier

## Project Structure

\`\`\`
src/
├── app/                 # Application module
│   ├── app.controller.ts
│   ├── app.module.ts
│   └── app.service.ts
├── auth/                # Authentication module
│   ├── decorators/      # Custom decorators
│   ├── dto/            # Data transfer objects
│   ├── guards/         # Authentication guards
│   ├── strategies/     # Passport strategies
│   ├── auth.controller.ts
│   ├── auth.module.ts
│   └── auth.service.ts
├── users/              # Users module
│   ├── dto/
│   ├── users.controller.ts
│   ├── users.module.ts
│   └── users.service.ts
├── health/             # Health check module
│   ├── health.controller.ts
│   ├── health.module.ts
│   └── health.service.ts
├── common/             # Shared utilities
│   ├── filters/        # Exception filters
│   └── interceptors/   # HTTP interceptors
├── config/             # Configuration
│   ├── configuration.ts
│   └── database.config.ts
└── main.ts             # Application entry point
\`\`\`

## Dependency Injection

NestJS provides a powerful dependency injection system:

\`\`\`typescript
@Injectable()
export class UserService {
  constructor(
    private configService: ConfigService,
    private jwtService: JwtService,
  ) {}
}
\`\`\`

## Decorators

### Custom Decorators
- \`@Roles()\` - Define required roles for endpoints

### Built-in Decorators
- \`@Controller()\` - Define controllers
- \`@Injectable()\` - Mark classes as injectable
- \`@UseGuards()\` - Apply guards to routes
- \`@UseInterceptors()\` - Apply interceptors

## Validation

Using class-validator for DTO validation:

\`\`\`typescript
export class CreateUserDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;
}
\`\`\`

## Testing

The template includes comprehensive testing setup:

\`\`\`bash
# Unit tests
npm run test

# Watch mode
npm run test:watch

# Coverage report
npm run test:cov

# End-to-end tests
npm run test:e2e
\`\`\`

Example test:

\`\`\`typescript
describe('AuthController', () => {
  let controller: AuthController;
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [AuthService],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
\`\`\`

## Database Integration

To enable database integration with TypeORM:

1. Uncomment the TypeORM configuration in \`app.module.ts\`
2. Create entity classes in each module
3. Update the database configuration in \`.env\`

Example entity:

\`\`\`typescript
@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ default: 'user' })
  role: string;
}
\`\`\`

## Microservices

NestJS supports multiple transport layers for microservices:

- TCP
- Redis
- NATS
- RabbitMQ (AMQP)
- gRPC
- Kafka

## Production Deployment

1. Set \`NODE_ENV=production\`
2. Use a strong \`JWT_SECRET\`
3. Configure proper database connection
4. Set up proper CORS origins
5. Use process manager (PM2, Docker)
6. Configure reverse proxy (nginx)
7. Set up SSL/TLS certificates
8. Monitor with health checks

## Docker Deployment

\`\`\`dockerfile
FROM node:18-alpine AS development
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=development
COPY . .
RUN npm run build

FROM node:18-alpine AS production
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force
COPY --from=development /usr/src/app/dist ./dist
CMD ["node", "dist/main"]
\`\`\`

## License

MIT
`,
    'Dockerfile': `# Multi-stage build for NestJS application
FROM node:18-alpine AS development

WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install all dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

WORKDIR /usr/src/app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \\
    adduser -S nestjs -u 1001

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy built application from development stage
COPY --from=development --chown=nestjs:nodejs /usr/src/app/dist ./dist

# Switch to non-root user
USER nestjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD node -e "require('http').get('http://localhost:3000/api/v1/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "dist/main.js"]
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
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USERNAME=postgres
      - DB_PASSWORD=postgres
      - DB_NAME=nestjs_app
    depends_on:
      - postgres
      - redis
    networks:
      - app-network
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=nestjs_app
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
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
  postgres-data:
  redis-data:

networks:
  app-network:
    driver: bridge
`,
    'test/jest-e2e.json': `{
  "moduleFileExtensions": ["js", "json", "ts"],
  "rootDir": ".",
  "testEnvironment": "node",
  "testRegex": ".e2e-spec.ts$",
  "transform": {
    "^.+\\.(t|j)s$": "ts-jest"
  }
}
`,
    'test/app.e2e-spec.ts': `import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app/app.module';

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('/api/v1 (GET)', () => {
    return request(app.getHttpServer())
      .get('/api/v1')
      .expect(200)
      .expect((res) => {
        expect(res.body.name).toBeDefined();
        expect(res.body.version).toBeDefined();
        expect(res.body.environment).toBeDefined();
      });
  });

  it('/api/v1/health (GET)', () => {
    return request(app.getHttpServer())
      .get('/api/v1/health')
      .expect(200)
      .expect((res) => {
        expect(res.body.status).toBe('ok');
        expect(res.body.uptime).toBeDefined();
      });
  });
});
`
  },
  prompts: [
    {
      type: 'input',
      name: 'projectName',
      message: 'What is your project name?',
      default: 'nestjs-api'
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
      message: 'Include database integration (TypeORM)?',
      default: true
    },
    {
      type: 'list',
      name: 'database',
      message: 'Which database would you like to use?',
      choices: ['PostgreSQL', 'MySQL', 'SQLite', 'MongoDB'],
      when: (answers) => answers.includeDatabase,
      default: 'PostgreSQL'
    },
    {
      type: 'confirm',
      name: 'includeDocker',
      message: 'Include Docker configuration?',
      default: true
    },
    {
      type: 'confirm',
      name: 'includeSwagger',
      message: 'Include Swagger/OpenAPI documentation?',
      default: true
    },
    {
      type: 'confirm',
      name: 'includeMicroservices',
      message: 'Include microservices support?',
      default: false
    }
  ],
  postInstall: [
    'npm install',
    'cp .env.example .env',
    'echo "✅ NestJS TypeScript template created successfully!"',
    'echo "📝 Don\'t forget to:"',
    'echo "   1. Update .env with your configuration"',
    'echo "   2. Run \'npm run start:dev\' to start development"',
    'echo "   3. Visit http://localhost:3000/docs for API documentation"',
    'echo "   4. Visit http://localhost:3000/api/v1/health for health check"'
      'npx prisma generate',
    'echo "📋 Database setup:"',
    'echo "1. Set DATABASE_URL in .env"',
    'echo "2. Run: npm run db:push"',
    'echo "3. Run: npm run db:seed"',]
};