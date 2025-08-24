import { NodeBackendGenerator } from './node-base-generator';
import * as path from 'path';

export class NestJSGenerator extends NodeBackendGenerator {
  constructor() {
    super('NestJS');
  }
  
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application file (NestJS uses main.ts instead of index.ts)
    await this.writeFile(path.join(projectPath, 'src/main.ts'), this.generateMainFile());
    
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
    
    // Generate util files
    const utilFiles = this.generateUtilFiles();
    for (const file of utilFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
  }
  
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      '@nestjs/common': '^10.3.3',
      '@nestjs/core': '^10.3.3',
      '@nestjs/platform-express': '^10.3.3',
      '@nestjs/config': '^3.2.0',
      '@nestjs/jwt': '^10.2.0',
      '@nestjs/passport': '^10.0.3',
      '@nestjs/throttler': '^5.1.2',
      '@nestjs/typeorm': '^10.0.2',
      '@nestjs/swagger': '^7.3.0',
      '@nestjs/websockets': '^10.3.3',
      '@nestjs/platform-socket.io': '^10.3.3',
      '@nestjs/serve-static': '^4.0.1',
      'typeorm': '^0.3.20',
      'pg': '^8.11.3',
      'redis': '^4.6.13',
      'bcryptjs': '^2.4.3',
      'passport': '^0.7.0',
      'passport-jwt': '^4.0.1',
      'passport-local': '^1.0.0',
      'class-validator': '^0.14.1',
      'class-transformer': '^0.5.1',
      'helmet': '^7.1.0',
      'compression': '^1.7.4',
      'cookie-parser': '^1.4.6',
      'multer': '^1.4.5-lts.1',
      'nodemailer': '^6.9.11',
      'socket.io': '^4.7.5',
      'reflect-metadata': '^0.2.1',
      'rxjs': '^7.8.1'
    };
  }
  
  protected getFrameworkDevDependencies(): Record<string, string> {
    return {
      '@nestjs/cli': '^10.3.2',
      '@nestjs/schematics': '^10.1.1',
      '@nestjs/testing': '^10.3.3',
      '@types/express': '^4.17.21',
      '@types/jest': '^29.5.12',
      '@types/node': '^20.11.24',
      '@types/supertest': '^6.0.2',
      '@types/bcryptjs': '^2.4.6',
      '@types/passport-jwt': '^4.0.1',
      '@types/passport-local': '^1.0.38',
      '@types/multer': '^1.4.11',
      '@types/nodemailer': '^6.4.14',
      '@types/cookie-parser': '^1.4.7',
      '@typescript-eslint/eslint-plugin': '^7.1.1',
      '@typescript-eslint/parser': '^7.1.1',
      'eslint': '^8.57.0',
      'eslint-config-prettier': '^9.1.0',
      'eslint-plugin-prettier': '^5.1.3',
      'jest': '^29.7.0',
      'prettier': '^3.2.5',
      'source-map-support': '^0.5.21',
      'supertest': '^6.3.4',
      'ts-jest': '^29.1.2',
      'ts-loader': '^9.5.1',
      'ts-node': '^10.9.2',
      'tsconfig-paths': '^4.2.0',
      'typescript': '^5.3.3'
    };
  }
  
  protected generateMainFile(): string {
    return `import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import * as compression from 'compression';
import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  
  // Global middleware
  app.use(helmet());
  app.use(compression());
  app.use(cookieParser());
  
  // CORS configuration
  app.enableCors({
    origin: configService.get('CORS_ORIGINS')?.split(',') || ['http://localhost:3000'],
    credentials: true,
  });
  
  // Global validation pipe
  app.useGlobalPipes(new ValidationPipe({
    transform: true,
    whitelist: true,
    forbidNonWhitelisted: true,
  }));
  
  // Global prefix
  app.setGlobalPrefix('api/v1');
  
  // Swagger documentation
  if (configService.get('NODE_ENV') !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('NestJS API')
      .setDescription('API documentation for NestJS application')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);
  }
  
  const port = configService.get('PORT') || 3000;
  await app.listen(port);
  console.log(\`🚀 Application is running on: http://localhost:\${port}\`);
  console.log(\`📚 API Documentation: http://localhost:\${port}/api/docs\`);
}

bootstrap();`;
  }
  
  protected generateRoutingFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/app.module.ts',
        content: `import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule } from '@nestjs/throttler';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ServeStaticModule } from '@nestjs/serve-static';
import { join } from 'path';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { HealthModule } from './health/health.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DatabaseConfig } from './config/database.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    TypeOrmModule.forRootAsync({
      useClass: DatabaseConfig,
    }),
    ThrottlerModule.forRoot([{
      ttl: 60000,
      limit: 100,
    }]),
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET || 'your-secret-key',
      signOptions: { expiresIn: '24h' },
    }),
    PassportModule,
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'uploads'),
      serveRoot: '/uploads',
    }),
    AuthModule,
    UsersModule,
    HealthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}`
      }
    ];
  }
  
  protected generateControllerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/app.controller.ts',
        content: `import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';

@ApiTags('App')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({ summary: 'Get application info' })
  @ApiResponse({ status: 200, description: 'Application information' })
  getHello(): string {
    return this.appService.getHello();
  }
}`
      },
      {
        path: 'src/auth/auth.controller.ts',
        content: `import { Controller, Post, Body, UseGuards, Request, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register new user' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({ status: 200, description: 'User logged in successfully' })
  async login(@Request() req, @Body() loginDto: LoginDto) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({ status: 200, description: 'User profile retrieved' })
  getProfile(@Request() req) {
    return req.user;
  }
}`
      },
      {
        path: 'src/users/users.controller.ts',
        content: `import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('Users')
@Controller('users')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @ApiOperation({ summary: 'Create user' })
  @ApiResponse({ status: 201, description: 'User created successfully' })
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Get()
  @ApiOperation({ summary: 'Get all users' })
  @ApiResponse({ status: 200, description: 'Users retrieved successfully' })
  findAll(@Query('page') page: string = '1', @Query('limit') limit: string = '10') {
    return this.usersService.findAll(+page, +limit);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get user by ID' })
  @ApiResponse({ status: 200, description: 'User retrieved successfully' })
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(+id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update user' })
  @ApiResponse({ status: 200, description: 'User updated successfully' })
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(+id, updateUserDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete user' })
  @ApiResponse({ status: 200, description: 'User deleted successfully' })
  remove(@Param('id') id: string) {
    return this.usersService.remove(+id);
  }
}`
      },
      {
        path: 'src/health/health.controller.ts',
        content: `import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { HealthService } from './health.service';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  @ApiOperation({ summary: 'Health check' })
  @ApiResponse({ status: 200, description: 'Health status' })
  check() {
    return this.healthService.check();
  }
}`
      }
    ];
  }
  
  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/app.service.ts',
        content: `import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello from NestJS API!';
  }
}`
      },
      {
        path: 'src/auth/auth.service.ts',
        content: `import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (user && await bcrypt.compare(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
      user,
    };
  }

  async register(registerDto: RegisterDto) {
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    return this.usersService.create({
      ...registerDto,
      password: hashedPassword,
    });
  }
}`
      },
      {
        path: 'src/users/users.service.ts',
        content: `import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  create(createUserDto: CreateUserDto) {
    const user = this.usersRepository.create(createUserDto);
    return this.usersRepository.save(user);
  }

  async findAll(page: number = 1, limit: number = 10) {
    const [users, total] = await this.usersRepository.findAndCount({
      skip: (page - 1) * limit,
      take: limit,
      select: ['id', 'email', 'firstName', 'lastName', 'createdAt', 'updatedAt'],
    });

    return {
      users,
      total,
      page,
      totalPages: Math.ceil(total / limit),
    };
  }

  async findOne(id: number) {
    const user = await this.usersRepository.findOne({
      where: { id },
      select: ['id', 'email', 'firstName', 'lastName', 'createdAt', 'updatedAt'],
    });
    
    if (!user) {
      throw new NotFoundException(\`User with ID \${id} not found\`);
    }
    
    return user;
  }

  async findByEmail(email: string) {
    return this.usersRepository.findOne({ where: { email } });
  }

  async update(id: number, updateUserDto: UpdateUserDto) {
    await this.usersRepository.update(id, updateUserDto);
    return this.findOne(id);
  }

  async remove(id: number) {
    const user = await this.findOne(id);
    await this.usersRepository.remove(user);
    return { message: 'User deleted successfully' };
  }
}`
      },
      {
        path: 'src/health/health.service.ts',
        content: `import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

@Injectable()
export class HealthService {
  constructor(
    @InjectDataSource()
    private dataSource: DataSource,
  ) {}

  async check() {
    const health = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      services: {
        database: 'unknown',
        memory: this.getMemoryUsage(),
        uptime: process.uptime(),
      },
    };

    try {
      await this.dataSource.query('SELECT 1');
      health.services.database = 'healthy';
    } catch (error) {
      health.services.database = 'unhealthy';
      health.status = 'degraded';
    }

    return health;
  }

  private getMemoryUsage() {
    const usage = process.memoryUsage();
    return {
      used: Math.round(usage.heapUsed / 1024 / 1024),
      total: Math.round(usage.heapTotal / 1024 / 1024),
      external: Math.round(usage.external / 1024 / 1024),
    };
  }
}`
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/auth/guards/local-auth.guard.ts',
        content: `import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}`
      },
      {
        path: 'src/auth/guards/jwt-auth.guard.ts',
        content: `import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}`
      },
      {
        path: 'src/auth/strategies/local.strategy.ts',
        content: `import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
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
}`
      },
      {
        path: 'src/auth/strategies/jwt.strategy.ts',
        content: `import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET') || 'your-secret-key',
    });
  }

  async validate(payload: any) {
    return { id: payload.sub, email: payload.email };
  }
}`
      }
    ];
  }
  
  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/config/database.config.ts',
        content: `import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions, TypeOrmOptionsFactory } from '@nestjs/typeorm';
import { User } from '../users/entities/user.entity';

@Injectable()
export class DatabaseConfig implements TypeOrmOptionsFactory {
  constructor(private configService: ConfigService) {}

  createTypeOrmOptions(): TypeOrmModuleOptions {
    return {
      type: 'postgres',
      host: this.configService.get('DB_HOST') || 'localhost',
      port: this.configService.get('DB_PORT') || 5432,
      username: this.configService.get('DB_USERNAME') || 'postgres',
      password: this.configService.get('DB_PASSWORD') || 'postgres',
      database: this.configService.get('DB_NAME') || 'nestjs_db',
      entities: [User],
      synchronize: this.configService.get('NODE_ENV') !== 'production',
      logging: this.configService.get('NODE_ENV') === 'development',
    };
  }
}`
      },
      {
        path: 'src/auth/auth.module.ts',
        content: `import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET') || 'your-secret-key',
        signOptions: { expiresIn: '24h' },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}`
      },
      {
        path: 'src/users/users.module.ts',
        content: `import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { User } from './entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}`
      },
      {
        path: 'src/health/health.module.ts',
        content: `import { Module } from '@nestjs/common';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';

@Module({
  controllers: [HealthController],
  providers: [HealthService],
})
export class HealthModule {}`
      }
    ];
  }
  
  protected generateUtilFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/users/entities/user.entity.ts',
        content: `import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { Exclude } from 'class-transformer';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude()
  password: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}`
      },
      {
        path: 'src/auth/dto/login.dto.ts',
        content: `import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class LoginDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsNotEmpty()
  @MinLength(6)
  password: string;
}`
      },
      {
        path: 'src/auth/dto/register.dto.ts',
        content: `import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class RegisterDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsNotEmpty()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'John' })
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({ example: 'Doe' })
  @IsNotEmpty()
  lastName: string;
}`
      },
      {
        path: 'src/users/dto/create-user.dto.ts',
        content: `import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class CreateUserDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsNotEmpty()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'John' })
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({ example: 'Doe' })
  @IsNotEmpty()
  lastName: string;
}`
      },
      {
        path: 'src/users/dto/update-user.dto.ts',
        content: `import { PartialType } from '@nestjs/swagger';
import { CreateUserDto } from './create-user.dto';

export class UpdateUserDto extends PartialType(CreateUserDto) {}`
      }
    ];
  }
}