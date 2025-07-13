/**
 * Angel3 Framework Template Generator
 * Full-stack server-side framework for Dart
 */

import { DartBackendGenerator } from './dart-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class Angel3Generator extends DartBackendGenerator {
  constructor() {
    super('Angel3');
  }

  protected getFrameworkDependencies(): string[] {
    return [
      'angel3_framework: ^8.0.0',
      'angel3_production: ^8.0.0',
      'angel3_hot: ^8.0.0',
      'angel3_static: ^8.0.0',
      'angel3_cors: ^8.0.0',
      'angel3_auth: ^8.0.0',
      'angel3_oauth2: ^8.0.0',
      'angel3_validate: ^8.0.0',
      'angel3_serialize: ^8.0.0',
      'angel3_orm: ^8.0.0',
      'angel3_orm_postgres: ^8.0.0',
      'angel3_migration: ^8.0.0',
      'angel3_configuration: ^8.0.0',
      'angel3_jael: ^8.0.0',
      'angel3_mustache: ^8.0.0',
      'angel3_redis: ^8.0.0',
      'angel3_cache: ^8.0.0',
      'angel3_websocket: ^8.0.0',
      'angel3_security: ^8.0.0',
      'angel3_test: ^8.0.0',
      'belatuk_pretty_logging: ^6.0.0',
      'postgres: ^2.6.3',
      'redis: ^3.1.0',
      'dotenv: ^4.1.0',
      'uuid: ^4.2.2',
      'crypto: ^3.0.3',
      'collection: ^1.18.0',
      'mime: ^1.0.4',
      'path: ^1.8.3'
    ];
  }

  protected getDevDependencies(): string[] {
    return [
      'angel3_serialize_generator: ^8.0.0',
      'angel3_orm_generator: ^8.0.0',
      'angel3_migration_runner: ^8.0.0',
      'build_runner: ^2.4.7',
      'build_config: ^1.1.1',
      'source_gen: ^1.4.0'
    ];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main server file
    await this.generateMainServer(projectPath, options);

    // Generate app configuration
    await this.generateAppConfig(projectPath, options);

    // Generate routes
    await this.generateRoutes(projectPath);

    // Generate controllers
    await this.generateControllers(projectPath);

    // Generate services
    await this.generateServices(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate middleware
    await this.generateMiddleware(projectPath);

    // Generate validators
    await this.generateValidators(projectPath);

    // Generate database setup
    await this.generateDatabase(projectPath);

    // Generate migrations
    await this.generateMigrations(projectPath);

    // Generate views
    await this.generateViews(projectPath);

    // Generate WebSocket handlers
    await this.generateWebSocketHandlers(projectPath);

    // Generate configuration files
    await this.generateConfigFiles(projectPath);

    // Generate plugins
    await this.generatePlugins(projectPath);
  }

  private async generateMainServer(projectPath: string, options: any): Promise<void> {
    const serverContent = `import 'dart:async';
import 'dart:io';
import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_framework/http.dart';
import 'package:angel3_framework/http2.dart';
import 'package:angel3_production/angel3_production.dart';
import 'package:angel3_hot/angel3_hot.dart';
import 'package:belatuk_pretty_logging/belatuk_pretty_logging.dart';
import 'package:dotenv/dotenv.dart';
import 'package:logging/logging.dart';

import '../lib/src/app.dart';
import '../lib/src/config/config.dart';

void main(List<String> args) async {
  // Load environment variables
  final env = DotEnv()..load();
  
  // Configure logging
  hierarchicalLoggingEnabled = true;
  
  if (env['ENVIRONMENT'] == 'production') {
    // Production mode
    return runZoned(() async {
      Logger.root.onRecord.listen(prettyLog);
      
      final app = await createApp();
      final server = await AngelHttp(app).startServer(
        InternetAddress.anyIPv4,
        int.parse(env['PORT'] ?? '3000'),
      );
      
      print('🚀 Angel3 server listening at http://\${server.address.host}:\${server.port}');
    });
  } else {
    // Development mode with hot reload
    final hot = HotReloader(() async {
      Logger.root.onRecord.listen(prettyLog);
      final app = await createApp();
      return app;
    }, [
      Directory('lib'),
      Directory('config'),
    ]);
    
    final server = await hot.startServer(
      InternetAddress.anyIPv4,
      int.parse(env['PORT'] ?? '3000'),
    );
    
    print('🚀 Angel3 development server listening at http://\${server.address.host}:\${server.port}');
    print('🔥 Hot reload enabled - watching for file changes...');
  }
}

// Create and configure the Angel application
Future<Angel> createApp() async {
  final app = Angel(
    logger: Logger('${options.name}'),
    reflector: MirrorsReflector(),
  );
  
  // Configure the application
  await app.configure(configureApp);
  
  return app;
}
`;

    await fs.writeFile(
      path.join(projectPath, 'bin', 'server.dart'),
      serverContent
    );
  }

  private async generateAppConfig(projectPath: string, options: any): Promise<void> {
    const appContent = `import 'dart:io';
import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_static/angel3_static.dart';
import 'package:angel3_cors/angel3_cors.dart';
import 'package:angel3_security/angel3_security.dart';
import 'package:angel3_cache/angel3_cache.dart';
import 'package:angel3_configuration/angel3_configuration.dart';
import 'package:file/local.dart';
import 'package:dotenv/dotenv.dart';

import 'config/config.dart';
import 'routes/routes.dart';
import 'services/services.dart';
import 'plugins/plugins.dart';
import 'hooks/hooks.dart';

// Main application configuration
Future<void> configureApp(Angel app) async {
  final env = DotEnv()..load();
  final fs = const LocalFileSystem();
  
  // Load configuration
  await app.configure(configuration(fs));
  
  // Apply security headers
  app.fallback(helmet());
  
  // Configure CORS
  app.fallback(cors(CorsOptions(
    origin: env['CORS_ORIGIN']?.split(',') ?? ['*'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 86400,
  )));
  
  // Configure caching
  app.fallback(cache());
  
  // Serve static files in production
  if (app.environment.isProduction) {
    final vDir = VirtualDirectory(
      app,
      fs,
      source: fs.directory('public'),
    );
    app.fallback(vDir.handleRequest);
  }
  
  // Mount services
  await app.configure(configureServices);
  
  // Mount routes
  await app.configure(configureRoutes);
  
  // Configure plugins
  await app.configure(configurePlugins);
  
  // Setup hooks
  await app.configure(configureHooks);
  
  // 404 handler
  app.fallback((req, res) {
    res
      ..statusCode = 404
      ..json({
        'error': 'Not Found',
        'message': 'The requested resource was not found',
        'path': req.uri.path,
      });
  });
  
  // Global error handler
  app.errorHandler = (e, req, res) {
    if (e.statusCode != null) {
      res.statusCode = e.statusCode;
    } else {
      res.statusCode = 500;
    }
    
    final error = {
      'error': e.message ?? 'Internal Server Error',
      'statusCode': res.statusCode,
    };
    
    if (!app.environment.isProduction && e.stackTrace != null) {
      error['stackTrace'] = e.stackTrace.toString();
    }
    
    res.json(error);
  };
}
`;

    await fs.mkdir(path.join(projectPath, 'lib', 'src'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'lib', 'src', 'app.dart'),
      appContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    const routesDir = path.join(projectPath, 'lib', 'src', 'routes');
    await fs.mkdir(routesDir, { recursive: true });

    // Main routes configuration
    const routesContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'api.dart';
import 'auth.dart';
import 'users.dart';
import 'websocket.dart';

// Configure all application routes
Future<void> configureRoutes(Angel app) async {
  // API prefix
  final api = app.group('/api/v1');
  
  // Mount route modules
  await api.configure(configureApiRoutes);
  await api.configure(configureAuthRoutes);
  await api.configure(configureUserRoutes);
  
  // WebSocket routes
  await app.configure(configureWebSocketRoutes);
  
  // Health check
  app.get('/health', (req, res) {
    res.json({
      'status': 'healthy',
      'timestamp': DateTime.now().toIso8601String(),
      'service': '${this.config.framework.toLowerCase()}-service',
      'version': '1.0.0',
    });
  });
  
  // Root route
  app.get('/', (req, res) {
    res.json({
      'message': 'Welcome to ${this.config.framework} API',
      'version': '1.0.0',
      'documentation': '/api/v1/docs',
    });
  });
}
`;

    await fs.writeFile(
      path.join(routesDir, 'routes.dart'),
      routesContent
    );

    // API routes
    const apiRoutesContent = `import 'package:angel3_framework/angel3_framework.dart';

// General API routes
Future<void> configureApiRoutes(Angel app) async {
  // API documentation
  app.get('/docs', (req, res) {
    res.json({
      'openapi': '3.0.0',
      'info': {
        'title': '${this.config.framework} API',
        'version': '1.0.0',
        'description': 'REST API built with Angel3 framework',
      },
      'servers': [
        {'url': '/api/v1'},
      ],
      'paths': {
        '/health': {
          'get': {
            'summary': 'Health check endpoint',
            'responses': {
              '200': {
                'description': 'Service is healthy',
              },
            },
          },
        },
      },
    });
  });
  
  // API info
  app.get('/info', (req, res) {
    res.json({
      'name': '${this.config.framework} API',
      'version': '1.0.0',
      'environment': app.environment.name,
      'features': [
        'Authentication',
        'WebSocket support',
        'Database integration',
        'Caching',
        'Rate limiting',
      ],
    });
  });
}
`;

    await fs.writeFile(
      path.join(routesDir, 'api.dart'),
      apiRoutesContent
    );
  }

  private async generateControllers(projectPath: string): Promise<void> {
    const controllersDir = path.join(projectPath, 'lib', 'src', 'controllers');
    await fs.mkdir(controllersDir, { recursive: true });

    // Base controller
    const baseControllerContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_orm/angel3_orm.dart';

/// Base controller with common functionality
abstract class BaseController<T> extends Controller {
  final QueryExecutor executor;
  
  BaseController(this.executor);
  
  /// Get paginated results
  Future<Map<String, dynamic>> paginate(
    RequestContext req,
    Query<T> query, {
    int defaultLimit = 20,
    int maxLimit = 100,
  }) async {
    final page = int.tryParse(req.queryParameters['page'] ?? '1') ?? 1;
    var limit = int.tryParse(req.queryParameters['limit'] ?? '\$defaultLimit') ?? defaultLimit;
    
    // Enforce max limit
    if (limit > maxLimit) limit = maxLimit;
    
    final offset = (page - 1) * limit;
    
    // Get total count
    final countQuery = query.clone();
    final total = await countQuery.count();
    
    // Get paginated results
    query.limit(limit).offset(offset);
    final items = await query.get(executor);
    
    return {
      'data': items,
      'pagination': {
        'page': page,
        'limit': limit,
        'total': total,
        'totalPages': (total / limit).ceil(),
      },
    };
  }
  
  /// Standard error response
  Map<String, dynamic> errorResponse(String message, {int? statusCode}) {
    return {
      'error': true,
      'message': message,
      'statusCode': statusCode ?? 400,
    };
  }
  
  /// Standard success response
  Map<String, dynamic> successResponse(dynamic data, {String? message}) {
    return {
      'success': true,
      'message': message ?? 'Operation successful',
      'data': data,
    };
  }
}
`;

    await fs.writeFile(
      path.join(controllersDir, 'base_controller.dart'),
      baseControllerContent
    );

    // User controller
    const userControllerContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_auth/angel3_auth.dart';
import 'package:angel3_validate/angel3_validate.dart';
import 'package:angel3_orm/angel3_orm.dart';
import 'package:crypto/crypto.dart';
import 'dart:convert';

import 'base_controller.dart';
import '../models/user.dart';
import '../services/user_service.dart';

@Expose('/users')
class UserController extends BaseController<User> {
  final UserService userService;
  
  UserController(QueryExecutor executor, this.userService) : super(executor);
  
  @Expose('/')
  @Middleware([requireAuth])
  Future<Map<String, dynamic>> index(RequestContext req, ResponseContext res) async {
    final query = UserQuery();
    
    // Apply filters
    if (req.queryParameters.containsKey('role')) {
      query.where!.role.equals(req.queryParameters['role']!);
    }
    
    if (req.queryParameters.containsKey('search')) {
      final search = req.queryParameters['search']!;
      query.where!.or([
        query.where!.name.contains(search),
        query.where!.email.contains(search),
      ]);
    }
    
    // Order by created date
    query.orderBy(UserFields.createdAt, descending: true);
    
    return await paginate(req, query);
  }
  
  @Expose('/:id')
  @Middleware([requireAuth])
  Future<Map<String, dynamic>> show(RequestContext req, ResponseContext res, String id) async {
    final user = await userService.findById(id);
    
    if (user == null) {
      throw AngelHttpException.notFound(message: 'User not found');
    }
    
    return successResponse(user.toJson()..remove('password'));
  }
  
  @Expose('/', method: 'POST')
  @Middleware([requireAuth, requireRole('admin')])
  Future<Map<String, dynamic>> create(RequestContext req, ResponseContext res) async {
    await req.parseBody();
    
    // Validate input
    final validation = Validator({
      'name*': isString,
      'email*': [isString, isEmail],
      'password*': [isString, minLength(8)],
      'role': [isString, isIn(['user', 'admin'])],
    });
    
    final result = await validation.check(req.bodyAsMap);
    if (result.errors.isNotEmpty) {
      throw AngelHttpException.badRequest(
        message: 'Validation failed',
        errors: result.errors,
      );
    }
    
    // Check if email exists
    final existing = await userService.findByEmail(result.data['email']);
    if (existing != null) {
      throw AngelHttpException.conflict(message: 'Email already exists');
    }
    
    // Hash password
    result.data['password'] = sha256.convert(
      utf8.encode(result.data['password'])
    ).toString();
    
    // Create user
    final user = await userService.create(result.data);
    
    return successResponse(
      user.toJson()..remove('password'),
      message: 'User created successfully',
    );
  }
  
  @Expose('/:id', method: 'PUT')
  @Middleware([requireAuth])
  Future<Map<String, dynamic>> update(RequestContext req, ResponseContext res, String id) async {
    await req.parseBody();
    
    // Check authorization
    final currentUser = req.container!.make<User>();
    if (currentUser.id != id && currentUser.role != 'admin') {
      throw AngelHttpException.forbidden(
        message: 'You can only update your own profile',
      );
    }
    
    // Validate input
    final validation = Validator({
      'name': isString,
      'email': [isString, isEmail],
      'role': [isString, isIn(['user', 'admin'])],
    });
    
    final result = await validation.check(req.bodyAsMap);
    if (result.errors.isNotEmpty) {
      throw AngelHttpException.badRequest(
        message: 'Validation failed',
        errors: result.errors,
      );
    }
    
    // Remove role update for non-admins
    if (currentUser.role != 'admin') {
      result.data.remove('role');
    }
    
    // Update user
    final user = await userService.update(id, result.data);
    
    if (user == null) {
      throw AngelHttpException.notFound(message: 'User not found');
    }
    
    return successResponse(
      user.toJson()..remove('password'),
      message: 'User updated successfully',
    );
  }
  
  @Expose('/:id', method: 'DELETE')
  @Middleware([requireAuth, requireRole('admin')])
  Future<Map<String, dynamic>> destroy(RequestContext req, ResponseContext res, String id) async {
    final deleted = await userService.delete(id);
    
    if (!deleted) {
      throw AngelHttpException.notFound(message: 'User not found');
    }
    
    return successResponse(null, message: 'User deleted successfully');
  }
  
  @Expose('/profile')
  @Middleware([requireAuth])
  Future<Map<String, dynamic>> profile(RequestContext req, ResponseContext res) async {
    final user = req.container!.make<User>();
    return successResponse(user.toJson()..remove('password'));
  }
  
  @Expose('/profile', method: 'PUT')
  @Middleware([requireAuth])
  Future<Map<String, dynamic>> updateProfile(RequestContext req, ResponseContext res) async {
    await req.parseBody();
    
    final user = req.container!.make<User>();
    
    // Validate input
    final validation = Validator({
      'name': isString,
      'email': [isString, isEmail],
      'currentPassword': isString,
      'newPassword': [isString, minLength(8)],
    });
    
    final result = await validation.check(req.bodyAsMap);
    if (result.errors.isNotEmpty) {
      throw AngelHttpException.badRequest(
        message: 'Validation failed',
        errors: result.errors,
      );
    }
    
    // Verify current password if changing password
    if (result.data.containsKey('newPassword')) {
      if (!result.data.containsKey('currentPassword')) {
        throw AngelHttpException.badRequest(
          message: 'Current password is required to change password',
        );
      }
      
      final currentHash = sha256.convert(
        utf8.encode(result.data['currentPassword'])
      ).toString();
      
      if (currentHash != user.password) {
        throw AngelHttpException.unauthorized(
          message: 'Current password is incorrect',
        );
      }
      
      result.data['password'] = sha256.convert(
        utf8.encode(result.data['newPassword'])
      ).toString();
      result.data.remove('currentPassword');
      result.data.remove('newPassword');
    }
    
    // Update profile
    final updated = await userService.update(user.id!, result.data);
    
    return successResponse(
      updated!.toJson()..remove('password'),
      message: 'Profile updated successfully',
    );
  }
}

// Helper middleware for role-based access
Middleware requireRole(String role) {
  return (RequestContext req, ResponseContext res) async {
    final user = req.container!.make<User>();
    
    if (user.role != role) {
      throw AngelHttpException.forbidden(
        message: 'Insufficient permissions. Required role: \$role',
      );
    }
    
    return true;
  };
}
`;

    await fs.writeFile(
      path.join(controllersDir, 'user_controller.dart'),
      userControllerContent
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    const servicesDir = path.join(projectPath, 'lib', 'src', 'services');
    await fs.mkdir(servicesDir, { recursive: true });

    // Services configuration
    const servicesContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_orm/angel3_orm.dart';
import 'package:angel3_orm_postgres/angel3_orm_postgres.dart';
import 'package:angel3_redis/angel3_redis.dart';
import 'package:postgres/postgres.dart';
import 'package:redis/redis.dart';
import 'package:dotenv/dotenv.dart';

import 'user_service.dart';
import 'auth_service.dart';
import 'cache_service.dart';
import 'email_service.dart';

// Configure all application services
Future<void> configureServices(Angel app) async {
  final env = DotEnv()..load();
  
  // Database connection
  final connection = PostgreSQLConnection(
    env['DB_HOST'] ?? 'localhost',
    int.parse(env['DB_PORT'] ?? '5432'),
    env['DB_NAME'] ?? 'angel3_db',
    username: env['DB_USER'] ?? 'postgres',
    password: env['DB_PASSWORD'] ?? 'postgres',
  );
  
  await connection.open();
  
  final executor = PostgreSqlExecutor(connection, logger: app.logger);
  app.container!.registerSingleton(executor);
  
  // Redis connection
  final redis = RedisConnection();
  final redisClient = await redis.connect(
    env['REDIS_HOST'] ?? 'localhost',
    int.parse(env['REDIS_PORT'] ?? '6379'),
  );
  
  if (env['REDIS_PASSWORD'] != null) {
    await redisClient.send_object(['AUTH', env['REDIS_PASSWORD']!]);
  }
  
  app.container!.registerSingleton(redisClient);
  
  // Register services
  app.container!.registerSingleton(UserService(executor));
  app.container!.registerSingleton(AuthService(executor, redisClient));
  app.container!.registerSingleton(CacheService(redisClient));
  app.container!.registerSingleton(EmailService());
  
  // Cleanup on shutdown
  app.shutdownHooks.add((_) async {
    await connection.close();
    await redisClient.close();
  });
}
`;

    await fs.writeFile(
      path.join(servicesDir, 'services.dart'),
      servicesContent
    );

    // User service
    const userServiceContent = `import 'package:angel3_orm/angel3_orm.dart';
import 'package:uuid/uuid.dart';
import '../models/user.dart';

class UserService {
  final QueryExecutor executor;
  final _uuid = Uuid();
  
  UserService(this.executor);
  
  /// Find user by ID
  Future<User?> findById(String id) async {
    final query = UserQuery()..where!.id.equals(id);
    final result = await query.getOne(executor);
    return result;
  }
  
  /// Find user by email
  Future<User?> findByEmail(String email) async {
    final query = UserQuery()..where!.email.equals(email);
    final result = await query.getOne(executor);
    return result;
  }
  
  /// Create new user
  Future<User> create(Map<String, dynamic> data) async {
    final query = UserQuery()..values
      ..id = _uuid.v4()
      ..name = data['name']
      ..email = data['email']
      ..password = data['password']
      ..role = data['role'] ?? 'user'
      ..createdAt = DateTime.now()
      ..updatedAt = DateTime.now();
    
    final result = await query.insert(executor);
    return result!;
  }
  
  /// Update user
  Future<User?> update(String id, Map<String, dynamic> data) async {
    final query = UserQuery()
      ..where!.id.equals(id)
      ..values.updatedAt = DateTime.now();
    
    // Update only provided fields
    if (data.containsKey('name')) query.values.name = data['name'];
    if (data.containsKey('email')) query.values.email = data['email'];
    if (data.containsKey('password')) query.values.password = data['password'];
    if (data.containsKey('role')) query.values.role = data['role'];
    if (data.containsKey('lastLogin')) query.values.lastLogin = data['lastLogin'];
    
    final result = await query.updateOne(executor);
    return result;
  }
  
  /// Delete user
  Future<bool> delete(String id) async {
    final query = UserQuery()..where!.id.equals(id);
    final result = await query.deleteOne(executor);
    return result != null;
  }
  
  /// Update last login
  Future<void> updateLastLogin(String id) async {
    final query = UserQuery()
      ..where!.id.equals(id)
      ..values.lastLogin = DateTime.now();
    
    await query.updateOne(executor);
  }
  
  /// Get all users with pagination
  Future<List<User>> getAll({
    int limit = 20,
    int offset = 0,
    String? role,
  }) async {
    final query = UserQuery()
      ..limit(limit)
      ..offset(offset)
      ..orderBy(UserFields.createdAt, descending: true);
    
    if (role != null) {
      query.where!.role.equals(role);
    }
    
    return await query.get(executor);
  }
  
  /// Count users
  Future<int> count({String? role}) async {
    final query = UserQuery();
    
    if (role != null) {
      query.where!.role.equals(role);
    }
    
    return await query.count(executor);
  }
}
`;

    await fs.writeFile(
      path.join(servicesDir, 'user_service.dart'),
      userServiceContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    const modelsDir = path.join(projectPath, 'lib', 'src', 'models');
    await fs.mkdir(modelsDir, { recursive: true });

    // User model
    const userModelContent = `import 'package:angel3_serialize/angel3_serialize.dart';
import 'package:angel3_orm/angel3_orm.dart';
import 'package:optional/optional.dart';

part 'user.g.dart';

@serializable
@orm
abstract class _User extends Model {
  @Column(isNullable: false)
  String? get name;
  
  @Column(isNullable: false, indexType: IndexType.unique)
  String? get email;
  
  @Column(isNullable: false)
  String? get password;
  
  @Column(defaultValue: 'user')
  String? get role;
  
  @Column()
  DateTime? get lastLogin;
  
  @HasMany()
  List<_Session>? get sessions;
  
  @HasMany()
  List<_RefreshToken>? get refreshTokens;
}

@serializable
@orm
abstract class _Session extends Model {
  @Column(isNullable: false)
  String? get token;
  
  @BelongsTo()
  _User? get user;
  
  @Column(isNullable: false)
  String? get ipAddress;
  
  @Column()
  String? get userAgent;
  
  @Column(isNullable: false)
  DateTime? get expiresAt;
  
  @Column(defaultValue: true)
  bool? get isActive;
}

@serializable
@orm
abstract class _RefreshToken extends Model {
  @Column(isNullable: false, indexType: IndexType.unique)
  String? get token;
  
  @BelongsTo()
  _User? get user;
  
  @Column(isNullable: false)
  DateTime? get expiresAt;
  
  @Column(defaultValue: false)
  bool? get isRevoked;
  
  @Column()
  String? get revokedAt;
  
  @Column()
  String? get replacedByToken;
}

// User roles enum
enum UserRole {
  user,
  admin,
  moderator
}

// Extension methods for User
extension UserExtensions on User {
  bool get isAdmin => role == 'admin';
  bool get isModerator => role == 'moderator';
  bool get isUser => role == 'user';
  
  bool hasRole(String requiredRole) => role == requiredRole;
  
  Map<String, dynamic> toPublicJson() {
    final json = toJson();
    json.remove('password');
    json.remove('sessions');
    json.remove('refreshTokens');
    return json;
  }
}
`;

    await fs.writeFile(
      path.join(modelsDir, 'user.dart'),
      userModelContent
    );

    // Base model
    const baseModelContent = `import 'package:angel3_serialize/angel3_serialize.dart';
import 'package:angel3_orm/angel3_orm.dart';

part 'base.g.dart';

@serializable
@orm
abstract class _BaseModel extends Model {
  @Column(isNullable: false, indexType: IndexType.primaryKey)
  @override
  String? get id;
  
  @Column(isNullable: false)
  @override
  DateTime? get createdAt;
  
  @Column(isNullable: false)
  @override
  DateTime? get updatedAt;
}
`;

    await fs.writeFile(
      path.join(modelsDir, 'base.dart'),
      baseModelContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    const middlewareDir = path.join(projectPath, 'lib', 'src', 'middleware');
    await fs.mkdir(middlewareDir, { recursive: true });

    // Auth middleware
    const authMiddlewareContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_auth/angel3_auth.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:dotenv/dotenv.dart';

import '../models/user.dart';
import '../services/auth_service.dart';

/// JWT authentication middleware
Middleware jwtAuth() {
  final env = DotEnv()..load();
  final secret = env['JWT_SECRET'] ?? 'your-secret-key';
  
  return (RequestContext req, ResponseContext res) async {
    final authHeader = req.headers?['authorization'];
    
    if (authHeader == null || !authHeader.startsWith('Bearer ')) {
      throw AngelHttpException.unauthorized(
        message: 'Missing or invalid authorization header',
      );
    }
    
    final token = authHeader.substring(7);
    
    try {
      final jwt = JWT.verify(token, SecretKey(secret));
      final payload = jwt.payload as Map<String, dynamic>;
      
      // Check token expiration
      final exp = payload['exp'] as int?;
      if (exp != null && DateTime.now().millisecondsSinceEpoch > exp * 1000) {
        throw AngelHttpException.unauthorized(message: 'Token expired');
      }
      
      // Get auth service
      final authService = req.container!.make<AuthService>();
      
      // Validate session
      final session = await authService.validateSession(token);
      if (!session) {
        throw AngelHttpException.unauthorized(message: 'Invalid session');
      }
      
      // Load user
      final userService = req.container!.make<UserService>();
      final user = await userService.findById(payload['userId']);
      
      if (user == null) {
        throw AngelHttpException.unauthorized(message: 'User not found');
      }
      
      // Inject user into request
      req.container!.registerSingleton(user);
      
      return true;
    } catch (e) {
      if (e is AngelHttpException) rethrow;
      
      throw AngelHttpException.unauthorized(
        message: 'Invalid token',
      );
    }
  };
}

/// Require authentication middleware
final requireAuth = jwtAuth();

/// API key authentication middleware
Middleware apiKeyAuth() {
  return (RequestContext req, ResponseContext res) async {
    final apiKey = req.headers?['x-api-key'] ?? req.queryParameters['api_key'];
    
    if (apiKey == null) {
      throw AngelHttpException.unauthorized(
        message: 'API key required',
      );
    }
    
    // Validate API key
    final authService = req.container!.make<AuthService>();
    final valid = await authService.validateApiKey(apiKey);
    
    if (!valid) {
      throw AngelHttpException.unauthorized(
        message: 'Invalid API key',
      );
    }
    
    return true;
  };
}

/// Combined auth middleware (JWT or API key)
Middleware flexibleAuth() {
  final jwt = jwtAuth();
  final apiKey = apiKeyAuth();
  
  return (RequestContext req, ResponseContext res) async {
    try {
      // Try JWT first
      await jwt(req, res);
      return true;
    } catch (_) {
      // Fall back to API key
      try {
        await apiKey(req, res);
        return true;
      } catch (_) {
        throw AngelHttpException.unauthorized(
          message: 'Authentication required (JWT or API key)',
        );
      }
    }
  };
}
`;

    await fs.writeFile(
      path.join(middlewareDir, 'auth.dart'),
      authMiddlewareContent
    );

    // Rate limiting middleware
    const rateLimitContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:redis/redis.dart';

/// Rate limiting middleware
Middleware rateLimit({
  int requests = 100,
  Duration window = const Duration(minutes: 15),
  String? keyGenerator,
  String? message,
}) {
  return (RequestContext req, ResponseContext res) async {
    final redis = req.container!.make<Command>();
    
    // Generate rate limit key
    String key;
    if (keyGenerator != null) {
      key = keyGenerator;
    } else {
      // Default: IP-based rate limiting
      final ip = req.ip ?? 'unknown';
      key = 'rate_limit:\$ip';
    }
    
    // Get current count
    final current = await redis.get(key);
    final count = current != null ? int.parse(current.toString()) : 0;
    
    if (count >= requests) {
      throw AngelHttpException(
        statusCode: 429,
        message: message ?? 'Too many requests. Please try again later.',
      );
    }
    
    // Increment counter
    await redis.multi();
    await redis.incr(key);
    
    if (count == 0) {
      // Set expiration on first request
      await redis.expire(key, window.inSeconds);
    }
    
    await redis.exec();
    
    // Add rate limit headers
    res.headers['X-RateLimit-Limit'] = requests.toString();
    res.headers['X-RateLimit-Remaining'] = (requests - count - 1).toString();
    res.headers['X-RateLimit-Reset'] = DateTime.now()
        .add(window)
        .millisecondsSinceEpoch
        .toString();
    
    return true;
  };
}

/// Strict rate limit for sensitive endpoints
final strictRateLimit = rateLimit(
  requests: 5,
  window: Duration(minutes: 15),
  message: 'Too many attempts. Please try again in 15 minutes.',
);

/// API rate limit
final apiRateLimit = rateLimit(
  requests: 1000,
  window: Duration(hours: 1),
);
`;

    await fs.writeFile(
      path.join(middlewareDir, 'rate_limit.dart'),
      rateLimitContent
    );
  }

  private async generateValidators(projectPath: string): Promise<void> {
    const validatorsDir = path.join(projectPath, 'lib', 'src', 'validators');
    await fs.mkdir(validatorsDir, { recursive: true });

    // Custom validators
    const validatorsContent = `import 'package:angel3_validate/angel3_validate.dart';

/// Password strength validator
final Matcher strongPassword = predicate((value) {
  if (value is! String) return false;
  
  // At least 8 characters
  if (value.length < 8) return false;
  
  // Contains uppercase
  if (!value.contains(RegExp(r'[A-Z]'))) return false;
  
  // Contains lowercase
  if (!value.contains(RegExp(r'[a-z]'))) return false;
  
  // Contains number
  if (!value.contains(RegExp(r'[0-9]'))) return false;
  
  // Contains special character
  if (!value.contains(RegExp(r'[!@#\$%^&*(),.?":{}|<>]'))) return false;
  
  return true;
}, 'must be at least 8 characters with uppercase, lowercase, number, and special character');

/// Username validator
final Matcher validUsername = predicate((value) {
  if (value is! String) return false;
  
  // 3-20 characters
  if (value.length < 3 || value.length > 20) return false;
  
  // Alphanumeric and underscore only
  if (!RegExp(r'^[a-zA-Z0-9_]+\$').hasMatch(value)) return false;
  
  return true;
}, 'must be 3-20 characters, alphanumeric and underscore only');

/// Phone number validator
final Matcher validPhone = predicate((value) {
  if (value is! String) return false;
  
  // Basic international phone validation
  return RegExp(r'^\+?[1-9]\d{1,14}\$').hasMatch(value);
}, 'must be a valid phone number');

/// URL validator
final Matcher validUrl = predicate((value) {
  if (value is! String) return false;
  
  try {
    final uri = Uri.parse(value);
    return uri.isAbsolute && (uri.scheme == 'http' || uri.scheme == 'https');
  } catch (_) {
    return false;
  }
}, 'must be a valid URL');

/// UUID validator
final Matcher validUuid = predicate((value) {
  if (value is! String) return false;
  
  return RegExp(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\$',
    caseSensitive: false,
  ).hasMatch(value);
}, 'must be a valid UUID');

/// Date string validator
final Matcher validDateString = predicate((value) {
  if (value is! String) return false;
  
  try {
    DateTime.parse(value);
    return true;
  } catch (_) {
    return false;
  }
}, 'must be a valid date string');

/// Common validation schemas
class ValidationSchemas {
  static final userRegistration = Validator({
    'name*': [isString, minLength(2), maxLength(100)],
    'email*': [isString, isEmail],
    'password*': [isString, strongPassword],
    'username': [isString, validUsername],
    'phone': [isString, validPhone],
    'acceptTerms*': equals(true),
  });
  
  static final userLogin = Validator({
    'email*': [isString, isEmail],
    'password*': [isString, isNotEmpty],
    'remember': isBool,
  });
  
  static final passwordReset = Validator({
    'email*': [isString, isEmail],
  });
  
  static final changePassword = Validator({
    'currentPassword*': [isString, isNotEmpty],
    'newPassword*': [isString, strongPassword],
    'confirmPassword*': [isString, isNotEmpty],
  });
  
  static final updateProfile = Validator({
    'name': [isString, minLength(2), maxLength(100)],
    'username': [isString, validUsername],
    'phone': [isString, validPhone],
    'bio': [isString, maxLength(500)],
    'website': [isString, validUrl],
  });
}

/// Custom validation middleware
Middleware validate(Validator validator, {bool throwOnError = true}) {
  return (RequestContext req, ResponseContext res) async {
    await req.parseBody();
    
    final result = await validator.check(req.bodyAsMap);
    
    if (result.errors.isNotEmpty && throwOnError) {
      throw AngelHttpException.badRequest(
        message: 'Validation failed',
        errors: result.errors,
      );
    }
    
    // Inject validated data
    req.container!.registerSingleton(result);
    
    return true;
  };
}
`;

    await fs.writeFile(
      path.join(validatorsDir, 'validators.dart'),
      validatorsContent
    );
  }

  private async generateDatabase(projectPath: string): Promise<void> {
    const databaseDir = path.join(projectPath, 'lib', 'src', 'database');
    await fs.mkdir(databaseDir, { recursive: true });

    // Database configuration
    const databaseContent = `import 'package:angel3_orm/angel3_orm.dart';
import 'package:angel3_orm_postgres/angel3_orm_postgres.dart';
import 'package:angel3_migration/angel3_migration.dart';
import 'package:postgres/postgres.dart';
import 'package:dotenv/dotenv.dart';
import 'package:logging/logging.dart';

class Database {
  static PostgreSQLConnection? _connection;
  static PostgreSqlExecutor? _executor;
  
  static Future<PostgreSqlExecutor> get executor async {
    if (_executor != null) return _executor!;
    
    final env = DotEnv()..load();
    
    _connection = PostgreSQLConnection(
      env['DB_HOST'] ?? 'localhost',
      int.parse(env['DB_PORT'] ?? '5432'),
      env['DB_NAME'] ?? 'angel3_db',
      username: env['DB_USER'] ?? 'postgres',
      password: env['DB_PASSWORD'] ?? 'postgres',
    );
    
    await _connection!.open();
    
    _executor = PostgreSqlExecutor(
      _connection!,
      logger: Logger('Database'),
    );
    
    return _executor!;
  }
  
  static Future<void> close() async {
    await _connection?.close();
    _connection = null;
    _executor = null;
  }
  
  /// Run database migrations
  static Future<void> migrate() async {
    final executor = await Database.executor;
    final migrationRunner = PostgresMigrationRunner(
      _connection!,
      migrations: [
        // Add your migrations here
        UserMigration(),
        SessionMigration(),
        RefreshTokenMigration(),
      ],
    );
    
    await migrationRunner.up();
  }
  
  /// Rollback database migrations
  static Future<void> rollback() async {
    final executor = await Database.executor;
    final migrationRunner = PostgresMigrationRunner(
      _connection!,
      migrations: [
        // Add your migrations here
        UserMigration(),
        SessionMigration(),
        RefreshTokenMigration(),
      ],
    );
    
    await migrationRunner.down();
  }
}

/// Base migration class
abstract class BaseMigration extends Migration {
  @override
  void up(Schema schema) {
    // Override in subclasses
  }
  
  @override
  void down(Schema schema) {
    // Override in subclasses
  }
}
`;

    await fs.writeFile(
      path.join(databaseDir, 'database.dart'),
      databaseContent
    );
  }

  private async generateMigrations(projectPath: string): Promise<void> {
    const migrationsDir = path.join(projectPath, 'lib', 'src', 'database', 'migrations');
    await fs.mkdir(migrationsDir, { recursive: true });

    // User migration
    const userMigrationContent = `import 'package:angel3_migration/angel3_migration.dart';
import '../database.dart';

class UserMigration extends BaseMigration {
  @override
  void up(Schema schema) {
    schema.create('users', (table) {
      table.varChar('id', length: 36).primaryKey();
      table.varChar('name', length: 255).notNull();
      table.varChar('email', length: 255).notNull().unique();
      table.varChar('password', length: 255).notNull();
      table.varChar('role', length: 50).defaultsTo('user');
      table.dateTime('last_login').nullable();
      table.dateTime('created_at').notNull();
      table.dateTime('updated_at').notNull();
      
      // Indexes
      table.index(['email']);
      table.index(['role']);
      table.index(['created_at']);
    });
  }
  
  @override
  void down(Schema schema) {
    schema.drop('users');
  }
}

class SessionMigration extends BaseMigration {
  @override
  void up(Schema schema) {
    schema.create('sessions', (table) {
      table.varChar('id', length: 36).primaryKey();
      table.varChar('token', length: 512).notNull();
      table.varChar('user_id', length: 36).notNull().references('users', 'id').onDelete('CASCADE');
      table.varChar('ip_address', length: 45).notNull();
      table.text('user_agent').nullable();
      table.dateTime('expires_at').notNull();
      table.boolean('is_active').defaultsTo(true);
      table.dateTime('created_at').notNull();
      table.dateTime('updated_at').notNull();
      
      // Indexes
      table.index(['token']);
      table.index(['user_id']);
      table.index(['expires_at']);
    });
  }
  
  @override
  void down(Schema schema) {
    schema.drop('sessions');
  }
}

class RefreshTokenMigration extends BaseMigration {
  @override
  void up(Schema schema) {
    schema.create('refresh_tokens', (table) {
      table.varChar('id', length: 36).primaryKey();
      table.varChar('token', length: 512).notNull().unique();
      table.varChar('user_id', length: 36).notNull().references('users', 'id').onDelete('CASCADE');
      table.dateTime('expires_at').notNull();
      table.boolean('is_revoked').defaultsTo(false);
      table.dateTime('revoked_at').nullable();
      table.varChar('replaced_by_token', length: 512).nullable();
      table.dateTime('created_at').notNull();
      table.dateTime('updated_at').notNull();
      
      // Indexes
      table.index(['token']);
      table.index(['user_id']);
      table.index(['expires_at']);
    });
  }
  
  @override
  void down(Schema schema) {
    schema.drop('refresh_tokens');
  }
}
`;

    await fs.writeFile(
      path.join(migrationsDir, '001_create_users.dart'),
      userMigrationContent
    );
  }

  private async generateViews(projectPath: string): Promise<void> {
    const viewsDir = path.join(projectPath, 'lib', 'src', 'views');
    await fs.mkdir(viewsDir, { recursive: true });

    // Welcome view template
    const welcomeViewContent = `import 'package:angel3_jael/angel3_jael.dart';

const String welcomeTemplate = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title ?? 'Angel3 Application' }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .container {
            text-align: center;
            padding: 2rem;
        }
        
        h1 {
            font-size: 4rem;
            font-weight: 700;
            margin-bottom: 1rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        p {
            font-size: 1.5rem;
            margin-bottom: 2rem;
            opacity: 0.9;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            max-width: 800px;
            margin: 3rem auto;
        }
        
        .feature {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 1.5rem;
            border-radius: 10px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .feature h3 {
            margin-bottom: 0.5rem;
        }
        
        .cta {
            margin-top: 3rem;
        }
        
        .button {
            display: inline-block;
            padding: 1rem 2rem;
            background: #fff;
            color: #667eea;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 600;
            transition: transform 0.2s;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        
        .button:hover {
            transform: translateY(-2px);
        }
        
        code {
            background: rgba(0,0,0,0.3);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Angel3</h1>
        <p>{{ message ?? 'Full-stack Dart Framework' }}</p>
        
        <div class="features">
            <div class="feature">
                <h3>⚡ Fast</h3>
                <p>Built for speed with async/await</p>
            </div>
            <div class="feature">
                <h3>🔧 Flexible</h3>
                <p>Modular plugin architecture</p>
            </div>
            <div class="feature">
                <h3>🛡️ Secure</h3>
                <p>Built-in security features</p>
            </div>
            <div class="feature">
                <h3>📦 Complete</h3>
                <p>Batteries included framework</p>
            </div>
        </div>
        
        <div class="cta">
            <a href="/api/v1/docs" class="button">View API Documentation</a>
        </div>
        
        <p style="margin-top: 3rem; font-size: 1rem; opacity: 0.7;">
            Server running on <code>{{ host }}:{{ port }}</code>
        </p>
    </div>
</body>
</html>
''';

/// Render welcome page
Map<String, dynamic> welcomeContext({
  String? title,
  String? message,
  String host = 'localhost',
  int port = 3000,
}) {
  return {
    'title': title,
    'message': message,
    'host': host,
    'port': port,
  };
}
`;

    await fs.writeFile(
      path.join(viewsDir, 'welcome.dart'),
      welcomeViewContent
    );
  }

  private async generateWebSocketHandlers(projectPath: string): Promise<void> {
    const wsDir = path.join(projectPath, 'lib', 'src', 'websocket');
    await fs.mkdir(wsDir, { recursive: true });

    // WebSocket configuration
    const wsConfigContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_websocket/server.dart';
import 'package:angel3_auth/angel3_auth.dart';
import 'package:dotenv/dotenv.dart';

import '../models/user.dart';
import '../services/auth_service.dart';

/// Configure WebSocket routes and handlers
Future<void> configureWebSocketRoutes(Angel app) async {
  final ws = AngelWebSocket(app, '/ws');
  
  // Authentication for WebSocket
  ws.onConnection.listen((socket) async {
    final req = socket.request;
    final token = req.uri.queryParameters['token'];
    
    if (token == null) {
      socket.close(1008, 'Authentication required');
      return;
    }
    
    try {
      // Validate token
      final authService = app.container!.make<AuthService>();
      final userId = await authService.validateToken(token);
      
      if (userId == null) {
        socket.close(1008, 'Invalid token');
        return;
      }
      
      // Store user ID in socket properties
      socket.properties['userId'] = userId;
      
      // Send welcome message
      socket.send('connected', {
        'message': 'Welcome to Angel3 WebSocket',
        'userId': userId,
        'timestamp': DateTime.now().toIso8601String(),
      });
      
      print('WebSocket client connected: \$userId');
    } catch (e) {
      socket.close(1008, 'Authentication failed');
    }
  });
  
  // Handle disconnection
  ws.onDisconnection.listen((socket) {
    final userId = socket.properties['userId'];
    print('WebSocket client disconnected: \$userId');
  });
  
  // Chat room example
  ws.onAction('chat:join', (socket, data) async {
    final room = data['room'] as String?;
    if (room == null) return;
    
    // Join room
    socket.rooms.add(room);
    
    // Notify room members
    ws.batchEvent('chat:user_joined', {
      'userId': socket.properties['userId'],
      'room': room,
      'timestamp': DateTime.now().toIso8601String(),
    }, filter: (s) => s.rooms.contains(room) && s.id != socket.id);
    
    // Send success response
    socket.send('chat:joined', {
      'room': room,
      'members': ws.clients.where((s) => s.rooms.contains(room)).length,
    });
  });
  
  // Handle chat messages
  ws.onAction('chat:message', (socket, data) async {
    final room = data['room'] as String?;
    final message = data['message'] as String?;
    
    if (room == null || message == null) return;
    if (!socket.rooms.contains(room)) return;
    
    final payload = {
      'userId': socket.properties['userId'],
      'message': message,
      'room': room,
      'timestamp': DateTime.now().toIso8601String(),
    };
    
    // Broadcast to room
    ws.batchEvent('chat:message', payload, 
      filter: (s) => s.rooms.contains(room));
  });
  
  // Real-time notifications
  ws.onAction('subscribe:notifications', (socket, data) async {
    final userId = socket.properties['userId'] as String;
    socket.rooms.add('notifications:\$userId');
    
    socket.send('subscribed', {
      'channel': 'notifications',
    });
  });
  
  // System broadcast example
  ws.onAction('admin:broadcast', (socket, data) async {
    final userId = socket.properties['userId'] as String;
    
    // Check if user is admin
    final userService = app.container!.make<UserService>();
    final user = await userService.findById(userId);
    
    if (user?.role != 'admin') {
      socket.send('error', {
        'message': 'Unauthorized',
      });
      return;
    }
    
    // Broadcast to all connected clients
    ws.batchEvent('system:announcement', {
      'message': data['message'],
      'priority': data['priority'] ?? 'info',
      'timestamp': DateTime.now().toIso8601String(),
    });
  });
  
  // Configure WebSocket with the app
  await app.configure(ws.configureServer);
}

/// Send notification to specific user
void sendNotification(AngelWebSocket ws, String userId, Map<String, dynamic> notification) {
  ws.batchEvent('notification', notification,
    filter: (s) => s.rooms.contains('notifications:\$userId'));
}

/// Broadcast to all users
void broadcast(AngelWebSocket ws, String event, Map<String, dynamic> data) {
  ws.batchEvent(event, data);
}

/// Send to specific room
void sendToRoom(AngelWebSocket ws, String room, String event, Map<String, dynamic> data) {
  ws.batchEvent(event, data,
    filter: (s) => s.rooms.contains(room));
}
`;

    await fs.writeFile(
      path.join(wsDir, 'websocket_routes.dart'),
      wsConfigContent
    );
  }

  private async generateConfigFiles(projectPath: string): Promise<void> {
    const configDir = path.join(projectPath, 'lib', 'src', 'config');
    await fs.mkdir(configDir, { recursive: true });

    // Main configuration
    const configContent = `import 'dart:io';
import 'package:angel3_configuration/angel3_configuration.dart';
import 'package:angel3_framework/angel3_framework.dart';
import 'package:file/file.dart';
import 'package:yaml/yaml.dart';

/// Load configuration from YAML files
Future<void> Function(Angel)> configuration(FileSystem fs) {
  return (Angel app) async {
    // Load base configuration
    final baseConfig = await loadConfig(
      fs,
      app.environment.isProduction ? 'config/production.yaml' : 'config/development.yaml',
    );
    
    // Load environment-specific overrides
    final envConfig = Platform.environment;
    
    // Merge configurations
    final config = <String, dynamic>{
      ...baseConfig,
      ...envConfig,
    };
    
    // Apply configuration to app
    app.configuration.addAll(config);
  };
}

/// Load configuration from YAML file
Future<Map<String, dynamic>> loadConfig(FileSystem fs, String path) async {
  final file = fs.file(path);
  
  if (!await file.exists()) {
    return {};
  }
  
  final contents = await file.readAsString();
  final yaml = loadYaml(contents);
  
  return Map<String, dynamic>.from(yaml as Map);
}

/// Application configuration class
class AppConfig {
  final String name;
  final String version;
  final String environment;
  final int port;
  final String host;
  final DatabaseConfig database;
  final RedisConfig redis;
  final JwtConfig jwt;
  final EmailConfig email;
  final Map<String, dynamic> features;
  
  AppConfig({
    required this.name,
    required this.version,
    required this.environment,
    required this.port,
    required this.host,
    required this.database,
    required this.redis,
    required this.jwt,
    required this.email,
    required this.features,
  });
  
  factory AppConfig.fromMap(Map<String, dynamic> map) {
    return AppConfig(
      name: map['name'] ?? 'Angel3 App',
      version: map['version'] ?? '1.0.0',
      environment: map['environment'] ?? 'development',
      port: map['port'] ?? 3000,
      host: map['host'] ?? 'localhost',
      database: DatabaseConfig.fromMap(map['database'] ?? {}),
      redis: RedisConfig.fromMap(map['redis'] ?? {}),
      jwt: JwtConfig.fromMap(map['jwt'] ?? {}),
      email: EmailConfig.fromMap(map['email'] ?? {}),
      features: Map<String, dynamic>.from(map['features'] ?? {}),
    );
  }
}

class DatabaseConfig {
  final String host;
  final int port;
  final String database;
  final String username;
  final String password;
  final int poolSize;
  
  DatabaseConfig({
    required this.host,
    required this.port,
    required this.database,
    required this.username,
    required this.password,
    required this.poolSize,
  });
  
  factory DatabaseConfig.fromMap(Map<String, dynamic> map) {
    return DatabaseConfig(
      host: map['host'] ?? 'localhost',
      port: map['port'] ?? 5432,
      database: map['database'] ?? 'angel3_db',
      username: map['username'] ?? 'postgres',
      password: map['password'] ?? 'postgres',
      poolSize: map['poolSize'] ?? 10,
    );
  }
}

class RedisConfig {
  final String host;
  final int port;
  final String? password;
  final int database;
  
  RedisConfig({
    required this.host,
    required this.port,
    this.password,
    required this.database,
  });
  
  factory RedisConfig.fromMap(Map<String, dynamic> map) {
    return RedisConfig(
      host: map['host'] ?? 'localhost',
      port: map['port'] ?? 6379,
      password: map['password'],
      database: map['database'] ?? 0,
    );
  }
}

class JwtConfig {
  final String secret;
  final Duration accessTokenExpiry;
  final Duration refreshTokenExpiry;
  final String issuer;
  
  JwtConfig({
    required this.secret,
    required this.accessTokenExpiry,
    required this.refreshTokenExpiry,
    required this.issuer,
  });
  
  factory JwtConfig.fromMap(Map<String, dynamic> map) {
    return JwtConfig(
      secret: map['secret'] ?? 'your-secret-key',
      accessTokenExpiry: Duration(minutes: map['accessTokenExpiry'] ?? 15),
      refreshTokenExpiry: Duration(days: map['refreshTokenExpiry'] ?? 30),
      issuer: map['issuer'] ?? 'angel3-app',
    );
  }
}

class EmailConfig {
  final String host;
  final int port;
  final String username;
  final String password;
  final bool secure;
  final String from;
  
  EmailConfig({
    required this.host,
    required this.port,
    required this.username,
    required this.password,
    required this.secure,
    required this.from,
  });
  
  factory EmailConfig.fromMap(Map<String, dynamic> map) {
    return EmailConfig(
      host: map['host'] ?? 'smtp.gmail.com',
      port: map['port'] ?? 587,
      username: map['username'] ?? '',
      password: map['password'] ?? '',
      secure: map['secure'] ?? true,
      from: map['from'] ?? 'noreply@example.com',
    );
  }
}
`;

    await fs.writeFile(
      path.join(configDir, 'config.dart'),
      configContent
    );

    // Development config
    const devConfigContent = `# Development configuration
name: Angel3 Development
version: 1.0.0
environment: development
port: 3000
host: localhost

database:
  host: localhost
  port: 5432
  database: angel3_dev
  username: postgres
  password: postgres
  poolSize: 5

redis:
  host: localhost
  port: 6379
  database: 0

jwt:
  secret: dev-secret-key-change-in-production
  accessTokenExpiry: 15  # minutes
  refreshTokenExpiry: 7  # days
  issuer: angel3-dev

email:
  host: localhost
  port: 1025
  username: ''
  password: ''
  secure: false
  from: dev@localhost

features:
  registration: true
  emailVerification: false
  socialAuth: false
  rateLimit: true
  caching: true
  websocket: true
`;

    await fs.writeFile(
      path.join(projectPath, 'config', 'development.yaml'),
      devConfigContent
    );

    // Production config
    const prodConfigContent = `# Production configuration
name: Angel3 Production
version: 1.0.0
environment: production
port: 8080
host: 0.0.0.0

database:
  host: \${DB_HOST}
  port: \${DB_PORT}
  database: \${DB_NAME}
  username: \${DB_USER}
  password: \${DB_PASSWORD}
  poolSize: 20

redis:
  host: \${REDIS_HOST}
  port: \${REDIS_PORT}
  password: \${REDIS_PASSWORD}
  database: 0

jwt:
  secret: \${JWT_SECRET}
  accessTokenExpiry: 15  # minutes
  refreshTokenExpiry: 30  # days
  issuer: angel3-prod

email:
  host: \${SMTP_HOST}
  port: \${SMTP_PORT}
  username: \${SMTP_USER}
  password: \${SMTP_PASSWORD}
  secure: true
  from: \${SMTP_FROM}

features:
  registration: true
  emailVerification: true
  socialAuth: true
  rateLimit: true
  caching: true
  websocket: true
`;

    await fs.writeFile(
      path.join(projectPath, 'config', 'production.yaml'),
      prodConfigContent
    );
  }

  private async generatePlugins(projectPath: string): Promise<void> {
    const pluginsDir = path.join(projectPath, 'lib', 'src', 'plugins');
    await fs.mkdir(pluginsDir, { recursive: true });

    // Plugins configuration
    const pluginsContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_mustache/angel3_mustache.dart';
import 'package:angel3_jael/angel3_jael.dart';
import 'package:file/local.dart';

import 'logging_plugin.dart';
import 'monitoring_plugin.dart';
import 'health_plugin.dart';

/// Configure all application plugins
Future<void> configurePlugins(Angel app) async {
  final fs = const LocalFileSystem();
  
  // Template engines
  await app.configure(mustache(fs.directory('views')));
  await app.configure(jael(fs.directory('views')));
  
  // Custom plugins
  await app.configure(loggingPlugin());
  await app.configure(monitoringPlugin());
  await app.configure(healthPlugin());
}
`;

    await fs.writeFile(
      path.join(pluginsDir, 'plugins.dart'),
      pluginsContent
    );

    // Logging plugin
    const loggingPluginContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:logging/logging.dart';
import 'package:intl/intl.dart';

/// Enhanced logging plugin
AngelConfigurer loggingPlugin() {
  return (Angel app) async {
    // Configure logger format
    final formatter = DateFormat('yyyy-MM-dd HH:mm:ss');
    
    app.logger.onRecord.listen((record) {
      final time = formatter.format(record.time);
      final level = record.level.name.padRight(7);
      final name = record.loggerName.padRight(20);
      final message = record.message;
      
      // Color-coded output for development
      if (!app.environment.isProduction) {
        final color = _getColorCode(record.level);
        print('\\x1B[\${color}m[\$time] \$level \$name - \$message\\x1B[0m');
      } else {
        // JSON format for production
        final log = {
          'timestamp': record.time.toIso8601String(),
          'level': record.level.name,
          'logger': record.loggerName,
          'message': record.message,
        };
        
        if (record.error != null) {
          log['error'] = record.error.toString();
        }
        
        if (record.stackTrace != null) {
          log['stackTrace'] = record.stackTrace.toString();
        }
        
        print(log);
      }
    });
    
    // Request logging middleware
    app.fallback((req, res) {
      final start = DateTime.now();
      
      res.done.then((_) {
        final duration = DateTime.now().difference(start);
        final status = res.statusCode;
        final method = req.method;
        final path = req.uri.path;
        
        app.logger.info('\$method \$path - \$status (\${duration.inMilliseconds}ms)');
      });
      
      return true;
    });
  };
}

String _getColorCode(Level level) {
  if (level >= Level.SEVERE) return '31'; // Red
  if (level >= Level.WARNING) return '33'; // Yellow
  if (level >= Level.INFO) return '32'; // Green
  return '36'; // Cyan
}
`;

    await fs.writeFile(
      path.join(pluginsDir, 'logging_plugin.dart'),
      loggingPluginContent
    );

    // Auth routes
    const authRoutesContent = `import 'package:angel3_framework/angel3_framework.dart';
import 'package:angel3_validate/angel3_validate.dart';
import '../middleware/auth.dart';
import '../middleware/rate_limit.dart';
import '../services/auth_service.dart';
import '../validators/validators.dart';

/// Configure authentication routes
Future<void> configureAuthRoutes(Angel app) async {
  // Login endpoint
  app.post('/auth/login',
    chain([
      strictRateLimit,
      validate(ValidationSchemas.userLogin),
    ]).call((req, res) async {
      final result = req.container!.make<ValidationResult>();
      final authService = req.container!.make<AuthService>();
      
      final response = await authService.login(
        result.data['email'],
        result.data['password'],
        remember: result.data['remember'] ?? false,
        ipAddress: req.ip,
        userAgent: req.headers?['user-agent'],
      );
      
      if (response == null) {
        throw AngelHttpException.unauthorized(
          message: 'Invalid credentials',
        );
      }
      
      res.json(response);
    }),
  );
  
  // Register endpoint
  app.post('/auth/register',
    chain([
      strictRateLimit,
      validate(ValidationSchemas.userRegistration),
    ]).call((req, res) async {
      final result = req.container!.make<ValidationResult>();
      final authService = req.container!.make<AuthService>();
      
      final response = await authService.register(result.data);
      
      res
        ..statusCode = 201
        ..json(response);
    }),
  );
  
  // Refresh token endpoint
  app.post('/auth/refresh',
    chain([
      apiRateLimit,
    ]).call((req, res) async {
      await req.parseBody();
      
      final refreshToken = req.bodyAsMap['refreshToken'] as String?;
      if (refreshToken == null) {
        throw AngelHttpException.badRequest(
          message: 'Refresh token required',
        );
      }
      
      final authService = req.container!.make<AuthService>();
      final response = await authService.refreshToken(refreshToken);
      
      if (response == null) {
        throw AngelHttpException.unauthorized(
          message: 'Invalid refresh token',
        );
      }
      
      res.json(response);
    }),
  );
  
  // Logout endpoint
  app.post('/auth/logout',
    chain([
      requireAuth,
    ]).call((req, res) async {
      final authHeader = req.headers?['authorization'];
      final token = authHeader?.substring(7); // Remove 'Bearer '
      
      final authService = req.container!.make<AuthService>();
      await authService.logout(token!);
      
      res.json({
        'message': 'Logged out successfully',
      });
    }),
  );
  
  // Forgot password endpoint
  app.post('/auth/forgot-password',
    chain([
      strictRateLimit,
      validate(ValidationSchemas.passwordReset),
    ]).call((req, res) async {
      final result = req.container!.make<ValidationResult>();
      final authService = req.container!.make<AuthService>();
      
      await authService.sendPasswordResetEmail(result.data['email']);
      
      res.json({
        'message': 'If the email exists, a password reset link has been sent',
      });
    }),
  );
  
  // Reset password endpoint
  app.post('/auth/reset-password',
    chain([
      strictRateLimit,
    ]).call((req, res) async {
      await req.parseBody();
      
      final token = req.bodyAsMap['token'] as String?;
      final password = req.bodyAsMap['password'] as String?;
      
      if (token == null || password == null) {
        throw AngelHttpException.badRequest(
          message: 'Token and password required',
        );
      }
      
      // Validate password strength
      if (!strongPassword.matches(password, {})) {
        throw AngelHttpException.badRequest(
          message: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character',
        );
      }
      
      final authService = req.container!.make<AuthService>();
      final success = await authService.resetPassword(token, password);
      
      if (!success) {
        throw AngelHttpException.badRequest(
          message: 'Invalid or expired reset token',
        );
      }
      
      res.json({
        'message': 'Password reset successfully',
      });
    }),
  );
  
  // Verify email endpoint
  app.get('/auth/verify-email/:token', (req, res) async {
    final token = req.params['token'] as String;
    
    final authService = req.container!.make<AuthService>();
    final success = await authService.verifyEmail(token);
    
    if (!success) {
      throw AngelHttpException.badRequest(
        message: 'Invalid or expired verification token',
      );
    }
    
    res.json({
      'message': 'Email verified successfully',
    });
  });
  
  // Resend verification email
  app.post('/auth/resend-verification',
    chain([
      requireAuth,
      strictRateLimit,
    ]).call((req, res) async {
      final user = req.container!.make<User>();
      
      if (user.emailVerified ?? false) {
        throw AngelHttpException.badRequest(
          message: 'Email already verified',
        );
      }
      
      final authService = req.container!.make<AuthService>();
      await authService.sendVerificationEmail(user.id!);
      
      res.json({
        'message': 'Verification email sent',
      });
    }),
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib', 'src', 'routes', 'auth.dart'),
      authRoutesContent
    );

    // User routes
    const userRoutesContent = `import 'package:angel3_framework/angel3_framework.dart';
import '../controllers/user_controller.dart';

/// Configure user routes
Future<void> configureUserRoutes(Angel app) async {
  // Mount user controller
  await app.mountController<UserController>();
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib', 'src', 'routes', 'users.dart'),
      userRoutesContent
    );

    // WebSocket routes
    const wsRoutesContent = `import 'package:angel3_framework/angel3_framework.dart';
import '../websocket/websocket_routes.dart';

/// Configure WebSocket routes
Future<void> configureWebSocketRoutes(Angel app) async {
  await configureWebSocketRoutes(app);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib', 'src', 'routes', 'websocket.dart'),
      wsRoutesContent
    );

    // Hooks
    const hooksDir = path.join(projectPath, 'lib', 'src', 'hooks');
    await fs.mkdir(hooksDir, { recursive: true });

    const hooksContent = `import 'package:angel3_framework/angel3_framework.dart';

/// Configure application hooks
Future<void> configureHooks(Angel app) async {
  // Before all requests
  app.all('*', (req, res) {
    // Add request ID
    req.container!.registerSingleton(
      'requestId',
      DateTime.now().millisecondsSinceEpoch.toString(),
    );
    
    return true;
  });
  
  // After all requests
  app.responseFinalizers.add((req, res) async {
    // Add custom headers
    res.headers['X-Powered-By'] = 'Angel3';
    res.headers['X-Request-ID'] = req.container!.make<String>('requestId');
  });
  
  // Shutdown hooks
  app.shutdownHooks.add((_) async {
    print('Gracefully shutting down Angel3 server...');
  });
}
`;

    await fs.writeFile(
      path.join(hooksDir, 'hooks.dart'),
      hooksContent
    );

    // Auth service
    const authServiceContent = `import 'dart:convert';
import 'package:angel3_orm/angel3_orm.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:redis/redis.dart';
import 'package:uuid/uuid.dart';
import 'package:dotenv/dotenv.dart';

import '../models/user.dart';
import 'user_service.dart';
import 'email_service.dart';

class AuthService {
  final QueryExecutor executor;
  final Command redis;
  final UserService userService;
  final EmailService emailService;
  final _uuid = Uuid();
  
  late final String jwtSecret;
  late final Duration accessTokenExpiry;
  late final Duration refreshTokenExpiry;
  
  AuthService(this.executor, this.redis) 
    : userService = UserService(executor),
      emailService = EmailService() {
    final env = DotEnv()..load();
    jwtSecret = env['JWT_SECRET'] ?? 'your-secret-key';
    accessTokenExpiry = Duration(minutes: 15);
    refreshTokenExpiry = Duration(days: 30);
  }
  
  /// Login user
  Future<Map<String, dynamic>?> login(
    String email,
    String password, {
    bool remember = false,
    String? ipAddress,
    String? userAgent,
  }) async {
    // Find user by email
    final user = await userService.findByEmail(email);
    if (user == null) return null;
    
    // Verify password
    final passwordHash = sha256.convert(utf8.encode(password)).toString();
    if (user.password != passwordHash) return null;
    
    // Update last login
    await userService.updateLastLogin(user.id!);
    
    // Generate tokens
    final accessToken = generateAccessToken(user);
    final refreshToken = generateRefreshToken(user);
    
    // Store session
    await storeSession(user.id!, accessToken, ipAddress, userAgent);
    
    // Store refresh token
    if (remember) {
      await storeRefreshToken(user.id!, refreshToken);
    }
    
    return {
      'user': user.toPublicJson(),
      'accessToken': accessToken,
      'refreshToken': remember ? refreshToken : null,
      'expiresIn': accessTokenExpiry.inSeconds,
    };
  }
  
  /// Register new user
  Future<Map<String, dynamic>> register(Map<String, dynamic> data) async {
    // Check if email exists
    final existing = await userService.findByEmail(data['email']);
    if (existing != null) {
      throw Exception('Email already registered');
    }
    
    // Hash password
    data['password'] = sha256.convert(
      utf8.encode(data['password'])
    ).toString();
    
    // Create user
    final user = await userService.create(data);
    
    // Send verification email
    await sendVerificationEmail(user.id!);
    
    // Generate tokens
    final accessToken = generateAccessToken(user);
    
    return {
      'user': user.toPublicJson(),
      'accessToken': accessToken,
      'expiresIn': accessTokenExpiry.inSeconds,
    };
  }
  
  /// Generate access token
  String generateAccessToken(User user) {
    final jwt = JWT({
      'userId': user.id,
      'email': user.email,
      'role': user.role,
      'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
      'exp': DateTime.now().add(accessTokenExpiry).millisecondsSinceEpoch ~/ 1000,
    });
    
    return jwt.sign(SecretKey(jwtSecret));
  }
  
  /// Generate refresh token
  String generateRefreshToken(User user) {
    final token = _uuid.v4();
    return base64Url.encode(utf8.encode('\${user.id}:\$token'));
  }
  
  /// Validate token
  Future<String?> validateToken(String token) async {
    try {
      final jwt = JWT.verify(token, SecretKey(jwtSecret));
      final payload = jwt.payload as Map<String, dynamic>;
      
      // Check expiration
      final exp = payload['exp'] as int?;
      if (exp != null && DateTime.now().millisecondsSinceEpoch > exp * 1000) {
        return null;
      }
      
      return payload['userId'] as String?;
    } catch (_) {
      return null;
    }
  }
  
  /// Validate session
  Future<bool> validateSession(String token) async {
    final key = 'session:\$token';
    final exists = await redis.send_object(['EXISTS', key]);
    return exists == 1;
  }
  
  /// Store session
  Future<void> storeSession(
    String userId,
    String token,
    String? ipAddress,
    String? userAgent,
  ) async {
    final key = 'session:\$token';
    final data = {
      'userId': userId,
      'ipAddress': ipAddress ?? 'unknown',
      'userAgent': userAgent ?? 'unknown',
      'createdAt': DateTime.now().toIso8601String(),
    };
    
    await redis.send_object(['HMSET', key, ...data.entries.expand((e) => [e.key, e.value])]);
    await redis.send_object(['EXPIRE', key, accessTokenExpiry.inSeconds]);
  }
  
  /// Store refresh token
  Future<void> storeRefreshToken(String userId, String token) async {
    final key = 'refresh_token:\$token';
    final data = {
      'userId': userId,
      'createdAt': DateTime.now().toIso8601String(),
      'expiresAt': DateTime.now().add(refreshTokenExpiry).toIso8601String(),
    };
    
    await redis.send_object(['HMSET', key, ...data.entries.expand((e) => [e.key, e.value])]);
    await redis.send_object(['EXPIRE', key, refreshTokenExpiry.inSeconds]);
  }
  
  /// Refresh access token
  Future<Map<String, dynamic>?> refreshToken(String refreshToken) async {
    final key = 'refresh_token:\$refreshToken';
    final data = await redis.send_object(['HGETALL', key]);
    
    if (data == null || (data as List).isEmpty) {
      return null;
    }
    
    // Convert Redis response to map
    final tokenData = <String, String>{};
    for (var i = 0; i < data.length; i += 2) {
      tokenData[data[i].toString()] = data[i + 1].toString();
    }
    
    // Check expiration
    final expiresAt = DateTime.parse(tokenData['expiresAt']!);
    if (DateTime.now().isAfter(expiresAt)) {
      await redis.send_object(['DEL', key]);
      return null;
    }
    
    // Get user
    final user = await userService.findById(tokenData['userId']!);
    if (user == null) return null;
    
    // Generate new access token
    final accessToken = generateAccessToken(user);
    
    return {
      'accessToken': accessToken,
      'expiresIn': accessTokenExpiry.inSeconds,
    };
  }
  
  /// Logout
  Future<void> logout(String token) async {
    // Remove session
    await redis.send_object(['DEL', 'session:\$token']);
  }
  
  /// Send verification email
  Future<void> sendVerificationEmail(String userId) async {
    final user = await userService.findById(userId);
    if (user == null) return;
    
    final token = _uuid.v4();
    final key = 'email_verification:\$token';
    
    // Store verification token
    await redis.send_object(['SET', key, userId, 'EX', 86400]); // 24 hours
    
    // Send email
    await emailService.sendEmail(
      to: user.email!,
      subject: 'Verify your email',
      html: '''
        <h1>Welcome to Angel3!</h1>
        <p>Please click the link below to verify your email:</p>
        <a href="http://localhost:3000/api/v1/auth/verify-email/\$token">Verify Email</a>
        <p>This link will expire in 24 hours.</p>
      ''',
    );
  }
  
  /// Verify email
  Future<bool> verifyEmail(String token) async {
    final key = 'email_verification:\$token';
    final userId = await redis.send_object(['GET', key]);
    
    if (userId == null) return false;
    
    // Update user
    await userService.update(userId.toString(), {
      'emailVerified': true,
    });
    
    // Delete token
    await redis.send_object(['DEL', key]);
    
    return true;
  }
  
  /// Send password reset email
  Future<void> sendPasswordResetEmail(String email) async {
    final user = await userService.findByEmail(email);
    if (user == null) return; // Don't reveal if email exists
    
    final token = _uuid.v4();
    final key = 'password_reset:\$token';
    
    // Store reset token
    await redis.send_object(['SET', key, user.id, 'EX', 3600]); // 1 hour
    
    // Send email
    await emailService.sendEmail(
      to: email,
      subject: 'Reset your password',
      html: '''
        <h1>Password Reset Request</h1>
        <p>Click the link below to reset your password:</p>
        <a href="http://localhost:3000/reset-password?token=\$token">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      ''',
    );
  }
  
  /// Reset password
  Future<bool> resetPassword(String token, String newPassword) async {
    final key = 'password_reset:\$token';
    final userId = await redis.send_object(['GET', key]);
    
    if (userId == null) return false;
    
    // Hash new password
    final passwordHash = sha256.convert(utf8.encode(newPassword)).toString();
    
    // Update user
    await userService.update(userId.toString(), {
      'password': passwordHash,
    });
    
    // Delete token
    await redis.send_object(['DEL', key]);
    
    // Invalidate all sessions for the user
    await invalidateUserSessions(userId.toString());
    
    return true;
  }
  
  /// Invalidate all user sessions
  Future<void> invalidateUserSessions(String userId) async {
    // Get all session keys
    final keys = await redis.send_object(['KEYS', 'session:*']);
    
    if (keys is List) {
      for (final key in keys) {
        final data = await redis.send_object(['HGET', key, 'userId']);
        if (data == userId) {
          await redis.send_object(['DEL', key]);
        }
      }
    }
  }
  
  /// Validate API key
  Future<bool> validateApiKey(String apiKey) async {
    final key = 'api_key:\$apiKey';
    final exists = await redis.send_object(['EXISTS', key]);
    return exists == 1;
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib', 'src', 'services', 'auth_service.dart'),
      authServiceContent
    );

    // Email service
    const emailServiceContent = `import 'package:mailer/mailer.dart';
import 'package:mailer/smtp_server.dart';
import 'package:dotenv/dotenv.dart';

class EmailService {
  late final SmtpServer smtpServer;
  late final String fromEmail;
  late final String fromName;
  
  EmailService() {
    final env = DotEnv()..load();
    
    if (env['ENVIRONMENT'] == 'production') {
      smtpServer = SmtpServer(
        env['SMTP_HOST'] ?? 'smtp.gmail.com',
        port: int.parse(env['SMTP_PORT'] ?? '587'),
        username: env['SMTP_USER'],
        password: env['SMTP_PASSWORD'],
        ssl: env['SMTP_SECURE'] == 'true',
      );
    } else {
      // Use local mail server for development
      smtpServer = SmtpServer(
        'localhost',
        port: 1025,
        ignoreBadCertificate: true,
        allowInsecure: true,
      );
    }
    
    fromEmail = env['SMTP_FROM'] ?? 'noreply@example.com';
    fromName = env['SMTP_FROM_NAME'] ?? 'Angel3 App';
  }
  
  /// Send email
  Future<void> sendEmail({
    required String to,
    required String subject,
    String? text,
    String? html,
    List<Attachment>? attachments,
  }) async {
    final message = Message()
      ..from = Address(fromEmail, fromName)
      ..recipients.add(to)
      ..subject = subject;
    
    if (text != null) {
      message.text = text;
    }
    
    if (html != null) {
      message.html = html;
    }
    
    if (attachments != null) {
      message.attachments.addAll(attachments);
    }
    
    try {
      await send(message, smtpServer);
    } catch (e) {
      print('Error sending email: \$e');
      // In production, you might want to log this or retry
    }
  }
  
  /// Send template email
  Future<void> sendTemplateEmail({
    required String to,
    required String template,
    required Map<String, dynamic> variables,
  }) async {
    final html = await renderEmailTemplate(template, variables);
    await sendEmail(
      to: to,
      subject: variables['subject'] ?? 'Angel3 Notification',
      html: html,
    );
  }
  
  /// Render email template
  Future<String> renderEmailTemplate(
    String template,
    Map<String, dynamic> variables,
  ) async {
    // In a real app, you'd use a template engine
    // For now, simple string replacement
    var html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: #667eea;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px 5px 0 0;
        }
        .content {
            background: #f4f4f4;
            padding: 20px;
            border-radius: 0 0 5px 5px;
        }
        .button {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            margin: 10px 0;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{app_name}}</h1>
    </div>
    <div class="content">
        {{content}}
    </div>
    <div class="footer">
        <p>&copy; {{year}} {{app_name}}. All rights reserved.</p>
    </div>
</body>
</html>
    ''';
    
    // Replace variables
    variables['app_name'] ??= 'Angel3 App';
    variables['year'] ??= DateTime.now().year.toString();
    
    for (final entry in variables.entries) {
      html = html.replaceAll('{{\\\${entry.key}}}', entry.value.toString());
    }
    
    return html;
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib', 'src', 'services', 'email_service.dart'),
      emailServiceContent
    );

    // Cache service
    const cacheServiceContent = `import 'dart:convert';
import 'package:redis/redis.dart';

class CacheService {
  final Command redis;
  final String prefix;
  
  CacheService(this.redis, {this.prefix = 'cache:'});
  
  /// Get cached value
  Future<T?> get<T>(String key) async {
    final data = await redis.send_object(['GET', '\$prefix\$key']);
    
    if (data == null) return null;
    
    try {
      final json = jsonDecode(data.toString());
      return json as T;
    } catch (_) {
      return data as T;
    }
  }
  
  /// Set cached value
  Future<void> set<T>(
    String key,
    T value, {
    Duration? ttl,
  }) async {
    final data = value is String ? value : jsonEncode(value);
    
    if (ttl != null) {
      await redis.send_object([
        'SET',
        '\$prefix\$key',
        data,
        'EX',
        ttl.inSeconds,
      ]);
    } else {
      await redis.send_object(['SET', '\$prefix\$key', data]);
    }
  }
  
  /// Delete cached value
  Future<void> delete(String key) async {
    await redis.send_object(['DEL', '\$prefix\$key']);
  }
  
  /// Delete multiple cached values
  Future<void> deleteMany(List<String> keys) async {
    if (keys.isEmpty) return;
    
    final prefixedKeys = keys.map((k) => '\$prefix\$k').toList();
    await redis.send_object(['DEL', ...prefixedKeys]);
  }
  
  /// Clear all cache with pattern
  Future<void> clear(String pattern) async {
    final keys = await redis.send_object(['KEYS', '\$prefix\$pattern']);
    
    if (keys is List && keys.isNotEmpty) {
      await redis.send_object(['DEL', ...keys]);
    }
  }
  
  /// Check if key exists
  Future<bool> exists(String key) async {
    final result = await redis.send_object(['EXISTS', '\$prefix\$key']);
    return result == 1;
  }
  
  /// Get or set cached value
  Future<T> getOrSet<T>(
    String key,
    Future<T> Function() factory, {
    Duration? ttl,
  }) async {
    final cached = await get<T>(key);
    if (cached != null) return cached;
    
    final value = await factory();
    await set(key, value, ttl: ttl);
    
    return value;
  }
  
  /// Cache decorator for functions
  Future<T> cached<T>(
    String key,
    Future<T> Function() fn, {
    Duration ttl = const Duration(minutes: 5),
  }) {
    return getOrSet(key, fn, ttl: ttl);
  }
  
  /// Invalidate cache tags
  Future<void> invalidateTags(List<String> tags) async {
    for (final tag in tags) {
      final keys = await redis.send_object(['SMEMBERS', 'tag:\$tag']);
      
      if (keys is List && keys.isNotEmpty) {
        await redis.send_object(['DEL', ...keys]);
        await redis.send_object(['DEL', 'tag:\$tag']);
      }
    }
  }
  
  /// Tag cache entry
  Future<void> tag(String key, List<String> tags) async {
    for (final tag in tags) {
      await redis.send_object(['SADD', 'tag:\$tag', '\$prefix\$key']);
    }
  }
}

/// Cache key builder
class CacheKeys {
  static String user(String id) => 'user:\$id';
  static String userByEmail(String email) => 'user:email:\$email';
  static String userList(int page, int limit) => 'users:page:\$page:limit:\$limit';
  static String session(String token) => 'session:\$token';
  static String apiKey(String key) => 'api_key:\$key';
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib', 'src', 'services', 'cache_service.dart'),
      cacheServiceContent
    );
  }

  protected async generateBuildScript(projectPath: string, options: any): Promise<void> {
    await super.generateBuildScript(projectPath, options);

    // Add Angel3-specific build script
    const buildScriptContent = `#!/bin/bash

# Build script for Angel3 application

set -e

echo "Building Angel3 application..."

# Get dependencies
echo "Installing dependencies..."
dart pub get

# Run code generation
echo "Running code generation..."
dart run build_runner build --delete-conflicting-outputs

# Run tests
echo "Running tests..."
dart test

# Analyze code
echo "Analyzing code..."
dart analyze

# Format code
echo "Formatting code..."
dart format --fix .

# Build executable
echo "Building executable..."
dart compile exe bin/server.dart -o build/server

echo "Build complete!"
echo "Run ./build/server to start the application"
`;

    await fs.writeFile(
      path.join(projectPath, 'scripts', 'build.sh'),
      buildScriptContent
    );

    await fs.chmod(path.join(projectPath, 'scripts', 'build.sh'), 0o755);
  }

  protected getDockerfileContent(options: any): string {
    return `# Multi-stage Dockerfile for Angel3 application

# Build stage
FROM dart:stable AS build

WORKDIR /app

# Copy pubspec files
COPY pubspec.* ./

# Get dependencies
RUN dart pub get

# Copy source code
COPY . .

# Run code generation
RUN dart run build_runner build --delete-conflicting-outputs

# Build executable
RUN dart compile exe bin/server.dart -o bin/server

# Runtime stage
FROM debian:bullseye-slim

# Install required libraries
RUN apt-get update && apt-get install -y \\
    ca-certificates \\
    libssl1.1 \\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 angel

WORKDIR /app

# Copy built executable
COPY --from=build --chown=angel:angel /app/bin/server /app/server
COPY --from=build --chown=angel:angel /app/config /app/config
COPY --from=build --chown=angel:angel /app/public /app/public
COPY --from=build --chown=angel:angel /app/views /app/views

# Switch to non-root user
USER angel

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:3000/health || exit 1

# Run the server
CMD ["./server"]
`;
  }
}