/**
 * Conduit Framework Template Generator
 * Modern HTTP framework for Dart with built-in ORM
 */

import { DartBackendGenerator } from './dart-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class ConduitGenerator extends DartBackendGenerator {
  constructor() {
    super('Conduit');
  }

  protected getFrameworkDependencies(): string[] {
    return [
      'conduit: ^4.0.0',
      'conduit_core: ^4.0.0',
      'conduit_postgresql: ^4.0.0',
      'conduit_test: ^4.0.0',
      'conduit_open_api: ^4.0.0',
      'conduit_codable: ^4.0.0',
      'conduit_isolate_exec: ^4.0.0',
      'jaguar_jwt: ^3.0.0',
      'crypto: ^3.0.3',
      'bcrypt: ^1.1.3',
      'uuid: ^4.2.2',
      'dotenv: ^4.1.0',
      'yaml: ^3.1.2',
      'args: ^2.4.2',
      'logging: ^1.2.0',
      'intl: ^0.18.1',
      'http: ^1.1.2',
      'collection: ^1.18.0',
      'meta: ^1.11.0'
    ];
  }

  protected getDevDependencies(): string[] {
    return [
      'conduit_test: ^4.0.0',
      'test_process: ^2.1.0',
      'mockito: ^5.4.4',
      'build_runner: ^2.4.7',
      'build_test: ^2.2.2'
    ];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application file
    await this.generateApplication(projectPath, options);

    // Generate channel configuration
    await this.generateChannel(projectPath, options);

    // Generate controllers
    await this.generateControllers(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate services
    await this.generateServices(projectPath);

    // Generate utilities
    await this.generateUtilities(projectPath);

    // Generate configuration
    await this.generateConfig(projectPath);

    // Generate migrations
    await this.generateMigrations(projectPath);

    // Generate test harness
    await this.generateTestHarness(projectPath);

    // Generate API documentation
    await this.generateApiDocs(projectPath);

    // Generate CLI commands
    await this.generateCommands(projectPath);
  }

  private async generateApplication(projectPath: string, options: any): Promise<void> {
    const appContent = `import 'package:conduit_core/conduit_core.dart';
import 'package:dotenv/dotenv.dart';
import 'package:${options.name}/channel.dart';

/// This is the entry point for the application.
Future main() async {
  // Load environment variables
  final env = DotEnv()..load();
  
  // Start the application
  final port = int.parse(env['PORT'] ?? '8080');
  final app = Application<${options.name.charAt(0).toUpperCase() + options.name.slice(1)}Channel>()
    ..options.port = port
    ..options.address = InternetAddress.anyIPv4;
    
  // Configure logging
  app.options.context['logger'] = Logger('${options.name}')
    ..level = env['LOG_LEVEL'] == 'debug' ? Level.ALL : Level.INFO;
  
  // Start the application
  await app.start(numberOfInstances: int.parse(env['INSTANCES'] ?? '1'));
  
  print('Application started on port \\\${app.options.port}');
  print('Use Ctrl-C (SIGINT) to stop running the application.');
}
`;

    await fs.writeFile(
      path.join(projectPath, 'bin', 'main.dart'),
      appContent
    );
  }

  private async generateChannel(projectPath: string, options: any): Promise<void> {
    const channelContent = `import 'dart:async';
import 'package:conduit_core/conduit_core.dart';
import 'package:conduit_postgresql/conduit_postgresql.dart';
import 'package:conduit_open_api/v3.dart';
import 'package:dotenv/dotenv.dart';

import 'controllers/auth_controller.dart';
import 'controllers/user_controller.dart';
import 'controllers/health_controller.dart';
import 'models/user.dart';
import 'services/auth_service.dart';
import 'utilities/auth_validator.dart';

/// This type initializes an application.
///
/// Override methods in this class to set up routes and initialize services like
/// database connections. See http://conduit.io/docs/http/channel/.
class ${options.name.charAt(0).toUpperCase() + options.name.slice(1)}Channel extends ApplicationChannel {
  late ManagedContext context;
  late AuthService authService;
  late AuthValidator authValidator;
  
  /// Initialize services in this method.
  ///
  /// Implement this method to initialize services, read values from [options]
  /// and any other initialization required before constructing [entryPoint].
  ///
  /// This method is invoked prior to [entryPoint] being accessed.
  @override
  Future prepare() async {
    final env = DotEnv()..load();
    
    // Configure logging
    logger.onRecord.listen((rec) {
      print("\\\${rec.level.name}: \\\${rec.time}: \\\${rec.message}");
    });
    
    // Configure database
    final config = DatabaseConfiguration()
      ..host = env['DB_HOST'] ?? 'localhost'
      ..port = int.parse(env['DB_PORT'] ?? '5432')
      ..databaseName = env['DB_NAME'] ?? 'conduit_db'
      ..username = env['DB_USER'] ?? 'postgres'
      ..password = env['DB_PASSWORD'] ?? 'postgres';
    
    final dataModel = ManagedDataModel.fromCurrentMirrorSystem();
    final persistentStore = PostgreSQLPersistentStore.fromConnectionInfo(
      config.username!,
      config.password!,
      config.host!,
      config.port!,
      config.databaseName!,
    );
    
    context = ManagedContext(dataModel, persistentStore);
    
    // Initialize services
    authService = AuthService(context);
    authValidator = AuthValidator(authService);
  }
  
  /// Construct the request channel.
  ///
  /// Return an instance of some [Controller] that will be the initial receiver
  /// of all HTTP requests.
  ///
  /// This method is invoked after [prepare].
  @override
  Controller get entryPoint {
    final router = Router();
    
    // API documentation
    router.route("/docs/*").link(() => FileController("doc/api"));
    
    // Health check
    router.route("/health").link(() => HealthController());
    
    // Authentication routes
    router
      .route("/auth/register")
      .link(() => AuthController(context, authService));
      
    router
      .route("/auth/login")
      .link(() => AuthController(context, authService));
      
    router
      .route("/auth/refresh")
      .link(() => AuthController(context, authService));
      
    router
      .route("/auth/logout")
      .link(() => Authorizer.bearer(authValidator))!
      .link(() => AuthController(context, authService));
    
    // Protected routes
    router
      .route("/users/[:id]")
      .link(() => Authorizer.bearer(authValidator))!
      .link(() => UserController(context));
      
    router
      .route("/profile")
      .link(() => Authorizer.bearer(authValidator))!
      .link(() => UserController(context));
    
    return router;
  }
  
  /// Final initialization tasks.
  ///
  /// This method allows any resources that require asynchronous initialization to complete their
  /// initialization process. This method is invoked after [entryPoint] has been constructed.
  @override
  Future didOpen() async {
    // Run database migrations if needed
    if (options!.context['migrate'] == true) {
      logger.info("Running database migrations...");
      await ManagedContext.defaultContext.upgrade();
    }
    
    // Log startup information
    logger.info("Server started on port \\\${options!.port}");
    logger.info("Database connected: \\\${context.persistentStore}");
  }
  
  /// Perform any cleanup tasks.
  ///
  /// This method is invoked when the application is shutting down.
  @override
  Future willClose() async {
    await context.close();
    await super.willClose();
  }
  
  /// Document the API
  @override
  void documentComponents(APIDocumentContext context) {
    super.documentComponents(context);
    
    // Add security schemes
    context.securitySchemes['bearer'] = APISecurityScheme.http('bearer');
    
    // Add common responses
    context.responses['BadRequest'] = APIResponse.schema(
      'Bad Request',
      APISchemaObject.object({
        'error': APISchemaObject.string(),
        'message': APISchemaObject.string(),
      }),
      contentType: 'application/json',
    );
    
    context.responses['Unauthorized'] = APIResponse.schema(
      'Unauthorized',
      APISchemaObject.object({
        'error': APISchemaObject.string(),
        'message': APISchemaObject.string(),
      }),
      contentType: 'application/json',
    );
    
    context.responses['NotFound'] = APIResponse.schema(
      'Not Found',
      APISchemaObject.object({
        'error': APISchemaObject.string(),
        'message': APISchemaObject.string(),
      }),
      contentType: 'application/json',
    );
  }
}
`;

    await fs.mkdir(path.join(projectPath, 'lib'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'lib', 'channel.dart'),
      channelContent
    );
  }

  private async generateControllers(projectPath: string): Promise<void> {
    const controllersDir = path.join(projectPath, 'lib', 'controllers');
    await fs.mkdir(controllersDir, { recursive: true });

    // Health controller
    const healthControllerContent = `import 'package:conduit_core/conduit_core.dart';

class HealthController extends Controller {
  @override
  FutureOr<RequestOrResponse?> handle(Request request) {
    return Response.ok({
      'status': 'healthy',
      'service': 'conduit-api',
      'timestamp': DateTime.now().toIso8601String(),
      'uptime': DateTime.now().difference(_startTime).inSeconds,
      'version': '1.0.0',
    });
  }
  
  static final _startTime = DateTime.now();
}
`;

    await fs.writeFile(
      path.join(controllersDir, 'health_controller.dart'),
      healthControllerContent
    );

    // Auth controller
    const authControllerContent = `import 'dart:async';
import 'package:conduit_core/conduit_core.dart';
import '../models/user.dart';
import '../services/auth_service.dart';
import '../utilities/validators.dart';

class AuthController extends ResourceController {
  AuthController(this.context, this.authService);
  
  final ManagedContext context;
  final AuthService authService;
  
  @Operation.post()
  Future<Response> register(@Bind.body() User user) async {
    // Validate input
    if (user.email == null || user.password == null || user.name == null) {
      return Response.badRequest(body: {
        'error': 'Missing required fields',
        'fields': ['email', 'password', 'name'],
      });
    }
    
    // Validate email format
    if (!Validators.isValidEmail(user.email!)) {
      return Response.badRequest(body: {
        'error': 'Invalid email format',
      });
    }
    
    // Validate password strength
    final passwordError = Validators.validatePassword(user.password!);
    if (passwordError != null) {
      return Response.badRequest(body: {
        'error': passwordError,
      });
    }
    
    // Check if email exists
    final existingQuery = Query<User>(context)
      ..where((u) => u.email).equalTo(user.email);
    final existing = await existingQuery.fetchOne();
    
    if (existing != null) {
      return Response.conflict(body: {
        'error': 'Email already registered',
      });
    }
    
    // Hash password
    user.hashedPassword = authService.hashPassword(user.password!);
    user.password = null;
    
    // Set defaults
    user.role = user.role ?? 'user';
    user.isActive = true;
    user.emailVerified = false;
    user.createdAt = DateTime.now();
    user.updatedAt = DateTime.now();
    
    // Create user
    final insertQuery = Query<User>(context)..values = user;
    final newUser = await insertQuery.insert();
    
    // Generate tokens
    final tokens = authService.generateTokens(newUser);
    
    // Remove sensitive data
    newUser.hashedPassword = null;
    
    return Response.created('/users/\\\${newUser.id}', body: {
      'user': newUser,
      'tokens': tokens,
    });
  }
  
  @Operation.post('login')
  Future<Response> login(@Bind.body() Map<String, dynamic> body) async {
    final email = body['email'] as String?;
    final password = body['password'] as String?;
    
    if (email == null || password == null) {
      return Response.badRequest(body: {
        'error': 'Email and password required',
      });
    }
    
    // Find user
    final query = Query<User>(context)
      ..where((u) => u.email).equalTo(email);
    final user = await query.fetchOne();
    
    if (user == null) {
      return Response.unauthorized(body: {
        'error': 'Invalid credentials',
      });
    }
    
    // Verify password
    if (!authService.verifyPassword(password, user.hashedPassword!)) {
      return Response.unauthorized(body: {
        'error': 'Invalid credentials',
      });
    }
    
    // Check if active
    if (user.isActive != true) {
      return Response.forbidden(body: {
        'error': 'Account deactivated',
      });
    }
    
    // Update last login
    user.lastLogin = DateTime.now();
    final updateQuery = Query<User>(context)
      ..values = user
      ..where((u) => u.id).equalTo(user.id);
    await updateQuery.updateOne();
    
    // Generate tokens
    final tokens = authService.generateTokens(user);
    
    // Remove sensitive data
    user.hashedPassword = null;
    
    return Response.ok({
      'user': user,
      'tokens': tokens,
    });
  }
  
  @Operation.post('refresh')
  Future<Response> refreshToken(@Bind.body() Map<String, dynamic> body) async {
    final refreshToken = body['refreshToken'] as String?;
    
    if (refreshToken == null) {
      return Response.badRequest(body: {
        'error': 'Refresh token required',
      });
    }
    
    try {
      final tokens = await authService.refreshTokens(refreshToken);
      return Response.ok({'tokens': tokens});
    } catch (e) {
      return Response.unauthorized(body: {
        'error': 'Invalid refresh token',
      });
    }
  }
  
  @Operation.post('logout')
  Future<Response> logout() async {
    final authorization = request!.authorization;
    if (authorization == null) {
      return Response.unauthorized();
    }
    
    await authService.revokeToken(authorization.credentials);
    
    return Response.ok({
      'message': 'Logged out successfully',
    });
  }
  
  @Operation.post('forgot-password')
  Future<Response> forgotPassword(@Bind.body() Map<String, dynamic> body) async {
    final email = body['email'] as String?;
    
    if (email == null) {
      return Response.badRequest(body: {
        'error': 'Email required',
      });
    }
    
    // Find user (don't reveal if email exists)
    final query = Query<User>(context)
      ..where((u) => u.email).equalTo(email);
    final user = await query.fetchOne();
    
    if (user != null) {
      await authService.sendPasswordResetEmail(user);
    }
    
    return Response.ok({
      'message': 'If the email exists, a password reset link has been sent',
    });
  }
  
  @Operation.post('reset-password')
  Future<Response> resetPassword(@Bind.body() Map<String, dynamic> body) async {
    final token = body['token'] as String?;
    final newPassword = body['password'] as String?;
    
    if (token == null || newPassword == null) {
      return Response.badRequest(body: {
        'error': 'Token and password required',
      });
    }
    
    // Validate password
    final passwordError = Validators.validatePassword(newPassword);
    if (passwordError != null) {
      return Response.badRequest(body: {
        'error': passwordError,
      });
    }
    
    try {
      await authService.resetPassword(token, newPassword);
      return Response.ok({
        'message': 'Password reset successfully',
      });
    } catch (e) {
      return Response.badRequest(body: {
        'error': 'Invalid or expired token',
      });
    }
  }
  
  @override
  Map<String, APIResponse> documentOperationResponses(
    APIDocumentContext context,
    Operation operation,
  ) {
    final responses = super.documentOperationResponses(context, operation);
    
    if (operation.method == 'POST') {
      responses['201'] = APIResponse.schema(
        'User created successfully',
        APISchemaObject.object({
          'user': context.schema['User']!,
          'tokens': APISchemaObject.object({
            'accessToken': APISchemaObject.string(),
            'refreshToken': APISchemaObject.string(),
            'expiresIn': APISchemaObject.integer(),
          }),
        }),
        contentType: 'application/json',
      );
      
      responses['400'] = context.responses['BadRequest']!;
      responses['401'] = context.responses['Unauthorized']!;
      responses['409'] = APIResponse.schema(
        'Conflict',
        APISchemaObject.object({
          'error': APISchemaObject.string(),
        }),
        contentType: 'application/json',
      );
    }
    
    return responses;
  }
}
`;

    await fs.writeFile(
      path.join(controllersDir, 'auth_controller.dart'),
      authControllerContent
    );

    // User controller
    const userControllerContent = `import 'dart:async';
import 'package:conduit_core/conduit_core.dart';
import '../models/user.dart';
import '../utilities/validators.dart';

class UserController extends ResourceController {
  UserController(this.context);
  
  final ManagedContext context;
  
  @Operation.get()
  Future<Response> getAllUsers({
    @Bind.query('page') int page = 1,
    @Bind.query('limit') int limit = 20,
    @Bind.query('search') String? search,
    @Bind.query('role') String? role,
  }) async {
    // Validate pagination
    if (page < 1) page = 1;
    if (limit < 1 || limit > 100) limit = 20;
    
    final query = Query<User>(context);
    
    // Apply filters
    if (search != null && search.isNotEmpty) {
      query.predicate = QueryPredicate(
        'name ILIKE @name OR email ILIKE @email',
        {'name': '%\\\$search%', 'email': '%\\\$search%'},
      );
    }
    
    if (role != null && ['user', 'admin', 'moderator'].contains(role)) {
      query.where((u) => u.role).equalTo(role);
    }
    
    // Apply pagination
    query
      ..offset = (page - 1) * limit
      ..fetchLimit = limit
      ..sortBy((u) => u.createdAt, QuerySortOrder.descending);
    
    // Execute query
    final users = await query.fetch();
    
    // Get total count
    final countQuery = Query<User>(context);
    if (search != null && search.isNotEmpty) {
      countQuery.predicate = QueryPredicate(
        'name ILIKE @name OR email ILIKE @email',
        {'name': '%\\\$search%', 'email': '%\\\$search%'},
      );
    }
    if (role != null) {
      countQuery.where((u) => u.role).equalTo(role);
    }
    final total = await countQuery.reduce.count();
    
    // Remove sensitive data
    for (final user in users) {
      user.hashedPassword = null;
    }
    
    return Response.ok({
      'data': users,
      'pagination': {
        'page': page,
        'limit': limit,
        'total': total,
        'totalPages': (total / limit).ceil(),
      },
    });
  }
  
  @Operation.get('id')
  Future<Response> getUserById(@Bind.path('id') int id) async {
    final query = Query<User>(context)
      ..where((u) => u.id).equalTo(id);
      
    final user = await query.fetchOne();
    
    if (user == null) {
      return Response.notFound(body: {
        'error': 'User not found',
      });
    }
    
    // Check authorization
    final requestUser = request!.authorization!.ownerID;
    if (requestUser != id && request!.authorization!.resourceOwnerIdentifier != 'admin') {
      // Only return public info for other users
      user
        ..hashedPassword = null
        ..email = null
        ..lastLogin = null;
    } else {
      user.hashedPassword = null;
    }
    
    return Response.ok(user);
  }
  
  @Operation.put('id')
  Future<Response> updateUser(
    @Bind.path('id') int id,
    @Bind.body() Map<String, dynamic> body,
  ) async {
    // Check authorization
    final requestUser = request!.authorization!.ownerID;
    final isAdmin = request!.authorization!.resourceOwnerIdentifier == 'admin';
    
    if (requestUser != id && !isAdmin) {
      return Response.forbidden(body: {
        'error': 'Cannot update other users',
      });
    }
    
    // Get existing user
    final query = Query<User>(context)
      ..where((u) => u.id).equalTo(id);
    final user = await query.fetchOne();
    
    if (user == null) {
      return Response.notFound(body: {
        'error': 'User not found',
      });
    }
    
    // Update allowed fields
    if (body.containsKey('name')) {
      user.name = body['name'] as String;
    }
    
    if (body.containsKey('email')) {
      final newEmail = body['email'] as String;
      if (!Validators.isValidEmail(newEmail)) {
        return Response.badRequest(body: {
          'error': 'Invalid email format',
        });
      }
      
      // Check if email is taken
      final emailQuery = Query<User>(context)
        ..where((u) => u.email).equalTo(newEmail)
        ..where((u) => u.id).notEqualTo(id);
      final existing = await emailQuery.fetchOne();
      
      if (existing != null) {
        return Response.conflict(body: {
          'error': 'Email already in use',
        });
      }
      
      user.email = newEmail;
      user.emailVerified = false; // Require re-verification
    }
    
    // Only admins can change roles
    if (isAdmin && body.containsKey('role')) {
      final role = body['role'] as String;
      if (['user', 'admin', 'moderator'].contains(role)) {
        user.role = role;
      }
    }
    
    // Only admins can change active status
    if (isAdmin && body.containsKey('isActive')) {
      user.isActive = body['isActive'] as bool;
    }
    
    // Update timestamp
    user.updatedAt = DateTime.now();
    
    // Save changes
    final updateQuery = Query<User>(context)
      ..values = user
      ..where((u) => u.id).equalTo(id);
    final updated = await updateQuery.updateOne();
    
    // Remove sensitive data
    updated!.hashedPassword = null;
    
    return Response.ok(updated);
  }
  
  @Operation.delete('id')
  Future<Response> deleteUser(@Bind.path('id') int id) async {
    // Only admins can delete users
    if (request!.authorization!.resourceOwnerIdentifier != 'admin') {
      return Response.forbidden(body: {
        'error': 'Admin access required',
      });
    }
    
    final query = Query<User>(context)
      ..where((u) => u.id).equalTo(id);
      
    final deleted = await query.delete();
    
    if (deleted == 0) {
      return Response.notFound(body: {
        'error': 'User not found',
      });
    }
    
    return Response.ok({
      'message': 'User deleted successfully',
    });
  }
  
  @Operation.get('profile')
  Future<Response> getProfile() async {
    final userId = request!.authorization!.ownerID;
    
    final query = Query<User>(context)
      ..where((u) => u.id).equalTo(userId);
    final user = await query.fetchOne();
    
    if (user == null) {
      return Response.notFound(body: {
        'error': 'User not found',
      });
    }
    
    user.hashedPassword = null;
    
    return Response.ok(user);
  }
  
  @Operation.put('profile')
  Future<Response> updateProfile(@Bind.body() Map<String, dynamic> body) async {
    final userId = request!.authorization!.ownerID;
    
    // Get user
    final query = Query<User>(context)
      ..where((u) => u.id).equalTo(userId);
    final user = await query.fetchOne();
    
    if (user == null) {
      return Response.notFound(body: {
        'error': 'User not found',
      });
    }
    
    // Update allowed fields
    if (body.containsKey('name')) {
      user.name = body['name'] as String;
    }
    
    if (body.containsKey('password')) {
      final currentPassword = body['currentPassword'] as String?;
      final newPassword = body['password'] as String;
      
      if (currentPassword == null) {
        return Response.badRequest(body: {
          'error': 'Current password required',
        });
      }
      
      // Verify current password
      final authService = AuthService(context);
      if (!authService.verifyPassword(currentPassword, user.hashedPassword!)) {
        return Response.unauthorized(body: {
          'error': 'Invalid current password',
        });
      }
      
      // Validate new password
      final passwordError = Validators.validatePassword(newPassword);
      if (passwordError != null) {
        return Response.badRequest(body: {
          'error': passwordError,
        });
      }
      
      user.hashedPassword = authService.hashPassword(newPassword);
    }
    
    // Update timestamp
    user.updatedAt = DateTime.now();
    
    // Save changes
    final updateQuery = Query<User>(context)
      ..values = user
      ..where((u) => u.id).equalTo(userId);
    final updated = await updateQuery.updateOne();
    
    updated!.hashedPassword = null;
    
    return Response.ok(updated);
  }
  
  @override
  Map<String, APIResponse> documentOperationResponses(
    APIDocumentContext context,
    Operation operation,
  ) {
    final responses = super.documentOperationResponses(context, operation);
    
    if (operation.method == 'GET') {
      responses['200'] = APIResponse.schema(
        'Success',
        operation.pathVariables.isEmpty
            ? APISchemaObject.object({
                'data': APISchemaObject.array(ofSchema: context.schema['User']!),
                'pagination': APISchemaObject.object({
                  'page': APISchemaObject.integer(),
                  'limit': APISchemaObject.integer(),
                  'total': APISchemaObject.integer(),
                  'totalPages': APISchemaObject.integer(),
                }),
              })
            : context.schema['User']!,
        contentType: 'application/json',
      );
    }
    
    responses['401'] = context.responses['Unauthorized']!;
    responses['403'] = APIResponse.schema(
      'Forbidden',
      APISchemaObject.object({
        'error': APISchemaObject.string(),
      }),
      contentType: 'application/json',
    );
    responses['404'] = context.responses['NotFound']!;
    
    return responses;
  }
}
`;

    await fs.writeFile(
      path.join(controllersDir, 'user_controller.dart'),
      userControllerContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    const modelsDir = path.join(projectPath, 'lib', 'models');
    await fs.mkdir(modelsDir, { recursive: true });

    // User model
    const userModelContent = `import 'package:conduit_core/conduit_core.dart';
import 'package:conduit_codable/conduit_codable.dart';

class User extends ManagedObject<_User> implements _User {
  @override
  void willUpdate() {
    updatedAt = DateTime.now();
  }
  
  @override
  void willInsert() {
    createdAt = DateTime.now();
    updatedAt = DateTime.now();
  }
  
  /// Transient property for password input
  @Serialize(input: true, output: false)
  String? password;
  
  /// Convert to public JSON (without sensitive data)
  Map<String, dynamic> toPublicJson() {
    final json = asMap();
    json.remove('hashedPassword');
    json.remove('sessions');
    json.remove('refreshTokens');
    return json;
  }
}

class _User {
  @primaryKey
  int? id;
  
  @Column(indexed: true, unique: true)
  String? email;
  
  @Column()
  String? name;
  
  @Column(omitByDefault: true)
  String? hashedPassword;
  
  @Column(defaultValue: "'user'")
  String? role;
  
  @Column(defaultValue: 'true')
  bool? isActive;
  
  @Column(defaultValue: 'false')
  bool? emailVerified;
  
  @Column()
  DateTime? lastLogin;
  
  @Column()
  DateTime? createdAt;
  
  @Column()
  DateTime? updatedAt;
  
  /// User's sessions
  ManagedSet<Session>? sessions;
  
  /// User's refresh tokens
  ManagedSet<RefreshToken>? refreshTokens;
}

class Session extends ManagedObject<_Session> implements _Session {
  @override
  void willInsert() {
    createdAt = DateTime.now();
  }
}

class _Session {
  @primaryKey
  int? id;
  
  @Column(indexed: true)
  String? token;
  
  @Relate(#sessions)
  User? user;
  
  @Column()
  String? ipAddress;
  
  @Column()
  String? userAgent;
  
  @Column()
  DateTime? expiresAt;
  
  @Column(defaultValue: 'true')
  bool? isActive;
  
  @Column()
  DateTime? createdAt;
}

class RefreshToken extends ManagedObject<_RefreshToken> implements _RefreshToken {
  @override
  void willInsert() {
    createdAt = DateTime.now();
  }
}

class _RefreshToken {
  @primaryKey
  int? id;
  
  @Column(indexed: true, unique: true)
  String? token;
  
  @Relate(#refreshTokens)
  User? user;
  
  @Column()
  DateTime? expiresAt;
  
  @Column(defaultValue: 'false')
  bool? isRevoked;
  
  @Column()
  DateTime? revokedAt;
  
  @Column()
  String? replacedByToken;
  
  @Column()
  DateTime? createdAt;
}

/// API Key model for service-to-service auth
class ApiKey extends ManagedObject<_ApiKey> implements _ApiKey {
  @override
  void willInsert() {
    createdAt = DateTime.now();
    lastUsed = DateTime.now();
  }
}

class _ApiKey {
  @primaryKey
  int? id;
  
  @Column(indexed: true, unique: true)
  String? key;
  
  @Column()
  String? name;
  
  @Column()
  String? description;
  
  @Column(defaultValue: "'read'")
  String? scope;
  
  @Column(defaultValue: 'true')
  bool? isActive;
  
  @Column()
  DateTime? expiresAt;
  
  @Column()
  DateTime? lastUsed;
  
  @Column()
  int? usageCount;
  
  @Column()
  DateTime? createdAt;
}
`;

    await fs.writeFile(
      path.join(modelsDir, 'user.dart'),
      userModelContent
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    const servicesDir = path.join(projectPath, 'lib', 'services');
    await fs.mkdir(servicesDir, { recursive: true });

    // Auth service
    const authServiceContent = `import 'dart:convert';
import 'dart:math';
import 'package:conduit_core/conduit_core.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';
import 'package:crypto/crypto.dart';
import 'package:bcrypt/bcrypt.dart';
import 'package:dotenv/dotenv.dart';
import '../models/user.dart';

class AuthService {
  AuthService(this.context) {
    final env = DotEnv()..load();
    _jwtSecret = env['JWT_SECRET'] ?? _generateSecret();
    _jwtIssuer = env['JWT_ISSUER'] ?? 'conduit-api';
    _accessTokenExpiry = Duration(minutes: int.parse(env['ACCESS_TOKEN_EXPIRY'] ?? '15'));
    _refreshTokenExpiry = Duration(days: int.parse(env['REFRESH_TOKEN_EXPIRY'] ?? '30'));
  }
  
  final ManagedContext context;
  late final String _jwtSecret;
  late final String _jwtIssuer;
  late final Duration _accessTokenExpiry;
  late final Duration _refreshTokenExpiry;
  
  /// Hash password using bcrypt
  String hashPassword(String password) {
    return BCrypt.hashpw(password, BCrypt.gensalt());
  }
  
  /// Verify password against hash
  bool verifyPassword(String password, String hash) {
    return BCrypt.checkpw(password, hash);
  }
  
  /// Generate access and refresh tokens
  Map<String, dynamic> generateTokens(User user) {
    final now = DateTime.now();
    final accessExpiry = now.add(_accessTokenExpiry);
    final refreshExpiry = now.add(_refreshTokenExpiry);
    
    // Create access token
    final accessClaims = JwtClaim(
      subject: user.id.toString(),
      issuer: _jwtIssuer,
      audience: ['conduit-api'],
      jwtId: _generateTokenId(),
      issuedAt: now,
      expiry: accessExpiry,
      otherClaims: {
        'email': user.email,
        'role': user.role,
        'type': 'access',
      },
    );
    
    final accessToken = issueJwtHS256(accessClaims, _jwtSecret);
    
    // Create refresh token
    final refreshToken = _generateRefreshToken();
    
    // Store refresh token
    final refreshQuery = Query<RefreshToken>(context)
      ..values.token = refreshToken
      ..values.user = user
      ..values.expiresAt = refreshExpiry;
    refreshQuery.insert();
    
    return {
      'accessToken': accessToken,
      'refreshToken': refreshToken,
      'tokenType': 'Bearer',
      'expiresIn': _accessTokenExpiry.inSeconds,
    };
  }
  
  /// Refresh access token using refresh token
  Future<Map<String, dynamic>> refreshTokens(String refreshToken) async {
    // Find refresh token
    final query = Query<RefreshToken>(context)
      ..where((t) => t.token).equalTo(refreshToken)
      ..where((t) => t.isRevoked).equalTo(false)
      ..join(object: (t) => t.user);
      
    final token = await query.fetchOne();
    
    if (token == null) {
      throw StateError('Invalid refresh token');
    }
    
    // Check expiry
    if (DateTime.now().isAfter(token.expiresAt!)) {
      // Revoke expired token
      token.isRevoked = true;
      token.revokedAt = DateTime.now();
      final updateQuery = Query<RefreshToken>(context)
        ..values = token
        ..where((t) => t.id).equalTo(token.id);
      await updateQuery.updateOne();
      
      throw StateError('Refresh token expired');
    }
    
    // Generate new tokens
    final newTokens = generateTokens(token.user!);
    
    // Revoke old refresh token and link to new one
    token.isRevoked = true;
    token.revokedAt = DateTime.now();
    token.replacedByToken = newTokens['refreshToken'];
    
    final updateQuery = Query<RefreshToken>(context)
      ..values = token
      ..where((t) => t.id).equalTo(token.id);
    await updateQuery.updateOne();
    
    return newTokens;
  }
  
  /// Validate access token
  Future<User?> validateAccessToken(String token) async {
    try {
      final claims = verifyJwtHS256Signature(token, _jwtSecret);
      
      // Check token type
      if (claims.otherClaims['type'] != 'access') {
        return null;
      }
      
      // Check expiry
      if (claims.expiry != null && DateTime.now().isAfter(claims.expiry!)) {
        return null;
      }
      
      // Get user
      final userId = int.parse(claims.subject!);
      final query = Query<User>(context)
        ..where((u) => u.id).equalTo(userId)
        ..where((u) => u.isActive).equalTo(true);
        
      return await query.fetchOne();
    } catch (e) {
      return null;
    }
  }
  
  /// Revoke token (logout)
  Future<void> revokeToken(String accessToken) async {
    try {
      final claims = verifyJwtHS256Signature(accessToken, _jwtSecret);
      final userId = int.parse(claims.subject!);
      
      // Revoke all user's refresh tokens
      final query = Query<RefreshToken>(context)
        ..where((t) => t.user.id).equalTo(userId)
        ..where((t) => t.isRevoked).equalTo(false)
        ..values.isRevoked = true
        ..values.revokedAt = DateTime.now();
        
      await query.update();
    } catch (e) {
      // Token might be invalid, but logout should still succeed
    }
  }
  
  /// Send password reset email
  Future<void> sendPasswordResetEmail(User user) async {
    final token = _generateResetToken();
    final expiry = DateTime.now().add(Duration(hours: 1));
    
    // Store reset token (in production, use Redis or similar)
    // For now, we'll store it in a temporary session
    final sessionQuery = Query<Session>(context)
      ..values.token = 'reset_\$token'
      ..values.user = user
      ..values.expiresAt = expiry
      ..values.ipAddress = 'password_reset'
      ..values.userAgent = 'email';
    await sessionQuery.insert();
    
    // In production, send actual email
    print('Password reset link: http://localhost:8080/reset-password?token=\\\$token');
  }
  
  /// Reset password with token
  Future<void> resetPassword(String token, String newPassword) async {
    // Find reset token
    final query = Query<Session>(context)
      ..where((s) => s.token).equalTo('reset_\$token')
      ..where((s) => s.isActive).equalTo(true)
      ..join(object: (s) => s.user);
      
    final session = await query.fetchOne();
    
    if (session == null) {
      throw StateError('Invalid reset token');
    }
    
    // Check expiry
    if (DateTime.now().isAfter(session.expiresAt!)) {
      throw StateError('Reset token expired');
    }
    
    // Update password
    final user = session.user!;
    user.hashedPassword = hashPassword(newPassword);
    
    final userQuery = Query<User>(context)
      ..values = user
      ..where((u) => u.id).equalTo(user.id);
    await userQuery.updateOne();
    
    // Invalidate reset token
    session.isActive = false;
    final sessionQuery = Query<Session>(context)
      ..values = session
      ..where((s) => s.id).equalTo(session.id);
    await sessionQuery.updateOne();
    
    // Revoke all refresh tokens for security
    final revokeQuery = Query<RefreshToken>(context)
      ..where((t) => t.user.id).equalTo(user.id)
      ..values.isRevoked = true
      ..values.revokedAt = DateTime.now();
    await revokeQuery.update();
  }
  
  /// Generate a random secret
  String _generateSecret() {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return base64Url.encode(bytes);
  }
  
  /// Generate token ID
  String _generateTokenId() {
    final random = Random.secure();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));
    return base64Url.encode(bytes);
  }
  
  /// Generate refresh token
  String _generateRefreshToken() {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return base64Url.encode(bytes);
  }
  
  /// Generate reset token
  String _generateResetToken() {
    final random = Random.secure();
    final bytes = List<int>.generate(24, (_) => random.nextInt(256));
    return base64Url.encode(bytes);
  }
}
`;

    await fs.writeFile(
      path.join(servicesDir, 'auth_service.dart'),
      authServiceContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    const utilitiesDir = path.join(projectPath, 'lib', 'utilities');
    await fs.mkdir(utilitiesDir, { recursive: true });

    // Auth validator
    const authValidatorContent = `import 'dart:async';
import 'package:conduit_core/conduit_core.dart';
import '../models/user.dart';
import '../services/auth_service.dart';

/// Bearer token validator for Conduit authorization
class AuthValidator extends AuthValidator<User> {
  AuthValidator(this.authService);
  
  final AuthService authService;
  
  @override
  FutureOr<Authorization?> validate<T>(
    AuthorizationParser<T> parser,
    T authorizationData,
    {List<AuthScope>? requiredScope}
  ) async {
    if (authorizationData is! String) {
      return null;
    }
    
    final user = await authService.validateAccessToken(authorizationData);
    if (user == null) {
      return null;
    }
    
    // Create authorization
    return Authorization(
      user.id!,
      this,
      credentials: authorizationData,
      resourceOwnerIdentifier: user.role,
    );
  }
}

/// API Key validator
class ApiKeyValidator extends AuthValidator<String> {
  ApiKeyValidator(this.context);
  
  final ManagedContext context;
  
  @override
  FutureOr<Authorization?> validate<T>(
    AuthorizationParser<T> parser,
    T authorizationData,
    {List<AuthScope>? requiredScope}
  ) async {
    if (authorizationData is! String) {
      return null;
    }
    
    // Find API key
    final query = Query<ApiKey>(context)
      ..where((k) => k.key).equalTo(authorizationData)
      ..where((k) => k.isActive).equalTo(true);
      
    final apiKey = await query.fetchOne();
    
    if (apiKey == null) {
      return null;
    }
    
    // Check expiry
    if (apiKey.expiresAt != null && DateTime.now().isAfter(apiKey.expiresAt!)) {
      return null;
    }
    
    // Update usage
    apiKey.lastUsed = DateTime.now();
    apiKey.usageCount = (apiKey.usageCount ?? 0) + 1;
    
    final updateQuery = Query<ApiKey>(context)
      ..values = apiKey
      ..where((k) => k.id).equalTo(apiKey.id);
    await updateQuery.updateOne();
    
    // Create authorization
    return Authorization(
      apiKey.id!,
      this,
      credentials: authorizationData,
      resourceOwnerIdentifier: apiKey.scope,
    );
  }
}
`;

    await fs.writeFile(
      path.join(utilitiesDir, 'auth_validator.dart'),
      authValidatorContent
    );

    // Validators
    const validatorsContent = `/// Input validation utilities
class Validators {
  /// Validate email format
  static bool isValidEmail(String email) {
    final regex = RegExp(
      r'^[a-zA-Z0-9.!#\$%&*+/=?^_\`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?)*\$',
    );
    return regex.hasMatch(email);
  }
  
  /// Validate password strength
  static String? validatePassword(String password) {
    if (password.length < 8) {
      return 'Password must be at least 8 characters';
    }
    
    if (!password.contains(RegExp(r'[A-Z]'))) {
      return 'Password must contain uppercase letter';
    }
    
    if (!password.contains(RegExp(r'[a-z]'))) {
      return 'Password must contain lowercase letter';
    }
    
    if (!password.contains(RegExp(r'[0-9]'))) {
      return 'Password must contain number';
    }
    
    if (!password.contains(RegExp(r'[!@#$%^&*(),.?":{}|<>]'))) {
      return 'Password must contain special character';
    }
    
    return null; // Valid
  }
  
  /// Validate username
  static String? validateUsername(String username) {
    if (username.length < 3 || username.length > 20) {
      return 'Username must be 3-20 characters';
    }
    
    if (!RegExp(r'^[a-zA-Z0-9_]+$').hasMatch(username)) {
      return 'Username can only contain letters, numbers, and underscore';
    }
    
    return null; // Valid
  }
  
  /// Validate phone number
  static bool isValidPhone(String phone) {
    final regex = RegExp(r'^\+?[1-9]\d{1,14}$');
    return regex.hasMatch(phone);
  }
  
  /// Validate URL
  static bool isValidUrl(String url) {
    try {
      final uri = Uri.parse(url);
      return uri.isAbsolute && (uri.scheme == 'http' || uri.scheme == 'https');
    } catch (_) {
      return false;
    }
  }
  
  /// Validate UUID
  static bool isValidUuid(String uuid) {
    final regex = RegExp(
      r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\$',
      caseSensitive: false,
    );
    return regex.hasMatch(uuid);
  }
  
  /// Sanitize input for security
  static String sanitizeInput(String input) {
    return input
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#x27;')
        .replaceAll('/', '&#x2F;');
  }
}

/// Rate limiting helper
class RateLimiter {
  static final Map<String, List<DateTime>> _requests = {};
  static final Duration _window = Duration(minutes: 15);
  static final int _maxRequests = 100;
  
  /// Check if request should be rate limited
  static bool shouldLimit(String key, {int? maxRequests, Duration? window}) {
    final now = DateTime.now();
    final windowDuration = window ?? _window;
    final limit = maxRequests ?? _maxRequests;
    
    // Get or create request list
    _requests[key] ??= [];
    final requests = _requests[key]!;
    
    // Remove old requests outside window
    requests.removeWhere((time) => now.difference(time) > windowDuration);
    
    // Check limit
    if (requests.length >= limit) {
      return true;
    }
    
    // Add current request
    requests.add(now);
    return false;
  }
  
  /// Get remaining requests
  static int remaining(String key, {int? maxRequests}) {
    final limit = maxRequests ?? _maxRequests;
    final requests = _requests[key]?.length ?? 0;
    return limit - requests;
  }
  
  /// Reset rate limit for key
  static void reset(String key) {
    _requests.remove(key);
  }
}
`;

    await fs.writeFile(
      path.join(utilitiesDir, 'validators.dart'),
      validatorsContent
    );

    // Response helpers
    const responseHelpersContent = `import 'package:conduit_core/conduit_core.dart';

/// Standard response helpers
class ResponseHelpers {
  /// Success response
  static Response success(dynamic data, {String? message, int statusCode = 200}) {
    return Response(
      statusCode,
      null,
      {
        'success': true,
        'message': message ?? 'Operation successful',
        'data': data,
      },
    );
  }
  
  /// Error response
  static Response error(String message, {int statusCode = 400, dynamic errors}) {
    final body = {
      'success': false,
      'message': message,
    };
    
    if (errors != null) {
      body['errors'] = errors;
    }
    
    return Response(statusCode, null, body);
  }
  
  /// Paginated response
  static Response paginated({
    required List<dynamic> data,
    required int page,
    required int limit,
    required int total,
    String? message,
  }) {
    return Response.ok({
      'success': true,
      'message': message ?? 'Data retrieved successfully',
      'data': data,
      'pagination': {
        'page': page,
        'limit': limit,
        'total': total,
        'totalPages': (total / limit).ceil(),
        'hasNext': page < (total / limit).ceil(),
        'hasPrev': page > 1,
      },
    });
  }
  
  /// File response
  static Response file(List<int> bytes, String filename, String contentType) {
    return Response.ok(bytes)
      ..contentType = ContentType.parse(contentType)
      ..headers['content-disposition'] = 'attachment; filename="\$filename"';
  }
  
  /// Stream response
  static Response stream(Stream<List<int>> stream, String contentType) {
    return Response.ok(stream)
      ..contentType = ContentType.parse(contentType);
  }
}

/// Common error messages
class ErrorMessages {
  static const String unauthorized = 'Unauthorized access';
  static const String forbidden = 'Access forbidden';
  static const String notFound = 'Resource not found';
  static const String badRequest = 'Invalid request';
  static const String conflict = 'Resource conflict';
  static const String serverError = 'Internal server error';
  static const String validationFailed = 'Validation failed';
  static const String rateLimited = 'Too many requests';
}
`;

    await fs.writeFile(
      path.join(utilitiesDir, 'response_helpers.dart'),
      responseHelpersContent
    );
  }

  private async generateConfig(projectPath: string): Promise<void> {
    const configDir = path.join(projectPath, 'config');
    await fs.mkdir(configDir, { recursive: true });

    // Database configuration
    const dbConfigContent = `name: ${this.config.framework.toLowerCase()}_db
host: localhost
port: 5432
username: postgres
password: postgres
databaseName: conduit_dev

# Test database
test:
  host: localhost
  port: 5432
  username: postgres
  password: postgres
  databaseName: conduit_test
`;

    await fs.writeFile(
      path.join(configDir, 'database.yaml'),
      dbConfigContent
    );

    // Application configuration
    const appConfigContent = `# Application configuration
server:
  port: 8080
  host: 0.0.0.0
  instances: 1

# Database
database:
  host: \${DB_HOST:-localhost}
  port: \${DB_PORT:-5432}
  name: \${DB_NAME:-conduit_db}
  username: \${DB_USER:-postgres}
  password: \${DB_PASSWORD:-postgres}
  ssl: \${DB_SSL:-false}
  poolSize: \${DB_POOL_SIZE:-10}

# JWT Configuration
jwt:
  secret: \${JWT_SECRET:-your-secret-key-change-in-production}
  issuer: \${JWT_ISSUER:-conduit-api}
  accessTokenExpiry: \${ACCESS_TOKEN_EXPIRY:-15} # minutes
  refreshTokenExpiry: \${REFRESH_TOKEN_EXPIRY:-30} # days

# Redis (optional)
redis:
  host: \${REDIS_HOST:-localhost}
  port: \${REDIS_PORT:-6379}
  password: \${REDIS_PASSWORD:-}
  database: \${REDIS_DB:-0}

# Email
email:
  smtp:
    host: \${SMTP_HOST:-smtp.gmail.com}
    port: \${SMTP_PORT:-587}
    username: \${SMTP_USER:-}
    password: \${SMTP_PASSWORD:-}
    secure: \${SMTP_SECURE:-true}
  from:
    email: \${EMAIL_FROM:-noreply@example.com}
    name: \${EMAIL_FROM_NAME:-Conduit API}

# CORS
cors:
  allowOrigins:
    - http://localhost:3000
    - http://localhost:8080
  allowMethods:
    - GET
    - POST
    - PUT
    - DELETE
    - PATCH
    - OPTIONS
  allowHeaders:
    - Content-Type
    - Authorization
    - X-Requested-With
  allowCredentials: true
  maxAge: 86400

# Rate Limiting
rateLimit:
  windowMinutes: 15
  maxRequests: 100
  strictWindowMinutes: 15
  strictMaxRequests: 5

# Features
features:
  registration: true
  emailVerification: true
  passwordReset: true
  apiKeys: true
  webhooks: false
  subscriptions: false

# Logging
logging:
  level: \${LOG_LEVEL:-info}
  format: \${LOG_FORMAT:-json}
  output: \${LOG_OUTPUT:-stdout}
`;

    await fs.writeFile(
      path.join(configDir, 'config.yaml'),
      appConfigContent
    );
  }

  private async generateMigrations(projectPath: string): Promise<void> {
    const migrationsDir = path.join(projectPath, 'migrations');
    await fs.mkdir(migrationsDir, { recursive: true });

    // Initial migration
    const migrationContent = `import 'dart:async';
import 'package:conduit_core/conduit_core.dart';

class Migration1 extends Migration {
  @override
  Future upgrade() async {
    // Create users table
    database.createTable(SchemaTable(
      '_User',
      [
        SchemaColumn('id', ManagedPropertyType.bigInteger,
            isPrimaryKey: true,
            autoincrement: true,
            isIndexed: true,
            isNullable: false,
            isUnique: true),
        SchemaColumn('email', ManagedPropertyType.string,
            isIndexed: true,
            isNullable: false,
            isUnique: true),
        SchemaColumn('name', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
        SchemaColumn('hashedPassword', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
        SchemaColumn('role', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: false,
            isUnique: false,
            defaultValue: "'user'"),
        SchemaColumn('isActive', ManagedPropertyType.boolean,
            isIndexed: false,
            isNullable: false,
            isUnique: false,
            defaultValue: 'true'),
        SchemaColumn('emailVerified', ManagedPropertyType.boolean,
            isIndexed: false,
            isNullable: false,
            isUnique: false,
            defaultValue: 'false'),
        SchemaColumn('lastLogin', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('createdAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
        SchemaColumn('updatedAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
      ],
    ));
    
    // Create sessions table
    database.createTable(SchemaTable(
      '_Session',
      [
        SchemaColumn('id', ManagedPropertyType.bigInteger,
            isPrimaryKey: true,
            autoincrement: true,
            isIndexed: true,
            isNullable: false,
            isUnique: true),
        SchemaColumn('token', ManagedPropertyType.string,
            isIndexed: true,
            isNullable: false,
            isUnique: false),
        SchemaColumn.relationship('user', ManagedPropertyType.bigInteger,
            relatedTableName: '_User',
            relatedColumnName: 'id',
            deleteRule: DeleteRule.cascade),
        SchemaColumn('ipAddress', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('userAgent', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('expiresAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
        SchemaColumn('isActive', ManagedPropertyType.boolean,
            isIndexed: false,
            isNullable: false,
            isUnique: false,
            defaultValue: 'true'),
        SchemaColumn('createdAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
      ],
    ));
    
    // Create refresh tokens table
    database.createTable(SchemaTable(
      '_RefreshToken',
      [
        SchemaColumn('id', ManagedPropertyType.bigInteger,
            isPrimaryKey: true,
            autoincrement: true,
            isIndexed: true,
            isNullable: false,
            isUnique: true),
        SchemaColumn('token', ManagedPropertyType.string,
            isIndexed: true,
            isNullable: false,
            isUnique: true),
        SchemaColumn.relationship('user', ManagedPropertyType.bigInteger,
            relatedTableName: '_User',
            relatedColumnName: 'id',
            deleteRule: DeleteRule.cascade),
        SchemaColumn('expiresAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
        SchemaColumn('isRevoked', ManagedPropertyType.boolean,
            isIndexed: false,
            isNullable: false,
            isUnique: false,
            defaultValue: 'false'),
        SchemaColumn('revokedAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('replacedByToken', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('createdAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
      ],
    ));
    
    // Create API keys table
    database.createTable(SchemaTable(
      '_ApiKey',
      [
        SchemaColumn('id', ManagedPropertyType.bigInteger,
            isPrimaryKey: true,
            autoincrement: true,
            isIndexed: true,
            isNullable: false,
            isUnique: true),
        SchemaColumn('key', ManagedPropertyType.string,
            isIndexed: true,
            isNullable: false,
            isUnique: true),
        SchemaColumn('name', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
        SchemaColumn('description', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('scope', ManagedPropertyType.string,
            isIndexed: false,
            isNullable: false,
            isUnique: false,
            defaultValue: "'read'"),
        SchemaColumn('isActive', ManagedPropertyType.boolean,
            isIndexed: false,
            isNullable: false,
            isUnique: false,
            defaultValue: 'true'),
        SchemaColumn('expiresAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('lastUsed', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('usageCount', ManagedPropertyType.integer,
            isIndexed: false,
            isNullable: true,
            isUnique: false),
        SchemaColumn('createdAt', ManagedPropertyType.datetime,
            isIndexed: false,
            isNullable: false,
            isUnique: false),
      ],
    ));
    
    // Create indexes
    database.addIndex('_User', ['email'], unique: true);
    database.addIndex('_User', ['createdAt']);
    database.addIndex('_Session', ['token']);
    database.addIndex('_Session', ['user_id']);
    database.addIndex('_RefreshToken', ['token'], unique: true);
    database.addIndex('_RefreshToken', ['user_id']);
    database.addIndex('_ApiKey', ['key'], unique: true);
  }
  
  @override
  Future downgrade() async {}
  
  @override
  Future seed() async {
    // Seed initial admin user
    final hashedPassword = authService.hashPassword('admin123!');
    
    await database.store.execute('''
      INSERT INTO _user (email, name, "hashedPassword", role, "isActive", "emailVerified", "createdAt", "updatedAt")
      VALUES ('admin@example.com', 'Admin User', '\$hashedPassword', 'admin', true, true, NOW(), NOW())
    ''');
  }
}
`;

    await fs.writeFile(
      path.join(migrationsDir, '00000001_initial.migration.dart'),
      migrationContent
    );
  }

  private async generateTestHarness(projectPath: string): Promise<void> {
    const testDir = path.join(projectPath, 'test');
    await fs.mkdir(testDir, { recursive: true });

    // Test harness
    const harnessContent = `import 'package:conduit_test/conduit_test.dart';
import 'package:conduit_core/conduit_core.dart';
import 'package:${this.config.framework.toLowerCase()}/channel.dart';

export 'package:conduit_test/conduit_test.dart';
export 'package:test/test.dart';
export 'package:conduit_core/conduit_core.dart';

/// Testing harness for ${this.config.framework} application.
class Harness extends TestHarness<${this.config.framework.charAt(0).toUpperCase() + this.config.framework.slice(1)}Channel> {
  @override
  Future onSetUp() async {
    await resetData();
  }
  
  @override
  Future onTearDown() async {}
  
  @override
  Future beforeStart() async {
    // Set test configuration
    options.context['migrate'] = true;
  }
  
  @override
  Future afterStart() async {}
  
  Future resetData() async {
    // Clear test data
    final tables = ['_RefreshToken', '_Session', '_ApiKey', '_User'];
    
    for (final table in tables) {
      try {
        await channel.context.persistentStore.execute('DELETE FROM \$table');
      } catch (_) {}
    }
    
    // Seed test data
    await seedTestData();
  }
  
  Future seedTestData() async {
    // Create test users
    final users = [
      {
        'email': 'user@test.com',
        'password': 'Test123!',
        'name': 'Test User',
        'role': 'user',
      },
      {
        'email': 'admin@test.com',
        'password': 'Admin123!',
        'name': 'Admin User',
        'role': 'admin',
      },
    ];
    
    for (final userData in users) {
      final response = await agent!.post(
        '/auth/register',
        body: userData,
      );
      
      expect(response.statusCode, 201);
    }
  }
  
  /// Get auth headers for user
  Future<Map<String, String>> getAuthHeaders(String email, String password) async {
    final response = await agent!.post(
      '/auth/login',
      body: {'email': email, 'password': password},
    );
    
    expect(response.statusCode, 200);
    
    final token = response.body.as<Map>()['tokens']['accessToken'];
    return {'Authorization': 'Bearer \$token'};
  }
}
`;

    await fs.writeFile(
      path.join(testDir, 'harness', 'app.dart'),
      harnessContent
    );

    // Example test
    const exampleTestContent = `import 'harness/app.dart';

void main() {
  final harness = Harness()..install();
  
  group('Health Check', () {
    test('GET /health returns 200', () async {
      final response = await harness.agent!.get('/health');
      
      expectResponse(response, 200,
        body: {
          'status': 'healthy',
          'service': 'conduit-api',
          'version': '1.0.0',
        },
        partial: true,
      );
    });
  });
  
  group('Authentication', () {
    test('POST /auth/register creates new user', () async {
      final response = await harness.agent!.post('/auth/register', body: {
        'email': 'newuser@test.com',
        'password': 'NewUser123!',
        'name': 'New User',
      });
      
      expectResponse(response, 201);
      expect(response.body.as<Map>()['user']['email'], 'newuser@test.com');
      expect(response.body.as<Map>()['tokens']['accessToken'], isNotNull);
    });
    
    test('POST /auth/login with valid credentials returns tokens', () async {
      final response = await harness.agent!.post('/auth/login', body: {
        'email': 'user@test.com',
        'password': 'Test123!',
      });
      
      expectResponse(response, 200);
      expect(response.body.as<Map>()['tokens']['accessToken'], isNotNull);
      expect(response.body.as<Map>()['tokens']['refreshToken'], isNotNull);
    });
    
    test('POST /auth/login with invalid credentials returns 401', () async {
      final response = await harness.agent!.post('/auth/login', body: {
        'email': 'user@test.com',
        'password': 'WrongPassword',
      });
      
      expectResponse(response, 401, body: {'error': 'Invalid credentials'});
    });
  });
  
  group('Users', () {
    late Map<String, String> userHeaders;
    late Map<String, String> adminHeaders;
    
    setUpAll(() async {
      userHeaders = await harness.getAuthHeaders('user@test.com', 'Test123!');
      adminHeaders = await harness.getAuthHeaders('admin@test.com', 'Admin123!');
    });
    
    test('GET /users requires authentication', () async {
      final response = await harness.agent!.get('/users');
      expectResponse(response, 401);
    });
    
    test('GET /users returns paginated users for admin', () async {
      final response = await harness.agent!.get(
        '/users?page=1&limit=10',
        headers: adminHeaders,
      );
      
      expectResponse(response, 200);
      expect(response.body.as<Map>()['data'], isList);
      expect(response.body.as<Map>()['pagination'], isMap);
    });
    
    test('GET /profile returns current user', () async {
      final response = await harness.agent!.get(
        '/profile',
        headers: userHeaders,
      );
      
      expectResponse(response, 200);
      expect(response.body.as<Map>()['email'], 'user@test.com');
    });
    
    test('PUT /profile updates current user', () async {
      final response = await harness.agent!.put(
        '/profile',
        body: {'name': 'Updated Name'},
        headers: userHeaders,
      );
      
      expectResponse(response, 200);
      expect(response.body.as<Map>()['name'], 'Updated Name');
    });
  });
}
`;

    await fs.writeFile(
      path.join(testDir, 'example_test.dart'),
      exampleTestContent
    );
  }

  private async generateApiDocs(projectPath: string): Promise<void> {
    const docsDir = path.join(projectPath, 'doc', 'api');
    await fs.mkdir(docsDir, { recursive: true });

    // API documentation script
    const apiDocScriptContent = `import 'dart:io';
import 'package:conduit_core/conduit_core.dart';
import 'package:${this.config.framework.toLowerCase()}/channel.dart';

void main() {
  final config = ApplicationOptions()..port = 8888;
  
  final app = Application<${this.config.framework.charAt(0).toUpperCase() + this.config.framework.slice(1)}Channel>()
    ..options = config;
    
  final document = APIDocument()
    ..version = '1.0.0'
    ..info = APIInfo(
      '${this.config.framework} API',
      '1.0.0',
      description: 'REST API built with Conduit framework',
      contact: APIContact(
        name: 'API Support',
        email: 'support@example.com',
      ),
      license: APILicense('MIT'),
    )
    ..servers = [
      APIServer('http://localhost:8080', description: 'Development server'),
      APIServer('https://api.example.com', description: 'Production server'),
    ];
    
  app.channel.documentAPI(document);
  
  final file = File('doc/api/openapi.json');
  file.writeAsStringSync(document.asJson());
  
  print('API documentation generated at: doc/api/openapi.json');
  
  // Generate HTML documentation
  final html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>${this.config.framework} API Documentation</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: './openapi.json',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.SwaggerUIStandalonePreset
            ],
            layout: "BaseLayout"
        });
    </script>
</body>
</html>
''';
  
  File('doc/api/index.html').writeAsStringSync(html);
  print('HTML documentation generated at: doc/api/index.html');
}
`;

    await fs.writeFile(
      path.join(projectPath, 'tool', 'generate_docs.dart'),
      apiDocScriptContent
    );
  }

  private async generateCommands(projectPath: string): Promise<void> {
    const commandsDir = path.join(projectPath, 'tool');
    await fs.mkdir(commandsDir, { recursive: true });

    // Admin CLI tool
    const adminCliContent = `import 'dart:io';
import 'package:args/args.dart';
import 'package:conduit_core/conduit_core.dart';
import 'package:postgres/postgres.dart';
import 'package:dotenv/dotenv.dart';
import 'package:${this.config.framework.toLowerCase()}/models/user.dart';
import 'package:${this.config.framework.toLowerCase()}/services/auth_service.dart';

void main(List<String> args) async {
  final parser = ArgParser()
    ..addCommand('create-user')
    ..addCommand('reset-password')
    ..addCommand('grant-admin')
    ..addCommand('list-users')
    ..addCommand('migrate')
    ..addCommand('seed');
    
  final results = parser.parse(args);
  
  if (results.command == null) {
    print('Usage: dart tool/admin.dart <command>');
    print('Commands:');
    print('  create-user      Create a new user');
    print('  reset-password   Reset user password');
    print('  grant-admin      Grant admin role to user');
    print('  list-users       List all users');
    print('  migrate          Run database migrations');
    print('  seed             Seed database with sample data');
    return;
  }
  
  // Load environment
  final env = DotEnv()..load();
  
  // Connect to database
  final connection = PostgreSQLConnection(
    env['DB_HOST'] ?? 'localhost',
    int.parse(env['DB_PORT'] ?? '5432'),
    env['DB_NAME'] ?? 'conduit_db',
    username: env['DB_USER'] ?? 'postgres',
    password: env['DB_PASSWORD'] ?? 'postgres',
  );
  
  await connection.open();
  
  try {
    switch (results.command!.name) {
      case 'create-user':
        await createUser(connection);
        break;
      case 'reset-password':
        await resetPassword(connection);
        break;
      case 'grant-admin':
        await grantAdmin(connection);
        break;
      case 'list-users':
        await listUsers(connection);
        break;
      case 'migrate':
        await runMigrations();
        break;
      case 'seed':
        await seedDatabase(connection);
        break;
    }
  } finally {
    await connection.close();
  }
}

Future<void> createUser(PostgreSQLConnection connection) async {
  stdout.write('Email: ');
  final email = stdin.readLineSync()!;
  
  stdout.write('Name: ');
  final name = stdin.readLineSync()!;
  
  stdout.write('Password: ');
  stdin.echoMode = false;
  final password = stdin.readLineSync()!;
  stdin.echoMode = true;
  print('');
  
  stdout.write('Role (user/admin) [user]: ');
  final role = stdin.readLineSync() ?? 'user';
  
  // Hash password
  final authService = AuthService(null);
  final hashedPassword = authService.hashPassword(password);
  
  // Create user
  await connection.execute(
    '''
    INSERT INTO _user (email, name, "hashedPassword", role, "isActive", "emailVerified", "createdAt", "updatedAt")
    VALUES (@email, @name, @password, @role, true, true, NOW(), NOW())
    ''',
    substitutionValues: {
      'email': email,
      'name': name,
      'password': hashedPassword,
      'role': role,
    },
  );
  
  print('User created successfully!');
}

Future<void> resetPassword(PostgreSQLConnection connection) async {
  stdout.write('Email: ');
  final email = stdin.readLineSync()!;
  
  stdout.write('New password: ');
  stdin.echoMode = false;
  final password = stdin.readLineSync()!;
  stdin.echoMode = true;
  print('');
  
  // Hash password
  final authService = AuthService(null);
  final hashedPassword = authService.hashPassword(password);
  
  // Update user
  final result = await connection.execute(
    '''
    UPDATE _user 
    SET "hashedPassword" = @password, "updatedAt" = NOW()
    WHERE email = @email
    ''',
    substitutionValues: {
      'email': email,
      'password': hashedPassword,
    },
  );
  
  if (result > 0) {
    print('Password reset successfully!');
  } else {
    print('User not found!');
  }
}

Future<void> grantAdmin(PostgreSQLConnection connection) async {
  stdout.write('Email: ');
  final email = stdin.readLineSync()!;
  
  final result = await connection.execute(
    '''
    UPDATE _user 
    SET role = 'admin', "updatedAt" = NOW()
    WHERE email = @email
    ''',
    substitutionValues: {'email': email},
  );
  
  if (result > 0) {
    print('Admin role granted successfully!');
  } else {
    print('User not found!');
  }
}

Future<void> listUsers(PostgreSQLConnection connection) async {
  final results = await connection.query(
    'SELECT id, email, name, role, "isActive", "emailVerified", "createdAt" FROM _user ORDER BY id',
  );
  
  print('Users:');
  print('-' * 80);
  
  for (final row in results) {
    print('ID: \\\${row[0]}');
    print('Email: \\\${row[1]}');
    print('Name: \\\${row[2]}');
    print('Role: \\\${row[3]}');
    print('Active: \\\${row[4]}');
    print('Verified: \\\${row[5]}');
    print('Created: \\\${row[6]}');
    print('-' * 80);
  }
  
  print('Total users: \\\${results.length}');
}

Future<void> runMigrations() async {
  print('Running migrations...');
  
  final process = await Process.start(
    'conduit',
    ['db', 'upgrade', '--connect', 'postgres://postgres:postgres@localhost:5432/conduit_db'],
  );
  
  await stdout.addStream(process.stdout);
  await stderr.addStream(process.stderr);
  
  final exitCode = await process.exitCode;
  
  if (exitCode == 0) {
    print('Migrations completed successfully!');
  } else {
    print('Migration failed with exit code: \\\$exitCode');
  }
}

Future<void> seedDatabase(PostgreSQLConnection connection) async {
  print('Seeding database...');
  
  // Create sample users
  final users = [
    {
      'email': 'john@example.com',
      'name': 'John Doe',
      'password': 'John123!',
      'role': 'user',
    },
    {
      'email': 'jane@example.com',
      'name': 'Jane Smith',
      'password': 'Jane123!',
      'role': 'admin',
    },
    {
      'email': 'bob@example.com',
      'name': 'Bob Wilson',
      'password': 'Bob123!',
      'role': 'user',
    },
  ];
  
  final authService = AuthService(null);
  
  for (final user in users) {
    final hashedPassword = authService.hashPassword(user['password']!);
    
    await connection.execute(
      '''
      INSERT INTO _user (email, name, "hashedPassword", role, "isActive", "emailVerified", "createdAt", "updatedAt")
      VALUES (@email, @name, @password, @role, true, true, NOW(), NOW())
      ON CONFLICT (email) DO NOTHING
      ''',
      substitutionValues: {
        'email': user['email'],
        'name': user['name'],
        'password': hashedPassword,
        'role': user['role'],
      },
    );
  }
  
  print('Database seeded successfully!');
}
`;

    await fs.writeFile(
      path.join(commandsDir, 'admin.dart'),
      adminCliContent
    );
  }

  protected async generateBuildScript(projectPath: string, options: any): Promise<void> {
    await super.generateBuildScript(projectPath, options);

    // Add Conduit-specific scripts
    const scriptsDir = path.join(projectPath, 'scripts');
    await fs.mkdir(scriptsDir, { recursive: true });

    // Development script
    const devScriptContent = `#!/bin/bash

# Development script for Conduit application

set -e

echo "Starting Conduit development server..."

# Check if PostgreSQL is running
if ! pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
  echo "PostgreSQL is not running. Please start PostgreSQL first."
  exit 1
fi

# Load environment variables
export $(cat .env | grep -v '^#' | xargs)

# Run migrations
echo "Running database migrations..."
conduit db upgrade --connect postgres://\$DB_USER:\$DB_PASSWORD@\$DB_HOST:\$DB_PORT/\$DB_NAME

# Generate API documentation
echo "Generating API documentation..."
dart tool/generate_docs.dart

# Start the server with hot reload
echo "Starting server on port \$PORT..."
dart --enable-vm-service bin/main.dart
`;

    await fs.writeFile(
      path.join(scriptsDir, 'dev.sh'),
      devScriptContent
    );

    await fs.chmod(path.join(scriptsDir, 'dev.sh'), 0o755);

    // Production build script
    const prodBuildContent = `#!/bin/bash

# Production build script for Conduit application

set -e

echo "Building Conduit application for production..."

# Clean previous builds
rm -rf build

# Get dependencies
echo "Installing dependencies..."
dart pub get

# Run tests
echo "Running tests..."
dart test

# Analyze code
echo "Analyzing code..."
dart analyze

# Generate API documentation
echo "Generating API documentation..."
dart tool/generate_docs.dart

# Compile to native executable
echo "Compiling to native executable..."
dart compile exe bin/main.dart -o build/server

# Copy necessary files
cp -r config build/
cp -r doc build/
cp .env.example build/.env

echo "Build complete!"
echo "Executable: build/server"
`;

    await fs.writeFile(
      path.join(scriptsDir, 'build.sh'),
      prodBuildContent
    );

    await fs.chmod(path.join(scriptsDir, 'build.sh'), 0o755);
  }

  protected getDockerfileContent(options: any): string {
    return `# Multi-stage Dockerfile for Conduit application

# Build stage
FROM dart:stable AS build

WORKDIR /app

# Copy pubspec files
COPY pubspec.* ./

# Get dependencies
RUN dart pub get

# Copy source code
COPY . .

# Run tests
RUN dart test

# Compile to native executable
RUN dart compile exe bin/main.dart -o bin/server

# Runtime stage
FROM debian:bullseye-slim

# Install required libraries and PostgreSQL client
RUN apt-get update && apt-get install -y \\
    ca-certificates \\
    libssl1.1 \\
    postgresql-client \\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 conduit

WORKDIR /app

# Copy built executable and necessary files
COPY --from=build --chown=conduit:conduit /app/bin/server /app/server
COPY --from=build --chown=conduit:conduit /app/config /app/config
COPY --from=build --chown=conduit:conduit /app/doc /app/doc
COPY --from=build --chown=conduit:conduit /app/migrations /app/migrations

# Create directories for runtime
RUN mkdir -p /app/logs && chown -R conduit:conduit /app

# Switch to non-root user
USER conduit

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:8080/health || exit 1

# Run the server
CMD ["./server"]
`;
  }
}