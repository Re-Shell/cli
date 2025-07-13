/**
 * Shelf Framework Template Generator
 * Composable web server middleware for Dart
 */

import { DartBackendGenerator } from './dart-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class ShelfGenerator extends DartBackendGenerator {
  constructor() {
    super('Shelf');
  }

  protected getFrameworkDependencies(): string[] {
    return [
      'shelf: ^1.4.1',
      'shelf_router: ^1.1.4',
      'shelf_static: ^1.1.2',
      'shelf_cors_headers: ^0.1.5',
      'shelf_helmet: ^2.0.0',
      'shelf_rate_limiter: ^1.0.0',
      'shelf_hotreload: ^1.1.0',
      'args: ^2.4.2',
      'dotenv: ^4.1.0',
      'logger: ^2.0.2',
      'postgres: ^2.6.3',
      'redis: ^3.1.0',
      'dart_jsonwebtoken: ^2.12.0',
      'crypto: ^3.0.3',
      'uuid: ^4.2.2',
      'collection: ^1.18.0',
      'http: ^1.1.2',
      'mime: ^1.0.4',
      'path: ^1.8.3'
    ];
  }

  protected getDevDependencies(): string[] {
    return [
      'http: ^1.1.2',
      'test_process: ^2.1.0',
      'shelf_test_handler: ^2.0.0'
    ];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main server file
    await this.generateMainServer(projectPath, options);

    // Generate app configuration
    await this.generateAppConfig(projectPath);

    // Generate router setup
    await this.generateRouter(projectPath);

    // Generate middleware
    await this.generateMiddleware(projectPath);

    // Generate auth controller
    await this.generateAuthController(projectPath);

    // Generate user controller
    await this.generateUserController(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate services
    await this.generateServices(projectPath);

    // Generate database setup
    await this.generateDatabase(projectPath);

    // Generate utilities
    await this.generateUtilities(projectPath);

    // Generate environment config
    await this.generateEnvConfig(projectPath, options);
  }

  private async generateMainServer(projectPath: string, options: any): Promise<void> {
    const serverContent = `import 'dart:io';
import 'package:args/args.dart';
import 'package:dotenv/dotenv.dart';
import 'package:logger/logger.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_hotreload/shelf_hotreload.dart';

import '../lib/src/app.dart';
import '../lib/src/config/environment.dart';
import '../lib/src/database/database.dart';
import '../lib/src/utils/logger.dart';

final logger = AppLogger.instance;

void main(List<String> arguments) async {
  // Parse command line arguments
  final parser = ArgParser()
    ..addOption('port', abbr: 'p', defaultsTo: '8080')
    ..addOption('address', abbr: 'a', defaultsTo: '0.0.0.0')
    ..addFlag('hot-reload', abbr: 'r', defaultsTo: true);

  final args = parser.parse(arguments);
  
  // Load environment variables
  final env = DotEnv(includePlatformEnvironment: true)..load();
  
  // Initialize environment
  await Environment.initialize(env);
  
  // Initialize database
  await Database.initialize();
  
  // Get server configuration
  final port = int.parse(args['port'] as String);
  final address = args['address'] as String;
  final hotReload = args['hot-reload'] as bool;
  
  // Create the application
  final app = await createApp();
  
  // Start server with or without hot reload
  if (hotReload && Environment.isDevelopment) {
    // Hot reload in development
    withHotreload(
      () => app,
      onReloaded: () => logger.info('🔄 Hot reload complete'),
      onHotReloadError: (error) => logger.error('Hot reload error: \$error'),
    ).then((server) async {
      await serveServer(server, address, port);
    });
  } else {
    // Normal server start
    final handler = const Pipeline()
        .addMiddleware(logRequests())
        .addHandler(app);
    
    await serveServer(handler, address, port);
  }
}

Future<void> serveServer(Handler handler, String address, int port) async {
  final server = await shelf_io.serve(
    handler,
    address,
    port,
    shared: true,
  );
  
  // Enable gzip compression
  server.autoCompress = true;
  
  logger.info('🚀 Server listening on http://\$address:\$port');
  logger.info('🌍 Environment: \${Environment.current}');
  logger.info('📝 API Docs: http://\$address:\$port/docs');
  
  // Graceful shutdown
  ProcessSignal.sigterm.watch().listen((_) async {
    logger.info('SIGTERM received, shutting down gracefully...');
    await shutdown(server);
  });
  
  ProcessSignal.sigint.watch().listen((_) async {
    logger.info('SIGINT received, shutting down gracefully...');
    await shutdown(server);
  });
}

Future<void> shutdown(HttpServer server) async {
  logger.info('Closing server...');
  await server.close(force: true);
  
  logger.info('Closing database connections...');
  await Database.close();
  
  logger.info('Shutdown complete');
  exit(0);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'bin/server.dart'),
      serverContent
    );
  }

  private async generateAppConfig(projectPath: string): Promise<void> {
    const appContent = `import 'package:shelf/shelf.dart';
import 'package:shelf_cors_headers/shelf_cors_headers.dart';
import 'package:shelf_helmet/shelf_helmet.dart';
import 'package:shelf_rate_limiter/shelf_rate_limiter.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:shelf_static/shelf_static.dart';

import 'middleware/error_handler.dart';
import 'middleware/auth_middleware.dart';
import 'middleware/logging_middleware.dart';
import 'middleware/validation_middleware.dart';
import 'routes/router.dart';
import 'utils/logger.dart';

/// Creates and configures the Shelf application
Future<Handler> createApp() async {
  final router = createRouter();
  
  // Configure CORS
  final corsHeaders = {
    ACCESS_CONTROL_ALLOW_ORIGIN: '*',
    ACCESS_CONTROL_ALLOW_METHODS: 'GET, POST, PUT, DELETE, OPTIONS',
    ACCESS_CONTROL_ALLOW_HEADERS: 'Origin, Content-Type, Accept, Authorization',
    ACCESS_CONTROL_MAX_AGE: '86400',
  };
  
  // Configure rate limiting
  final memoryStorage = MemStorage();
  final rateLimiter = ShelfRateLimiter(
    storage: memoryStorage,
    duration: const Duration(minutes: 1),
    maxRequests: 60,
  );
  
  // Build middleware pipeline
  final handler = const Pipeline()
      // Security headers
      .addMiddleware(helmet())
      
      // CORS
      .addMiddleware(corsHeaders())
      
      // Rate limiting
      .addMiddleware(rateLimiter.rateLimiter())
      
      // Custom middleware
      .addMiddleware(errorHandler())
      .addMiddleware(loggingMiddleware())
      
      // Routes
      .addHandler(router);
  
  return handler;
}

/// Creates a fallback handler for undefined routes
Handler _notFoundHandler() {
  return (Request request) {
    return Response.notFound(
      '{"error": {"code": "NOT_FOUND", "message": "Route not found"}}',
      headers: {'Content-Type': 'application/json'},
    );
  };
}

/// Serve static files
Handler createStaticHandler() {
  return createStaticFileHandler(
    'public',
    defaultDocument: 'index.html',
    listDirectories: false,
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/app.dart'),
      appContent
    );
  }

  private async generateRouter(projectPath: string): Promise<void> {
    const routerContent = `import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';

import '../controllers/health_controller.dart';
import '../controllers/auth_controller.dart';
import '../controllers/user_controller.dart';
import '../middleware/auth_middleware.dart';
import '../utils/swagger_generator.dart';

/// Creates and configures all application routes
Router createRouter() {
  final router = Router();
  
  // Health check routes
  router.get('/health', HealthController.health);
  router.get('/ready', HealthController.ready);
  router.get('/live', HealthController.live);
  
  // API documentation
  router.get('/docs', (Request request) async {
    return Response.ok(
      SwaggerGenerator.generateHTML(),
      headers: {'Content-Type': 'text/html'},
    );
  });
  
  router.get('/openapi.json', (Request request) async {
    return Response.ok(
      SwaggerGenerator.generateSpec(),
      headers: {'Content-Type': 'application/json'},
    );
  });
  
  // API routes
  router.mount('/api/v1/', _createApiRouter());
  
  // Fallback for undefined routes
  router.all('/<ignored|.*>', (Request request) {
    return Response.notFound(
      '{"error": {"code": "NOT_FOUND", "message": "Route not found"}}',
      headers: {'Content-Type': 'application/json'},
    );
  });
  
  return router;
}

/// Creates API v1 routes
Router _createApiRouter() {
  final api = Router();
  
  // Public auth routes
  api.post('/auth/register', AuthController.register);
  api.post('/auth/login', AuthController.login);
  api.post('/auth/refresh', AuthController.refresh);
  api.post('/auth/forgot-password', AuthController.forgotPassword);
  api.post('/auth/reset-password', AuthController.resetPassword);
  api.get('/auth/verify/<token>', AuthController.verifyEmail);
  
  // Protected routes
  final protected = const Pipeline()
      .addMiddleware(authMiddleware())
      .addHandler(_createProtectedRouter());
  
  api.mount('/', protected);
  
  return api;
}

/// Creates protected routes that require authentication
Router _createProtectedRouter() {
  final router = Router();
  
  // Auth routes
  router.post('/auth/logout', AuthController.logout);
  router.post('/auth/change-password', AuthController.changePassword);
  
  // User routes
  router.get('/users/me', UserController.getCurrentUser);
  router.put('/users/me', UserController.updateCurrentUser);
  router.delete('/users/me', UserController.deleteCurrentUser);
  router.get('/users', UserController.listUsers);
  router.get('/users/<id>', UserController.getUser);
  
  // Admin routes
  router.mount('/admin/', _createAdminRouter());
  
  return router;
}

/// Creates admin routes that require admin privileges
Router _createAdminRouter() {
  final router = Router();
  
  // Apply admin middleware to all routes
  final adminPipeline = const Pipeline()
      .addMiddleware(adminMiddleware())
      .addHandler((Request request) async {
        final adminRouter = Router();
        
        // User management
        adminRouter.get('/users', UserController.listAllUsers);
        adminRouter.put('/users/<id>', UserController.updateUser);
        adminRouter.delete('/users/<id>', UserController.deleteUser);
        adminRouter.post('/users/<id>/activate', UserController.activateUser);
        adminRouter.post('/users/<id>/deactivate', UserController.deactivateUser);
        
        // System management
        adminRouter.get('/stats', (Request r) async {
          return Response.ok(
            '{"users": 100, "requests": 1000}',
            headers: {'Content-Type': 'application/json'},
          );
        });
        
        return adminRouter(request);
      });
  
  router.all('/<ignored|.*>', adminPipeline);
  
  return router;
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/routes/router.dart'),
      routerContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    // Error handler middleware
    const errorHandlerContent = `import 'dart:convert';
import 'dart:io';
import 'package:shelf/shelf.dart';
import '../utils/logger.dart';
import '../utils/exceptions.dart';

/// Middleware to handle errors and exceptions
Middleware errorHandler() {
  return (Handler innerHandler) {
    return (Request request) async {
      try {
        final response = await innerHandler(request);
        return response;
      } on ValidationException catch (e) {
        return Response(
          HttpStatus.badRequest,
          body: jsonEncode({
            'error': {
              'code': 'VALIDATION_ERROR',
              'message': e.message,
              'details': e.details,
            }
          }),
          headers: {'Content-Type': 'application/json'},
        );
      } on AuthenticationException catch (e) {
        return Response(
          HttpStatus.unauthorized,
          body: jsonEncode({
            'error': {
              'code': 'AUTHENTICATION_ERROR',
              'message': e.message,
            }
          }),
          headers: {'Content-Type': 'application/json'},
        );
      } on AuthorizationException catch (e) {
        return Response(
          HttpStatus.forbidden,
          body: jsonEncode({
            'error': {
              'code': 'AUTHORIZATION_ERROR',
              'message': e.message,
            }
          }),
          headers: {'Content-Type': 'application/json'},
        );
      } on NotFoundException catch (e) {
        return Response(
          HttpStatus.notFound,
          body: jsonEncode({
            'error': {
              'code': 'NOT_FOUND',
              'message': e.message,
            }
          }),
          headers: {'Content-Type': 'application/json'},
        );
      } on ConflictException catch (e) {
        return Response(
          HttpStatus.conflict,
          body: jsonEncode({
            'error': {
              'code': 'CONFLICT',
              'message': e.message,
            }
          }),
          headers: {'Content-Type': 'application/json'},
        );
      } on RateLimitException catch (e) {
        return Response(
          429, // Too Many Requests
          body: jsonEncode({
            'error': {
              'code': 'RATE_LIMIT_ERROR',
              'message': e.message,
            }
          }),
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': e.retryAfter.toString(),
          },
        );
      } catch (e, stackTrace) {
        // Log unexpected errors
        AppLogger.instance.error(
          'Unhandled error in request \${request.method} \${request.url.path}',
          error: e,
          stackTrace: stackTrace,
        );
        
        // Don't expose internal errors in production
        final message = Environment.isProduction
            ? 'An unexpected error occurred'
            : e.toString();
        
        return Response(
          HttpStatus.internalServerError,
          body: jsonEncode({
            'error': {
              'code': 'INTERNAL_ERROR',
              'message': message,
            }
          }),
          headers: {'Content-Type': 'application/json'},
        );
      }
    };
  };
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/middleware/error_handler.dart'),
      errorHandlerContent
    );

    // Logging middleware
    const loggingMiddlewareContent = `import 'package:shelf/shelf.dart';
import '../utils/logger.dart';

/// Middleware for request/response logging
Middleware loggingMiddleware() {
  return (Handler innerHandler) {
    return (Request request) async {
      final stopwatch = Stopwatch()..start();
      final method = request.method;
      final path = request.url.path;
      final query = request.url.query.isNotEmpty ? '?\${request.url.query}' : '';
      
      Response response;
      try {
        response = await innerHandler(request);
      } catch (e) {
        stopwatch.stop();
        AppLogger.instance.error(
          '\$method \$path\$query - ERROR (\${stopwatch.elapsedMilliseconds}ms)',
          error: e,
        );
        rethrow;
      }
      
      stopwatch.stop();
      final duration = stopwatch.elapsedMilliseconds;
      final statusCode = response.statusCode;
      final level = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'info';
      
      final message = '\$method \$path\$query - \$statusCode (\${duration}ms)';
      
      switch (level) {
        case 'error':
          AppLogger.instance.error(message);
          break;
        case 'warning':
          AppLogger.instance.warning(message);
          break;
        default:
          AppLogger.instance.info(message);
      }
      
      // Add request ID header for tracing
      final requestId = request.headers['x-request-id'] ?? _generateRequestId();
      return response.change(headers: {'x-request-id': requestId});
    };
  };
}

String _generateRequestId() {
  return DateTime.now().millisecondsSinceEpoch.toString();
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/middleware/logging_middleware.dart'),
      loggingMiddlewareContent
    );

    // Auth middleware
    const authMiddlewareContent = `import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import '../config/environment.dart';
import '../models/user.dart';
import '../services/user_service.dart';
import '../utils/exceptions.dart';

/// Middleware for JWT authentication
Middleware authMiddleware() {
  return (Handler innerHandler) {
    return (Request request) async {
      // Extract token from Authorization header
      final authHeader = request.headers['authorization'];
      if (authHeader == null || !authHeader.startsWith('Bearer ')) {
        throw AuthenticationException('Missing or invalid authorization header');
      }
      
      final token = authHeader.substring(7); // Remove 'Bearer ' prefix
      
      try {
        // Verify JWT token
        final jwt = JWT.verify(
          token,
          SecretKey(Environment.jwtSecret),
          audience: Audience([Environment.jwtAudience]),
          issuer: Environment.jwtIssuer,
        );
        
        // Extract user ID from payload
        final payload = jwt.payload as Map<String, dynamic>;
        final userId = payload['sub'] as String?;
        
        if (userId == null) {
          throw AuthenticationException('Invalid token payload');
        }
        
        // Load user from database
        final userService = UserService.instance;
        final user = await userService.findById(userId);
        
        if (user == null || !user.isActive) {
          throw AuthenticationException('User not found or inactive');
        }
        
        // Add user to request context
        final updatedRequest = request.change(context: {
          'user': user,
          'userId': userId,
          'token': token,
        });
        
        return await innerHandler(updatedRequest);
      } on JWTExpiredException {
        throw AuthenticationException('Token has expired');
      } on JWTException catch (e) {
        throw AuthenticationException('Invalid token: \${e.message}');
      }
    };
  };
}

/// Middleware for admin authorization
Middleware adminMiddleware() {
  return (Handler innerHandler) {
    return (Request request) async {
      final user = request.context['user'] as User?;
      
      if (user == null) {
        throw AuthenticationException('User not authenticated');
      }
      
      if (!user.isAdmin) {
        throw AuthorizationException('Admin access required');
      }
      
      return await innerHandler(request);
    };
  };
}

/// Extension to get authenticated user from request
extension AuthenticatedRequest on Request {
  User? get user => context['user'] as User?;
  String? get userId => context['userId'] as String?;
  String? get token => context['token'] as String?;
  
  User get requiredUser {
    final user = this.user;
    if (user == null) {
      throw AuthenticationException('User not authenticated');
    }
    return user;
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/middleware/auth_middleware.dart'),
      authMiddlewareContent
    );

    // Validation middleware
    const validationMiddlewareContent = `import 'dart:convert';
import 'package:shelf/shelf.dart';
import '../utils/exceptions.dart';

/// Middleware for request validation
Middleware validationMiddleware() {
  return (Handler innerHandler) {
    return (Request request) async {
      // Validate content type for POST/PUT requests
      if (request.method == 'POST' || request.method == 'PUT') {
        final contentType = request.headers['content-type'];
        if (contentType == null || !contentType.contains('application/json')) {
          throw ValidationException(
            'Content-Type must be application/json',
            details: {'content-type': 'Invalid or missing Content-Type header'},
          );
        }
      }
      
      // Validate request body size
      final contentLength = request.headers['content-length'];
      if (contentLength != null) {
        final length = int.tryParse(contentLength);
        if (length != null && length > 1024 * 1024) { // 1MB limit
          throw ValidationException(
            'Request body too large',
            details: {'content-length': 'Maximum allowed size is 1MB'},
          );
        }
      }
      
      return await innerHandler(request);
    };
  };
}

/// Helper to parse and validate JSON body
Future<Map<String, dynamic>> parseJsonBody(Request request) async {
  try {
    final body = await request.readAsString();
    if (body.isEmpty) {
      throw ValidationException('Request body is empty');
    }
    
    final json = jsonDecode(body);
    if (json is! Map<String, dynamic>) {
      throw ValidationException('Request body must be a JSON object');
    }
    
    return json;
  } on FormatException {
    throw ValidationException('Invalid JSON in request body');
  }
}

/// Validates required fields in a map
void validateRequired(
  Map<String, dynamic> data,
  List<String> requiredFields,
) {
  final missing = <String>[];
  
  for (final field in requiredFields) {
    if (!data.containsKey(field) || data[field] == null) {
      missing.add(field);
    }
  }
  
  if (missing.isNotEmpty) {
    throw ValidationException(
      'Missing required fields',
      details: {
        for (final field in missing) field: 'This field is required',
      },
    );
  }
}

/// Validates email format
bool isValidEmail(String email) {
  final emailRegex = RegExp(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
  );
  return emailRegex.hasMatch(email);
}

/// Validates password strength
bool isValidPassword(String password) {
  return password.length >= 8;
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/middleware/validation_middleware.dart'),
      validationMiddlewareContent
    );
  }

  private async generateAuthController(projectPath: string): Promise<void> {
    const authControllerContent = `import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';

import '../middleware/validation_middleware.dart';
import '../middleware/auth_middleware.dart';
import '../models/user.dart';
import '../services/user_service.dart';
import '../services/email_service.dart';
import '../services/redis_service.dart';
import '../config/environment.dart';
import '../utils/exceptions.dart';

/// Handles authentication-related requests
class AuthController {
  static final _userService = UserService.instance;
  static final _emailService = EmailService.instance;
  static final _redisService = RedisService.instance;
  static final _uuid = Uuid();
  
  /// POST /api/v1/auth/register
  static Future<Response> register(Request request) async {
    final body = await parseJsonBody(request);
    
    // Validate required fields
    validateRequired(body, ['email', 'password', 'name']);
    
    final email = body['email'] as String;
    final password = body['password'] as String;
    final name = body['name'] as String;
    
    // Validate email format
    if (!isValidEmail(email)) {
      throw ValidationException(
        'Invalid email format',
        details: {'email': 'Please provide a valid email address'},
      );
    }
    
    // Validate password strength
    if (!isValidPassword(password)) {
      throw ValidationException(
        'Password too weak',
        details: {'password': 'Password must be at least 8 characters long'},
      );
    }
    
    // Check if user exists
    final existingUser = await _userService.findByEmail(email);
    if (existingUser != null) {
      throw ConflictException('Email already registered');
    }
    
    // Create user
    final passwordHash = _hashPassword(password);
    final user = User(
      id: _uuid.v4(),
      email: email.toLowerCase(),
      passwordHash: passwordHash,
      name: name,
      isActive: true,
      isAdmin: false,
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
    );
    
    await _userService.create(user);
    
    // Send verification email
    final verificationToken = _uuid.v4();
    await _redisService.setex(
      'email_verification:\$verificationToken',
      user.id,
      Duration(hours: 24).inSeconds,
    );
    
    await _emailService.sendVerificationEmail(
      email: user.email,
      name: user.name,
      token: verificationToken,
    );
    
    // Generate tokens
    final authResponse = _generateAuthResponse(user);
    
    return Response(
      201,
      body: jsonEncode(authResponse),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// POST /api/v1/auth/login
  static Future<Response> login(Request request) async {
    final body = await parseJsonBody(request);
    
    // Validate required fields
    validateRequired(body, ['email', 'password']);
    
    final email = body['email'] as String;
    final password = body['password'] as String;
    
    // Find user
    final user = await _userService.findByEmail(email.toLowerCase());
    if (user == null) {
      throw AuthenticationException('Invalid credentials');
    }
    
    // Verify password
    if (!_verifyPassword(password, user.passwordHash)) {
      throw AuthenticationException('Invalid credentials');
    }
    
    // Check if active
    if (!user.isActive) {
      throw AuthenticationException('Account is deactivated');
    }
    
    // Update last login
    user.lastLoginAt = DateTime.now();
    await _userService.update(user);
    
    // Generate tokens
    final authResponse = _generateAuthResponse(user);
    
    return Response.ok(
      jsonEncode(authResponse),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// POST /api/v1/auth/refresh
  static Future<Response> refresh(Request request) async {
    final body = await parseJsonBody(request);
    
    // Validate required fields
    validateRequired(body, ['refreshToken']);
    
    final refreshToken = body['refreshToken'] as String;
    
    // Verify refresh token
    final userId = await _redisService.get('refresh_token:\$refreshToken');
    if (userId == null) {
      throw AuthenticationException('Invalid refresh token');
    }
    
    // Get user
    final user = await _userService.findById(userId);
    if (user == null || !user.isActive) {
      throw AuthenticationException('User not found or inactive');
    }
    
    // Delete old refresh token
    await _redisService.delete('refresh_token:\$refreshToken');
    
    // Generate new tokens
    final authResponse = _generateAuthResponse(user);
    
    return Response.ok(
      jsonEncode(authResponse),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// POST /api/v1/auth/logout
  static Future<Response> logout(Request request) async {
    final token = request.token;
    if (token != null) {
      // Add token to blacklist
      await _redisService.setex(
        'token_blacklist:\$token',
        '1',
        Duration(hours: 24).inSeconds,
      );
    }
    
    return Response(
      204, // No Content
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// POST /api/v1/auth/forgot-password
  static Future<Response> forgotPassword(Request request) async {
    final body = await parseJsonBody(request);
    
    // Validate required fields
    validateRequired(body, ['email']);
    
    final email = body['email'] as String;
    
    // Find user (don't reveal if not found)
    final user = await _userService.findByEmail(email.toLowerCase());
    
    if (user != null) {
      // Generate reset token
      final resetToken = _uuid.v4();
      await _redisService.setex(
        'password_reset:\$resetToken',
        user.id,
        Duration(hours: 1).inSeconds,
      );
      
      // Send email
      await _emailService.sendPasswordResetEmail(
        email: user.email,
        name: user.name,
        token: resetToken,
      );
    }
    
    // Always return success (security best practice)
    return Response.ok(
      jsonEncode({
        'message': 'If the email exists, a reset link has been sent',
      }),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// POST /api/v1/auth/reset-password
  static Future<Response> resetPassword(Request request) async {
    final body = await parseJsonBody(request);
    
    // Validate required fields
    validateRequired(body, ['token', 'newPassword']);
    
    final token = body['token'] as String;
    final newPassword = body['newPassword'] as String;
    
    // Validate password strength
    if (!isValidPassword(newPassword)) {
      throw ValidationException(
        'Password too weak',
        details: {'newPassword': 'Password must be at least 8 characters long'},
      );
    }
    
    // Verify token
    final userId = await _redisService.get('password_reset:\$token');
    if (userId == null) {
      throw ValidationException('Invalid or expired reset token');
    }
    
    // Get user
    final user = await _userService.findById(userId);
    if (user == null) {
      throw ValidationException('Invalid or expired reset token');
    }
    
    // Update password
    user.passwordHash = _hashPassword(newPassword);
    user.updatedAt = DateTime.now();
    await _userService.update(user);
    
    // Delete reset token
    await _redisService.delete('password_reset:\$token');
    
    // Send confirmation email
    await _emailService.sendPasswordChangedEmail(
      email: user.email,
      name: user.name,
    );
    
    return Response.ok(
      jsonEncode({
        'message': 'Password reset successful',
      }),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// GET /api/v1/auth/verify/:token
  static Future<Response> verifyEmail(Request request, String token) async {
    // Get user ID from token
    final userId = await _redisService.get('email_verification:\$token');
    if (userId == null) {
      throw ValidationException('Invalid or expired verification token');
    }
    
    // Get user
    final user = await _userService.findById(userId);
    if (user == null) {
      throw ValidationException('Invalid or expired verification token');
    }
    
    // Update user
    user.emailVerifiedAt = DateTime.now();
    user.updatedAt = DateTime.now();
    await _userService.update(user);
    
    // Delete verification token
    await _redisService.delete('email_verification:\$token');
    
    return Response.ok(
      jsonEncode({
        'message': 'Email verified successfully',
      }),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// POST /api/v1/auth/change-password
  static Future<Response> changePassword(Request request) async {
    final user = request.requiredUser;
    final body = await parseJsonBody(request);
    
    // Validate required fields
    validateRequired(body, ['currentPassword', 'newPassword']);
    
    final currentPassword = body['currentPassword'] as String;
    final newPassword = body['newPassword'] as String;
    
    // Verify current password
    if (!_verifyPassword(currentPassword, user.passwordHash)) {
      throw ValidationException('Current password is incorrect');
    }
    
    // Validate new password
    if (!isValidPassword(newPassword)) {
      throw ValidationException(
        'Password too weak',
        details: {'newPassword': 'Password must be at least 8 characters long'},
      );
    }
    
    // Update password
    user.passwordHash = _hashPassword(newPassword);
    user.updatedAt = DateTime.now();
    await _userService.update(user);
    
    // Send notification email
    await _emailService.sendPasswordChangedEmail(
      email: user.email,
      name: user.name,
    );
    
    return Response.ok(
      jsonEncode({
        'message': 'Password changed successfully',
      }),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  // Helper methods
  
  static String _hashPassword(String password) {
    final bytes = utf8.encode(password + Environment.passwordSalt);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }
  
  static bool _verifyPassword(String password, String hash) {
    return _hashPassword(password) == hash;
  }
  
  static Map<String, dynamic> _generateAuthResponse(User user) {
    final token = _generateJWT(user);
    final refreshToken = _uuid.v4();
    
    // Store refresh token
    _redisService.setex(
      'refresh_token:\$refreshToken',
      user.id,
      Duration(days: 30).inSeconds,
    );
    
    return {
      'user': user.toPublicJson(),
      'token': token,
      'refreshToken': refreshToken,
      'expiresIn': 86400, // 24 hours
    };
  }
  
  static String _generateJWT(User user) {
    final jwt = JWT(
      {
        'sub': user.id,
        'email': user.email,
        'name': user.name,
        'isAdmin': user.isAdmin,
        'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
        'exp': DateTime.now().add(Duration(hours: 24)).millisecondsSinceEpoch ~/ 1000,
      },
      audience: Audience([Environment.jwtAudience]),
      issuer: Environment.jwtIssuer,
    );
    
    return jwt.sign(SecretKey(Environment.jwtSecret));
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/controllers/auth_controller.dart'),
      authControllerContent
    );
  }

  private async generateUserController(projectPath: string): Promise<void> {
    const userControllerContent = `import 'dart:convert';
import 'package:shelf/shelf.dart';

import '../middleware/validation_middleware.dart';
import '../middleware/auth_middleware.dart';
import '../models/user.dart';
import '../services/user_service.dart';
import '../utils/exceptions.dart';
import '../utils/pagination.dart';

/// Handles user-related requests
class UserController {
  static final _userService = UserService.instance;
  
  /// GET /api/v1/users/me
  static Future<Response> getCurrentUser(Request request) async {
    final user = request.requiredUser;
    
    return Response.ok(
      jsonEncode(user.toPublicJson()),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// PUT /api/v1/users/me
  static Future<Response> updateCurrentUser(Request request) async {
    final user = request.requiredUser;
    final body = await parseJsonBody(request);
    
    // Update allowed fields
    if (body.containsKey('name')) {
      final name = body['name'] as String;
      if (name.isEmpty || name.length < 2) {
        throw ValidationException(
          'Invalid name',
          details: {'name': 'Name must be at least 2 characters long'},
        );
      }
      user.name = name;
    }
    
    if (body.containsKey('avatarUrl')) {
      user.avatarUrl = body['avatarUrl'] as String?;
    }
    
    user.updatedAt = DateTime.now();
    await _userService.update(user);
    
    return Response.ok(
      jsonEncode(user.toPublicJson()),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// DELETE /api/v1/users/me
  static Future<Response> deleteCurrentUser(Request request) async {
    final user = request.requiredUser;
    
    // Soft delete - deactivate user
    user.isActive = false;
    user.updatedAt = DateTime.now();
    await _userService.update(user);
    
    return Response(
      204, // No Content
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// GET /api/v1/users
  static Future<Response> listUsers(Request request) async {
    final pagination = PaginationParams.fromRequest(request);
    final search = request.url.queryParameters['search'];
    
    final result = await _userService.list(
      pagination: pagination,
      search: search,
      activeOnly: true,
    );
    
    final response = {
      'data': result.items.map((user) => user.toPublicJson()).toList(),
      'pagination': result.pagination.toJson(),
    };
    
    return Response.ok(
      jsonEncode(response),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// GET /api/v1/users/:id
  static Future<Response> getUser(Request request, String id) async {
    final user = await _userService.findById(id);
    
    if (user == null || !user.isActive) {
      throw NotFoundException('User not found');
    }
    
    return Response.ok(
      jsonEncode(user.toPublicJson()),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  // Admin endpoints
  
  /// GET /api/v1/admin/users
  static Future<Response> listAllUsers(Request request) async {
    final pagination = PaginationParams.fromRequest(request);
    final search = request.url.queryParameters['search'];
    final status = request.url.queryParameters['status']; // active, inactive, all
    
    final result = await _userService.list(
      pagination: pagination,
      search: search,
      activeOnly: status == 'active' ? true : status == 'inactive' ? false : null,
    );
    
    final response = {
      'data': result.items.map((user) => user.toAdminJson()).toList(),
      'pagination': result.pagination.toJson(),
    };
    
    return Response.ok(
      jsonEncode(response),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// PUT /api/v1/admin/users/:id
  static Future<Response> updateUser(Request request, String id) async {
    final body = await parseJsonBody(request);
    
    final user = await _userService.findById(id);
    if (user == null) {
      throw NotFoundException('User not found');
    }
    
    // Update allowed fields
    if (body.containsKey('name')) {
      user.name = body['name'] as String;
    }
    
    if (body.containsKey('isActive')) {
      user.isActive = body['isActive'] as bool;
    }
    
    if (body.containsKey('isAdmin')) {
      user.isAdmin = body['isAdmin'] as bool;
    }
    
    user.updatedAt = DateTime.now();
    await _userService.update(user);
    
    return Response.ok(
      jsonEncode(user.toAdminJson()),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// DELETE /api/v1/admin/users/:id
  static Future<Response> deleteUser(Request request, String id) async {
    final user = await _userService.findById(id);
    if (user == null) {
      throw NotFoundException('User not found');
    }
    
    // Prevent self-deletion
    if (user.id == request.userId) {
      throw ValidationException('Cannot delete your own account');
    }
    
    await _userService.delete(id);
    
    return Response(
      204, // No Content
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// POST /api/v1/admin/users/:id/activate
  static Future<Response> activateUser(Request request, String id) async {
    final user = await _userService.findById(id);
    if (user == null) {
      throw NotFoundException('User not found');
    }
    
    user.isActive = true;
    user.updatedAt = DateTime.now();
    await _userService.update(user);
    
    return Response.ok(
      jsonEncode({
        'message': 'User activated successfully',
        'user': user.toAdminJson(),
      }),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// POST /api/v1/admin/users/:id/deactivate
  static Future<Response> deactivateUser(Request request, String id) async {
    final user = await _userService.findById(id);
    if (user == null) {
      throw NotFoundException('User not found');
    }
    
    // Prevent self-deactivation
    if (user.id == request.userId) {
      throw ValidationException('Cannot deactivate your own account');
    }
    
    user.isActive = false;
    user.updatedAt = DateTime.now();
    await _userService.update(user);
    
    return Response.ok(
      jsonEncode({
        'message': 'User deactivated successfully',
        'user': user.toAdminJson(),
      }),
      headers: {'Content-Type': 'application/json'},
    );
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/controllers/user_controller.dart'),
      userControllerContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    const userModelContent = `import 'package:collection/collection.dart';

/// User model
class User {
  final String id;
  String email;
  String passwordHash;
  String name;
  String? avatarUrl;
  bool isActive;
  bool isAdmin;
  DateTime? emailVerifiedAt;
  DateTime? lastLoginAt;
  final DateTime createdAt;
  DateTime updatedAt;
  
  User({
    required this.id,
    required this.email,
    required this.passwordHash,
    required this.name,
    this.avatarUrl,
    required this.isActive,
    required this.isAdmin,
    this.emailVerifiedAt,
    this.lastLoginAt,
    required this.createdAt,
    required this.updatedAt,
  });
  
  /// Create User from database row
  factory User.fromJson(Map<String, dynamic> json) {
    return User(
      id: json['id'] as String,
      email: json['email'] as String,
      passwordHash: json['password_hash'] as String,
      name: json['name'] as String,
      avatarUrl: json['avatar_url'] as String?,
      isActive: json['is_active'] as bool,
      isAdmin: json['is_admin'] as bool,
      emailVerifiedAt: json['email_verified_at'] != null
          ? DateTime.parse(json['email_verified_at'] as String)
          : null,
      lastLoginAt: json['last_login_at'] != null
          ? DateTime.parse(json['last_login_at'] as String)
          : null,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
    );
  }
  
  /// Convert User to database row
  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'email': email,
      'password_hash': passwordHash,
      'name': name,
      'avatar_url': avatarUrl,
      'is_active': isActive,
      'is_admin': isAdmin,
      'email_verified_at': emailVerifiedAt?.toIso8601String(),
      'last_login_at': lastLoginAt?.toIso8601String(),
      'created_at': createdAt.toIso8601String(),
      'updated_at': updatedAt.toIso8601String(),
    };
  }
  
  /// Convert to public JSON (no sensitive data)
  Map<String, dynamic> toPublicJson() {
    return {
      'id': id,
      'email': email,
      'name': name,
      'avatarUrl': avatarUrl,
      'isVerified': emailVerifiedAt != null,
      'createdAt': createdAt.toIso8601String(),
    };
  }
  
  /// Convert to admin JSON (includes more fields)
  Map<String, dynamic> toAdminJson() {
    return {
      'id': id,
      'email': email,
      'name': name,
      'avatarUrl': avatarUrl,
      'isActive': isActive,
      'isAdmin': isAdmin,
      'isVerified': emailVerifiedAt != null,
      'emailVerifiedAt': emailVerifiedAt?.toIso8601String(),
      'lastLoginAt': lastLoginAt?.toIso8601String(),
      'createdAt': createdAt.toIso8601String(),
      'updatedAt': updatedAt.toIso8601String(),
    };
  }
  
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is User &&
          runtimeType == other.runtimeType &&
          id == other.id;
  
  @override
  int get hashCode => id.hashCode;
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/models/user.dart'),
      userModelContent
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    // User service
    const userServiceContent = `import 'package:postgres/postgres.dart';
import '../database/database.dart';
import '../models/user.dart';
import '../utils/pagination.dart';

/// Service for user-related operations
class UserService {
  static final UserService _instance = UserService._internal();
  static UserService get instance => _instance;
  
  UserService._internal();
  
  /// Find user by ID
  Future<User?> findById(String id) async {
    final result = await Database.connection.execute(
      Sql.named('SELECT * FROM users WHERE id = @id'),
      parameters: {'id': id},
    );
    
    if (result.isEmpty) {
      return null;
    }
    
    return User.fromJson(result.first.toColumnMap());
  }
  
  /// Find user by email
  Future<User?> findByEmail(String email) async {
    final result = await Database.connection.execute(
      Sql.named('SELECT * FROM users WHERE LOWER(email) = LOWER(@email)'),
      parameters: {'email': email},
    );
    
    if (result.isEmpty) {
      return null;
    }
    
    return User.fromJson(result.first.toColumnMap());
  }
  
  /// Create new user
  Future<void> create(User user) async {
    await Database.connection.execute(
      Sql.named('''
        INSERT INTO users (
          id, email, password_hash, name, avatar_url,
          is_active, is_admin, email_verified_at, last_login_at,
          created_at, updated_at
        ) VALUES (
          @id, @email, @password_hash, @name, @avatar_url,
          @is_active, @is_admin, @email_verified_at, @last_login_at,
          @created_at, @updated_at
        )
      '''),
      parameters: user.toJson(),
    );
  }
  
  /// Update existing user
  Future<void> update(User user) async {
    await Database.connection.execute(
      Sql.named('''
        UPDATE users SET
          email = @email,
          password_hash = @password_hash,
          name = @name,
          avatar_url = @avatar_url,
          is_active = @is_active,
          is_admin = @is_admin,
          email_verified_at = @email_verified_at,
          last_login_at = @last_login_at,
          updated_at = @updated_at
        WHERE id = @id
      '''),
      parameters: user.toJson(),
    );
  }
  
  /// Delete user
  Future<void> delete(String id) async {
    await Database.connection.execute(
      Sql.named('DELETE FROM users WHERE id = @id'),
      parameters: {'id': id},
    );
  }
  
  /// List users with pagination
  Future<PaginatedResult<User>> list({
    required PaginationParams pagination,
    String? search,
    bool? activeOnly,
  }) async {
    // Build WHERE clause
    final conditions = <String>[];
    final parameters = <String, dynamic>{};
    
    if (search != null && search.isNotEmpty) {
      conditions.add('(LOWER(name) LIKE @search OR LOWER(email) LIKE @search)');
      parameters['search'] = '%\${search.toLowerCase()}%';
    }
    
    if (activeOnly != null) {
      conditions.add('is_active = @is_active');
      parameters['is_active'] = activeOnly;
    }
    
    final whereClause = conditions.isEmpty ? '' : 'WHERE \${conditions.join(' AND ')}';
    
    // Count total
    final countResult = await Database.connection.execute(
      Sql.named('SELECT COUNT(*) as total FROM users \$whereClause'),
      parameters: parameters,
    );
    
    final total = countResult.first.toColumnMap()['total'] as int;
    
    // Get paginated results
    parameters['limit'] = pagination.limit;
    parameters['offset'] = pagination.offset;
    
    final result = await Database.connection.execute(
      Sql.named('''
        SELECT * FROM users
        \$whereClause
        ORDER BY \${pagination.sortBy} \${pagination.sortOrder}
        LIMIT @limit OFFSET @offset
      '''),
      parameters: parameters,
    );
    
    final users = result.map((row) => User.fromJson(row.toColumnMap())).toList();
    
    return PaginatedResult(
      items: users,
      pagination: pagination.withTotal(total),
    );
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/services/user_service.dart'),
      userServiceContent
    );

    // Email service
    const emailServiceContent = `import 'dart:io';
import '../config/environment.dart';
import '../utils/logger.dart';

/// Service for sending emails
class EmailService {
  static final EmailService _instance = EmailService._internal();
  static EmailService get instance => _instance;
  
  EmailService._internal();
  
  final _logger = AppLogger.instance;
  
  /// Send verification email
  Future<void> sendVerificationEmail({
    required String email,
    required String name,
    required String token,
  }) async {
    final verifyUrl = '\${Environment.appUrl}/auth/verify/\$token';
    
    await _sendEmail(
      to: email,
      subject: 'Verify your email address',
      html: '''
        <h2>Hello \$name,</h2>
        <p>Thank you for registering! Please verify your email address by clicking the link below:</p>
        <p><a href="\$verifyUrl">Verify Email</a></p>
        <p>Or copy and paste this URL into your browser:</p>
        <p>\$verifyUrl</p>
        <p>This link will expire in 24 hours.</p>
        <p>Best regards,<br>The Team</p>
      ''',
    );
  }
  
  /// Send password reset email
  Future<void> sendPasswordResetEmail({
    required String email,
    required String name,
    required String token,
  }) async {
    final resetUrl = '\${Environment.appUrl}/auth/reset-password?token=\$token';
    
    await _sendEmail(
      to: email,
      subject: 'Reset your password',
      html: '''
        <h2>Hello \$name,</h2>
        <p>We received a request to reset your password. Click the link below to create a new password:</p>
        <p><a href="\$resetUrl">Reset Password</a></p>
        <p>Or copy and paste this URL into your browser:</p>
        <p>\$resetUrl</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Best regards,<br>The Team</p>
      ''',
    );
  }
  
  /// Send password changed notification
  Future<void> sendPasswordChangedEmail({
    required String email,
    required String name,
  }) async {
    await _sendEmail(
      to: email,
      subject: 'Your password has been changed',
      html: '''
        <h2>Hello \$name,</h2>
        <p>This is to confirm that your password has been successfully changed.</p>
        <p>If you did not make this change, please contact support immediately.</p>
        <p>Best regards,<br>The Team</p>
      ''',
    );
  }
  
  /// Send email using configured provider
  Future<void> _sendEmail({
    required String to,
    required String subject,
    required String html,
  }) async {
    // In development, just log the email
    if (Environment.isDevelopment) {
      _logger.info('Email sent (dev mode):', {
        'to': to,
        'subject': subject,
      });
      return;
    }
    
    // TODO: Implement actual email sending
    // This could use SendGrid, AWS SES, Mailgun, etc.
    
    _logger.info('Email sent:', {
      'to': to,
      'subject': subject,
    });
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/services/email_service.dart'),
      emailServiceContent
    );

    // Redis service
    const redisServiceContent = `import 'package:redis/redis.dart';
import '../config/environment.dart';
import '../utils/logger.dart';

/// Service for Redis operations
class RedisService {
  static final RedisService _instance = RedisService._internal();
  static RedisService get instance => _instance;
  
  RedisService._internal();
  
  late final RedisConnection _connection;
  Command? _command;
  final _logger = AppLogger.instance;
  
  /// Initialize Redis connection
  Future<void> initialize() async {
    try {
      _connection = RedisConnection();
      _command = await _connection.connect(
        Environment.redisHost,
        Environment.redisPort,
      );
      
      if (Environment.redisPassword.isNotEmpty) {
        await _command!.send_object(['AUTH', Environment.redisPassword]);
      }
      
      _logger.info('Redis connected successfully');
    } catch (e) {
      _logger.error('Failed to connect to Redis', error: e);
      // Redis is optional, so don't throw
    }
  }
  
  /// Get value by key
  Future<String?> get(String key) async {
    if (_command == null) return null;
    
    try {
      final result = await _command!.get(key);
      return result?.toString();
    } catch (e) {
      _logger.error('Redis GET error', error: e);
      return null;
    }
  }
  
  /// Set value with optional expiration
  Future<void> set(String key, String value, {Duration? expiration}) async {
    if (_command == null) return;
    
    try {
      await _command!.set(key, value);
      
      if (expiration != null) {
        await _command!.send_object(['EXPIRE', key, expiration.inSeconds]);
      }
    } catch (e) {
      _logger.error('Redis SET error', error: e);
    }
  }
  
  /// Set value with expiration in seconds
  Future<void> setex(String key, String value, int seconds) async {
    if (_command == null) return;
    
    try {
      await _command!.send_object(['SETEX', key, seconds, value]);
    } catch (e) {
      _logger.error('Redis SETEX error', error: e);
    }
  }
  
  /// Delete key
  Future<void> delete(String key) async {
    if (_command == null) return;
    
    try {
      await _command!.send_object(['DEL', key]);
    } catch (e) {
      _logger.error('Redis DELETE error', error: e);
    }
  }
  
  /// Check if key exists
  Future<bool> exists(String key) async {
    if (_command == null) return false;
    
    try {
      final result = await _command!.send_object(['EXISTS', key]);
      return result == 1;
    } catch (e) {
      _logger.error('Redis EXISTS error', error: e);
      return false;
    }
  }
  
  /// Close connection
  Future<void> close() async {
    await _connection.close();
    _logger.info('Redis connection closed');
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/services/redis_service.dart'),
      redisServiceContent
    );
  }

  private async generateDatabase(projectPath: string): Promise<void> {
    const databaseContent = `import 'package:postgres/postgres.dart';
import '../config/environment.dart';
import '../utils/logger.dart';

/// Database connection manager
class Database {
  static late Connection _connection;
  static Connection get connection => _connection;
  
  static final _logger = AppLogger.instance;
  
  /// Initialize database connection
  static Future<void> initialize() async {
    final endpoint = Endpoint(
      host: Environment.dbHost,
      port: Environment.dbPort,
      database: Environment.dbName,
      username: Environment.dbUser,
      password: Environment.dbPassword,
    );
    
    _connection = await Connection.open(
      endpoint,
      settings: ConnectionSettings(
        sslMode: Environment.isProduction ? SslMode.require : SslMode.disable,
      ),
    );
    
    _logger.info('Database connected successfully');
    
    // Run migrations
    await _runMigrations();
  }
  
  /// Run database migrations
  static Future<void> _runMigrations() async {
    // Create users table
    await _connection.execute('''
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        avatar_url VARCHAR(512),
        is_active BOOLEAN DEFAULT true,
        is_admin BOOLEAN DEFAULT false,
        email_verified_at TIMESTAMP,
        last_login_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      )
    ''');
    
    // Create indexes
    await _connection.execute('''
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(LOWER(email));
      CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
    ''');
    
    _logger.info('Database migrations completed');
  }
  
  /// Close database connection
  static Future<void> close() async {
    await _connection.close();
    _logger.info('Database connection closed');
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/database/database.dart'),
      databaseContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    // Logger utility
    const loggerContent = `import 'package:logger/logger.dart';
import '../config/environment.dart';

/// Application logger
class AppLogger {
  static final AppLogger _instance = AppLogger._internal();
  static AppLogger get instance => _instance;
  
  late final Logger _logger;
  
  AppLogger._internal() {
    _logger = Logger(
      filter: ProductionFilter(),
      printer: PrettyPrinter(
        methodCount: 2,
        errorMethodCount: 8,
        lineLength: 120,
        colors: true,
        printEmojis: true,
        printTime: true,
      ),
      level: _getLogLevel(),
    );
  }
  
  Level _getLogLevel() {
    switch (Environment.logLevel.toLowerCase()) {
      case 'verbose':
        return Level.verbose;
      case 'debug':
        return Level.debug;
      case 'info':
        return Level.info;
      case 'warning':
        return Level.warning;
      case 'error':
        return Level.error;
      case 'wtf':
        return Level.wtf;
      default:
        return Level.info;
    }
  }
  
  void verbose(dynamic message, [dynamic error, StackTrace? stackTrace]) {
    _logger.v(message, error: error, stackTrace: stackTrace);
  }
  
  void debug(dynamic message, [dynamic error, StackTrace? stackTrace]) {
    _logger.d(message, error: error, stackTrace: stackTrace);
  }
  
  void info(dynamic message, [dynamic error, StackTrace? stackTrace]) {
    _logger.i(message, error: error, stackTrace: stackTrace);
  }
  
  void warning(dynamic message, [dynamic error, StackTrace? stackTrace]) {
    _logger.w(message, error: error, stackTrace: stackTrace);
  }
  
  void error(dynamic message, {dynamic error, StackTrace? stackTrace}) {
    _logger.e(message, error: error, stackTrace: stackTrace);
  }
  
  void wtf(dynamic message, [dynamic error, StackTrace? stackTrace]) {
    _logger.wtf(message, error: error, stackTrace: stackTrace);
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/utils/logger.dart'),
      loggerContent
    );

    // Exceptions
    const exceptionsContent = `/// Base exception for application errors
abstract class AppException implements Exception {
  final String message;
  final String code;
  
  AppException(this.message, this.code);
  
  @override
  String toString() => '\$runtimeType: \$message';
}

/// Validation exception
class ValidationException extends AppException {
  final Map<String, String>? details;
  
  ValidationException(String message, {this.details})
      : super(message, 'VALIDATION_ERROR');
}

/// Authentication exception
class AuthenticationException extends AppException {
  AuthenticationException(String message)
      : super(message, 'AUTHENTICATION_ERROR');
}

/// Authorization exception
class AuthorizationException extends AppException {
  AuthorizationException(String message)
      : super(message, 'AUTHORIZATION_ERROR');
}

/// Not found exception
class NotFoundException extends AppException {
  NotFoundException(String message)
      : super(message, 'NOT_FOUND');
}

/// Conflict exception
class ConflictException extends AppException {
  ConflictException(String message)
      : super(message, 'CONFLICT');
}

/// Rate limit exception
class RateLimitException extends AppException {
  final int retryAfter;
  
  RateLimitException(String message, {required this.retryAfter})
      : super(message, 'RATE_LIMIT_ERROR');
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/utils/exceptions.dart'),
      exceptionsContent
    );

    // Pagination utility
    const paginationContent = `import 'package:shelf/shelf.dart';

/// Pagination parameters
class PaginationParams {
  final int page;
  final int limit;
  final String sortBy;
  final String sortOrder;
  
  PaginationParams({
    this.page = 1,
    this.limit = 20,
    this.sortBy = 'created_at',
    this.sortOrder = 'DESC',
  });
  
  int get offset => (page - 1) * limit;
  
  /// Create from request query parameters
  factory PaginationParams.fromRequest(Request request) {
    final query = request.url.queryParameters;
    
    return PaginationParams(
      page: int.tryParse(query['page'] ?? '1') ?? 1,
      limit: _validateLimit(int.tryParse(query['limit'] ?? '20') ?? 20),
      sortBy: _validateSortBy(query['sort'] ?? 'created_at'),
      sortOrder: _validateSortOrder(query['order'] ?? 'DESC'),
    );
  }
  
  static int _validateLimit(int limit) {
    if (limit < 1) return 1;
    if (limit > 100) return 100;
    return limit;
  }
  
  static String _validateSortBy(String sortBy) {
    const allowedFields = ['created_at', 'updated_at', 'name', 'email'];
    return allowedFields.contains(sortBy) ? sortBy : 'created_at';
  }
  
  static String _validateSortOrder(String order) {
    final upperOrder = order.toUpperCase();
    return (upperOrder == 'ASC' || upperOrder == 'DESC') ? upperOrder : 'DESC';
  }
  
  PaginationParams withTotal(int total) {
    return PaginationParams(
      page: page,
      limit: limit,
      sortBy: sortBy,
      sortOrder: sortOrder,
    );
  }
}

/// Paginated result
class PaginatedResult<T> {
  final List<T> items;
  final PaginationMetadata pagination;
  
  PaginatedResult({
    required this.items,
    required this.pagination,
  });
}

/// Pagination metadata
class PaginationMetadata {
  final int page;
  final int limit;
  final int total;
  final int pages;
  
  PaginationMetadata({
    required this.page,
    required this.limit,
    required this.total,
  }) : pages = (total / limit).ceil();
  
  Map<String, dynamic> toJson() {
    return {
      'page': page,
      'limit': limit,
      'total': total,
      'pages': pages,
    };
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/utils/pagination.dart'),
      paginationContent
    );

    // Validators
    const validatorsContent = `/// Email validation
bool isValidEmail(String email) {
  final emailRegex = RegExp(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
  );
  return emailRegex.hasMatch(email);
}

/// Password validation
bool isValidPassword(String password) {
  return password.length >= 8;
}

/// UUID validation
bool isValidUuid(String uuid) {
  final uuidRegex = RegExp(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
  );
  return uuidRegex.hasMatch(uuid);
}

/// URL validation
bool isValidUrl(String url) {
  try {
    final uri = Uri.parse(url);
    return uri.hasScheme && (uri.scheme == 'http' || uri.scheme == 'https');
  } catch (e) {
    return false;
  }
}

/// Phone number validation (basic)
bool isValidPhoneNumber(String phone) {
  final phoneRegex = RegExp(r'^\+?[\d\s\-\(\)]+$');
  return phone.length >= 10 && phoneRegex.hasMatch(phone);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/utils/validators.dart'),
      validatorsContent
    );

    // Swagger generator
    const swaggerContent = `import 'dart:convert';
import '../config/environment.dart';

/// Generates OpenAPI/Swagger documentation
class SwaggerGenerator {
  static String generateSpec() {
    final spec = {
      'openapi': '3.0.0',
      'info': {
        'title': 'Shelf API',
        'description': 'API documentation for Shelf microservice',
        'version': '1.0.0',
        'contact': {
          'name': 'API Support',
          'email': 'support@example.com',
        },
      },
      'servers': [
        {
          'url': Environment.appUrl,
          'description': Environment.current,
        },
      ],
      'paths': _generatePaths(),
      'components': _generateComponents(),
    };
    
    return jsonEncode(spec);
  }
  
  static String generateHTML() {
    return '''
<!DOCTYPE html>
<html>
<head>
  <title>API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>
    ''';
  }
  
  static Map<String, dynamic> _generatePaths() {
    // TODO: Generate paths dynamically from routes
    return {
      '/health': {
        'get': {
          'tags': ['Health'],
          'summary': 'Health check',
          'responses': {
            '200': {
              'description': 'Service is healthy',
              'content': {
                'application/json': {
                  'schema': {
                    '\$ref': '#/components/schemas/HealthResponse',
                  },
                },
              },
            },
          },
        },
      },
      // Add more paths...
    };
  }
  
  static Map<String, dynamic> _generateComponents() {
    return {
      'securitySchemes': {
        'bearerAuth': {
          'type': 'http',
          'scheme': 'bearer',
          'bearerFormat': 'JWT',
        },
      },
      'schemas': {
        'HealthResponse': {
          'type': 'object',
          'properties': {
            'status': {'type': 'string'},
            'timestamp': {'type': 'string', 'format': 'date-time'},
            'version': {'type': 'string'},
            'checks': {
              'type': 'object',
              'additionalProperties': {'type': 'boolean'},
            },
          },
        },
        // Add more schemas...
      },
    };
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/utils/swagger_generator.dart'),
      swaggerContent
    );
  }

  private async generateEnvConfig(projectPath: string, options: any): Promise<void> {
    const environmentContent = `import 'package:dotenv/dotenv.dart';

/// Environment configuration
class Environment {
  static late DotEnv _env;
  static bool _initialized = false;
  
  /// Initialize environment
  static Future<void> initialize(DotEnv env) async {
    _env = env;
    _initialized = true;
  }
  
  static void _checkInitialized() {
    if (!_initialized) {
      throw StateError('Environment not initialized. Call Environment.initialize() first.');
    }
  }
  
  /// Current environment
  static String get current {
    _checkInitialized();
    return _env['ENVIRONMENT'] ?? 'development';
  }
  
  static bool get isDevelopment => current == 'development';
  static bool get isStaging => current == 'staging';
  static bool get isProduction => current == 'production';
  static bool get isTesting => current == 'testing';
  
  /// Server configuration
  static int get port => int.parse(_env['PORT'] ?? '8080');
  static String get host => _env['HOST'] ?? '0.0.0.0';
  
  /// Application URL
  static String get appUrl => _env['APP_URL'] ?? 'http://localhost:\$port';
  
  /// Database configuration
  static String get dbHost => _env['DB_HOST'] ?? 'localhost';
  static int get dbPort => int.parse(_env['DB_PORT'] ?? '5432');
  static String get dbName => _env['DB_NAME'] ?? 'shelf_app';
  static String get dbUser => _env['DB_USER'] ?? 'postgres';
  static String get dbPassword => _env['DB_PASSWORD'] ?? 'postgres';
  
  /// Redis configuration
  static String get redisHost => _env['REDIS_HOST'] ?? 'localhost';
  static int get redisPort => int.parse(_env['REDIS_PORT'] ?? '6379');
  static String get redisPassword => _env['REDIS_PASSWORD'] ?? '';
  
  /// JWT configuration
  static String get jwtSecret => _env['JWT_SECRET'] ?? 'your-secret-key-change-in-production';
  static String get jwtIssuer => _env['JWT_ISSUER'] ?? 'shelf-app';
  static String get jwtAudience => _env['JWT_AUDIENCE'] ?? 'shelf-app-users';
  
  /// Security
  static String get passwordSalt => _env['PASSWORD_SALT'] ?? 'default-salt-change-in-production';
  
  /// Logging
  static String get logLevel => _env['LOG_LEVEL'] ?? 'info';
  
  /// Email configuration
  static String get emailFrom => _env['EMAIL_FROM'] ?? 'noreply@example.com';
  static String get emailProvider => _env['EMAIL_PROVIDER'] ?? 'smtp';
  
  // SMTP settings
  static String get smtpHost => _env['SMTP_HOST'] ?? 'localhost';
  static int get smtpPort => int.parse(_env['SMTP_PORT'] ?? '587');
  static String get smtpUser => _env['SMTP_USER'] ?? '';
  static String get smtpPassword => _env['SMTP_PASSWORD'] ?? '';
  
  // SendGrid settings
  static String get sendgridApiKey => _env['SENDGRID_API_KEY'] ?? '';
  
  /// Feature flags
  static bool get enableSwagger => _env['ENABLE_SWAGGER'] != 'false';
  static bool get enableMetrics => _env['ENABLE_METRICS'] != 'false';
  static bool get enableHealthCheck => _env['ENABLE_HEALTH_CHECK'] != 'false';
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/config/environment.dart'),
      environmentContent
    );

    // Also create the main library export file
    const libContent = `/// Shelf backend application
library ${options.name};

export 'src/app.dart';
export 'src/config/environment.dart';
export 'src/database/database.dart';
export 'src/utils/logger.dart';
`;

    await fs.writeFile(
      path.join(projectPath, 'lib', `${options.name}.dart`),
      libContent
    );
  }
}

// Export for use in template system
export default ShelfGenerator;