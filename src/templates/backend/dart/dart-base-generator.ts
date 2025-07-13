/**
 * Dart Backend Template Base Generator
 * Shared functionality for all Dart web frameworks
 */

import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class DartBackendGenerator extends BackendTemplateGenerator {
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Dart',
      framework,
      packageManager: 'pub',
      buildTool: 'dart',
      testFramework: 'test',
      features: [
        'Async/await support',
        'Type-safe routing',
        'Middleware pipeline',
        'JSON serialization',
        'WebSocket support',
        'Database integration',
        'Authentication & Authorization',
        'Structured logging',
        'Environment configuration',
        'Docker support',
        'Hot reload development',
        'Null safety'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'start': 'dart run bin/server.dart',
        'dev': 'dart run --enable-vm-service --enable-asserts bin/server.dart',
        'build': 'dart compile exe bin/server.dart -o build/server',
        'test': 'dart test',
        'test:coverage': 'dart test --coverage=coverage',
        'analyze': 'dart analyze',
        'format': 'dart format .',
        'fix': 'dart fix --apply',
        'clean': 'dart clean'
      },
      dockerConfig: {
        baseImage: 'dart:stable-slim',
        workDir: '/app',
        exposedPorts: [8080],
        buildSteps: [
          'COPY pubspec.* ./',
          'RUN dart pub get',
          'COPY . .',
          'RUN dart compile exe bin/server.dart -o bin/server'
        ],
        runCommand: './bin/server',
        multistage: true
      },
      envVars: {
        'PORT': '8080',
        'ENVIRONMENT': 'development',
        'LOG_LEVEL': 'info',
        'DATABASE_URL': 'postgresql://user:password@localhost:5432/dbname',
        'JWT_SECRET': 'your-secret-key',
        'REDIS_URL': 'redis://localhost:6379',
        'API_PREFIX': '/api/v1'
      }
    };
    super(config);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate pubspec.yaml
    await this.generatePubspec(projectPath, options);

    // Generate analysis_options.yaml
    await this.generateAnalysisOptions(projectPath);

    // Generate .gitignore
    await this.generateDartGitignore(projectPath);

    // Create directory structure
    const directories = [
      'bin',
      'lib',
      'lib/src',
      'lib/src/controllers',
      'lib/src/services',
      'lib/src/models',
      'lib/src/middleware',
      'lib/src/utils',
      'lib/src/config',
      'lib/src/database',
      'lib/src/routes',
      'test',
      'test/unit',
      'test/integration',
      'test/fixtures'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }
  }

  protected async generatePubspec(projectPath: string, options: any): Promise<void> {
    const pubspecContent = `name: ${options.name}
description: A ${this.config.framework} server application built with Re-Shell CLI
version: 1.0.0
publish_to: none

environment:
  sdk: '>=3.0.0 <4.0.0'

dependencies:
${this.getFrameworkDependencies().map(dep => '  ' + dep).join('\n')}

dev_dependencies:
  test: ^1.24.0
  coverage: ^1.6.0
  mockito: ^5.4.0
  build_runner: ^2.4.0
  lints: ^3.0.0
  ${this.getDevDependencies().join('\n  ')}

executables:
  server: server
`;

    await fs.writeFile(path.join(projectPath, 'pubspec.yaml'), pubspecContent);
  }

  protected async generateAnalysisOptions(projectPath: string): Promise<void> {
    const analysisOptions = `include: package:lints/recommended.yaml

analyzer:
  strong-mode:
    implicit-casts: false
    implicit-dynamic: false
  
  exclude:
    - build/**
    - '**.g.dart'
    - '**.freezed.dart'
    - test/.test_coverage.dart
  
  errors:
    missing_required_param: error
    missing_return: error
    todo: info
    deprecated_member_use_from_same_package: info

linter:
  rules:
    - always_declare_return_types
    - always_put_control_body_on_new_line
    - always_put_required_named_parameters_first
    - always_require_non_null_named_parameters
    - annotate_overrides
    - avoid_bool_literals_in_conditional_expressions
    - avoid_catching_errors
    - avoid_classes_with_only_static_members
    - avoid_empty_else
    - avoid_escaping_inner_quotes
    - avoid_field_initializers_in_const_classes
    - avoid_function_literals_in_foreach_calls
    - avoid_init_to_null
    - avoid_null_checks_in_equality_operators
    - avoid_print
    - avoid_private_typedef_functions
    - avoid_redundant_argument_values
    - avoid_relative_lib_imports
    - avoid_return_types_on_setters
    - avoid_returning_null_for_void
    - avoid_setters_without_getters
    - avoid_shadowing_type_parameters
    - avoid_single_cascade_in_expression_statements
    - avoid_slow_async_io
    - avoid_types_as_parameter_names
    - avoid_unnecessary_containers
    - avoid_unused_constructor_parameters
    - avoid_void_async
    - await_only_futures
    - camel_case_extensions
    - camel_case_types
    - cancel_subscriptions
    - cast_nullable_to_non_nullable
    - close_sinks
    - collection_methods_unrelated_type
    - constant_identifier_names
    - control_flow_in_finally
    - curly_braces_in_flow_control_structures
    - depend_on_referenced_packages
    - deprecated_consistency
    - directives_ordering
    - empty_catches
    - empty_constructor_bodies
    - empty_statements
    - eol_at_end_of_file
    - exhaustive_cases
    - file_names
    - flutter_style_todos
    - hash_and_equals
    - implementation_imports
    - iterable_contains_unrelated_type
    - join_return_with_assignment
    - leading_newlines_in_multiline_strings
    - library_names
    - library_prefixes
    - library_private_types_in_public_api
    - lines_longer_than_80_chars
    - list_remove_unrelated_type
    - literal_only_boolean_expressions
    - missing_whitespace_between_adjacent_strings
    - no_adjacent_strings_in_list
    - no_duplicate_case_values
    - no_leading_underscores_for_library_prefixes
    - no_leading_underscores_for_local_identifiers
    - no_logic_in_create_state
    - no_runtimeType_toString
    - non_constant_identifier_names
    - noop_primitive_operations
    - null_check_on_nullable_type_parameter
    - null_closures
    - omit_local_variable_types
    - one_member_abstracts
    - only_throw_errors
    - overridden_fields
    - package_api_docs
    - package_names
    - package_prefixed_library_names
    - parameter_assignments
    - prefer_adjacent_string_concatenation
    - prefer_asserts_in_initializer_lists
    - prefer_collection_literals
    - prefer_conditional_assignment
    - prefer_const_constructors
    - prefer_const_constructors_in_immutables
    - prefer_const_declarations
    - prefer_const_literals_to_create_immutables
    - prefer_constructors_over_static_methods
    - prefer_contains
    - prefer_equal_for_default_values
    - prefer_final_fields
    - prefer_final_in_for_each
    - prefer_final_locals
    - prefer_for_elements_to_map_fromIterable
    - prefer_function_declarations_over_variables
    - prefer_generic_function_type_aliases
    - prefer_if_elements_to_conditional_expressions
    - prefer_if_null_operators
    - prefer_initializing_formals
    - prefer_inlined_adds
    - prefer_int_literals
    - prefer_interpolation_to_compose_strings
    - prefer_is_empty
    - prefer_is_not_empty
    - prefer_is_not_operator
    - prefer_iterable_whereType
    - prefer_null_aware_method_calls
    - prefer_null_aware_operators
    - prefer_single_quotes
    - prefer_spread_collections
    - prefer_typing_uninitialized_variables
    - prefer_void_to_null
    - provide_deprecation_message
    - public_member_api_docs
    - recursive_getters
    - require_trailing_commas
    - secure_pubspec_urls
    - sized_box_for_whitespace
    - sized_box_shrink_expand
    - slash_for_doc_comments
    - sort_child_properties_last
    - sort_constructors_first
    - sort_pub_dependencies
    - sort_unnamed_constructors_first
    - test_types_in_equals
    - throw_in_finally
    - tighten_type_of_initializing_formals
    - type_annotate_public_apis
    - type_init_formals
    - unawaited_futures
    - unnecessary_await_in_return
    - unnecessary_brace_in_string_interps
    - unnecessary_const
    - unnecessary_constructor_name
    - unnecessary_getters_setters
    - unnecessary_lambdas
    - unnecessary_late
    - unnecessary_new
    - unnecessary_null_aware_assignments
    - unnecessary_null_checks
    - unnecessary_null_in_if_null_operators
    - unnecessary_nullable_for_final_variable_declarations
    - unnecessary_overrides
    - unnecessary_parenthesis
    - unnecessary_raw_strings
    - unnecessary_statements
    - unnecessary_string_escapes
    - unnecessary_string_interpolations
    - unnecessary_this
    - unnecessary_to_list_in_spreads
    - unrelated_type_equality_checks
    - unsafe_html
    - use_build_context_synchronously
    - use_full_hex_values_for_flutter_colors
    - use_function_type_syntax_for_parameters
    - use_if_null_to_convert_nulls_to_bools
    - use_is_even_rather_than_modulo
    - use_key_in_widget_constructors
    - use_late_for_private_fields_and_variables
    - use_named_constants
    - use_raw_strings
    - use_rethrow_when_possible
    - use_setters_to_change_properties
    - use_string_buffers
    - use_super_parameters
    - use_test_throws_matchers
    - use_to_and_as_if_applicable
    - valid_regexps
    - void_checks
`;

    await fs.writeFile(path.join(projectPath, 'analysis_options.yaml'), analysisOptions);
  }

  protected async generateDartGitignore(projectPath: string): Promise<void> {
    const gitignore = `# Dart/Pub related
.dart_tool/
.packages
pubspec.lock
build/
doc/api/

# IDE
.idea/
.vscode/
*.iml
*.ipr
*.iws
.DS_Store

# Test coverage
coverage/
test/.test_coverage.dart

# Environment
.env
.env.*

# Logs
*.log

# Generated files
*.g.dart
*.freezed.dart
*.gr.dart

# Temporary files
*.tmp
*.temp
.cache/

# macOS
.DS_Store

# Linux
*~

# Windows
Thumbs.db
ehthumbs.db
Desktop.ini

# Build output
server
server.exe
*.exe
*.dll
*.so
*.dylib
`;

    await fs.writeFile(path.join(projectPath, '.gitignore'), gitignore);
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Test helper
    const testHelper = `import 'dart:io';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;

/// Base URL for test server
String get baseUrl => 'http://localhost:\${testPort}';

/// Test server port
int get testPort => int.parse(Platform.environment['TEST_PORT'] ?? '8081');

/// Create test HTTP client
http.Client createTestClient() {
  return http.Client();
}

/// Test authentication helper
Future<String> getAuthToken(http.Client client, {
  String email = 'test@example.com',
  String password = 'password123',
}) async {
  final response = await client.post(
    Uri.parse('\$baseUrl/api/v1/auth/login'),
    headers: {'Content-Type': 'application/json'},
    body: '{"email": "\$email", "password": "\$password"}',
  );
  
  if (response.statusCode != 200) {
    throw Exception('Failed to authenticate: \${response.body}');
  }
  
  final data = jsonDecode(response.body);
  return data['token'];
}

/// Authenticated request helper
Future<http.Response> authenticatedRequest(
  http.Client client,
  String method,
  String path, {
  String? token,
  Map<String, String>? headers,
  String? body,
}) async {
  token ??= await getAuthToken(client);
  
  final uri = Uri.parse('\$baseUrl\$path');
  final requestHeaders = {
    'Authorization': 'Bearer \$token',
    'Content-Type': 'application/json',
    ...?headers,
  };
  
  switch (method.toUpperCase()) {
    case 'GET':
      return client.get(uri, headers: requestHeaders);
    case 'POST':
      return client.post(uri, headers: requestHeaders, body: body);
    case 'PUT':
      return client.put(uri, headers: requestHeaders, body: body);
    case 'DELETE':
      return client.delete(uri, headers: requestHeaders);
    default:
      throw ArgumentError('Unsupported HTTP method: \$method');
  }
}

/// Test data fixtures
class TestFixtures {
  static Map<String, dynamic> get validUser => {
    'email': 'test@example.com',
    'password': 'password123',
    'name': 'Test User',
  };
  
  static Map<String, dynamic> get invalidUser => {
    'email': 'invalid-email',
    'password': '123', // Too short
    'name': '',
  };
}

/// Custom test matchers
Matcher isValidationError() => allOf(
  isA<Map>(),
  containsPair('error', isA<Map>()),
);

Matcher hasStatus(int status) => allOf(
  isA<http.Response>(),
  predicate<http.Response>(
    (r) => r.statusCode == status,
    'has status code \$status',
  ),
);
`;

    await fs.writeFile(
      path.join(projectPath, 'test/test_helper.dart'),
      testHelper
    );

    // Example unit test
    const exampleUnitTest = `import 'package:test/test.dart';
import 'package:${options.name}/src/utils/validators.dart';

void main() {
  group('Validators', () {
    group('email validation', () {
      test('accepts valid email addresses', () {
        expect(isValidEmail('user@example.com'), isTrue);
        expect(isValidEmail('user.name@example.co.uk'), isTrue);
        expect(isValidEmail('user+tag@example.com'), isTrue);
      });
      
      test('rejects invalid email addresses', () {
        expect(isValidEmail(''), isFalse);
        expect(isValidEmail('invalid'), isFalse);
        expect(isValidEmail('@example.com'), isFalse);
        expect(isValidEmail('user@'), isFalse);
        expect(isValidEmail('user @example.com'), isFalse);
      });
    });
    
    group('password validation', () {
      test('accepts valid passwords', () {
        expect(isValidPassword('password123'), isTrue);
        expect(isValidPassword('P@ssw0rd!'), isTrue);
      });
      
      test('rejects invalid passwords', () {
        expect(isValidPassword(''), isFalse);
        expect(isValidPassword('short'), isFalse);
        expect(isValidPassword('1234567'), isFalse);
      });
    });
  });
}
`;

    await fs.writeFile(
      path.join(projectPath, 'test/unit/validators_test.dart'),
      exampleUnitTest
    );

    // Integration test example
    const integrationTest = `import 'dart:convert';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import '../test_helper.dart';

void main() {
  late http.Client client;
  
  setUpAll(() {
    client = createTestClient();
  });
  
  tearDownAll(() {
    client.close();
  });
  
  group('Health Check', () {
    test('GET /health returns healthy status', () async {
      final response = await client.get(Uri.parse('\$baseUrl/health'));
      
      expect(response, hasStatus(200));
      
      final data = jsonDecode(response.body);
      expect(data['status'], equals('healthy'));
      expect(data['timestamp'], isNotNull);
      expect(data['version'], isNotNull);
    });
    
    test('GET /ready returns ready status', () async {
      final response = await client.get(Uri.parse('\$baseUrl/ready'));
      
      expect(response, hasStatus(200));
      
      final data = jsonDecode(response.body);
      expect(data['ready'], isTrue);
    });
  });
  
  group('Authentication', () {
    test('POST /auth/register creates new user', () async {
      final user = {
        'email': 'newuser\${DateTime.now().millisecondsSinceEpoch}@example.com',
        'password': 'password123',
        'name': 'New User',
      };
      
      final response = await client.post(
        Uri.parse('\$baseUrl/api/v1/auth/register'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(user),
      );
      
      expect(response, hasStatus(201));
      
      final data = jsonDecode(response.body);
      expect(data['user']['email'], equals(user['email']));
      expect(data['token'], isNotEmpty);
      expect(data['refreshToken'], isNotEmpty);
    });
    
    test('POST /auth/login authenticates user', () async {
      final response = await client.post(
        Uri.parse('\$baseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestFixtures.validUser['email'],
          'password': TestFixtures.validUser['password'],
        }),
      );
      
      expect(response, hasStatus(200));
      
      final data = jsonDecode(response.body);
      expect(data['token'], isNotEmpty);
      expect(data['user']['email'], equals(TestFixtures.validUser['email']));
    });
    
    test('POST /auth/login rejects invalid credentials', () async {
      final response = await client.post(
        Uri.parse('\$baseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': 'wrong@example.com',
          'password': 'wrongpassword',
        }),
      );
      
      expect(response, hasStatus(401));
    });
  });
}
`;

    await fs.writeFile(
      path.join(projectPath, 'test/integration/auth_test.dart'),
      integrationTest
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    const healthController = `import 'dart:convert';
import 'dart:io';
import 'package:${this.config.framework.toLowerCase()}/${this.config.framework.toLowerCase()}.dart';

/// Health check controller
class HealthController {
  static final _startTime = DateTime.now();
  
  /// Comprehensive health check
  static Future<Response> health(Request request) async {
    final checks = await _performHealthChecks();
    final allHealthy = checks.values.every((check) => check);
    
    final response = {
      'status': allHealthy ? 'healthy' : 'degraded',
      'timestamp': DateTime.now().toIso8601String(),
      'version': _getVersion(),
      'uptime': DateTime.now().difference(_startTime).inSeconds,
      'environment': Platform.environment['ENVIRONMENT'] ?? 'development',
      'checks': checks,
    };
    
    return Response.ok(
      jsonEncode(response),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// Simple readiness check
  static Future<Response> ready(Request request) async {
    return Response.ok(
      jsonEncode({
        'ready': true,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      }),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  /// Liveness check
  static Future<Response> live(Request request) async {
    return Response.ok(
      jsonEncode({'alive': true}),
      headers: {'Content-Type': 'application/json'},
    );
  }
  
  static Future<Map<String, bool>> _performHealthChecks() async {
    final checks = <String, bool>{};
    
    // Database check
    checks['database'] = await _checkDatabase();
    
    // Redis check
    checks['redis'] = await _checkRedis();
    
    // File system check
    checks['filesystem'] = _checkFilesystem();
    
    // Memory check
    checks['memory'] = _checkMemory();
    
    return checks;
  }
  
  static Future<bool> _checkDatabase() async {
    try {
      // TODO: Implement actual database connectivity check
      return true;
    } catch (e) {
      return false;
    }
  }
  
  static Future<bool> _checkRedis() async {
    try {
      // TODO: Implement actual Redis connectivity check
      return true;
    } catch (e) {
      return false;
    }
  }
  
  static bool _checkFilesystem() {
    try {
      final tempDir = Directory.systemTemp;
      final testFile = File('\${tempDir.path}/health_check_\${DateTime.now().millisecondsSinceEpoch}');
      testFile.writeAsStringSync('test');
      testFile.deleteSync();
      return true;
    } catch (e) {
      return false;
    }
  }
  
  static bool _checkMemory() {
    // Check if memory usage is reasonable
    // This is a simplified check
    return true;
  }
  
  static String _getVersion() {
    // Read from pubspec.yaml or environment
    return Platform.environment['VERSION'] ?? '1.0.0';
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'lib/src/controllers/health_controller.dart'),
      healthController
    );
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // Generate OpenAPI specification
    const openAPISpec = `openapi: 3.0.0
info:
  title: ${this.config.framework} API
  description: API documentation for ${this.config.framework} microservice built with Dart
  version: 1.0.0
  contact:
    name: API Support
    email: support@example.com
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT

servers:
  - url: http://localhost:8080
    description: Development server
  - url: https://api.example.com
    description: Production server

tags:
  - name: Health
    description: Health check endpoints
  - name: Auth
    description: Authentication endpoints
  - name: Users
    description: User management

paths:
  /health:
    get:
      tags:
        - Health
      summary: Health check
      description: Returns the health status of the service
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'

  /ready:
    get:
      tags:
        - Health
      summary: Readiness check
      description: Returns whether the service is ready to accept requests
      responses:
        '200':
          description: Service is ready
          content:
            application/json:
              schema:
                type: object
                properties:
                  ready:
                    type: boolean
                  timestamp:
                    type: integer

  /live:
    get:
      tags:
        - Health
      summary: Liveness check
      description: Returns whether the service is alive
      responses:
        '200':
          description: Service is alive
          content:
            application/json:
              schema:
                type: object
                properties:
                  alive:
                    type: boolean

  /api/v1/auth/register:
    post:
      tags:
        - Auth
      summary: Register new user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterRequest'
      responses:
        '201':
          description: User registered successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        '400':
          description: Invalid registration data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /api/v1/auth/login:
    post:
      tags:
        - Auth
      summary: User login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        '401':
          description: Invalid credentials
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /api/v1/auth/refresh:
    post:
      tags:
        - Auth
      summary: Refresh access token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - refreshToken
              properties:
                refreshToken:
                  type: string
      responses:
        '200':
          description: Token refreshed successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        '401':
          description: Invalid refresh token

  /api/v1/users/me:
    get:
      tags:
        - Users
      summary: Get current user profile
      security:
        - bearerAuth: []
      responses:
        '200':
          description: User profile
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '401':
          description: Unauthorized

    put:
      tags:
        - Users
      summary: Update current user profile
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateUserRequest'
      responses:
        '200':
          description: User updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '400':
          description: Invalid update data
        '401':
          description: Unauthorized

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    HealthResponse:
      type: object
      properties:
        status:
          type: string
          enum: [healthy, degraded, unhealthy]
        timestamp:
          type: string
          format: date-time
        version:
          type: string
        uptime:
          type: integer
          description: Uptime in seconds
        environment:
          type: string
        checks:
          type: object
          additionalProperties:
            type: boolean

    RegisterRequest:
      type: object
      required:
        - email
        - password
        - name
      properties:
        email:
          type: string
          format: email
        password:
          type: string
          minLength: 8
        name:
          type: string
          minLength: 2

    LoginRequest:
      type: object
      required:
        - email
        - password
      properties:
        email:
          type: string
          format: email
        password:
          type: string

    AuthResponse:
      type: object
      properties:
        user:
          $ref: '#/components/schemas/User'
        token:
          type: string
        refreshToken:
          type: string
        expiresIn:
          type: integer
          description: Token expiration time in seconds

    User:
      type: object
      properties:
        id:
          type: string
        email:
          type: string
          format: email
        name:
          type: string
        avatarUrl:
          type: string
          nullable: true
        isActive:
          type: boolean
        createdAt:
          type: string
          format: date-time
        updatedAt:
          type: string
          format: date-time

    UpdateUserRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 2
        avatarUrl:
          type: string
          nullable: true

    ErrorResponse:
      type: object
      properties:
        error:
          type: object
          properties:
            code:
              type: string
            message:
              type: string
            details:
              type: object
              additionalProperties:
                type: string

    PaginatedResponse:
      type: object
      properties:
        data:
          type: array
          items: {}
        pagination:
          type: object
          properties:
            page:
              type: integer
            limit:
              type: integer
            total:
              type: integer
            pages:
              type: integer
`;

    await fs.writeFile(
      path.join(projectPath, 'docs/openapi.yaml'),
      openAPISpec
    );
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    // Multi-stage Dockerfile
    const dockerfile = `# ================================
# Build Stage
# ================================
FROM dart:stable AS builder

# Install dependencies for compilation
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy pubspec files
COPY pubspec.* ./

# Get dependencies
RUN dart pub get

# Copy source code
COPY . .

# Ensure the project is sound
RUN dart analyze --fatal-infos --fatal-warnings

# Compile to native executable
RUN dart compile exe bin/server.dart -o bin/server

# ================================
# Runtime Stage
# ================================
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r dartuser && useradd -r -g dartuser dartuser

# Set working directory
WORKDIR /app

# Copy compiled executable from builder
COPY --from=builder /app/bin/server /app/bin/server

# Copy any static assets if needed
COPY --from=builder /app/public ./public

# Set ownership
RUN chown -R dartuser:dartuser /app

# Switch to non-root user
USER dartuser

# Expose port
EXPOSE ${options.port || 8080}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:${options.port || 8080}/health || exit 1

# Run the server
CMD ["./bin/server"]
`;

    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerfile);

    // Docker compose for local development
    const dockerCompose = `version: '3.8'

services:
  app:
    build:
      context: .
      target: builder
    ports:
      - "\${PORT:-8080}:8080"
    environment:
      - ENVIRONMENT=development
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/${options.name}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
      - /app/.dart_tool
      - /app/build
    command: dart run --enable-vm-service bin/server.dart

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=${options.name}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  adminer:
    image: adminer
    ports:
      - "8081:8080"
    depends_on:
      - db

volumes:
  postgres_data:
  redis_data:
`;

    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), dockerCompose);

    // .dockerignore
    const dockerignore = `.dart_tool/
.packages
build/
coverage/
doc/api/
.git/
.gitignore
.dockerignore
Dockerfile
docker-compose.yml
README.md
.env
.env.*
*.log
test/
analysis_options.yaml
`;

    await fs.writeFile(path.join(projectPath, '.dockerignore'), dockerignore);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // README.md already generated by base class
    
    // API documentation guide
    const apiGuide = `# API Documentation

## Overview

This ${this.config.framework} API provides a robust foundation for building microservices with Dart.

## Base URL

- Development: \`http://localhost:8080\`
- Production: \`https://api.example.com\`

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

### Obtaining a Token

1. Register a new account:
   \`\`\`bash
   curl -X POST http://localhost:8080/api/v1/auth/register \\
     -H "Content-Type: application/json" \\
     -d '{
       "email": "user@example.com",
       "password": "securepassword",
       "name": "John Doe"
     }'
   \`\`\`

2. Login with credentials:
   \`\`\`bash
   curl -X POST http://localhost:8080/api/v1/auth/login \\
     -H "Content-Type: application/json" \\
     -d '{
       "email": "user@example.com",
       "password": "securepassword"
     }'
   \`\`\`

3. Refresh an expired token:
   \`\`\`bash
   curl -X POST http://localhost:8080/api/v1/auth/refresh \\
     -H "Content-Type: application/json" \\
     -d '{
       "refreshToken": "<your-refresh-token>"
     }'
   \`\`\`

## Rate Limiting

API endpoints are rate-limited to prevent abuse:
- Anonymous requests: 100 requests per hour
- Authenticated requests: 1000 requests per hour

Rate limit information is included in response headers:
- \`X-RateLimit-Limit\`: Maximum requests allowed
- \`X-RateLimit-Remaining\`: Requests remaining
- \`X-RateLimit-Reset\`: Unix timestamp when limit resets

## Error Handling

The API returns consistent error responses:

\`\`\`json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "email": "Invalid email format",
      "password": "Password must be at least 8 characters"
    }
  }
}
\`\`\`

### Error Codes

- \`VALIDATION_ERROR\`: Input validation failed
- \`AUTHENTICATION_ERROR\`: Authentication failed
- \`AUTHORIZATION_ERROR\`: Insufficient permissions
- \`NOT_FOUND\`: Resource not found
- \`CONFLICT\`: Resource conflict (e.g., duplicate email)
- \`RATE_LIMIT_ERROR\`: Too many requests
- \`INTERNAL_ERROR\`: Server error

## Pagination

List endpoints support pagination using query parameters:

\`\`\`
GET /api/v1/users?page=2&limit=20&sort=createdAt&order=desc
\`\`\`

Parameters:
- \`page\`: Page number (default: 1)
- \`limit\`: Items per page (default: 20, max: 100)
- \`sort\`: Field to sort by
- \`order\`: Sort order (asc/desc)

Response includes pagination metadata:

\`\`\`json
{
  "data": [...],
  "pagination": {
    "page": 2,
    "limit": 20,
    "total": 100,
    "pages": 5
  }
}
\`\`\`

## Filtering

Most list endpoints support filtering:

\`\`\`
GET /api/v1/users?search=john&status=active&createdAfter=2023-01-01
\`\`\`

## WebSocket Support

WebSocket connections are available for real-time features:

\`\`\`javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = () => {
  console.log('Connected');
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'updates'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
\`\`\`

## Development

### Running Locally

1. Install dependencies:
   \`\`\`bash
   dart pub get
   \`\`\`

2. Run database migrations:
   \`\`\`bash
   dart run bin/migrate.dart
   \`\`\`

3. Start the server:
   \`\`\`bash
   dart run bin/server.dart
   \`\`\`

### Running Tests

\`\`\`bash
# All tests
dart test

# With coverage
dart test --coverage=coverage

# Specific test file
dart test test/unit/validators_test.dart
\`\`\`

### Code Quality

\`\`\`bash
# Analyze code
dart analyze

# Format code
dart format .

# Fix issues
dart fix --apply
\`\`\`

## Deployment

### Environment Variables

Required environment variables:

- \`PORT\`: Server port (default: 8080)
- \`ENVIRONMENT\`: Environment mode (development/staging/production)
- \`DATABASE_URL\`: PostgreSQL connection string
- \`JWT_SECRET\`: Secret key for JWT signing
- \`REDIS_URL\`: Redis connection string (optional)

### Docker Deployment

\`\`\`bash
# Build image
docker build -t ${options.name} .

# Run container
docker run -p 8080:8080 \\
  -e DATABASE_URL=postgresql://user:pass@host:5432/db \\
  -e JWT_SECRET=your-secret-key \\
  ${options.name}
\`\`\`

### Health Monitoring

- \`GET /health\`: Comprehensive health check with subsystem status
- \`GET /ready\`: Simple readiness check
- \`GET /live\`: Liveness probe for container orchestration

## Security Best Practices

1. **Environment Variables**: Never commit secrets to version control
2. **HTTPS**: Always use HTTPS in production
3. **Input Validation**: All inputs are validated and sanitized
4. **SQL Injection**: Use parameterized queries
5. **Rate Limiting**: Protect against abuse
6. **CORS**: Configure allowed origins appropriately
7. **Security Headers**: Enable security headers in production
`;

    await fs.writeFile(path.join(projectPath, 'docs/API.md'), apiGuide);

    // Development guide
    const devGuide = `# Development Guide

## Prerequisites

- Dart SDK 3.0+
- Docker & Docker Compose (optional)
- PostgreSQL 15+
- Redis 7+ (optional)

## Project Structure

\`\`\`
${options.name}/
├── bin/
│   └── server.dart          # Application entry point
├── lib/
│   ├── ${options.name}.dart        # Public API exports
│   └── src/
│       ├── controllers/     # Request handlers
│       ├── models/         # Data models
│       ├── services/       # Business logic
│       ├── middleware/     # Middleware functions
│       ├── database/       # Database connections
│       ├── routes/         # Route definitions
│       ├── utils/          # Utilities
│       └── config/         # Configuration
├── test/
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── test_helper.dart   # Test utilities
├── docs/                  # Documentation
├── pubspec.yaml          # Dependencies
└── analysis_options.yaml # Linting rules
\`\`\`

## Getting Started

1. **Clone the repository**:
   \`\`\`bash
   git clone <repository-url>
   cd ${options.name}
   \`\`\`

2. **Install dependencies**:
   \`\`\`bash
   dart pub get
   \`\`\`

3. **Set up environment**:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

4. **Start services** (Docker):
   \`\`\`bash
   docker-compose up -d db redis
   \`\`\`

5. **Run migrations**:
   \`\`\`bash
   dart run bin/migrate.dart
   \`\`\`

6. **Start the server**:
   \`\`\`bash
   dart run bin/server.dart
   \`\`\`

## Development Workflow

### Hot Reload

During development, the server automatically reloads on file changes:

\`\`\`bash
dart run --enable-vm-service --enable-asserts bin/server.dart
\`\`\`

### Database Migrations

Create a new migration:
\`\`\`bash
dart run bin/migrate.dart create add_users_table
\`\`\`

Run pending migrations:
\`\`\`bash
dart run bin/migrate.dart up
\`\`\`

Rollback migrations:
\`\`\`bash
dart run bin/migrate.dart down
\`\`\`

### Testing

Run all tests:
\`\`\`bash
dart test
\`\`\`

Run with coverage:
\`\`\`bash
dart test --coverage=coverage
dart pub global run coverage:format_coverage \\
  --lcov \\
  --in=coverage \\
  --out=coverage/lcov.info \\
  --report-on=lib
\`\`\`

Generate HTML coverage report:
\`\`\`bash
genhtml coverage/lcov.info -o coverage/html
open coverage/html/index.html
\`\`\`

### Code Quality

Analyze code:
\`\`\`bash
dart analyze
\`\`\`

Format code:
\`\`\`bash
dart format .
\`\`\`

Fix issues automatically:
\`\`\`bash
dart fix --apply
\`\`\`

### Debugging

1. **VS Code**: Use the Dart extension and launch configuration
2. **IntelliJ IDEA**: Use the Dart plugin and debug configuration
3. **Command line**: Use \`dart run --enable-vm-service\` and connect debugger

### Performance Profiling

1. Run with Observatory:
   \`\`\`bash
   dart run --enable-vm-service --pause-isolates-on-start bin/server.dart
   \`\`\`

2. Open Observatory in browser (URL shown in console)

3. Use DevTools for profiling:
   \`\`\`bash
   dart pub global activate devtools
   dart pub global run devtools
   \`\`\`

## Coding Standards

### Naming Conventions

- **Classes**: PascalCase (e.g., \`UserController\`)
- **Files**: snake_case (e.g., \`user_controller.dart\`)
- **Variables/Functions**: camelCase (e.g., \`getUserById\`)
- **Constants**: SCREAMING_SNAKE_CASE (e.g., \`MAX_RETRY_COUNT\`)

### Project Organization

- One class per file
- Group related files in subdirectories
- Keep controllers thin, logic in services
- Use dependency injection

### Error Handling

\`\`\`dart
try {
  final result = await riskyOperation();
  return Response.ok(jsonEncode(result));
} on ValidationException catch (e) {
  return Response.badRequest(body: jsonEncode({
    'error': {
      'code': 'VALIDATION_ERROR',
      'message': e.message,
      'details': e.details,
    }
  }));
} catch (e, stackTrace) {
  logger.error('Unexpected error', error: e, stackTrace: stackTrace);
  return Response.internalServerError(body: jsonEncode({
    'error': {
      'code': 'INTERNAL_ERROR',
      'message': 'An unexpected error occurred',
    }
  }));
}
\`\`\`

### Documentation

- Use dartdoc comments for public APIs
- Include examples in documentation
- Keep README.md up to date

\`\`\`dart
/// Authenticates a user with email and password.
///
/// Returns an [AuthResponse] containing the user data and tokens.
/// Throws [ValidationException] if input is invalid.
/// Throws [AuthenticationException] if credentials are incorrect.
///
/// Example:
/// \`\`\`dart
/// final response = await authService.login(
///   email: 'user@example.com',
///   password: 'securepassword',
/// );
/// \`\`\`
Future<AuthResponse> login({
  required String email,
  required String password,
}) async {
  // Implementation
}
\`\`\`

## Troubleshooting

### Common Issues

1. **Port already in use**:
   \`\`\`bash
   lsof -i :8080
   kill -9 <PID>
   \`\`\`

2. **Database connection failed**:
   - Check DATABASE_URL format
   - Ensure PostgreSQL is running
   - Verify credentials and database exists

3. **Dependency conflicts**:
   \`\`\`bash
   dart pub cache clean
   rm pubspec.lock
   dart pub get
   \`\`\`

4. **Tests failing**:
   - Ensure test database is set up
   - Check for hardcoded ports/URLs
   - Run tests individually to isolate issues

### Getting Help

1. Check the [Dart documentation](https://dart.dev/guides)
2. Review ${this.config.framework} [documentation](https://pub.dev/packages/${this.config.framework.toLowerCase()})
3. Search for issues in the repository
4. Ask in the team chat or create an issue
`;

    await fs.writeFile(path.join(projectPath, 'docs/DEVELOPMENT.md'), devGuide);
  }

  // Utility methods
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '.dart_tool/',
      '.packages',
      'build/',
      'doc/api/',
      '*.g.dart',
      '*.freezed.dart',
      'coverage/',
      '.test_coverage.dart'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'Dart SDK 3.0+ (install via https://dart.dev/get-dart)';
  }

  protected getInstallCommand(): string {
    return 'dart pub get';
  }

  protected getDevCommand(): string {
    return 'dart run --enable-vm-service --enable-asserts bin/server.dart';
  }

  protected getProdCommand(): string {
    return 'dart compile exe bin/server.dart -o build/server && ./build/server';
  }

  protected getTestCommand(): string {
    return 'dart test';
  }

  protected getCoverageCommand(): string {
    return 'dart test --coverage=coverage';
  }

  protected getLintCommand(): string {
    return 'dart analyze';
  }

  protected getBuildCommand(): string {
    return 'dart compile exe bin/server.dart -o build/server';
  }

  protected getSetupAction(): string {
    return 'dart-lang/setup-dart@v1';
  }

  // Abstract methods to be implemented by specific frameworks
  protected abstract getFrameworkDependencies(): string[];
  protected abstract getDevDependencies(): string[];
  protected abstract generateFrameworkFiles(projectPath: string, options: any): Promise<void>;

  protected async generateBuildScript(projectPath: string, options: any): Promise<void> {
    const buildScriptContent = `#!/bin/bash

# Build script for Dart ${this.config.framework} application

set -e

echo "Building Dart ${this.config.framework} application..."

# Get dependencies
echo "Installing dependencies..."
dart pub get

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

    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'scripts', 'build.sh'),
      buildScriptContent
    );

    await fs.chmod(path.join(projectPath, 'scripts', 'build.sh'), 0o755);
  }
}