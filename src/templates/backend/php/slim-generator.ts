import { PhpBackendGenerator } from './php-base-generator';

export class SlimGenerator extends PhpBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Slim Framework';
    this.config.features = [
      'Slim Framework 4',
      'PSR-7 HTTP messages',
      'PSR-15 middleware',
      'Dependency injection container',
      'Twig templating support',
      'Monolog logging',
      'JWT authentication',
      'Eloquent ORM integration',
      'Redis caching support'
    ];
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'slim/slim': '^4.12',
      'slim/psr7': '^1.6',
      'nyholm/psr7': '^1.8',
      'nyholm/psr7-server': '^1.0',
      'php-di/php-di': '^7.0',
      'monolog/monolog': '^3.0',
      'firebase/php-jwt': '^6.8',
      'illuminate/database': '^10.0',
      'vlucas/phpdotenv': '^5.5',
      'twig/twig': '^3.7',
      'predis/predis': '^2.2',
      'respect/validation': '^2.2'
    };
  }

  protected generateMainFile(): string {
    return `<?php

declare(strict_types=1);

use DI\\ContainerBuilder;
use Slim\\Factory\\AppFactory;
use Dotenv\\Dotenv;

require __DIR__ . '/../vendor/autoload.php';

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

// Build DI Container
$containerBuilder = new ContainerBuilder();

// Add container definitions
$containerBuilder->addDefinitions(__DIR__ . '/../config/container.php');

// Build container
$container = $containerBuilder->build();

// Create App
AppFactory::setContainer($container);
$app = AppFactory::create();

// Add middleware
$app->addRoutingMiddleware();

// Add error middleware
$errorMiddleware = $app->addErrorMiddleware(
    displayErrorDetails: (bool) ($_ENV['APP_DEBUG'] ?? false),
    logErrors: true,
    logErrorDetails: true
);

// Set error handler
$errorHandler = $errorMiddleware->getDefaultErrorHandler();
$errorHandler->setDefaultErrorRenderer('application/json', App\\Handler\\JsonErrorRenderer::class);

// Register routes
require __DIR__ . '/../config/routes.php';

$app->run();`;
  }

  protected generateRoutingFile(): string {
    return `<?php

declare(strict_types=1);

use Slim\\App;
use App\\Controller\\AuthController;
use App\\Controller\\UserController;
use App\\Controller\\HealthController;
use App\\Middleware\\JwtMiddleware;
use App\\Middleware\\CorsMiddleware;

return function (App $app) {
    // Add CORS middleware
    $app->add(CorsMiddleware::class);

    // Health check
    $app->get('/health', [HealthController::class, 'check']);

    // API routes
    $app->group('/api', function ($group) {
        
        // Authentication routes
        $group->group('/auth', function ($auth) {
            $auth->post('/register', [AuthController::class, 'register']);
            $auth->post('/login', [AuthController::class, 'login']);
            $auth->post('/refresh', [AuthController::class, 'refresh']);
            
            // Protected auth routes
            $auth->post('/logout', [AuthController::class, 'logout'])->add(JwtMiddleware::class);
            $auth->get('/me', [AuthController::class, 'me'])->add(JwtMiddleware::class);
        });

        // User routes
        $group->group('/users', function ($users) {
            $users->get('', [UserController::class, 'index']);
            $users->post('', [UserController::class, 'create']);
            $users->get('/{id}', [UserController::class, 'show']);
            $users->put('/{id}', [UserController::class, 'update']);
            $users->delete('/{id}', [UserController::class, 'delete']);
            $users->get('/me', [UserController::class, 'me']);
        })->add(JwtMiddleware::class);
    });
};`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/Service/UserService.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Service;

use App\\Model\\User;
use App\\Exception\\ValidationException;
use App\\Exception\\NotFoundException;
use Illuminate\\Database\\Eloquent\\Collection;

class UserService
{
    public function createUser(array $data): User
    {
        $this->validateUserData($data);

        // Check if email already exists
        $existingUser = User::where('email', $data['email'])->first();
        if ($existingUser) {
            throw new ValidationException('Email already exists');
        }

        $user = new User();
        $user->email = $data['email'];
        $user->name = $data['name'];
        $user->role = $data['role'] ?? 'user';
        $user->password = password_hash($data['password'], PASSWORD_ARGON2ID);
        $user->save();

        return $user;
    }

    public function updateUser(User $user, array $data): User
    {
        if (isset($data['name'])) {
            $user->name = $data['name'];
        }

        if (isset($data['email'])) {
            // Check if new email already exists
            $existingUser = User::where('email', $data['email'])
                ->where('id', '!=', $user->id)
                ->first();
            if ($existingUser) {
                throw new ValidationException('Email already exists');
            }
            $user->email = $data['email'];
        }

        if (isset($data['password'])) {
            $user->password = password_hash($data['password'], PASSWORD_ARGON2ID);
        }

        if (isset($data['role'])) {
            $user->role = $data['role'];
        }

        $user->save();
        return $user;
    }

    public function deleteUser(User $user): bool
    {
        return $user->delete();
    }

    public function findById(string $id): User
    {
        $user = User::find($id);
        if (!$user) {
            throw new NotFoundException('User not found');
        }
        return $user;
    }

    public function findByEmail(string $email): ?User
    {
        return User::where('email', $email)->first();
    }

    public function getAllUsers(int $page = 1, int $perPage = 20): array
    {
        $offset = ($page - 1) * $perPage;
        
        $users = User::offset($offset)
            ->limit($perPage)
            ->orderBy('created_at', 'desc')
            ->get();
            
        $total = User::count();

        return [
            'data' => $users,
            'meta' => [
                'total' => $total,
                'page' => $page,
                'perPage' => $perPage,
                'pages' => ceil($total / $perPage)
            ]
        ];
    }

    public function verifyCredentials(string $email, string $password): ?User
    {
        $user = $this->findByEmail($email);
        
        if ($user && password_verify($password, $user->password)) {
            return $user;
        }
        
        return null;
    }

    private function validateUserData(array $data): void
    {
        $errors = [];

        if (empty($data['name'])) {
            $errors[] = 'Name is required';
        }

        if (empty($data['email'])) {
            $errors[] = 'Email is required';
        } elseif (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Email is not valid';
        }

        if (empty($data['password'])) {
            $errors[] = 'Password is required';
        } elseif (strlen($data['password']) < 8) {
            $errors[] = 'Password must be at least 8 characters';
        }

        if (!empty($errors)) {
            throw new ValidationException(implode(', ', $errors));
        }
    }
}`
      },
      {
        path: 'src/Service/AuthService.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Service;

use App\\Model\\User;
use App\\Exception\\ValidationException;
use App\\Exception\\UnauthorizedException;
use Firebase\\JWT\\JWT;
use Firebase\\JWT\\Key;

class AuthService
{
    private string $jwtSecret;
    private int $jwtExpiration;

    public function __construct(
        private UserService $userService
    ) {
        $this->jwtSecret = $_ENV['JWT_SECRET'] ?? 'your-secret-key';
        $this->jwtExpiration = (int) ($_ENV['JWT_EXPIRATION'] ?? 3600);
    }

    public function register(array $data): array
    {
        $user = $this->userService->createUser($data);
        $token = $this->generateToken($user);

        return [
            'user' => $this->serializeUser($user),
            'token' => $token,
            'expiresAt' => time() + $this->jwtExpiration
        ];
    }

    public function login(string $email, string $password): array
    {
        $user = $this->userService->verifyCredentials($email, $password);
        
        if (!$user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        $token = $this->generateToken($user);

        return [
            'user' => $this->serializeUser($user),
            'token' => $token,
            'expiresAt' => time() + $this->jwtExpiration
        ];
    }

    public function validateToken(string $token): ?User
    {
        try {
            $decoded = JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
            return $this->userService->findById($decoded->userId);
        } catch (\\Exception $e) {
            return null;
        }
    }

    public function refreshToken(string $token): array
    {
        $user = $this->validateToken($token);
        
        if (!$user) {
            throw new UnauthorizedException('Invalid token');
        }

        $newToken = $this->generateToken($user);

        return [
            'user' => $this->serializeUser($user),
            'token' => $newToken,
            'expiresAt' => time() + $this->jwtExpiration
        ];
    }

    private function generateToken(User $user): string
    {
        $payload = [
            'userId' => $user->id,
            'email' => $user->email,
            'role' => $user->role,
            'iat' => time(),
            'exp' => time() + $this->jwtExpiration
        ];

        return JWT::encode($payload, $this->jwtSecret, 'HS256');
    }

    private function serializeUser(User $user): array
    {
        return [
            'id' => $user->id,
            'email' => $user->email,
            'name' => $user->name,
            'role' => $user->role,
            'createdAt' => $user->created_at->toISOString(),
            'updatedAt' => $user->updated_at->toISOString()
        ];
    }
}`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'config/container.php',
        content: `<?php

declare(strict_types=1);

use App\\Service\\UserService;
use App\\Service\\AuthService;
use Monolog\\Logger;
use Monolog\\Handler\\StreamHandler;
use Monolog\\Handler\\RotatingFileHandler;
use Illuminate\\Database\\Capsule\\Manager as Capsule;
use Predis\\Client as RedisClient;
use Psr\\Container\\ContainerInterface;
use Psr\\Log\\LoggerInterface;

return [
    // Logger
    LoggerInterface::class => function () {
        $logger = new Logger('app');
        
        if ($_ENV['APP_ENV'] === 'production') {
            $logger->pushHandler(new RotatingFileHandler(
                __DIR__ . '/../storage/logs/app.log',
                0,
                Logger::INFO
            ));
        } else {
            $logger->pushHandler(new StreamHandler('php://stdout', Logger::DEBUG));
        }
        
        return $logger;
    },

    // Database
    'database' => function () {
        $capsule = new Capsule();
        
        $capsule->addConnection([
            'driver' => 'pgsql',
            'host' => $_ENV['DB_HOST'] ?? 'localhost',
            'port' => $_ENV['DB_PORT'] ?? 5432,
            'database' => $_ENV['DB_NAME'] ?? 'app_db',
            'username' => $_ENV['DB_USER'] ?? 'postgres',
            'password' => $_ENV['DB_PASSWORD'] ?? 'postgres',
            'charset' => 'utf8',
            'prefix' => '',
            'schema' => 'public',
        ]);

        $capsule->setAsGlobal();
        $capsule->bootEloquent();
        
        return $capsule;
    },

    // Redis
    'redis' => function () {
        return new RedisClient([
            'scheme' => 'tcp',
            'host' => $_ENV['REDIS_HOST'] ?? 'localhost',
            'port' => $_ENV['REDIS_PORT'] ?? 6379,
            'password' => $_ENV['REDIS_PASSWORD'] ?? null,
        ]);
    },

    // Services
    UserService::class => \\DI\\autowire(),
    
    AuthService::class => function (ContainerInterface $c) {
        return new AuthService($c->get(UserService::class));
    },
];`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/Model/User.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Model;

use Illuminate\\Database\\Eloquent\\Model;
use Illuminate\\Database\\Eloquent\\Concerns\\HasUuids;

class User extends Model
{
    use HasUuids;

    protected $table = 'users';

    protected $fillable = [
        'email',
        'name',
        'password',
        'role',
        'is_active'
    ];

    protected $hidden = [
        'password'
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime'
    ];

    public function hasRole(string $role): bool
    {
        return $this->role === $role;
    }

    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    public function isActive(): bool
    {
        return $this->is_active;
    }
}`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'config/routes.php',
        content: `<?php

declare(strict_types=1);

use Slim\\App;

return function (App $app) {
    $routes = require __DIR__ . '/routes/api.php';
    $routes($app);
};`
      },
      {
        path: 'config/routes/api.php',
        content: this.generateRoutingFile()
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/Middleware/JwtMiddleware.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Middleware;

use App\\Service\\AuthService;
use Psr\\Http\\Message\\ResponseInterface;
use Psr\\Http\\Message\\ServerRequestInterface;
use Psr\\Http\\Server\\MiddlewareInterface;
use Psr\\Http\\Server\\RequestHandlerInterface;
use Slim\\Psr7\\Response;

class JwtMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthService $authService
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $authHeader = $request->getHeaderLine('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return $this->unauthorizedResponse('Authorization header required');
        }

        $token = substr($authHeader, 7);
        $user = $this->authService->validateToken($token);

        if (!$user) {
            return $this->unauthorizedResponse('Invalid token');
        }

        // Add user to request attributes
        $request = $request->withAttribute('user', $user);

        return $handler->handle($request);
    }

    private function unauthorizedResponse(string $message): ResponseInterface
    {
        $response = new Response();
        $response->getBody()->write(json_encode([
            'error' => 'Unauthorized',
            'message' => $message
        ]));
        
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(401);
    }
}`
      },
      {
        path: 'src/Middleware/CorsMiddleware.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Middleware;

use Psr\\Http\\Message\\ResponseInterface;
use Psr\\Http\\Message\\ServerRequestInterface;
use Psr\\Http\\Server\\MiddlewareInterface;
use Psr\\Http\\Server\\RequestHandlerInterface;

class CorsMiddleware implements MiddlewareInterface
{
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $response = $handler->handle($request);
        
        return $response
            ->withHeader('Access-Control-Allow-Origin', '*')
            ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
            ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    }
}`
      },
      {
        path: 'src/Controller/HealthController.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Controller;

use Psr\\Http\\Message\\ResponseInterface;
use Psr\\Http\\Message\\ServerRequestInterface;
use Slim\\Psr7\\Response;

class HealthController
{
    public function check(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $data = [
            'status' => 'OK',
            'timestamp' => date('c'),
            'service' => $_ENV['APP_NAME'] ?? 'Slim API',
            'version' => '1.0.0'
        ];

        $response->getBody()->write(json_encode($data));
        return $response->withHeader('Content-Type', 'application/json');
    }
}`
      },
      {
        path: 'src/Controller/AuthController.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Controller;

use App\\Service\\AuthService;
use App\\Exception\\ValidationException;
use App\\Exception\\UnauthorizedException;
use Psr\\Http\\Message\\ResponseInterface;
use Psr\\Http\\Message\\ServerRequestInterface;
use Slim\\Psr7\\Response;

class AuthController
{
    public function __construct(
        private AuthService $authService
    ) {}

    public function register(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $data = json_decode($request->getBody()->getContents(), true);
            $result = $this->authService->register($data);

            $response->getBody()->write(json_encode([
                'message' => 'User registered successfully',
                'data' => $result
            ]));

            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(201);
        } catch (ValidationException $e) {
            return $this->errorResponse($response, $e->getMessage(), 422);
        } catch (\\Exception $e) {
            return $this->errorResponse($response, 'Registration failed', 500);
        }
    }

    public function login(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $data = json_decode($request->getBody()->getContents(), true);
            $result = $this->authService->login($data['email'], $data['password']);

            $response->getBody()->write(json_encode([
                'message' => 'Login successful',
                'data' => $result
            ]));

            return $response->withHeader('Content-Type', 'application/json');
        } catch (UnauthorizedException $e) {
            return $this->errorResponse($response, $e->getMessage(), 401);
        } catch (\\Exception $e) {
            return $this->errorResponse($response, 'Login failed', 500);
        }
    }

    public function refresh(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $data = json_decode($request->getBody()->getContents(), true);
            $result = $this->authService->refreshToken($data['token']);

            $response->getBody()->write(json_encode([
                'message' => 'Token refreshed successfully',
                'data' => $result
            ]));

            return $response->withHeader('Content-Type', 'application/json');
        } catch (UnauthorizedException $e) {
            return $this->errorResponse($response, $e->getMessage(), 401);
        } catch (\\Exception $e) {
            return $this->errorResponse($response, 'Token refresh failed', 500);
        }
    }

    public function logout(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        // In a real application, you might want to blacklist the token
        $response->getBody()->write(json_encode([
            'message' => 'Logout successful'
        ]));

        return $response->withHeader('Content-Type', 'application/json');
    }

    public function me(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $user = $request->getAttribute('user');

        $response->getBody()->write(json_encode([
            'data' => [
                'id' => $user->id,
                'email' => $user->email,
                'name' => $user->name,
                'role' => $user->role,
                'createdAt' => $user->created_at->toISOString(),
                'updatedAt' => $user->updated_at->toISOString()
            ]
        ]));

        return $response->withHeader('Content-Type', 'application/json');
    }

    private function errorResponse(ResponseInterface $response, string $message, int $status): ResponseInterface
    {
        $response->getBody()->write(json_encode([
            'error' => 'Error',
            'message' => $message
        ]));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus($status);
    }
}`
      },
      {
        path: 'src/Controller/UserController.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Controller;

use App\\Service\\UserService;
use App\\Exception\\ValidationException;
use App\\Exception\\NotFoundException;
use Psr\\Http\\Message\\ResponseInterface;
use Psr\\Http\\Message\\ServerRequestInterface;
use Slim\\Psr7\\Response;

class UserController
{
    public function __construct(
        private UserService $userService
    ) {}

    public function index(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $queryParams = $request->getQueryParams();
        $page = (int) ($queryParams['page'] ?? 1);
        $perPage = (int) ($queryParams['perPage'] ?? 20);

        $result = $this->userService->getAllUsers($page, $perPage);

        $response->getBody()->write(json_encode($result));
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function create(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $data = json_decode($request->getBody()->getContents(), true);
            $user = $this->userService->createUser($data);

            $response->getBody()->write(json_encode([
                'message' => 'User created successfully',
                'data' => $user->toArray()
            ]));

            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(201);
        } catch (ValidationException $e) {
            return $this->errorResponse($response, $e->getMessage(), 422);
        } catch (\\Exception $e) {
            return $this->errorResponse($response, 'User creation failed', 500);
        }
    }

    public function show(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        try {
            $user = $this->userService->findById($args['id']);

            $response->getBody()->write(json_encode([
                'data' => $user->toArray()
            ]));

            return $response->withHeader('Content-Type', 'application/json');
        } catch (NotFoundException $e) {
            return $this->errorResponse($response, $e->getMessage(), 404);
        }
    }

    public function update(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        try {
            $user = $this->userService->findById($args['id']);
            $data = json_decode($request->getBody()->getContents(), true);
            
            $updatedUser = $this->userService->updateUser($user, $data);

            $response->getBody()->write(json_encode([
                'message' => 'User updated successfully',
                'data' => $updatedUser->toArray()
            ]));

            return $response->withHeader('Content-Type', 'application/json');
        } catch (NotFoundException $e) {
            return $this->errorResponse($response, $e->getMessage(), 404);
        } catch (ValidationException $e) {
            return $this->errorResponse($response, $e->getMessage(), 422);
        } catch (\\Exception $e) {
            return $this->errorResponse($response, 'User update failed', 500);
        }
    }

    public function delete(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        try {
            $user = $this->userService->findById($args['id']);
            $this->userService->deleteUser($user);

            $response->getBody()->write(json_encode([
                'message' => 'User deleted successfully'
            ]));

            return $response->withHeader('Content-Type', 'application/json');
        } catch (NotFoundException $e) {
            return $this->errorResponse($response, $e->getMessage(), 404);
        } catch (\\Exception $e) {
            return $this->errorResponse($response, 'User deletion failed', 500);
        }
    }

    public function me(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $user = $request->getAttribute('user');

        $response->getBody()->write(json_encode([
            'data' => $user->toArray()
        ]));

        return $response->withHeader('Content-Type', 'application/json');
    }

    private function errorResponse(ResponseInterface $response, string $message, int $status): ResponseInterface
    {
        $response->getBody()->write(json_encode([
            'error' => 'Error',
            'message' => $message
        ]));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus($status);
    }
}`
      },
      {
        path: 'src/Exception/ValidationException.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Exception;

class ValidationException extends \\Exception
{
}`
      },
      {
        path: 'src/Exception/NotFoundException.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Exception;

class NotFoundException extends \\Exception
{
}`
      },
      {
        path: 'src/Exception/UnauthorizedException.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Exception;

class UnauthorizedException extends \\Exception
{
}`
      },
      {
        path: 'src/Handler/JsonErrorRenderer.php',
        content: `<?php

declare(strict_types=1);

namespace App\\Handler;

use Slim\\Exception\\HttpNotFoundException;
use Slim\\Interfaces\\ErrorRendererInterface;
use Throwable;

class JsonErrorRenderer implements ErrorRendererInterface
{
    public function __invoke(Throwable $exception, bool $displayErrorDetails): string
    {
        $error = [
            'error' => $this->getErrorTitle($exception),
            'message' => $exception->getMessage()
        ];

        if ($displayErrorDetails) {
            $error['details'] = [
                'file' => $exception->getFile(),
                'line' => $exception->getLine(),
                'trace' => $exception->getTraceAsString()
            ];
        }

        return json_encode($error, JSON_PRETTY_PRINT);
    }

    private function getErrorTitle(Throwable $exception): string
    {
        return match (true) {
            $exception instanceof HttpNotFoundException => 'Not Found',
            default => 'Server Error'
        };
    }
}`
      }
    ];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'tests/Controller/AuthControllerTest.php',
        content: `<?php

declare(strict_types=1);

namespace Tests\\Controller;

use PHPUnit\\Framework\\TestCase;
use App\\Service\\AuthService;
use App\\Service\\UserService;
use App\\Model\\User;

class AuthControllerTest extends TestCase
{
    private AuthService $authService;
    private UserService $userService;

    protected function setUp(): void
    {
        parent::setUp();
        
        // Initialize test database
        $this->initializeDatabase();
        
        $this->userService = new UserService();
        $this->authService = new AuthService($this->userService);
    }

    public function testRegister(): void
    {
        $userData = [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123'
        ];

        $result = $this->authService->register($userData);

        $this->assertArrayHasKey('user', $result);
        $this->assertArrayHasKey('token', $result);
        $this->assertEquals('Test User', $result['user']['name']);
        $this->assertEquals('test@example.com', $result['user']['email']);
    }

    public function testLogin(): void
    {
        // Create a user first
        $this->userService->createUser([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123'
        ]);

        $result = $this->authService->login('test@example.com', 'password123');

        $this->assertArrayHasKey('user', $result);
        $this->assertArrayHasKey('token', $result);
        $this->assertEquals('test@example.com', $result['user']['email']);
    }

    public function testInvalidLogin(): void
    {
        $this->expectException(\\App\\Exception\\UnauthorizedException::class);
        $this->authService->login('invalid@example.com', 'wrongpassword');
    }

    private function initializeDatabase(): void
    {
        // Initialize in-memory SQLite for testing
        $capsule = new \\Illuminate\\Database\\Capsule\\Manager();
        $capsule->addConnection([
            'driver' => 'sqlite',
            'database' => ':memory:',
        ]);
        $capsule->setAsGlobal();
        $capsule->bootEloquent();

        // Create users table
        $capsule->schema()->create('users', function ($table) {
            $table->uuid('id')->primary();
            $table->string('email')->unique();
            $table->string('name');
            $table->string('password');
            $table->string('role')->default('user');
            $table->boolean('is_active')->default(true);
            $table->timestamps();
        });
    }
}`
      }
    ];
  }
}