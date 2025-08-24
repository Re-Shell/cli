import { PhpBackendGenerator } from './php-base-generator';

export class CodeIgniterGenerator extends PhpBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'CodeIgniter';
    this.config.features = [
      'CodeIgniter 4 framework',
      'MVC architecture',
      'Built-in ORM (Entity, Model)',
      'RESTful API support',
      'Authentication library',
      'Database migrations',
      'Form validation',
      'Shield authentication',
      'Query builder'
    ];
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'codeigniter4/framework': '^4.4',
      'codeigniter4/shield': '^1.0',
      'firebase/php-jwt': '^6.8',
      'predis/predis': '^2.2'
    };
  }

  protected generateMainFile(): string {
    return `<?php

/*
 *---------------------------------------------------------------
 * CODEIGNITER 4 APPLICATION STARTER
 *---------------------------------------------------------------
 *
 * You can load different configurations depending on your
 * current environment. Setting the environment also influences
 * things like logging and error reporting.
 *
 * This can be set to anything, but default usage is:
 *
 *     development
 *     testing
 *     production
 *
 * NOTE: If you change these, also change the error_reporting() code below
 */
define('ENVIRONMENT', $_SERVER['CI_ENVIRONMENT'] ?? 'development');

/*
 *---------------------------------------------------------------
 * ERROR REPORTING
 *---------------------------------------------------------------
 *
 * Different environments will require different levels of error reporting.
 * By default development will show errors but testing and live will hide them.
 */

switch (ENVIRONMENT) {
    case 'development':
        error_reporting(-1);
        ini_set('display_errors', '1');
        break;

    case 'testing':
    case 'production':
        ini_set('display_errors', '0');
        error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED & ~E_STRICT & ~E_USER_NOTICE & ~E_USER_DEPRECATED);
        break;

    default:
        header('HTTP/1.1 503 Service Unavailable.', true, 503);
        echo 'The application environment is not set correctly.';
        exit(1); // EXIT_ERROR
}

/*
 *---------------------------------------------------------------
 * BOOTSTRAP THE APPLICATION
 *---------------------------------------------------------------
 *
 * This process sets up the path constants, loads and registers
 * our autoloader, along with Composer's, loads our constants
 * and fires up an environment-specific bootstrapping.
 */

// Ensure the current directory is pointing to the front controller's directory
chdir(__DIR__);

// Load our paths config file
$pathsConfig = FCPATH . '../app/Config/Paths.php';
require realpath($pathsConfig) ?: $pathsConfig;

// Location of the Paths config file.
$paths = new Config\\Paths();

// Location of the framework bootstrap file.
require rtrim($paths->systemDirectory, '\\\\/ ') . DIRECTORY_SEPARATOR . 'bootstrap.php';

// Load environment settings from .env files into $_SERVER and $_ENV
require_once SYSTEMPATH . 'Config/DotEnv.php';
(new CodeIgniter\\Config\\DotEnv(ROOTPATH))->load();

/*
 * ---------------------------------------------------------------
 * GRAB OUR CODEIGNITER INSTANCE
 * ---------------------------------------------------------------
 *
 * The CodeIgniter class contains the core functionality to make
 * the application run, and does all the dirty work for us.
 */
$app = Config\\Services::codeigniter();
$app->initialize();
$context = is_cli() ? 'php-cli' : 'web';
$app->setContext($context);

/*
 *---------------------------------------------------------------
 * LAUNCH THE APPLICATION
 *---------------------------------------------------------------
 *
 * Now that everything is setup, it's time to actually fire
 * up the engines and make this app do its thing.
 */

$app->run();`;
  }

  protected generateRoutingFile(): string {
    return `<?php

use CodeIgniter\\Router\\RouteCollection;

/**
 * @var RouteCollection $routes
 */

// Default home page
$routes->get('/', 'Home::index');

// Health check
$routes->get('health', 'Health::check');

// API routes
$routes->group('api', function ($routes) {
    
    // Authentication routes
    $routes->group('auth', function ($routes) {
        $routes->post('register', 'Auth::register');
        $routes->post('login', 'Auth::login');
        $routes->post('refresh', 'Auth::refresh');
        $routes->post('logout', 'Auth::logout', ['filter' => 'auth']);
        $routes->get('me', 'Auth::me', ['filter' => 'auth']);
    });

    // User routes (protected)
    $routes->group('users', ['filter' => 'auth'], function ($routes) {
        $routes->get('/', 'Users::index');
        $routes->post('/', 'Users::create');
        $routes->get('me', 'Users::me');
        $routes->get('(:segment)', 'Users::show/$1');
        $routes->put('(:segment)', 'Users::update/$1');
        $routes->delete('(:segment)', 'Users::delete/$1');
    });

    // Admin routes
    $routes->group('admin', ['filter' => 'auth:admin'], function ($routes) {
        $routes->get('users', 'Admin\\Users::index');
        $routes->delete('users/(:segment)', 'Admin\\Users::delete/$1');
    });
});`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Services/UserService.php',
        content: `<?php

namespace App\\Services;

use App\\Models\\UserModel;
use App\\Entities\\User;
use CodeIgniter\\Database\\Exceptions\\DatabaseException;

class UserService
{
    protected UserModel $userModel;

    public function __construct()
    {
        $this->userModel = new UserModel();
    }

    public function createUser(array $data): User
    {
        // Validate email doesn't exist
        if ($this->userModel->where('email', $data['email'])->first()) {
            throw new \\InvalidArgumentException('Email already exists');
        }

        // Hash password
        $data['password'] = password_hash($data['password'], PASSWORD_ARGON2ID);
        $data['role'] = $data['role'] ?? 'user';

        $userId = $this->userModel->insert($data);
        
        if (!$userId) {
            throw new DatabaseException('Failed to create user');
        }

        return $this->userModel->find($userId);
    }

    public function updateUser(string $id, array $data): User
    {
        $user = $this->findById($id);
        
        if (!$user) {
            throw new \\InvalidArgumentException('User not found');
        }

        // Check email uniqueness if changing
        if (isset($data['email']) && $data['email'] !== $user->email) {
            if ($this->userModel->where('email', $data['email'])->first()) {
                throw new \\InvalidArgumentException('Email already exists');
            }
        }

        // Hash password if provided
        if (isset($data['password'])) {
            $data['password'] = password_hash($data['password'], PASSWORD_ARGON2ID);
        }

        $success = $this->userModel->update($id, $data);
        
        if (!$success) {
            throw new DatabaseException('Failed to update user');
        }

        return $this->userModel->find($id);
    }

    public function deleteUser(string $id): bool
    {
        $user = $this->findById($id);
        
        if (!$user) {
            throw new \\InvalidArgumentException('User not found');
        }

        return $this->userModel->delete($id);
    }

    public function findById(string $id): ?User
    {
        return $this->userModel->find($id);
    }

    public function findByEmail(string $email): ?User
    {
        return $this->userModel->where('email', $email)->first();
    }

    public function getAllUsers(int $page = 1, int $perPage = 20): array
    {
        $offset = ($page - 1) * $perPage;
        
        $users = $this->userModel
            ->select('id, email, name, role, is_active, created_at, updated_at')
            ->orderBy('created_at', 'DESC')
            ->findAll($perPage, $offset);
            
        $total = $this->userModel->countAllResults();

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

    public function validateUserData(array $data): array
    {
        $rules = [
            'name' => 'required|min_length[2]|max_length[255]',
            'email' => 'required|valid_email|max_length[255]',
            'password' => 'required|min_length[8]'
        ];

        $validation = \\Config\\Services::validation();
        $validation->setRules($rules);

        if (!$validation->run($data)) {
            throw new \\InvalidArgumentException(implode(', ', $validation->getErrors()));
        }

        return $data;
    }
}`
      },
      {
        path: 'app/Services/AuthService.php',
        content: `<?php

namespace App\\Services;

use App\\Entities\\User;
use App\\Services\\UserService;
use Firebase\\JWT\\JWT;
use Firebase\\JWT\\Key;

class AuthService
{
    protected UserService $userService;
    protected string $jwtSecret;
    protected int $jwtExpiration;

    public function __construct()
    {
        $this->userService = new UserService();
        $this->jwtSecret = env('JWT_SECRET', 'your-secret-key');
        $this->jwtExpiration = (int) env('JWT_EXPIRATION', 3600);
    }

    public function register(array $data): array
    {
        $validatedData = $this->userService->validateUserData($data);
        $user = $this->userService->createUser($validatedData);
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
            throw new \\InvalidArgumentException('Invalid credentials');
        }

        if (!$user->is_active) {
            throw new \\InvalidArgumentException('Account is disabled');
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
            throw new \\InvalidArgumentException('Invalid token');
        }

        $newToken = $this->generateToken($user);

        return [
            'user' => $this->serializeUser($user),
            'token' => $newToken,
            'expiresAt' => time() + $this->jwtExpiration
        ];
    }

    protected function generateToken(User $user): string
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

    protected function serializeUser(User $user): array
    {
        return [
            'id' => $user->id,
            'email' => $user->email,
            'name' => $user->name,
            'role' => $user->role,
            'isActive' => $user->is_active,
            'createdAt' => $user->created_at,
            'updatedAt' => $user->updated_at
        ];
    }
}`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Models/UserModel.php',
        content: `<?php

namespace App\\Models;

use CodeIgniter\\Model;
use App\\Entities\\User;

class UserModel extends Model
{
    protected $table = 'users';
    protected $primaryKey = 'id';
    protected $useAutoIncrement = false;
    protected $returnType = User::class;
    protected $useSoftDeletes = false;
    protected $protectFields = true;
    protected $allowedFields = [
        'id',
        'email',
        'name',
        'password',
        'role',
        'is_active'
    ];

    // Dates
    protected $useTimestamps = true;
    protected $dateFormat = 'datetime';
    protected $createdField = 'created_at';
    protected $updatedField = 'updated_at';
    protected $deletedField = 'deleted_at';

    // Validation
    protected $validationRules = [
        'email' => 'required|valid_email|max_length[255]|is_unique[users.email,id,{id}]',
        'name' => 'required|min_length[2]|max_length[255]',
        'password' => 'required|min_length[8]',
        'role' => 'in_list[user,admin,moderator]'
    ];

    protected $validationMessages = [
        'email' => [
            'required' => 'Email is required',
            'valid_email' => 'Email must be a valid email address',
            'is_unique' => 'Email already exists'
        ],
        'name' => [
            'required' => 'Name is required',
            'min_length' => 'Name must be at least 2 characters'
        ],
        'password' => [
            'required' => 'Password is required',
            'min_length' => 'Password must be at least 8 characters'
        ]
    ];

    protected $skipValidation = false;
    protected $cleanValidationRules = true;

    // Callbacks
    protected $allowCallbacks = true;
    protected $beforeInsert = ['generateId', 'hashPassword'];
    protected $beforeUpdate = ['hashPassword'];

    protected function generateId(array $data): array
    {
        if (!isset($data['data']['id'])) {
            $data['data']['id'] = bin2hex(random_bytes(16));
        }
        return $data;
    }

    protected function hashPassword(array $data): array
    {
        if (isset($data['data']['password'])) {
            $data['data']['password'] = password_hash($data['data']['password'], PASSWORD_ARGON2ID);
        }
        return $data;
    }

    public function findByEmail(string $email): ?User
    {
        return $this->where('email', $email)->first();
    }

    public function findByRole(string $role): array
    {
        return $this->where('role', $role)->findAll();
    }

    public function getActiveUsers(): array
    {
        return $this->where('is_active', true)->findAll();
    }
}`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Entities/User.php',
        content: `<?php

namespace App\\Entities;

use CodeIgniter\\Entity\\Entity;

class User extends Entity
{
    protected $attributes = [
        'id' => null,
        'email' => null,
        'name' => null,
        'password' => null,
        'role' => 'user',
        'is_active' => true,
        'created_at' => null,
        'updated_at' => null
    ];

    protected $datamap = [];
    protected $dates = ['created_at', 'updated_at'];
    protected $casts = [
        'is_active' => 'boolean'
    ];

    // Automatically hash passwords when set
    public function setPassword(string $password): self
    {
        $this->attributes['password'] = password_hash($password, PASSWORD_ARGON2ID);
        return $this;
    }

    // Check if user has a specific role
    public function hasRole(string $role): bool
    {
        return $this->role === $role;
    }

    // Check if user is admin
    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    // Check if user is active
    public function isActive(): bool
    {
        return $this->is_active;
    }

    // Get user's display name
    public function getDisplayName(): string
    {
        return $this->name ?: $this->email;
    }

    // Convert to array (excluding password)
    public function toArray(): array
    {
        $data = parent::toArray();
        unset($data['password']);
        return $data;
    }
}`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Config/Routes.php',
        content: this.generateRoutingFile()
      },
      {
        path: 'app/Config/Database.php',
        content: `<?php

namespace Config;

use CodeIgniter\\Database\\Config;

/**
 * Database Configuration
 */
class Database extends Config
{
    /**
     * The directory that holds the Migrations
     * and Seeds directories.
     */
    public string $filesPath = APPPATH . 'Database' . DIRECTORY_SEPARATOR;

    /**
     * Lets you choose which connection group to
     * use if no other is specified.
     */
    public string $defaultGroup = 'default';

    /**
     * The default database connection.
     */
    public array $default = [
        'DSN'          => '',
        'hostname'     => '',
        'username'     => '',
        'password'     => '',
        'database'     => '',
        'DBDriver'     => 'Postgre',
        'DBPrefix'     => '',
        'pConnect'     => false,
        'DBDebug'      => true,
        'charset'      => 'utf8',
        'DBCollat'     => 'utf8_general_ci',
        'swapPre'      => '',
        'encrypt'      => false,
        'compress'     => false,
        'strictOn'     => false,
        'failover'     => [],
        'port'         => 5432,
        'numberNative' => false,
    ];

    /**
     * This database connection is used when
     * running PHPUnit database tests.
     */
    public array $tests = [
        'DSN'         => '',
        'hostname'    => '127.0.0.1',
        'username'    => 'root',
        'password'    => '',
        'database'    => ':memory:',
        'DBDriver'    => 'SQLite3',
        'DBPrefix'    => 'db_',  // Needed to ensure we're working correctly with prefixes live. DO NOT REMOVE FOR CI DEVS
        'pConnect'    => false,
        'DBDebug'     => true,
        'charset'     => 'utf8',
        'DBCollat'    => 'utf8_general_ci',
        'swapPre'     => '',
        'encrypt'     => false,
        'compress'    => false,
        'strictOn'    => false,
        'failover'    => [],
        'port'        => 3306,
        'foreignKeys' => true,
        'busyTimeout' => 1000,
    ];

    public function __construct()
    {
        parent::__construct();

        // Ensure that we always set the database group to 'tests' if
        // we are currently running an automated test suite, so that
        // we don't overwrite live data on accident.
        if (ENVIRONMENT === 'testing') {
            $this->defaultGroup = 'tests';
        }

        // Build the default connection from environment variables
        $this->default = [
            'DSN'          => env('DATABASE_URL', ''),
            'hostname'     => env('DB_HOST', 'localhost'),
            'username'     => env('DB_USER', 'postgres'),
            'password'     => env('DB_PASSWORD', 'postgres'),
            'database'     => env('DB_NAME', 'app_db'),
            'DBDriver'     => env('DB_DRIVER', 'Postgre'),
            'DBPrefix'     => '',
            'pConnect'     => false,
            'DBDebug'      => ENVIRONMENT !== 'production',
            'charset'      => 'utf8',
            'DBCollat'     => 'utf8_general_ci',
            'swapPre'      => '',
            'encrypt'      => false,
            'compress'     => false,
            'strictOn'     => false,
            'failover'     => [],
            'port'         => (int) env('DB_PORT', 5432),
            'numberNative' => false,
        ];
    }
}`
      },
      {
        path: 'app/Config/Filters.php',
        content: `<?php

namespace Config;

use CodeIgniter\\Config\\BaseConfig;
use CodeIgniter\\Filters\\CSRF;
use CodeIgniter\\Filters\\DebugToolbar;
use CodeIgniter\\Filters\\Honeypot;
use CodeIgniter\\Filters\\InvalidChars;
use CodeIgniter\\Filters\\SecureHeaders;

class Filters extends BaseConfig
{
    /**
     * Configures aliases for Filter classes to
     * make reading things nicer and simpler.
     */
    public array $aliases = [
        'csrf'          => CSRF::class,
        'toolbar'       => DebugToolbar::class,
        'honeypot'      => Honeypot::class,
        'invalidchars'  => InvalidChars::class,
        'secureheaders' => SecureHeaders::class,
        'auth'          => \\App\\Filters\\AuthFilter::class,
        'cors'          => \\App\\Filters\\CorsFilter::class,
    ];

    /**
     * List of filter aliases that are always
     * applied before and after every request.
     */
    public array $globals = [
        'before' => [
            'cors',
            // 'honeypot',
            // 'csrf',
            // 'invalidchars',
        ],
        'after' => [
            'toolbar',
            // 'honeypot',
            // 'secureheaders',
        ],
    ];

    /**
     * List of filter aliases that works on a
     * particular HTTP method (GET, POST, etc.).
     */
    public array $methods = [];

    /**
     * List of filter aliases that should run on any
     * before or after URI patterns.
     */
    public array $filters = [];
}`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Filters/AuthFilter.php',
        content: `<?php

namespace App\\Filters;

use CodeIgniter\\Filters\\FilterInterface;
use CodeIgniter\\HTTP\\RequestInterface;
use CodeIgniter\\HTTP\\ResponseInterface;
use App\\Services\\AuthService;

class AuthFilter implements FilterInterface
{
    protected AuthService $authService;

    public function __construct()
    {
        $this->authService = new AuthService();
    }

    public function before(RequestInterface $request, $arguments = null)
    {
        $authHeader = $request->getHeaderLine('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return $this->unauthorizedResponse('Authorization header required');
        }

        $token = substr($authHeader, 7);
        $user = $this->authService->validateToken($token);

        if (!$user) {
            return $this->unauthorizedResponse('Invalid token');
        }

        // Check role if specified
        if (!empty($arguments)) {
            $requiredRole = $arguments[0];
            if (!$user->hasRole($requiredRole)) {
                return $this->forbiddenResponse('Insufficient permissions');
            }
        }

        // Store user in request for controllers to access
        $request->user = $user;
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // Nothing to do here
    }

    protected function unauthorizedResponse(string $message)
    {
        $response = service('response');
        $response->setStatusCode(401);
        $response->setContentType('application/json');
        $response->setBody(json_encode([
            'error' => 'Unauthorized',
            'message' => $message
        ]));
        return $response;
    }

    protected function forbiddenResponse(string $message)
    {
        $response = service('response');
        $response->setStatusCode(403);
        $response->setContentType('application/json');
        $response->setBody(json_encode([
            'error' => 'Forbidden',
            'message' => $message
        ]));
        return $response;
    }
}`
      },
      {
        path: 'app/Filters/CorsFilter.php',
        content: `<?php

namespace App\\Filters;

use CodeIgniter\\Filters\\FilterInterface;
use CodeIgniter\\HTTP\\RequestInterface;
use CodeIgniter\\HTTP\\ResponseInterface;

class CorsFilter implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        // Handle preflight requests
        if ($request->getMethod() === 'OPTIONS') {
            $response = service('response');
            $response->setHeader('Access-Control-Allow-Origin', '*');
            $response->setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            $response->setHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization');
            $response->setHeader('Access-Control-Max-Age', '86400');
            $response->setStatusCode(200);
            return $response;
        }
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        $response->setHeader('Access-Control-Allow-Origin', '*');
        $response->setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        $response->setHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization');
    }
}`
      },
      {
        path: 'app/Controllers/Health.php',
        content: `<?php

namespace App\\Controllers;

use CodeIgniter\\RESTful\\ResourceController;

class Health extends ResourceController
{
    protected $format = 'json';

    public function check()
    {
        return $this->respond([
            'status' => 'OK',
            'timestamp' => date('c'),
            'service' => env('APP_NAME', 'CodeIgniter API'),
            'version' => '1.0.0'
        ]);
    }
}`
      },
      {
        path: 'app/Controllers/Auth.php',
        content: `<?php

namespace App\\Controllers;

use CodeIgniter\\RESTful\\ResourceController;
use App\\Services\\AuthService;

class Auth extends ResourceController
{
    protected $format = 'json';
    protected AuthService $authService;

    public function __construct()
    {
        $this->authService = new AuthService();
    }

    public function register()
    {
        try {
            $data = $this->request->getJSON(true);
            $result = $this->authService->register($data);

            return $this->respond([
                'message' => 'User registered successfully',
                'data' => $result
            ], 201);
        } catch (\\InvalidArgumentException $e) {
            return $this->failValidationError($e->getMessage());
        } catch (\\Exception $e) {
            return $this->failServerError('Registration failed');
        }
    }

    public function login()
    {
        try {
            $data = $this->request->getJSON(true);
            $result = $this->authService->login($data['email'], $data['password']);

            return $this->respond([
                'message' => 'Login successful',
                'data' => $result
            ]);
        } catch (\\InvalidArgumentException $e) {
            return $this->failUnauthorized($e->getMessage());
        } catch (\\Exception $e) {
            return $this->failServerError('Login failed');
        }
    }

    public function refresh()
    {
        try {
            $data = $this->request->getJSON(true);
            $result = $this->authService->refreshToken($data['token']);

            return $this->respond([
                'message' => 'Token refreshed successfully',
                'data' => $result
            ]);
        } catch (\\InvalidArgumentException $e) {
            return $this->failUnauthorized($e->getMessage());
        } catch (\\Exception $e) {
            return $this->failServerError('Token refresh failed');
        }
    }

    public function logout()
    {
        // In a real application, you might want to blacklist the token
        return $this->respond([
            'message' => 'Logout successful'
        ]);
    }

    public function me()
    {
        $user = $this->request->user;

        return $this->respond([
            'data' => $user->toArray()
        ]);
    }
}`
      },
      {
        path: 'app/Controllers/Users.php',
        content: `<?php

namespace App\\Controllers;

use CodeIgniter\\RESTful\\ResourceController;
use App\\Services\\UserService;

class Users extends ResourceController
{
    protected $format = 'json';
    protected UserService $userService;

    public function __construct()
    {
        $this->userService = new UserService();
    }

    public function index()
    {
        $page = (int) ($this->request->getGet('page') ?? 1);
        $perPage = (int) ($this->request->getGet('perPage') ?? 20);

        $result = $this->userService->getAllUsers($page, $perPage);

        return $this->respond($result);
    }

    public function create()
    {
        try {
            $data = $this->request->getJSON(true);
            $user = $this->userService->createUser($data);

            return $this->respond([
                'message' => 'User created successfully',
                'data' => $user->toArray()
            ], 201);
        } catch (\\InvalidArgumentException $e) {
            return $this->failValidationError($e->getMessage());
        } catch (\\Exception $e) {
            return $this->failServerError('User creation failed');
        }
    }

    public function show($id = null)
    {
        try {
            $user = $this->userService->findById($id);
            
            if (!$user) {
                return $this->failNotFound('User not found');
            }

            return $this->respond([
                'data' => $user->toArray()
            ]);
        } catch (\\Exception $e) {
            return $this->failServerError('Failed to retrieve user');
        }
    }

    public function update($id = null)
    {
        try {
            $data = $this->request->getJSON(true);
            $user = $this->userService->updateUser($id, $data);

            return $this->respond([
                'message' => 'User updated successfully',
                'data' => $user->toArray()
            ]);
        } catch (\\InvalidArgumentException $e) {
            return $this->failValidationError($e->getMessage());
        } catch (\\Exception $e) {
            return $this->failServerError('User update failed');
        }
    }

    public function delete($id = null)
    {
        try {
            $this->userService->deleteUser($id);

            return $this->respond([
                'message' => 'User deleted successfully'
            ]);
        } catch (\\InvalidArgumentException $e) {
            return $this->failNotFound($e->getMessage());
        } catch (\\Exception $e) {
            return $this->failServerError('User deletion failed');
        }
    }

    public function me()
    {
        $user = $this->request->user;

        return $this->respond([
            'data' => $user->toArray()
        ]);
    }
}`
      }
    ];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'tests/Feature/AuthTest.php',
        content: `<?php

namespace Tests\\Feature;

use CodeIgniter\\Test\\CIUnitTestCase;
use CodeIgniter\\Test\\FeatureTestTrait;
use CodeIgniter\\Test\\DatabaseTestTrait;

class AuthTest extends CIUnitTestCase
{
    use FeatureTestTrait;
    use DatabaseTestTrait;

    protected $migrate = true;
    protected $migrateOnce = false;
    protected $refresh = true;
    protected $namespace = null;

    public function testRegister()
    {
        $userData = [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123'
        ];

        $result = $this->withBodyFormat('json')
            ->post('/api/auth/register', $userData);

        $result->assertStatus(201);
        $result->assertJSONFragment(['message' => 'User registered successfully']);
        
        $response = $result->getJSON();
        $this->assertArrayHasKey('data', $response);
        $this->assertArrayHasKey('user', $response['data']);
        $this->assertArrayHasKey('token', $response['data']);
    }

    public function testLogin()
    {
        // Create a user first
        $userData = [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123'
        ];

        $this->withBodyFormat('json')->post('/api/auth/register', $userData);

        // Now try to login
        $loginData = [
            'email' => 'test@example.com',
            'password' => 'password123'
        ];

        $result = $this->withBodyFormat('json')
            ->post('/api/auth/login', $loginData);

        $result->assertStatus(200);
        $result->assertJSONFragment(['message' => 'Login successful']);
        
        $response = $result->getJSON();
        $this->assertArrayHasKey('data', $response);
        $this->assertArrayHasKey('token', $response['data']);
    }

    public function testHealthCheck()
    {
        $result = $this->get('/health');

        $result->assertStatus(200);
        $result->assertJSONFragment(['status' => 'OK']);
    }

    public function testProtectedRoute()
    {
        $result = $this->get('/api/users/me');

        $result->assertStatus(401);
        $result->assertJSONFragment(['error' => 'Unauthorized']);
    }
}`
      },
      {
        path: 'app/Database/Migrations/2024-01-01-000001_CreateUsersTable.php',
        content: `<?php

namespace App\\Database\\Migrations;

use CodeIgniter\\Database\\Migration;

class CreateUsersTable extends Migration
{
    public function up()
    {
        $this->forge->addField([
            'id' => [
                'type' => 'VARCHAR',
                'constraint' => 32,
            ],
            'email' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'unique' => true,
            ],
            'name' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
            ],
            'password' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
            ],
            'role' => [
                'type' => 'VARCHAR',
                'constraint' => 50,
                'default' => 'user',
            ],
            'is_active' => [
                'type' => 'BOOLEAN',
                'default' => true,
            ],
            'created_at' => [
                'type' => 'DATETIME',
                'null' => true,
            ],
            'updated_at' => [
                'type' => 'DATETIME',
                'null' => true,
            ],
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey('email');
        $this->forge->addKey(['role']);
        $this->forge->addKey(['is_active']);
        $this->forge->createTable('users');
    }

    public function down()
    {
        $this->forge->dropTable('users');
    }
}`
      }
    ];
  }
}