import { PhpBackendGenerator } from './php-base-generator';

export class LaravelGenerator extends PhpBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Laravel';
    this.config.features = [
      'Laravel 11 framework',
      'Eloquent ORM with migrations',
      'Artisan command-line tool',
      'Blade templating engine',
      'Laravel Sanctum authentication',
      'Queue system with Redis',
      'Event-driven architecture',
      'Laravel Mix for asset compilation',
      'Comprehensive testing suite'
    ];
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'laravel/framework': '^11.0',
      'laravel/sanctum': '^4.0',
      'laravel/tinker': '^2.9',
      'predis/predis': '^2.2',
      'guzzlehttp/guzzle': '^7.8',
      'symfony/http-client': '^7.0',
      'doctrine/dbal': '^4.0'
    };
  }

  protected generateMainFile(): string {
    return `<?php

use Illuminate\\Http\\Request;
use Illuminate\\Foundation\\Application;
use Illuminate\\Foundation\\Configuration\\Exceptions;
use Illuminate\\Foundation\\Configuration\\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/health',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->api(prepend: [
            \\Laravel\\Sanctum\\Http\\Middleware\\EnsureFrontendRequestsAreStateful::class,
        ]);

        $middleware->alias([
            'verified' => \\Illuminate\\Auth\\Middleware\\EnsureEmailIsVerified::class,
        ]);

        $middleware->throttleApi();
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();`;
  }

  protected generateRoutingFile(): string {
    return `<?php

use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\AuthController;
use App\\Http\\Controllers\\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Health check
Route::get('/health', function () {
    return response()->json([
        'status' => 'OK',
        'timestamp' => now(),
        'service' => config('app.name'),
        'version' => config('app.version', '1.0.0')
    ]);
});

// Authentication routes
Route::prefix('auth')->group(function () {
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('me', [AuthController::class, 'me']);
    });
});

// User routes
Route::middleware('auth:sanctum')->group(function () {
    Route::apiResource('users', UserController::class);
    Route::get('users/me', [UserController::class, 'me']);
});

// Admin routes
Route::middleware(['auth:sanctum', 'role:admin'])->prefix('admin')->group(function () {
    Route::get('users', [UserController::class, 'index']);
    Route::delete('users/{user}', [UserController::class, 'destroy']);
});`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Services/UserService.php',
        content: `<?php

namespace App\\Services;

use App\\Models\\User;
use App\\Http\\Requests\\CreateUserRequest;
use App\\Http\\Requests\\UpdateUserRequest;
use Illuminate\\Support\\Facades\\Hash;
use Illuminate\\Support\\Facades\\DB;
use Illuminate\\Pagination\\LengthAwarePaginator;

class UserService
{
    public function createUser(CreateUserRequest $request): User
    {
        return DB::transaction(function () use ($request) {
            return User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'role' => $request->role ?? 'user'
            ]);
        });
    }

    public function updateUser(User $user, UpdateUserRequest $request): User
    {
        return DB::transaction(function () use ($user, $request) {
            $data = $request->only(['name', 'email', 'role']);
            
            if ($request->filled('password')) {
                $data['password'] = Hash::make($request->password);
            }

            $user->update($data);
            return $user->fresh();
        });
    }

    public function deleteUser(User $user): bool
    {
        return DB::transaction(function () use ($user) {
            // Revoke all tokens
            $user->tokens()->delete();
            
            return $user->delete();
        });
    }

    public function getAllUsers(int $page = 1, int $perPage = 20): LengthAwarePaginator
    {
        return User::select(['id', 'name', 'email', 'role', 'email_verified_at', 'created_at'])
            ->paginate($perPage, ['*'], 'page', $page);
    }

    public function findById(string $id): ?User
    {
        return User::find($id);
    }

    public function findByEmail(string $email): ?User
    {
        return User::where('email', $email)->first();
    }

    public function verifyCredentials(string $email, string $password): ?User
    {
        $user = $this->findByEmail($email);
        
        if ($user && Hash::check($password, $user->password)) {
            return $user;
        }
        
        return null;
    }
}`
      },
      {
        path: 'app/Services/AuthService.php',
        content: `<?php

namespace App\\Services;

use App\\Models\\User;
use App\\Http\\Requests\\RegisterRequest;
use App\\Http\\Requests\\LoginRequest;
use Illuminate\\Support\\Facades\\Hash;
use Illuminate\\Support\\Facades\\Auth;
use Illuminate\\Support\\Facades\\RateLimiter;
use Illuminate\\Validation\\ValidationException;
use Laravel\\Sanctum\\PersonalAccessToken;

class AuthService
{
    public function __construct(
        private UserService $userService
    ) {}

    public function register(RegisterRequest $request): array
    {
        $user = $this->userService->createUser($request);
        
        $token = $user->createToken('auth-token', ['*'], now()->addHours(24));
        
        return [
            'user' => $user->toArray(),
            'token' => $token->plainTextToken,
            'expires_at' => $token->accessToken->expires_at
        ];
    }

    public function login(LoginRequest $request): array
    {
        $this->checkRateLimit($request->email);

        $user = $this->userService->verifyCredentials(
            $request->email,
            $request->password
        );

        if (!$user) {
            RateLimiter::hit($this->getRateLimitKey($request->email));
            
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        // Clear rate limit on successful login
        RateLimiter::clear($this->getRateLimitKey($request->email));

        // Revoke existing tokens if requested
        if ($request->boolean('revoke_existing_tokens')) {
            $user->tokens()->delete();
        }

        $token = $user->createToken('auth-token', ['*'], now()->addHours(24));

        return [
            'user' => $user->toArray(),
            'token' => $token->plainTextToken,
            'expires_at' => $token->accessToken->expires_at
        ];
    }

    public function logout(?string $tokenId = null): bool
    {
        $user = Auth::user();
        
        if ($tokenId) {
            // Logout from specific token
            $token = $user->tokens()->where('id', $tokenId)->first();
            return $token ? $token->delete() : false;
        }
        
        // Logout from current token
        return $user->currentAccessToken()->delete();
    }

    public function logoutFromAllDevices(): bool
    {
        $user = Auth::user();
        return $user->tokens()->delete();
    }

    public function refreshToken(string $tokenId): array
    {
        $token = PersonalAccessToken::find($tokenId);
        
        if (!$token || $token->expires_at < now()) {
            throw ValidationException::withMessages([
                'token' => ['Invalid or expired token.'],
            ]);
        }

        $user = $token->tokenable;
        
        // Create new token
        $newToken = $user->createToken('auth-token', ['*'], now()->addHours(24));
        
        // Delete old token
        $token->delete();

        return [
            'user' => $user->toArray(),
            'token' => $newToken->plainTextToken,
            'expires_at' => $newToken->accessToken->expires_at
        ];
    }

    private function checkRateLimit(string $email): void
    {
        $key = $this->getRateLimitKey($email);
        
        if (RateLimiter::tooManyAttempts($key, 5)) {
            $seconds = RateLimiter::availableIn($key);
            
            throw ValidationException::withMessages([
                'email' => ["Too many login attempts. Please try again in {$seconds} seconds."],
            ]);
        }
    }

    private function getRateLimitKey(string $email): string
    {
        return 'login:' . strtolower($email);
    }
}`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Repositories/UserRepository.php',
        content: `<?php

namespace App\\Repositories;

use App\\Models\\User;
use Illuminate\\Database\\Eloquent\\Collection;
use Illuminate\\Pagination\\LengthAwarePaginator;

class UserRepository
{
    public function create(array $data): User
    {
        return User::create($data);
    }

    public function findById(string $id): ?User
    {
        return User::find($id);
    }

    public function findByEmail(string $email): ?User
    {
        return User::where('email', $email)->first();
    }

    public function update(User $user, array $data): bool
    {
        return $user->update($data);
    }

    public function delete(User $user): bool
    {
        return $user->delete();
    }

    public function paginate(int $perPage = 15, array $columns = ['*']): LengthAwarePaginator
    {
        return User::select($columns)->paginate($perPage);
    }

    public function getByRole(string $role): Collection
    {
        return User::where('role', $role)->get();
    }

    public function getActive(): Collection
    {
        return User::whereNotNull('email_verified_at')->get();
    }

    public function search(string $query, int $perPage = 15): LengthAwarePaginator
    {
        return User::where('name', 'like', "%{$query}%")
            ->orWhere('email', 'like', "%{$query}%")
            ->paginate($perPage);
    }
}`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Models/User.php',
        content: `<?php

namespace App\\Models;

use Illuminate\\Database\\Eloquent\\Concerns\\HasUuids;
use Illuminate\\Database\\Eloquent\\Factories\\HasFactory;
use Illuminate\\Foundation\\Auth\\User as Authenticatable;
use Illuminate\\Notifications\\Notifiable;
use Laravel\\Sanctum\\HasApiTokens;
use Illuminate\\Database\\Eloquent\\SoftDeletes;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable, HasUuids, SoftDeletes;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'role',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    /**
     * Check if user has a specific role.
     */
    public function hasRole(string $role): bool
    {
        return $this->role === $role;
    }

    /**
     * Check if user is admin.
     */
    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    /**
     * Check if user is verified.
     */
    public function isVerified(): bool
    {
        return !is_null($this->email_verified_at);
    }

    /**
     * Scope for filtering by role.
     */
    public function scopeRole($query, string $role)
    {
        return $query->where('role', $role);
    }

    /**
     * Scope for verified users.
     */
    public function scopeVerified($query)
    {
        return $query->whereNotNull('email_verified_at');
    }
}`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'config/app.php',
        content: `<?php

use Illuminate\\Support\\Facades\\Facade;
use Illuminate\\Support\\ServiceProvider;

return [
    'name' => env('APP_NAME', 'Laravel API'),
    'env' => env('APP_ENV', 'production'),
    'debug' => (bool) env('APP_DEBUG', false),
    'url' => env('APP_URL', 'http://localhost'),
    'asset_url' => env('ASSET_URL'),
    'timezone' => env('APP_TIMEZONE', 'UTC'),
    'locale' => env('APP_LOCALE', 'en'),
    'fallback_locale' => env('APP_FALLBACK_LOCALE', 'en'),
    'faker_locale' => env('APP_FAKER_LOCALE', 'en_US'),
    'cipher' => 'AES-256-CBC',
    'key' => env('APP_KEY'),
    'previous_keys' => [
        ...array_filter(
            explode(',', env('APP_PREVIOUS_KEYS', ''))
        ),
    ],
    'maintenance' => [
        'driver' => env('APP_MAINTENANCE_DRIVER', 'file'),
        'store' => env('APP_MAINTENANCE_STORE', 'database'),
    ],
];`
      },
      {
        path: 'config/database.php',
        content: `<?php

use Illuminate\\Support\\Str;

return [
    'default' => env('DB_CONNECTION', 'pgsql'),

    'connections' => [
        'pgsql' => [
            'driver' => 'pgsql',
            'url' => env('DB_URL'),
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '5432'),
            'database' => env('DB_DATABASE', 'laravel'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'charset' => env('DB_CHARSET', 'utf8'),
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => 'prefer',
        ],

        'redis' => [
            'client' => env('REDIS_CLIENT', 'phpredis'),
            'options' => [
                'cluster' => env('REDIS_CLUSTER', 'redis'),
                'prefix' => env('REDIS_PREFIX', Str::slug(env('APP_NAME', 'laravel'), '_').'_database_'),
            ],
            'default' => [
                'url' => env('REDIS_URL'),
                'host' => env('REDIS_HOST', '127.0.0.1'),
                'username' => env('REDIS_USERNAME'),
                'password' => env('REDIS_PASSWORD'),
                'port' => env('REDIS_PORT', '6379'),
                'database' => env('REDIS_DB', '0'),
            ],
            'cache' => [
                'url' => env('REDIS_URL'),
                'host' => env('REDIS_HOST', '127.0.0.1'),
                'username' => env('REDIS_USERNAME'),
                'password' => env('REDIS_PASSWORD'),
                'port' => env('REDIS_PORT', '6379'),
                'database' => env('REDIS_CACHE_DB', '1'),
            ],
        ],
    ],

    'migrations' => [
        'table' => 'migrations',
        'update_date_on_publish' => true,
    ],
];`
      },
      {
        path: 'config/sanctum.php',
        content: `<?php

return [
    'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS', sprintf(
        '%s%s%s',
        'localhost,localhost:3000,127.0.0.1,127.0.0.1:8000,::1',
        env('APP_URL') ? ','.parse_url(env('APP_URL'), PHP_URL_HOST) : '',
        env('FRONTEND_URL') ? ','.parse_url(env('FRONTEND_URL'), PHP_URL_HOST) : ''
    ))),

    'guard' => ['web'],

    'expiration' => null,

    'token_prefix' => env('SANCTUM_TOKEN_PREFIX', ''),

    'middleware' => [
        'authenticate_session' => Laravel\\Sanctum\\Http\\Middleware\\AuthenticateSession::class,
        'encrypt_cookies' => Illuminate\\Cookie\\Middleware\\EncryptCookies::class,
        'validate_csrf_token' => Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class,
    ],
];`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/Http/Middleware/RoleMiddleware.php',
        content: `<?php

namespace App\\Http\\Middleware;

use Closure;
use Illuminate\\Http\\Request;
use Illuminate\\Http\\Response;
use Symfony\\Component\\HttpFoundation\\Response as BaseResponse;

class RoleMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \\Closure(\\Illuminate\\Http\\Request): (\\Symfony\\Component\\HttpFoundation\\Response)  $next
     */
    public function handle(Request $request, Closure $next, string $role): BaseResponse
    {
        if (!$request->user() || !$request->user()->hasRole($role)) {
            return response()->json([
                'message' => 'Forbidden. Insufficient permissions.'
            ], Response::HTTP_FORBIDDEN);
        }

        return $next($request);
    }
}`
      },
      {
        path: 'app/Http/Controllers/AuthController.php',
        content: `<?php

namespace App\\Http\\Controllers;

use App\\Http\\Requests\\RegisterRequest;
use App\\Http\\Requests\\LoginRequest;
use App\\Services\\AuthService;
use Illuminate\\Http\\JsonResponse;
use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\Auth;

class AuthController extends Controller
{
    public function __construct(
        private AuthService $authService
    ) {}

    public function register(RegisterRequest $request): JsonResponse
    {
        try {
            $result = $this->authService->register($request);
            
            return response()->json([
                'message' => 'User registered successfully',
                'data' => $result
            ], 201);
        } catch (\\Exception $e) {
            return response()->json([
                'message' => 'Registration failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    public function login(LoginRequest $request): JsonResponse
    {
        try {
            $result = $this->authService->login($request);
            
            return response()->json([
                'message' => 'Login successful',
                'data' => $result
            ]);
        } catch (\\Exception $e) {
            return response()->json([
                'message' => 'Login failed',
                'error' => $e->getMessage()
            ], 401);
        }
    }

    public function logout(Request $request): JsonResponse
    {
        try {
            $tokenId = $request->input('token_id');
            $this->authService->logout($tokenId);
            
            return response()->json([
                'message' => 'Logout successful'
            ]);
        } catch (\\Exception $e) {
            return response()->json([
                'message' => 'Logout failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    public function me(): JsonResponse
    {
        return response()->json([
            'data' => Auth::user()
        ]);
    }

    public function refresh(Request $request): JsonResponse
    {
        try {
            $tokenId = $request->input('token_id');
            $result = $this->authService->refreshToken($tokenId);
            
            return response()->json([
                'message' => 'Token refreshed successfully',
                'data' => $result
            ]);
        } catch (\\Exception $e) {
            return response()->json([
                'message' => 'Token refresh failed',
                'error' => $e->getMessage()
            ], 401);
        }
    }
}`
      },
      {
        path: 'app/Http/Controllers/UserController.php',
        content: `<?php

namespace App\\Http\\Controllers;

use App\\Http\\Requests\\CreateUserRequest;
use App\\Http\\Requests\\UpdateUserRequest;
use App\\Http\\Resources\\UserResource;
use App\\Models\\User;
use App\\Services\\UserService;
use Illuminate\\Http\\JsonResponse;
use Illuminate\\Http\\Request;
use Illuminate\\Http\\Resources\\Json\\AnonymousResourceCollection;

class UserController extends Controller
{
    public function __construct(
        private UserService $userService
    ) {}

    public function index(Request $request): AnonymousResourceCollection
    {
        $perPage = $request->input('per_page', 15);
        $users = $this->userService->getAllUsers(perPage: $perPage);
        
        return UserResource::collection($users);
    }

    public function store(CreateUserRequest $request): JsonResponse
    {
        try {
            $user = $this->userService->createUser($request);
            
            return response()->json([
                'message' => 'User created successfully',
                'data' => new UserResource($user)
            ], 201);
        } catch (\\Exception $e) {
            return response()->json([
                'message' => 'User creation failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    public function show(User $user): JsonResponse
    {
        return response()->json([
            'data' => new UserResource($user)
        ]);
    }

    public function update(UpdateUserRequest $request, User $user): JsonResponse
    {
        try {
            $updatedUser = $this->userService->updateUser($user, $request);
            
            return response()->json([
                'message' => 'User updated successfully',
                'data' => new UserResource($updatedUser)
            ]);
        } catch (\\Exception $e) {
            return response()->json([
                'message' => 'User update failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    public function destroy(User $user): JsonResponse
    {
        try {
            $this->userService->deleteUser($user);
            
            return response()->json([
                'message' => 'User deleted successfully'
            ]);
        } catch (\\Exception $e) {
            return response()->json([
                'message' => 'User deletion failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    public function me(Request $request): JsonResponse
    {
        return response()->json([
            'data' => new UserResource($request->user())
        ]);
    }
}`
      },
      {
        path: 'app/Http/Requests/RegisterRequest.php',
        content: `<?php

namespace App\\Http\\Requests;

use Illuminate\\Foundation\\Http\\FormRequest;
use Illuminate\\Validation\\Rules\\Password;

class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'confirmed', Password::defaults()],
            'role' => ['sometimes', 'string', 'in:user,admin']
        ];
    }
}`
      },
      {
        path: 'app/Http/Requests/LoginRequest.php',
        content: `<?php

namespace App\\Http\\Requests;

use Illuminate\\Foundation\\Http\\FormRequest;

class LoginRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
            'revoke_existing_tokens' => ['sometimes', 'boolean']
        ];
    }
}`
      },
      {
        path: 'app/Http/Resources/UserResource.php',
        content: `<?php

namespace App\\Http\\Resources;

use Illuminate\\Http\\Request;
use Illuminate\\Http\\Resources\\Json\\JsonResource;

class UserResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'role' => $this->role,
            'email_verified_at' => $this->email_verified_at,
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
        ];
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

use App\\Models\\User;
use Illuminate\\Foundation\\Testing\\RefreshDatabase;
use Tests\\TestCase;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_register(): void
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123'
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'message',
                'data' => [
                    'user' => ['id', 'name', 'email'],
                    'token',
                    'expires_at'
                ]
            ]);

        $this->assertDatabaseHas('users', [
            'email' => 'test@example.com'
        ]);
    }

    public function test_user_can_login(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password123')
        ]);

        $response = $this->postJson('/api/auth/login', [
            'email' => 'test@example.com',
            'password' => 'password123'
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'data' => [
                    'user' => ['id', 'name', 'email'],
                    'token',
                    'expires_at'
                ]
            ]);
    }

    public function test_user_can_logout(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token');

        $response = $this->postJson('/api/auth/logout', [], [
            'Authorization' => 'Bearer ' . $token->plainTextToken
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Logout successful']);

        $this->assertDatabaseMissing('personal_access_tokens', [
            'id' => $token->accessToken->id
        ]);
    }
}`
      },
      {
        path: 'tests/Unit/UserServiceTest.php',
        content: `<?php

namespace Tests\\Unit;

use App\\Models\\User;
use App\\Services\\UserService;
use App\\Http\\Requests\\CreateUserRequest;
use Illuminate\\Foundation\\Testing\\RefreshDatabase;
use Tests\\TestCase;

class UserServiceTest extends TestCase
{
    use RefreshDatabase;

    private UserService $userService;

    protected function setUp(): void
    {
        parent::setUp();
        $this->userService = new UserService();
    }

    public function test_can_create_user(): void
    {
        $request = new CreateUserRequest([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123'
        ]);

        $user = $this->userService->createUser($request);

        $this->assertInstanceOf(User::class, $user);
        $this->assertEquals('Test User', $user->name);
        $this->assertEquals('test@example.com', $user->email);
        $this->assertDatabaseHas('users', [
            'email' => 'test@example.com'
        ]);
    }

    public function test_can_find_user_by_email(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com'
        ]);

        $foundUser = $this->userService->findByEmail('test@example.com');

        $this->assertNotNull($foundUser);
        $this->assertEquals($user->id, $foundUser->id);
    }

    public function test_can_verify_credentials(): void
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password123')
        ]);

        $verifiedUser = $this->userService->verifyCredentials(
            'test@example.com',
            'password123'
        );

        $this->assertNotNull($verifiedUser);
        $this->assertEquals($user->id, $verifiedUser->id);
    }
}`
      }
    ];
  }
}