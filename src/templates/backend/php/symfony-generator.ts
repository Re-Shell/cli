import { PhpBackendGenerator } from './php-base-generator';

export class SymfonyGenerator extends PhpBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Symfony';
    this.config.features = [
      'Symfony 7 framework',
      'Doctrine ORM with migrations',
      'Symfony Console commands',
      'Twig templating engine',
      'JWT authentication with LexikJWTAuthenticationBundle',
      'API Platform for REST APIs',
      'Symfony Messenger for async processing',
      'Comprehensive testing with PHPUnit',
      'Symfony Profiler for debugging'
    ];
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'symfony/framework-bundle': '^7.0',
      'symfony/runtime': '^7.0',
      'symfony/flex': '^2.4',
      'doctrine/doctrine-bundle': '^2.11',
      'doctrine/doctrine-migrations-bundle': '^3.3',
      'doctrine/orm': '^3.0',
      'symfony/security-bundle': '^7.0',
      'lexik/jwt-authentication-bundle': '^2.20',
      'api-platform/core': '^3.2',
      'symfony/messenger': '^7.0',
      'symfony/redis-messenger': '^7.0',
      'predis/predis': '^2.2',
      'symfony/serializer': '^7.0',
      'symfony/validator': '^7.0',
      'symfony/property-access': '^7.0',
      'symfony/console': '^7.0',
      'symfony/yaml': '^7.0'
    };
  }

  protected generateMainFile(): string {
    return `<?php

use App\\Kernel;

require_once dirname(__DIR__).'/vendor/autoload_runtime.php';

return function (array $context) {
    return new Kernel($context['APP_ENV'], (bool) $context['APP_DEBUG']);
};`;
  }

  protected generateRoutingFile(): string {
    return `# config/routes.yaml

# Health check
health_check:
    path: /health
    controller: App\\Controller\\HealthController::check
    methods: [GET]

# API routes
api:
    resource: '../src/Controller/'
    type: attribute
    prefix: /api

# Authentication routes (handled by LexikJWTAuthenticationBundle)
api_login_check:
    path: /api/auth/login

# Custom auth routes
auth:
    resource: '../src/Controller/AuthController.php'
    type: attribute
    prefix: /api/auth

# User routes
users:
    resource: '../src/Controller/UserController.php'
    type: attribute
    prefix: /api/users`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/Service/UserService.php',
        content: `<?php

namespace App\\Service;

use App\\Entity\\User;
use App\\Repository\\UserRepository;
use Doctrine\\ORM\\EntityManagerInterface;
use Symfony\\Component\\PasswordHasher\\Hasher\\UserPasswordHasherInterface;
use Symfony\\Component\\Validator\\Validator\\ValidatorInterface;

class UserService
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private UserRepository $userRepository,
        private UserPasswordHasherInterface $passwordHasher,
        private ValidatorInterface $validator
    ) {}

    public function createUser(array $data): User
    {
        $user = new User();
        $user->setEmail($data['email']);
        $user->setName($data['name']);
        $user->setRole($data['role'] ?? 'ROLE_USER');
        
        // Hash password
        $hashedPassword = $this->passwordHasher->hashPassword($user, $data['password']);
        $user->setPassword($hashedPassword);

        // Validate user
        $errors = $this->validator->validate($user);
        if (count($errors) > 0) {
            throw new \\InvalidArgumentException((string) $errors);
        }

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }

    public function updateUser(User $user, array $data): User
    {
        if (isset($data['name'])) {
            $user->setName($data['name']);
        }

        if (isset($data['email'])) {
            $user->setEmail($data['email']);
        }

        if (isset($data['password'])) {
            $hashedPassword = $this->passwordHasher->hashPassword($user, $data['password']);
            $user->setPassword($hashedPassword);
        }

        if (isset($data['role'])) {
            $user->setRole($data['role']);
        }

        // Validate user
        $errors = $this->validator->validate($user);
        if (count($errors) > 0) {
            throw new \\InvalidArgumentException((string) $errors);
        }

        $this->entityManager->flush();

        return $user;
    }

    public function deleteUser(User $user): void
    {
        $this->entityManager->remove($user);
        $this->entityManager->flush();
    }

    public function findById(string $id): ?User
    {
        return $this->userRepository->find($id);
    }

    public function findByEmail(string $email): ?User
    {
        return $this->userRepository->findOneBy(['email' => $email]);
    }

    public function getAllUsers(int $page = 1, int $limit = 20): array
    {
        $offset = ($page - 1) * $limit;
        return $this->userRepository->findBy([], ['createdAt' => 'DESC'], $limit, $offset);
    }

    public function getUserCount(): int
    {
        return $this->userRepository->count([]);
    }
}`
      },
      {
        path: 'src/Service/AuthService.php',
        content: `<?php

namespace App\\Service;

use App\\Entity\\User;
use Lexik\\Bundle\\JWTAuthenticationBundle\\Services\\JWTTokenManagerInterface;
use Symfony\\Component\\PasswordHasher\\Hasher\\UserPasswordHasherInterface;
use Symfony\\Component\\Security\\Core\\Exception\\BadCredentialsException;
use Symfony\\Component\\Security\\Core\\User\\UserProviderInterface;

class AuthService
{
    public function __construct(
        private UserService $userService,
        private UserPasswordHasherInterface $passwordHasher,
        private JWTTokenManagerInterface $jwtManager,
        private UserProviderInterface $userProvider
    ) {}

    public function register(array $data): array
    {
        // Check if user already exists
        $existingUser = $this->userService->findByEmail($data['email']);
        if ($existingUser) {
            throw new \\InvalidArgumentException('User with this email already exists');
        }

        $user = $this->userService->createUser($data);
        $token = $this->jwtManager->create($user);

        return [
            'user' => $this->serializeUser($user),
            'token' => $token
        ];
    }

    public function login(string $email, string $password): array
    {
        $user = $this->userService->findByEmail($email);
        
        if (!$user || !$this->passwordHasher->isPasswordValid($user, $password)) {
            throw new BadCredentialsException('Invalid credentials');
        }

        $token = $this->jwtManager->create($user);

        return [
            'user' => $this->serializeUser($user),
            'token' => $token
        ];
    }

    public function refreshToken(string $refreshToken): array
    {
        // In a real application, you would validate the refresh token
        // and generate a new access token
        throw new \\BadMethodCallException('Refresh token functionality not implemented');
    }

    private function serializeUser(User $user): array
    {
        return [
            'id' => $user->getId(),
            'email' => $user->getEmail(),
            'name' => $user->getName(),
            'role' => $user->getRole(),
            'createdAt' => $user->getCreatedAt()->format('c'),
            'updatedAt' => $user->getUpdatedAt()->format('c')
        ];
    }
}`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/Repository/UserRepository.php',
        content: `<?php

namespace App\\Repository;

use App\\Entity\\User;
use Doctrine\\Bundle\\DoctrineBundle\\Repository\\ServiceEntityRepository;
use Doctrine\\Persistence\\ManagerRegistry;
use Symfony\\Component\\Security\\Core\\Exception\\UnsupportedUserException;
use Symfony\\Component\\Security\\Core\\User\\PasswordAuthenticatedUserInterface;
use Symfony\\Component\\Security\\Core\\User\\PasswordUpgraderInterface;

/**
 * @extends ServiceEntityRepository<User>
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', $user::class));
        }

        $user->setPassword($newHashedPassword);
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
    }

    /**
     * Find users by role
     */
    public function findByRole(string $role): array
    {
        return $this->createQueryBuilder('u')
            ->andWhere('u.role = :role')
            ->setParameter('role', $role)
            ->orderBy('u.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /**
     * Search users by name or email
     */
    public function search(string $query): array
    {
        return $this->createQueryBuilder('u')
            ->andWhere('u.name LIKE :query OR u.email LIKE :query')
            ->setParameter('query', '%' . $query . '%')
            ->orderBy('u.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /**
     * Get users with pagination
     */
    public function findWithPagination(int $page = 1, int $limit = 20): array
    {
        $offset = ($page - 1) * $limit;
        
        return $this->createQueryBuilder('u')
            ->orderBy('u.createdAt', 'DESC')
            ->setMaxResults($limit)
            ->setFirstResult($offset)
            ->getQuery()
            ->getResult();
    }
}`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/Entity/User.php',
        content: `<?php

namespace App\\Entity;

use App\\Repository\\UserRepository;
use Doctrine\\ORM\\Mapping as ORM;
use Symfony\\Bridge\\Doctrine\\Types\\UuidType;
use Symfony\\Component\\Security\\Core\\User\\PasswordAuthenticatedUserInterface;
use Symfony\\Component\\Security\\Core\\User\\UserInterface;
use Symfony\\Component\\Uid\\Uuid;
use Symfony\\Component\\Validator\\Constraints as Assert;

#[ORM\\Entity(repositoryClass: UserRepository::class)]
#[ORM\\Table(name: 'users')]
#[ORM\\HasLifecycleCallbacks]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\\Id]
    #[ORM\\Column(type: UuidType::NAME, unique: true)]
    #[ORM\\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    #[ORM\\Column(length: 180, unique: true)]
    #[Assert\\NotBlank]
    #[Assert\\Email]
    private ?string $email = null;

    #[ORM\\Column]
    private ?string $password = null;

    #[ORM\\Column(length: 255)]
    #[Assert\\NotBlank]
    #[Assert\\Length(min: 2, max: 255)]
    private ?string $name = null;

    #[ORM\\Column(length: 50)]
    private string $role = 'ROLE_USER';

    #[ORM\\Column]
    private bool $isActive = true;

    #[ORM\\Column]
    private \\DateTimeImmutable $createdAt;

    #[ORM\\Column]
    private \\DateTimeImmutable $updatedAt;

    public function __construct()
    {
        $this->id = Uuid::v4();
        $this->createdAt = new \\DateTimeImmutable();
        $this->updatedAt = new \\DateTimeImmutable();
    }

    public function getId(): ?Uuid
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;
        return $this;
    }

    /**
     * A visual identifier that represents this user.
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        return [$this->role];
    }

    public function setRoles(array $roles): static
    {
        $this->role = $roles[0] ?? 'ROLE_USER';
        return $this;
    }

    public function getRole(): string
    {
        return $this->role;
    }

    public function setRole(string $role): static
    {
        $this->role = $role;
        return $this;
    }

    /**
     * @see PasswordAuthenticatedUserInterface
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;
        return $this;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): static
    {
        $this->name = $name;
        return $this;
    }

    public function isActive(): bool
    {
        return $this->isActive;
    }

    public function setIsActive(bool $isActive): static
    {
        $this->isActive = $isActive;
        return $this;
    }

    public function getCreatedAt(): \\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getUpdatedAt(): \\DateTimeImmutable
    {
        return $this->updatedAt;
    }

    #[ORM\\PreUpdate]
    public function setUpdatedAt(): void
    {
        $this->updatedAt = new \\DateTimeImmutable();
    }

    /**
     * @see UserInterface
     */
    public function eraseCredentials(): void
    {
        // If you store any temporary, sensitive data on the user, clear it here
    }

    public function hasRole(string $role): bool
    {
        return $this->role === $role;
    }

    public function isAdmin(): bool
    {
        return $this->hasRole('ROLE_ADMIN');
    }
}`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/Kernel.php',
        content: `<?php

namespace App;

use Symfony\\Bundle\\FrameworkBundle\\Kernel\\MicroKernelTrait;
use Symfony\\Component\\HttpKernel\\Kernel as BaseKernel;

class Kernel extends BaseKernel
{
    use MicroKernelTrait;
}`
      },
      {
        path: 'config/services.yaml',
        content: `# This file is the entry point to configure your own services.
# Files in the packages/ subdirectory configure your dependencies.

# Put parameters here that don't need to change on each machine where the app is deployed
parameters:

services:
    # default configuration for services in *this* file
    _defaults:
        autowire: true      # Automatically injects dependencies in your services.
        autoconfigure: true # Automatically registers your services as commands, event subscribers, etc.

    # makes classes in src/ available to be used as services
    # this creates a service per class whose id is the fully-qualified class name
    App\\:
        resource: '../src/'
        exclude:
            - '../src/DependencyInjection/'
            - '../src/Entity/'
            - '../src/Kernel.php'

    # add more service definitions when explicit configuration is needed
    # please note that last definitions always *replace* previous ones`
      },
      {
        path: 'config/packages/framework.yaml',
        content: `# see https://symfony.com/doc/current/reference/configuration/framework.html
framework:
    secret: '%env(APP_SECRET)%'
    #csrf_protection: true
    http_method_override: false
    handle_all_throwables: true

    # Enables session support. Note that the session will ONLY be started if you read or write from it.
    # Remove or comment this section to explicitly disable session support.
    session:
        handler_id: null
        cookie_secure: auto
        cookie_samesite: lax
        storage_factory_id: session.storage.factory.native

    #esi: true
    #fragments: true
    php_errors:
        log: true

    cache:
        # Unique name of your app: used to compute stable namespaces for cache keys.
        app: cache.adapter.redis
        default_redis_provider: '%env(REDIS_URL)%'

when@test:
    framework:
        test: true
        session:
            storage_factory_id: session.storage.factory.mock_file`
      },
      {
        path: 'config/packages/doctrine.yaml',
        content: `doctrine:
    dbal:
        url: '%env(resolve:DATABASE_URL)%'

        # IMPORTANT: You MUST configure your server version,
        # either here or in the DATABASE_URL env var (see .env file)
        #server_version: '16'

        profiling_collect_backtrace: '%kernel.debug%'
        use_savepoints: true
    orm:
        auto_generate_proxy_classes: true
        enable_lazy_ghost_objects: true
        report_fields_where_declared: true
        validate_xml_mapping: true
        naming_strategy: doctrine.orm.naming_strategy.underscore_number_aware
        auto_mapping: true
        mappings:
            App:
                type: attribute
                is_bundle: false
                dir: '%kernel.project_dir%/src/Entity'
                prefix: 'App\\Entity'
                alias: App

when@test:
    doctrine:
        dbal:
            # "TEST_TOKEN" is typically set by ParaTest
            dbname_suffix: '_test%env(default::TEST_TOKEN)%'

when@prod:
    doctrine:
        orm:
            auto_generate_proxy_classes: false
            proxy_dir: '%kernel.build_dir%/doctrine/orm/Proxies'
            query_cache_driver:
                type: pool
                pool: doctrine.result_cache_pool
            result_cache_driver:
                type: pool
                pool: doctrine.result_cache_pool

    framework:
        cache:
            pools:
                doctrine.result_cache_pool:
                    adapter: cache.app
                doctrine.system_cache_pool:
                    adapter: cache.system`
      },
      {
        path: 'config/packages/security.yaml',
        content: `security:
    # https://symfony.com/doc/current/security.html#registering-the-user-hashing-passwords
    password_hashers:
        Symfony\\Component\\Security\\Core\\User\\PasswordAuthenticatedUserInterface: 'auto'

    # https://symfony.com/doc/current/security.html#loading-the-user-the-user-provider
    providers:
        # used to reload user from session & other features (e.g. switch_user)
        app_user_provider:
            entity:
                class: App\\Entity\\User
                property: email

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        login:
            pattern: ^/api/auth/login
            stateless: true
            json_login:
                check_path: /api/auth/login
                success_handler: lexik_jwt_authentication.handler.authentication_success
                failure_handler: lexik_jwt_authentication.handler.authentication_failure

        api:
            pattern:   ^/api
            stateless: true
            jwt: ~

        main:
            lazy: true
            provider: app_user_provider

    # Easy way to control access for large sections of your site
    # Note: Only the *first* access control that matches will be used
    access_control:
        - { path: ^/api/auth/login, roles: PUBLIC_ACCESS }
        - { path: ^/api/auth/register, roles: PUBLIC_ACCESS }
        - { path: ^/health, roles: PUBLIC_ACCESS }
        - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }`
      },
      {
        path: 'config/packages/lexik_jwt_authentication.yaml',
        content: `lexik_jwt_authentication:
    secret_key: '%env(resolve:JWT_SECRET_KEY)%'
    public_key: '%env(resolve:JWT_PUBLIC_KEY)%'
    pass_phrase: '%env(JWT_PASSPHRASE)%'
    token_ttl: 3600
    user_identity_field: email`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/Controller/HealthController.php',
        content: `<?php

namespace App\\Controller;

use Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController;
use Symfony\\Component\\HttpFoundation\\JsonResponse;
use Symfony\\Component\\Routing\\Attribute\\Route;

class HealthController extends AbstractController
{
    #[Route('/health', name: 'health_check', methods: ['GET'])]
    public function check(): JsonResponse
    {
        return $this->json([
            'status' => 'OK',
            'timestamp' => (new \\DateTimeImmutable())->format('c'),
            'service' => $_ENV['APP_NAME'] ?? 'Symfony API',
            'version' => '1.0.0'
        ]);
    }
}`
      },
      {
        path: 'src/Controller/AuthController.php',
        content: `<?php

namespace App\\Controller;

use App\\Service\\AuthService;
use Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController;
use Symfony\\Component\\HttpFoundation\\JsonResponse;
use Symfony\\Component\\HttpFoundation\\Request;
use Symfony\\Component\\Routing\\Attribute\\Route;
use Symfony\\Component\\Validator\\Validator\\ValidatorInterface;

#[Route('/api/auth')]
class AuthController extends AbstractController
{
    public function __construct(
        private AuthService $authService,
        private ValidatorInterface $validator
    ) {}

    #[Route('/register', name: 'auth_register', methods: ['POST'])]
    public function register(Request $request): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);
            
            // Basic validation
            $required = ['name', 'email', 'password'];
            foreach ($required as $field) {
                if (empty($data[$field])) {
                    return $this->json(['error' => "Field '{$field}' is required"], 400);
                }
            }

            $result = $this->authService->register($data);

            return $this->json([
                'message' => 'User registered successfully',
                'data' => $result
            ], 201);
        } catch (\\Exception $e) {
            return $this->json([
                'message' => 'Registration failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    #[Route('/me', name: 'auth_me', methods: ['GET'])]
    public function me(): JsonResponse
    {
        $user = $this->getUser();
        
        return $this->json([
            'data' => [
                'id' => $user->getId(),
                'email' => $user->getEmail(),
                'name' => $user->getName(),
                'role' => $user->getRole(),
                'createdAt' => $user->getCreatedAt()->format('c'),
                'updatedAt' => $user->getUpdatedAt()->format('c')
            ]
        ]);
    }
}`
      },
      {
        path: 'src/Controller/UserController.php',
        content: `<?php

namespace App\\Controller;

use App\\Entity\\User;
use App\\Service\\UserService;
use Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController;
use Symfony\\Component\\HttpFoundation\\JsonResponse;
use Symfony\\Component\\HttpFoundation\\Request;
use Symfony\\Component\\Routing\\Attribute\\Route;
use Symfony\\Component\\Security\\Http\\Attribute\\IsGranted;

#[Route('/api/users')]
class UserController extends AbstractController
{
    public function __construct(
        private UserService $userService
    ) {}

    #[Route('', name: 'users_index', methods: ['GET'])]
    #[IsGranted('ROLE_ADMIN')]
    public function index(Request $request): JsonResponse
    {
        $page = $request->query->getInt('page', 1);
        $limit = $request->query->getInt('limit', 20);
        
        $users = $this->userService->getAllUsers($page, $limit);
        $total = $this->userService->getUserCount();
        
        return $this->json([
            'data' => array_map([$this, 'serializeUser'], $users),
            'meta' => [
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'pages' => ceil($total / $limit)
            ]
        ]);
    }

    #[Route('', name: 'users_create', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function create(Request $request): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);
            $user = $this->userService->createUser($data);
            
            return $this->json([
                'message' => 'User created successfully',
                'data' => $this->serializeUser($user)
            ], 201);
        } catch (\\Exception $e) {
            return $this->json([
                'message' => 'User creation failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    #[Route('/{id}', name: 'users_show', methods: ['GET'])]
    public function show(string $id): JsonResponse
    {
        $user = $this->userService->findById($id);
        
        if (!$user) {
            return $this->json(['message' => 'User not found'], 404);
        }
        
        // Users can only see their own data unless they're admin
        if (!$this->isGranted('ROLE_ADMIN') && $user !== $this->getUser()) {
            return $this->json(['message' => 'Access denied'], 403);
        }
        
        return $this->json([
            'data' => $this->serializeUser($user)
        ]);
    }

    #[Route('/{id}', name: 'users_update', methods: ['PUT', 'PATCH'])]
    public function update(string $id, Request $request): JsonResponse
    {
        try {
            $user = $this->userService->findById($id);
            
            if (!$user) {
                return $this->json(['message' => 'User not found'], 404);
            }
            
            // Users can only update their own data unless they're admin
            if (!$this->isGranted('ROLE_ADMIN') && $user !== $this->getUser()) {
                return $this->json(['message' => 'Access denied'], 403);
            }
            
            $data = json_decode($request->getContent(), true);
            $updatedUser = $this->userService->updateUser($user, $data);
            
            return $this->json([
                'message' => 'User updated successfully',
                'data' => $this->serializeUser($updatedUser)
            ]);
        } catch (\\Exception $e) {
            return $this->json([
                'message' => 'User update failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    #[Route('/{id}', name: 'users_delete', methods: ['DELETE'])]
    #[IsGranted('ROLE_ADMIN')]
    public function delete(string $id): JsonResponse
    {
        try {
            $user = $this->userService->findById($id);
            
            if (!$user) {
                return $this->json(['message' => 'User not found'], 404);
            }
            
            $this->userService->deleteUser($user);
            
            return $this->json(['message' => 'User deleted successfully']);
        } catch (\\Exception $e) {
            return $this->json([
                'message' => 'User deletion failed',
                'error' => $e->getMessage()
            ], 422);
        }
    }

    private function serializeUser(User $user): array
    {
        return [
            'id' => $user->getId(),
            'email' => $user->getEmail(),
            'name' => $user->getName(),
            'role' => $user->getRole(),
            'isActive' => $user->isActive(),
            'createdAt' => $user->getCreatedAt()->format('c'),
            'updatedAt' => $user->getUpdatedAt()->format('c')
        ];
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

namespace App\\Tests\\Controller;

use Symfony\\Bundle\\FrameworkBundle\\Test\\WebTestCase;

class AuthControllerTest extends WebTestCase
{
    public function testRegister(): void
    {
        $client = static::createClient();
        
        $client->request('POST', '/api/auth/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], json_encode([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123'
        ]));

        $this->assertResponseStatusCodeSame(201);
        
        $response = json_decode($client->getResponse()->getContent(), true);
        $this->assertArrayHasKey('data', $response);
        $this->assertArrayHasKey('user', $response['data']);
        $this->assertArrayHasKey('token', $response['data']);
    }

    public function testLogin(): void
    {
        $client = static::createClient();
        
        // First register a user
        $client->request('POST', '/api/auth/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], json_encode([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123'
        ]));

        // Then try to login
        $client->request('POST', '/api/auth/login', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], json_encode([
            'username' => 'test@example.com',
            'password' => 'password123'
        ]));

        $this->assertResponseStatusCodeSame(200);
        
        $response = json_decode($client->getResponse()->getContent(), true);
        $this->assertArrayHasKey('token', $response);
    }

    public function testHealthCheck(): void
    {
        $client = static::createClient();
        $client->request('GET', '/health');

        $this->assertResponseIsSuccessful();
        
        $response = json_decode($client->getResponse()->getContent(), true);
        $this->assertEquals('OK', $response['status']);
        $this->assertArrayHasKey('timestamp', $response);
    }
}`
      },
      {
        path: 'tests/Service/UserServiceTest.php',
        content: `<?php

namespace App\\Tests\\Service;

use App\\Entity\\User;
use App\\Service\\UserService;
use Symfony\\Bundle\\FrameworkBundle\\Test\\KernelTestCase;

class UserServiceTest extends KernelTestCase
{
    private UserService $userService;

    protected function setUp(): void
    {
        $kernel = self::bootKernel();
        $this->userService = static::getContainer()->get(UserService::class);
    }

    public function testCreateUser(): void
    {
        $userData = [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123',
            'role' => 'ROLE_USER'
        ];

        $user = $this->userService->createUser($userData);

        $this->assertInstanceOf(User::class, $user);
        $this->assertEquals('Test User', $user->getName());
        $this->assertEquals('test@example.com', $user->getEmail());
        $this->assertEquals('ROLE_USER', $user->getRole());
    }

    public function testFindByEmail(): void
    {
        $userData = [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123'
        ];

        $user = $this->userService->createUser($userData);
        $foundUser = $this->userService->findByEmail('test@example.com');

        $this->assertNotNull($foundUser);
        $this->assertEquals($user->getId(), $foundUser->getId());
    }
}`
      }
    ];
  }
}