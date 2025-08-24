/**
 * ASP.NET Core Web API Generator
 * Full-featured web API with Entity Framework, authentication, and comprehensive features
 */

import { DotnetBaseGenerator } from './dotnet-base-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export class AspNetWebApiGenerator extends DotnetBaseGenerator {
  protected framework = 'ASP.NET Core Web API';
  protected dotnetVersion = '8.0';
  protected targetFramework = 'net8.0';

  constructor() {
    super('ASP.NET Core Web API');
  }

  protected getPackageReferences(): Record<string, string> {
    return {
      'Microsoft.AspNetCore.OpenApi': '8.0.0',
      'Swashbuckle.AspNetCore': '6.5.0',
      'Microsoft.EntityFrameworkCore': '8.0.0',
      'Microsoft.EntityFrameworkCore.SqlServer': '8.0.0',
      'Microsoft.EntityFrameworkCore.InMemory': '8.0.0',
      'Microsoft.EntityFrameworkCore.Tools': '8.0.0',
      'Microsoft.EntityFrameworkCore.Design': '8.0.0',
      'Microsoft.AspNetCore.Authentication.JwtBearer': '8.0.0',
      'Microsoft.AspNetCore.Identity.EntityFrameworkCore': '8.0.0',
      'System.IdentityModel.Tokens.Jwt': '7.0.3',
      'BCrypt.Net-Next': '4.0.3',
      'AutoMapper': '12.0.1',
      'AutoMapper.Extensions.Microsoft.DependencyInjection': '12.0.1',
      'FluentValidation.AspNetCore': '11.3.0',
      'Serilog.AspNetCore': '8.0.0',
      'Serilog.Sinks.File': '5.0.0',
      'Serilog.Sinks.Console': '5.0.0',
      'Microsoft.AspNetCore.Mvc.Versioning': '5.1.0',
      'Microsoft.AspNetCore.Mvc.Versioning.ApiExplorer': '5.1.0',
      'Microsoft.AspNetCore.ResponseCaching': '2.2.0',
      'Microsoft.Extensions.Caching.StackExchangeRedis': '8.0.0',
      'Microsoft.AspNetCore.RateLimiting': '8.0.0',
      'Microsoft.AspNetCore.Cors': '2.2.0',
      'Microsoft.Extensions.Diagnostics.HealthChecks': '8.0.0',
      'Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore': '8.0.0',
      'AspNetCore.HealthChecks.SqlServer': '8.0.0',
      'AspNetCore.HealthChecks.Redis': '8.0.0'
    };
  }

  protected generateProgramFile(): string {
    const projectName = this.options?.name || 'WebApi';
    const port = this.options?.port || 5000;
    
    return `using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Serilog;
using ${projectName}.Data;
using ${projectName}.Extensions;
using ${projectName}.Middleware;
using ${projectName}.Services;
using FluentValidation.AspNetCore;
using FluentValidation;

var builder = WebApplication.CreateBuilder(args);

// Serilog Configuration
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

// Add services to the container
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.WriteIndented = true;
    });

// Database Context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
        ?? "Server=(localdb)\\\\mssqllocaldb;Database=${projectName}Db;Trusted_Connection=true;";
    options.UseSqlServer(connectionString);
});

// JWT Authentication
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? "YourSuperSecretKeyThatIsAtLeast32CharactersLong!";
var issuer = jwtSettings["Issuer"] ?? "YourIssuer";
var audience = jwtSettings["Audience"] ?? "YourAudience";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
        };
    });

builder.Services.AddAuthorization();

// API Versioning
builder.Services.AddApiVersioning(options =>
{
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.DefaultApiVersion = new Microsoft.AspNetCore.Mvc.ApiVersion(1, 0);
    options.ApiVersionReader = Microsoft.AspNetCore.Mvc.ApiVersionReader.Combine(
        new Microsoft.AspNetCore.Mvc.QueryStringApiVersionReader("version"),
        new Microsoft.AspNetCore.Mvc.HeaderApiVersionReader("X-Version"),
        new Microsoft.AspNetCore.Mvc.UrlSegmentApiVersionReader()
    );
});

builder.Services.AddVersionedApiExplorer(setup =>
{
    setup.GroupNameFormat = "'v'VVV";
    setup.SubstituteApiVersionInUrl = true;
});

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Rate Limiting
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
        httpContext => RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name ?? httpContext.Request.Headers.Host.ToString(),
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1)
            }));
});

// Caching
builder.Services.AddMemoryCache();
builder.Services.AddResponseCaching();

// Redis Cache (optional)
// var redisConnection = builder.Configuration.GetConnectionString("Redis");
// if (!string.IsNullOrEmpty(redisConnection))
// {
//     builder.Services.AddStackExchangeRedisCache(options =>
//     {
//         options.Configuration = redisConnection;
//     });
// }

// FluentValidation
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddValidatorsFromAssemblyContaining<Program>();

// AutoMapper
builder.Services.AddAutoMapper(typeof(Program));

// Health Checks
builder.Services.AddHealthChecks()
    .AddDbContextCheck<ApplicationDbContext>()
    .AddCheck("self", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy());

// Application Services
builder.Services.AddApplicationServices();

// Swagger Services
builder.Services.AddSwaggerServices();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "${projectName} API v1");
        c.RoutePrefix = string.Empty; // Set Swagger UI at the app's root
    });
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Custom Error Handling Middleware
app.UseMiddleware<ErrorHandlingMiddleware>();

app.UseHttpsRedirection();
app.UseRouting();

// CORS
app.UseCors("AllowAllOrigins");

// Rate Limiting
app.UseRateLimiter();

// Response Caching
app.UseResponseCaching();

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

// Health Checks
app.MapHealthChecks("/health");

// Controllers
app.MapControllers();

// Ensure database is created
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();
}

Log.Information("Starting ${projectName} API on port ${port}");

try
{
    await app.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}`;
  }

  protected async generateFrameworkSpecificFiles(projectPath: string): Promise<void> {
    const projectName = this.options?.name || 'WebApi';

    // Data Context
    const dbContext = this.generateDbContext();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Data', 'ApplicationDbContext.cs'), dbContext);

    // Entity configurations
    const userConfiguration = this.generateUserConfiguration();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Data', 'UserConfiguration.cs'), userConfiguration);

    // AutoMapper Profile
    const mappingProfile = this.generateMappingProfile();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Extensions', 'MappingProfile.cs'), mappingProfile);

    // FluentValidation Validators
    const createUserValidator = this.generateCreateUserValidator();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'DTOs', 'CreateUserDtoValidator.cs'), createUserValidator);

    // JWT Service
    const jwtService = this.generateJwtService();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Services', 'JwtService.cs'), jwtService);

    const jwtServiceInterface = this.generateJwtServiceInterface();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Services', 'IJwtService.cs'), jwtServiceInterface);

    // Authentication Controller
    const authController = this.generateAuthController();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Controllers', 'AuthController.cs'), authController);

    // Enhanced User Service with EF Core
    const enhancedUserService = this.generateEnhancedUserService();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Services', 'UserService.cs'), enhancedUserService);

    // Configuration files
    const appsettings = this.generateAppSettings();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'appsettings.json'), appsettings);

    const appsettingsDev = this.generateAppSettingsDevelopment();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'appsettings.Development.json'), appsettingsDev);

    // Global.json
    const globalJson = this.generateGlobalJson();
    await fs.writeFile(path.join(projectPath, 'global.json'), globalJson);
  }

  protected generateDbContext(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.EntityFrameworkCore;
using ${projectName}.Models;
using ${projectName}.Data;

namespace ${projectName}.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; } = default!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Apply configurations
        modelBuilder.ApplyConfiguration(new UserConfiguration());
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            // Fallback to InMemory for development
            optionsBuilder.UseInMemoryDatabase("DefaultInMemoryDb");
        }
    }
}`;
  }

  protected generateUserConfiguration(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using ${projectName}.Models;

namespace ${projectName}.Data;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(u => u.Id);

        builder.Property(u => u.Name)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(u => u.Email)
            .IsRequired()
            .HasMaxLength(255);

        builder.HasIndex(u => u.Email)
            .IsUnique();

        builder.Property(u => u.CreatedAt)
            .IsRequired()
            .HasDefaultValueSql("GETUTCDATE()");

        builder.Property(u => u.UpdatedAt)
            .IsRequired(false);

        // Seed data
        builder.HasData(
            new User 
            { 
                Id = 1, 
                Name = "Admin User", 
                Email = "admin@example.com",
                CreatedAt = DateTime.UtcNow
            },
            new User 
            { 
                Id = 2, 
                Name = "Test User", 
                Email = "test@example.com",
                CreatedAt = DateTime.UtcNow
            }
        );
    }
}`;
  }

  protected generateMappingProfile(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using AutoMapper;
using ${projectName}.Models;
using ${projectName}.DTOs;

namespace ${projectName}.Extensions;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        CreateMap<User, UserDto>();
        CreateMap<CreateUserDto, User>()
            .ForMember(dest => dest.Id, opt => opt.Ignore())
            .ForMember(dest => dest.CreatedAt, opt => opt.Ignore())
            .ForMember(dest => dest.UpdatedAt, opt => opt.Ignore());
    }
}`;
  }

  protected generateCreateUserValidator(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using FluentValidation;

namespace ${projectName}.DTOs;

public class CreateUserDtoValidator : AbstractValidator<CreateUserDto>
{
    public CreateUserDtoValidator()
    {
        RuleFor(x => x.Name)
            .NotEmpty().WithMessage("Name is required")
            .MaximumLength(100).WithMessage("Name must not exceed 100 characters")
            .MinimumLength(2).WithMessage("Name must be at least 2 characters");

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required")
            .EmailAddress().WithMessage("Email must be a valid email address")
            .MaximumLength(255).WithMessage("Email must not exceed 255 characters");
    }
}`;
  }

  protected generateJwtServiceInterface(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using ${projectName}.Models;

namespace ${projectName}.Services;

public interface IJwtService
{
    string GenerateToken(User user);
    Task<bool> ValidateTokenAsync(string token);
}`;
  }

  protected generateJwtService(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ${projectName}.Models;

namespace ${projectName}.Services;

public class JwtService : IJwtService
{
    private readonly IConfiguration _configuration;
    private readonly string _secretKey;
    private readonly string _issuer;
    private readonly string _audience;

    public JwtService(IConfiguration configuration)
    {
        _configuration = configuration;
        _secretKey = _configuration["JwtSettings:SecretKey"] ?? "YourSuperSecretKeyThatIsAtLeast32CharactersLong!";
        _issuer = _configuration["JwtSettings:Issuer"] ?? "YourIssuer";
        _audience = _configuration["JwtSettings:Audience"] ?? "YourAudience";
    }

    public string GenerateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_secretKey);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Name),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(24),
            Issuer = _issuer,
            Audience = _audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_secretKey);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _issuer,
                ValidAudience = _audience,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = TimeSpan.Zero
            };

            await tokenHandler.ValidateTokenAsync(token, validationParameters);
            return true;
        }
        catch
        {
            return false;
        }
    }
}`;
  }

  protected generateAuthController(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.AspNetCore.Mvc;
using ${projectName}.DTOs;
using ${projectName}.Services;

namespace ${projectName}.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly IJwtService _jwtService;

    public AuthController(IUserService userService, IJwtService jwtService)
    {
        _userService = userService;
        _jwtService = jwtService;
    }

    /// <summary>
    /// Authenticate user and get JWT token
    /// </summary>
    /// <param name="loginDto">Login credentials</param>
    /// <returns>JWT token</returns>
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<object>> Login([FromBody] LoginDto loginDto)
    {
        // For demo purposes, we'll just check if user exists by email
        var users = await _userService.GetAllUsersAsync();
        var user = users.FirstOrDefault(u => u.Email == loginDto.Email);
        
        if (user == null)
        {
            return Unauthorized(new { message = "Invalid credentials" });
        }

        // Convert UserDto back to User for JWT generation
        var userModel = new Models.User
        {
            Id = user.Id,
            Name = user.Name,
            Email = user.Email,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt
        };

        var token = _jwtService.GenerateToken(userModel);

        return Ok(new
        {
            token,
            user = new
            {
                user.Id,
                user.Name,
                user.Email
            },
            expiresAt = DateTime.UtcNow.AddHours(24)
        });
    }

    /// <summary>
    /// Register a new user
    /// </summary>
    /// <param name="createUserDto">User registration data</param>
    /// <returns>Created user with JWT token</returns>
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<object>> Register([FromBody] CreateUserDto createUserDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        try
        {
            var user = await _userService.CreateUserAsync(createUserDto);
            
            // Convert UserDto back to User for JWT generation
            var userModel = new Models.User
            {
                Id = user.Id,
                Name = user.Name,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt
            };

            var token = _jwtService.GenerateToken(userModel);

            return CreatedAtAction(nameof(Login), new
            {
                token,
                user = new
                {
                    user.Id,
                    user.Name,
                    user.Email
                },
                expiresAt = DateTime.UtcNow.AddHours(24)
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }
}

public record LoginDto(string Email, string Password);`;
  }

  protected generateEnhancedUserService(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.EntityFrameworkCore;
using AutoMapper;
using ${projectName}.DTOs;
using ${projectName}.Models;
using ${projectName}.Data;

namespace ${projectName}.Services;

public class UserService : IUserService
{
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;
    private readonly ILogger<UserService> _logger;

    public UserService(ApplicationDbContext context, IMapper mapper, ILogger<UserService> logger)
    {
        _context = context;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
    {
        _logger.LogInformation("Retrieving all users");
        
        var users = await _context.Users
            .OrderBy(u => u.CreatedAt)
            .ToListAsync();
            
        return _mapper.Map<IEnumerable<UserDto>>(users);
    }

    public async Task<UserDto?> GetUserByIdAsync(int id)
    {
        _logger.LogInformation("Retrieving user with ID: {UserId}", id);
        
        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            _logger.LogWarning("User with ID {UserId} not found", id);
            return null;
        }

        return _mapper.Map<UserDto>(user);
    }

    public async Task<UserDto> CreateUserAsync(CreateUserDto createUserDto)
    {
        _logger.LogInformation("Creating new user with email: {Email}", createUserDto.Email);

        // Check if user with email already exists
        var existingUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == createUserDto.Email);
            
        if (existingUser != null)
        {
            throw new InvalidOperationException($"User with email {createUserDto.Email} already exists");
        }

        var user = _mapper.Map<User>(createUserDto);
        user.CreatedAt = DateTime.UtcNow;

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User created successfully with ID: {UserId}", user.Id);
        
        return _mapper.Map<UserDto>(user);
    }

    public async Task<UserDto?> UpdateUserAsync(int id, CreateUserDto updateUserDto)
    {
        _logger.LogInformation("Updating user with ID: {UserId}", id);
        
        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            _logger.LogWarning("User with ID {UserId} not found for update", id);
            return null;
        }

        // Check if email is being changed and if it conflicts with another user
        if (user.Email != updateUserDto.Email)
        {
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == updateUserDto.Email && u.Id != id);
                
            if (existingUser != null)
            {
                throw new InvalidOperationException($"User with email {updateUserDto.Email} already exists");
            }
        }

        user.Name = updateUserDto.Name;
        user.Email = updateUserDto.Email;
        user.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation("User with ID {UserId} updated successfully", id);
        
        return _mapper.Map<UserDto>(user);
    }

    public async Task<bool> DeleteUserAsync(int id)
    {
        _logger.LogInformation("Deleting user with ID: {UserId}", id);
        
        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            _logger.LogWarning("User with ID {UserId} not found for deletion", id);
            return false;
        }

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User with ID {UserId} deleted successfully", id);
        
        return true;
    }
}`;
  }

  protected generateAppSettings(): string {
    const projectName = this.options?.name || 'WebApi';
    const port = this.options?.port || 5000;
    
    return `{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.EntityFrameworkCore": "Information"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\\\mssqllocaldb;Database=${projectName}Db;Trusted_Connection=true;MultipleActiveResultSets=true;",
    "Redis": "localhost:6379"
  },
  "JwtSettings": {
    "SecretKey": "YourSuperSecretKeyThatIsAtLeast32CharactersLong!",
    "Issuer": "${projectName}",
    "Audience": "${projectName}-users",
    "ExpirationHours": 24
  },
  "AllowedHosts": "*",
  "Kestrel": {
    "Endpoints": {
      "Http": {
        "Url": "http://localhost:${port}"
      },
      "Https": {
        "Url": "https://localhost:${port + 1}"
      }
    }
  },
  "Serilog": {
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    },
    "WriteTo": [
      {
        "Name": "Console",
        "Args": {
          "outputTemplate": "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}"
        }
      },
      {
        "Name": "File",
        "Args": {
          "path": "logs/log-.txt",
          "rollingInterval": "Day",
          "outputTemplate": "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}"
        }
      }
    ],
    "Enrich": ["FromLogContext"]
  }
}`;
  }

  protected generateAppSettingsDevelopment(): string {
    return `{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Information",
      "Microsoft.EntityFrameworkCore": "Information"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\\\mssqllocaldb;Database=DevDatabase;Trusted_Connection=true;MultipleActiveResultSets=true;"
  },
  "JwtSettings": {
    "SecretKey": "DevSecretKeyThatIsAtLeast32CharactersLongForDevelopment!"
  }
}`;
  }

  protected generateGlobalJson(): string {
    return `{
  "sdk": {
    "version": "8.0.0",
    "rollForward": "latestMinor"
  }
}`;
  }

  protected generateServiceCollectionExtensions(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using ${projectName}.Services;

namespace ${projectName}.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        // Register services
        services.AddScoped<IUserService, UserService>();
        services.AddScoped<IJwtService, JwtService>();
        
        return services;
    }
    
    public static IServiceCollection AddSwaggerServices(this IServiceCollection services)
    {
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new() 
            { 
                Title = "${projectName} API", 
                Version = "v1",
                Description = "A comprehensive ASP.NET Core Web API built with Re-Shell CLI",
                Contact = new()
                {
                    Name = "Re-Shell Team",
                    Email = "support@re-shell.com"
                }
            });

            // JWT Authentication
            c.AddSecurityDefinition("Bearer", new()
            {
                Name = "Authorization",
                Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token in the text input below.\\n\\nExample: \\"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\""
            });

            c.AddSecurityRequirement(new()
            {
                {
                    new()
                    {
                        Reference = new()
                        {
                            Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }
            });

            // Include XML comments
            var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            if (File.Exists(xmlPath))
            {
                c.IncludeXmlComments(xmlPath);
            }
        });
        
        return services;
    }
}`;
  }
}