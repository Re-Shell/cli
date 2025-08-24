/**
 * ASP.NET Core Minimal API Generator
 * Lightweight, high-performance API with minimal ceremony
 */

import { DotnetBaseGenerator } from './dotnet-base-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export class MinimalApiGenerator extends DotnetBaseGenerator {
  protected framework = 'ASP.NET Core Minimal API';
  protected dotnetVersion = '8.0';
  protected targetFramework = 'net8.0';

  constructor() {
    super('ASP.NET Core Minimal API');
  }

  protected getPackageReferences(): Record<string, string> {
    return {
      'Microsoft.AspNetCore.OpenApi': '8.0.0',
      'Swashbuckle.AspNetCore': '6.5.0',
      'Microsoft.EntityFrameworkCore': '8.0.0',
      'Microsoft.EntityFrameworkCore.Sqlite': '8.0.0',
      'Microsoft.EntityFrameworkCore.InMemory': '8.0.0',
      'Microsoft.EntityFrameworkCore.Tools': '8.0.0',
      'Microsoft.EntityFrameworkCore.Design': '8.0.0',
      'Microsoft.AspNetCore.Authentication.JwtBearer': '8.0.0',
      'System.IdentityModel.Tokens.Jwt': '7.0.3',
      'FluentValidation': '11.8.0',
      'Serilog.AspNetCore': '8.0.0',
      'Serilog.Sinks.File': '5.0.0',
      'Serilog.Sinks.Console': '5.0.0',
      'Microsoft.AspNetCore.RateLimiting': '8.0.0',
      'Microsoft.Extensions.Diagnostics.HealthChecks': '8.0.0',
      'Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore': '8.0.0',
      'Microsoft.AspNetCore.Mvc.Testing': '8.0.0'
    };
  }

  protected generateProgramFile(): string {
    const projectName = this.options?.name || 'MinimalApi';
    const port = this.options?.port || 5000;
    
    return `using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Serilog;
using FluentValidation;
using ${projectName}.Data;
using ${projectName}.Models;
using ${projectName}.DTOs;
using ${projectName}.Services;
using ${projectName}.Extensions;

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
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo 
    { 
        Title = "${projectName} Minimal API", 
        Version = "v1",
        Description = "A high-performance Minimal API built with Re-Shell CLI"
    });

    // JWT Authentication
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme."
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Database Context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
        ?? "Data Source=${projectName}.db";
    options.UseSqlite(connectionString);
});

// JWT Authentication
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? "YourSuperSecretKeyThatIsAtLeast32CharactersLong!";
var issuer = jwtSettings["Issuer"] ?? "MinimalApi";
var audience = jwtSettings["Audience"] ?? "MinimalApi-users";

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

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Rate Limiting
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("DefaultPolicy", options =>
    {
        options.PermitLimit = 100;
        options.Window = TimeSpan.FromMinutes(1);
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 10;
    });
});

// Validation
builder.Services.AddValidatorsFromAssemblyContaining<Program>();

// Health Checks
builder.Services.AddHealthChecks()
    .AddDbContextCheck<ApplicationDbContext>()
    .AddCheck("self", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy());

// Application Services
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IJwtService, JwtService>();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "${projectName} Minimal API v1");
        c.RoutePrefix = string.Empty;
    });
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Health Check
app.MapGet("/health", async (ApplicationDbContext context) =>
{
    var canConnect = await context.Database.CanConnectAsync();
    var status = canConnect ? "Healthy" : "Unhealthy";
    
    return Results.Ok(new
    {
        Status = status,
        Timestamp = DateTime.UtcNow,
        Environment = app.Environment.EnvironmentName,
        Framework = "ASP.NET Core Minimal API",
        Version = "1.0.0"
    });
}).WithName("HealthCheck").WithOpenApi();

// User Endpoints
var userGroup = app.MapGroup("/api/users")
    .WithTags("Users")
    .WithOpenApi();

// GET /api/users
userGroup.MapGet("/", async (IUserService userService) =>
{
    var users = await userService.GetAllUsersAsync();
    return Results.Ok(users);
})
.WithName("GetUsers")
.WithSummary("Get all users")
.Produces<IEnumerable<UserDto>>(StatusCodes.Status200OK);

// GET /api/users/{id}
userGroup.MapGet("/{id:int}", async (int id, IUserService userService) =>
{
    var user = await userService.GetUserByIdAsync(id);
    return user is not null ? Results.Ok(user) : Results.NotFound();
})
.WithName("GetUserById")
.WithSummary("Get user by ID")
.Produces<UserDto>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status404NotFound);

// POST /api/users
userGroup.MapPost("/", async (CreateUserDto createUserDto, IUserService userService, IValidator<CreateUserDto> validator) =>
{
    var validationResult = await validator.ValidateAsync(createUserDto);
    if (!validationResult.IsValid)
    {
        return Results.BadRequest(validationResult.Errors.Select(e => new { e.PropertyName, e.ErrorMessage }));
    }

    try
    {
        var user = await userService.CreateUserAsync(createUserDto);
        return Results.Created($"/api/users/{user.Id}", user);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
})
.WithName("CreateUser")
.WithSummary("Create a new user")
.Produces<UserDto>(StatusCodes.Status201Created)
.Produces(StatusCodes.Status400BadRequest);

// PUT /api/users/{id}
userGroup.MapPut("/{id:int}", async (int id, CreateUserDto updateUserDto, IUserService userService, IValidator<CreateUserDto> validator) =>
{
    var validationResult = await validator.ValidateAsync(updateUserDto);
    if (!validationResult.IsValid)
    {
        return Results.BadRequest(validationResult.Errors.Select(e => new { e.PropertyName, e.ErrorMessage }));
    }

    try
    {
        var user = await userService.UpdateUserAsync(id, updateUserDto);
        return user is not null ? Results.Ok(user) : Results.NotFound();
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
})
.WithName("UpdateUser")
.WithSummary("Update an existing user")
.Produces<UserDto>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status404NotFound);

// DELETE /api/users/{id}
userGroup.MapDelete("/{id:int}", async (int id, IUserService userService) =>
{
    var deleted = await userService.DeleteUserAsync(id);
    return deleted ? Results.NoContent() : Results.NotFound();
})
.WithName("DeleteUser")
.WithSummary("Delete a user")
.Produces(StatusCodes.Status204NoContent)
.Produces(StatusCodes.Status404NotFound);

// Authentication Endpoints
var authGroup = app.MapGroup("/api/auth")
    .WithTags("Authentication")
    .WithOpenApi();

// POST /api/auth/login
authGroup.MapPost("/login", async (LoginDto loginDto, IUserService userService, IJwtService jwtService) =>
{
    // Simple email-based login for demo
    var users = await userService.GetAllUsersAsync();
    var user = users.FirstOrDefault(u => u.Email == loginDto.Email);
    
    if (user == null)
    {
        return Results.Unauthorized();
    }

    var userModel = new User
    {
        Id = user.Id,
        Name = user.Name,
        Email = user.Email,
        CreatedAt = user.CreatedAt,
        UpdatedAt = user.UpdatedAt
    };

    var token = jwtService.GenerateToken(userModel);

    return Results.Ok(new
    {
        token,
        user = new { user.Id, user.Name, user.Email },
        expiresAt = DateTime.UtcNow.AddHours(24)
    });
})
.WithName("Login")
.WithSummary("Authenticate user")
.Produces(StatusCodes.Status200OK)
.Produces(StatusCodes.Status401Unauthorized);

// POST /api/auth/register
authGroup.MapPost("/register", async (CreateUserDto createUserDto, IUserService userService, IJwtService jwtService, IValidator<CreateUserDto> validator) =>
{
    var validationResult = await validator.ValidateAsync(createUserDto);
    if (!validationResult.IsValid)
    {
        return Results.BadRequest(validationResult.Errors.Select(e => new { e.PropertyName, e.ErrorMessage }));
    }

    try
    {
        var user = await userService.CreateUserAsync(createUserDto);
        
        var userModel = new User
        {
            Id = user.Id,
            Name = user.Name,
            Email = user.Email,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt
        };

        var token = jwtService.GenerateToken(userModel);

        return Results.Created($"/api/users/{user.Id}", new
        {
            token,
            user = new { user.Id, user.Name, user.Email },
            expiresAt = DateTime.UtcNow.AddHours(24)
        });
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
})
.WithName("Register")
.WithSummary("Register new user")
.Produces(StatusCodes.Status201Created)
.Produces(StatusCodes.Status400BadRequest);

// Secured endpoint example
app.MapGet("/api/profile", (System.Security.Claims.ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        Id = user.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value,
        Name = user.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value,
        Email = user.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
    });
})
.RequireAuthorization()
.WithName("GetProfile")
.WithSummary("Get current user profile")
.WithTags("Profile")
.Produces(StatusCodes.Status200OK)
.Produces(StatusCodes.Status401Unauthorized);

// Map health checks
app.MapHealthChecks("/health");

// Ensure database is created
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();
}

Log.Information("Starting ${projectName} Minimal API on port ${port}");

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
}

// DTOs
public record LoginDto(string Email, string Password);
public record ApiResponse<T>(bool Success, T? Data, string? Message = null);`;
  }

  protected async generateFrameworkSpecificFiles(projectPath: string): Promise<void> {
    const projectName = this.options?.name || 'MinimalApi';

    // SQLite Database Context
    const dbContext = this.generateSqliteDbContext();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Data', 'ApplicationDbContext.cs'), dbContext);

    // Entity configurations
    const userConfiguration = this.generateSqliteUserConfiguration();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Data', 'UserConfiguration.cs'), userConfiguration);

    // Validators
    const createUserValidator = this.generateCreateUserValidator();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'DTOs', 'CreateUserDtoValidator.cs'), createUserValidator);

    // Services
    const userService = this.generateMinimalUserService();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Services', 'UserService.cs'), userService);

    const jwtService = this.generateJwtService();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Services', 'JwtService.cs'), jwtService);

    const jwtServiceInterface = this.generateJwtServiceInterface();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Services', 'IJwtService.cs'), jwtServiceInterface);

    // Configuration files
    const appsettings = this.generateMinimalAppSettings();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'appsettings.json'), appsettings);

    const appsettingsDev = this.generateMinimalAppSettingsDevelopment();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'appsettings.Development.json'), appsettingsDev);

    // Global.json
    const globalJson = this.generateGlobalJson();
    await fs.writeFile(path.join(projectPath, 'global.json'), globalJson);

    // Extensions
    const extensions = this.generateMinimalExtensions();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Extensions', 'ServiceCollectionExtensions.cs'), extensions);
  }

  protected generateSqliteDbContext(): string {
    const projectName = this.options?.name || 'MinimalApi';
    return `using Microsoft.EntityFrameworkCore;
using ${projectName}.Models;

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
            // Fallback to SQLite for development
            optionsBuilder.UseSqlite("Data Source=app.db");
        }
    }
}`;
  }

  protected generateSqliteUserConfiguration(): string {
    const projectName = this.options?.name || 'MinimalApi';
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
            .HasDefaultValueSql("datetime('now')");

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
                Name = "Demo User", 
                Email = "demo@example.com",
                CreatedAt = DateTime.UtcNow
            }
        );
    }
}`;
  }

  protected generateMinimalUserService(): string {
    const projectName = this.options?.name || 'MinimalApi';
    return `using Microsoft.EntityFrameworkCore;
using ${projectName}.DTOs;
using ${projectName}.Models;
using ${projectName}.Data;

namespace ${projectName}.Services;

public class UserService : IUserService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UserService> _logger;

    public UserService(ApplicationDbContext context, ILogger<UserService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
    {
        _logger.LogInformation("Retrieving all users");
        
        var users = await _context.Users
            .OrderBy(u => u.CreatedAt)
            .Select(u => new UserDto(u.Id, u.Name, u.Email, u.CreatedAt, u.UpdatedAt))
            .ToListAsync();
            
        return users;
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

        return new UserDto(user.Id, user.Name, user.Email, user.CreatedAt, user.UpdatedAt);
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

        var user = new User
        {
            Name = createUserDto.Name,
            Email = createUserDto.Email,
            CreatedAt = DateTime.UtcNow
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User created successfully with ID: {UserId}", user.Id);
        
        return new UserDto(user.Id, user.Name, user.Email, user.CreatedAt, user.UpdatedAt);
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
        
        return new UserDto(user.Id, user.Name, user.Email, user.CreatedAt, user.UpdatedAt);
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

  protected generateJwtServiceInterface(): string {
    const projectName = this.options?.name || 'MinimalApi';
    return `using ${projectName}.Models;

namespace ${projectName}.Services;

public interface IJwtService
{
    string GenerateToken(User user);
    Task<bool> ValidateTokenAsync(string token);
}`;
  }

  protected generateJwtService(): string {
    const projectName = this.options?.name || 'MinimalApi';
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
        _issuer = _configuration["JwtSettings:Issuer"] ?? "MinimalApi";
        _audience = _configuration["JwtSettings:Audience"] ?? "MinimalApi-users";
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

  protected generateMinimalAppSettings(): string {
    const projectName = this.options?.name || 'MinimalApi';
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
    "DefaultConnection": "Data Source=${projectName}.db"
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
          "outputTemplate": "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}"
        }
      },
      {
        "Name": "File",
        "Args": {
          "path": "logs/log-.txt",
          "rollingInterval": "Day",
          "outputTemplate": "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}"
        }
      }
    ],
    "Enrich": ["FromLogContext"]
  }
}`;
  }

  protected generateMinimalAppSettingsDevelopment(): string {
    return `{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Information",
      "Microsoft.EntityFrameworkCore": "Information"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=dev.db"
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

  protected generateMinimalExtensions(): string {
    const projectName = this.options?.name || 'MinimalApi';
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
}`;
  }

  protected generateCreateUserValidator(): string {
    const projectName = this.options?.name || 'MinimalApi';
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
}