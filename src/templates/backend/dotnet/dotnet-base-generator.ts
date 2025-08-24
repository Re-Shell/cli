/**
 * .NET Base Generator
 * Base class for all .NET backend framework generators
 */

import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export abstract class DotnetBaseGenerator extends BackendTemplateGenerator {
  protected options: any;
  protected abstract framework: string;
  protected abstract dotnetVersion: string;
  protected abstract targetFramework: string;

  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'C#',
      framework: framework,
      packageManager: 'dotnet',
      buildTool: 'dotnet',
      testFramework: 'xunit',
      features: [
        '.NET 8.0 framework',
        'C# 12 language features',
        'Entity Framework Core',
        'JWT authentication',
        'Swagger/OpenAPI',
        'Structured logging',
        'Dependency injection',
        'Health checks',
        'Rate limiting',
        'Cross-platform'
      ],
      dependencies: {
        'Microsoft.AspNetCore.OpenApi': '8.0.0',
        'Swashbuckle.AspNetCore': '6.5.0',
        'Microsoft.EntityFrameworkCore': '8.0.0',
        'Microsoft.AspNetCore.Authentication.JwtBearer': '8.0.0',
        'System.IdentityModel.Tokens.Jwt': '7.0.3',
        'Serilog.AspNetCore': '8.0.0'
      },
      devDependencies: {
        'Microsoft.NET.Test.Sdk': '17.8.0',
        'xunit': '2.6.2',
        'xunit.runner.visualstudio': '2.5.3',
        'Microsoft.AspNetCore.Mvc.Testing': '8.0.0'
      },
      scripts: {
        'dev': 'dotnet run',
        'build': 'dotnet build',
        'test': 'dotnet test',
        'clean': 'dotnet clean'
      },
      envVars: {
        'ASPNETCORE_ENVIRONMENT': 'Development',
        'ConnectionStrings__DefaultConnection': 'Server=(localdb)\\mssqllocaldb;Database=AppDb;Trusted_Connection=true;',
        'JwtSettings__SecretKey': 'YourSuperSecretKeyThatIsAtLeast32CharactersLong!',
        'JwtSettings__Issuer': 'YourIssuer',
        'JwtSettings__Audience': 'YourAudience'
      }
    };
    super(config);
  }

  // Implement required abstract methods
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await this.createDotnetDirectoryStructure(projectPath);
    await this.generateProjectFiles(projectPath);
    await this.generateSourceFiles(projectPath);
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    await this.generateFrameworkSpecificFiles(projectPath);
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    await this.generateTestFiles(projectPath);
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is generated as part of source files
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are generated via Swagger/OpenAPI
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerfile = this.generateDockerfile();
    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerfile);

    const dockerignore = this.generateDockerignore();
    await fs.writeFile(path.join(projectPath, '.dockerignore'), dockerignore);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // Documentation is handled by README generation
  }

  // Helper methods
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '# .NET Core',
      'bin/',
      'obj/',
      '*.user',
      '*.userosscache',
      '*.sln.docstates',
      '[Dd]ebug/',
      '[Dd]ebugPublic/',
      '[Rr]elease/',
      '[Rr]eleases/',
      'x64/',
      'x86/',
      'bld/',
      '[Bb]in/',
      '[Oo]bj/',
      '[Ll]og/',
      '[Ll]ogs/',
      '*.pdb',
      '*.vspscc',
      '*.vssscc',
      '.builds',
      '*.pidb',
      '*.svclog',
      '*.scc',
      '_Chutzpah*',
      '*.cache',
      '!?*.[Cc]ache/',
      '[Tt]est[Rr]esult*/',
      '[Bb]uild[Ll]og.*',
      '*.VisualState.xml',
      'TestResult.xml',
      '[Dd]erivedData/',
      '*.moved-aside',
      '*.xccheckout',
      '*.xcscmblueprint',
      '# Visual Studio',
      '.vs/',
      '*.suo',
      '*.user',
      '*.sln.docstates'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return '.NET 8.0 SDK or later';
  }

  protected getInstallCommand(): string {
    return 'dotnet restore';
  }

  protected getDevCommand(): string {
    return 'dotnet run';
  }

  protected getProdCommand(): string {
    return 'dotnet run --configuration Release';
  }

  protected getTestCommand(): string {
    return 'dotnet test';
  }

  protected getCoverageCommand(): string {
    return 'dotnet test --collect:"XPlat Code Coverage"';
  }

  protected getLintCommand(): string {
    return 'dotnet format --verify-no-changes';
  }

  protected getBuildCommand(): string {
    return 'dotnet build';
  }

  protected getSetupAction(): string {
    return 'actions/setup-dotnet@v3\\n      with:\\n        dotnet-version: 8.0.x';
  }

  protected async createDotnetDirectoryStructure(projectPath: string): Promise<void> {
    const projectName = this.options?.name || 'WebApi';
    const directories = [
      'src',
      `src/${projectName}`,
      `src/${projectName}/Controllers`,
      `src/${projectName}/Models`,
      `src/${projectName}/Services`,
      `src/${projectName}/DTOs`,
      `src/${projectName}/Data`,
      `src/${projectName}/Extensions`,
      `src/${projectName}/Middleware`,
      'tests',
      `tests/${projectName}.Tests`,
      `tests/${projectName}.Tests/Controllers`,
      `tests/${projectName}.Tests/Services`,
      'scripts',
      'docs'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }
  }

  protected abstract generateFrameworkSpecificFiles(projectPath: string): Promise<void>;

  protected async generateProjectFiles(projectPath: string): Promise<void> {
    const projectName = this.options?.name || 'WebApi';
    
    // Main project file
    const csproj = this.generateCsprojFile(projectName);
    await fs.writeFile(path.join(projectPath, 'src', projectName, `${projectName}.csproj`), csproj);

    // Test project file
    const testCsproj = this.generateTestProjectFile(projectName);
    await fs.writeFile(path.join(projectPath, 'tests', `${projectName}.Tests`, `${projectName}.Tests.csproj`), testCsproj);

    // Solution file
    const sln = this.generateSolutionFile(projectName);
    await fs.writeFile(path.join(projectPath, `${projectName}.sln`), sln);

    // Directory.Build.props
    const buildProps = this.generateDirectoryBuildProps();
    await fs.writeFile(path.join(projectPath, 'Directory.Build.props'), buildProps);

    // .editorconfig
    const editorConfig = this.generateEditorConfig();
    await fs.writeFile(path.join(projectPath, '.editorconfig'), editorConfig);

    // NuGet.Config
    const nugetConfig = this.generateNuGetConfig();
    await fs.writeFile(path.join(projectPath, 'NuGet.Config'), nugetConfig);

    await this.generateFrameworkSpecificFiles(projectPath);
  }

  protected generateCsprojFile(projectName: string): string {
    const packageReferences = this.getPackageReferences();
    const packageReferenceElements = Object.entries(packageReferences)
      .map(([name, version]) => `    <PackageReference Include="${name}" Version="${version}" />`)
      .join('\n');

    return `<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>${this.targetFramework}</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
    <NoWarn>$(NoWarn);1591</NoWarn>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <WarningsNotAsErrors>$(WarningsNotAsErrors);1591</WarningsNotAsErrors>
  </PropertyGroup>

  <PropertyGroup Condition="'$(Configuration)' == 'Debug'">
    <DefineConstants>DEBUG;TRACE</DefineConstants>
  </PropertyGroup>

  <ItemGroup>
${packageReferenceElements}
  </ItemGroup>

</Project>`;
  }

  protected generateTestProjectFile(projectName: string): string {
    return `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>${this.targetFramework}</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <IsPackable>false</IsPackable>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" />
    <PackageReference Include="xunit" Version="2.6.2" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.5.3">
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
    <PackageReference Include="Microsoft.AspNetCore.Mvc.Testing" Version="8.0.0" />
    <PackageReference Include="FluentAssertions" Version="6.12.0" />
    <PackageReference Include="Moq" Version="4.20.69" />
    <PackageReference Include="Testcontainers.PostgreSql" Version="3.6.0" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\\..\\src\\${projectName}\\${projectName}.csproj" />
  </ItemGroup>

</Project>`;
  }

  protected generateSolutionFile(projectName: string): string {
    return `
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "${projectName}", "src\\${projectName}\\${projectName}.csproj", "{${this.generateGuid()}}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "${projectName}.Tests", "tests\\${projectName}.Tests\\${projectName}.Tests.csproj", "{${this.generateGuid()}}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|Any CPU = Debug|Any CPU
		Release|Any CPU = Release|Any CPU
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{${this.generateGuid()}}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
		{${this.generateGuid()}}.Debug|Any CPU.Build.0 = Debug|Any CPU
		{${this.generateGuid()}}.Release|Any CPU.ActiveCfg = Release|Any CPU
		{${this.generateGuid()}}.Release|Any CPU.Build.0 = Release|Any CPU
	EndGlobalSection
EndGlobal`.trim();
  }

  protected generateDirectoryBuildProps(): string {
    return `<Project>
  <PropertyGroup>
    <LangVersion>latest</LangVersion>
    <Authors>Re-Shell CLI</Authors>
    <Company>Re-Shell</Company>
    <Copyright>Copyright © ${new Date().getFullYear()}</Copyright>
    <Version>1.0.0</Version>
    <AssemblyVersion>1.0.0</AssemblyVersion>
    <FileVersion>1.0.0</FileVersion>
  </PropertyGroup>

  <PropertyGroup>
    <AnalysisLevel>latest</AnalysisLevel>
    <EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.CodeAnalysis.Analyzers" Version="3.3.4">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
    </PackageReference>
  </ItemGroup>
</Project>`;
  }

  protected generateEditorConfig(): string {
    return `root = true

[*]
charset = utf-8
insert_final_newline = true
trim_trailing_whitespace = true

[*.cs]
indent_style = space
indent_size = 4
end_of_line = crlf

# C# coding conventions
dotnet_style_qualification_for_field = false
dotnet_style_qualification_for_property = false
dotnet_style_qualification_for_method = false
dotnet_style_qualification_for_event = false
dotnet_style_predefined_type_for_locals_parameters_members = true
dotnet_style_predefined_type_for_member_access = true
dotnet_style_require_accessibility_modifiers = always
dotnet_style_readonly_field = true

# Expression-level preferences
dotnet_style_object_initializer = true
dotnet_style_collection_initializer = true
dotnet_style_explicit_tuple_names = true
dotnet_style_null_propagation = true
dotnet_style_coalesce_expression = true
dotnet_style_prefer_is_null_check_over_reference_equality_method = true
dotnet_style_prefer_inferred_tuple_names = true
dotnet_style_prefer_inferred_anonymous_type_member_names = true

# C# formatting rules
csharp_new_line_before_open_brace = all
csharp_new_line_before_else = true
csharp_new_line_before_catch = true
csharp_new_line_before_finally = true
csharp_new_line_before_members_in_object_initializers = true
csharp_new_line_before_members_in_anonymous_types = true
csharp_new_line_between_query_expression_clauses = true

# Indentation preferences
csharp_indent_case_contents = true
csharp_indent_switch_labels = true
csharp_indent_labels = flush_left

# Space preferences
csharp_space_after_cast = false
csharp_space_after_keywords_in_control_flow_statements = true
csharp_space_between_method_call_parameter_list_parentheses = false
csharp_space_between_method_declaration_parameter_list_parentheses = false
csharp_space_between_parentheses = false
csharp_space_before_colon_in_inheritance_clause = true
csharp_space_after_colon_in_inheritance_clause = true
csharp_space_around_binary_operators = before_and_after
csharp_space_between_method_declaration_empty_parameter_list_parentheses = false
csharp_space_between_method_call_name_and_opening_parenthesis = false
csharp_space_between_method_call_empty_parameter_list_parentheses = false

# Wrapping preferences
csharp_preserve_single_line_statements = true
csharp_preserve_single_line_blocks = true

[*.{json,yml,yaml}]
indent_style = space
indent_size = 2

[*.md]
trim_trailing_whitespace = false`;
  }

  protected generateNuGetConfig(): string {
    return `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>`;
  }

  protected async generateSourceFiles(projectPath: string): Promise<void> {
    const projectName = this.options?.name || 'WebApi';

    // Program.cs
    const program = this.generateProgramFile();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Program.cs'), program);

    // Models
    const userModel = this.generateUserModel();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Models', 'User.cs'), userModel);

    // DTOs
    const userDto = this.generateUserDto();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'DTOs', 'UserDto.cs'), userDto);

    const createUserDto = this.generateCreateUserDto();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'DTOs', 'CreateUserDto.cs'), createUserDto);

    // Services
    const userService = this.generateUserService();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Services', 'UserService.cs'), userService);

    const userServiceInterface = this.generateUserServiceInterface();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Services', 'IUserService.cs'), userServiceInterface);

    // Controllers
    const userController = this.generateUserController();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Controllers', 'UsersController.cs'), userController);

    const healthController = this.generateHealthController();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Controllers', 'HealthController.cs'), healthController);

    // Extensions
    const serviceCollectionExtensions = this.generateServiceCollectionExtensions();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Extensions', 'ServiceCollectionExtensions.cs'), serviceCollectionExtensions);

    // Middleware
    const errorHandlingMiddleware = this.generateErrorHandlingMiddleware();
    await fs.writeFile(path.join(projectPath, 'src', projectName, 'Middleware', 'ErrorHandlingMiddleware.cs'), errorHandlingMiddleware);
  }

  protected abstract generateProgramFile(): string;
  protected abstract getPackageReferences(): Record<string, string>;

  protected generateUserModel(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using System.ComponentModel.DataAnnotations;

namespace ${projectName}.Models;

public class User
{
    public int Id { get; set; }
    
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
    
    [Required]
    [EmailAddress]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? UpdatedAt { get; set; }
}`;
  }

  protected generateUserDto(): string {
    const projectName = this.options?.name || 'WebApi';
    return `namespace ${projectName}.DTOs;

public record UserDto(
    int Id,
    string Name,
    string Email,
    DateTime CreatedAt,
    DateTime? UpdatedAt
);`;
  }

  protected generateCreateUserDto(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using System.ComponentModel.DataAnnotations;

namespace ${projectName}.DTOs;

public record CreateUserDto(
    [Required] [MaxLength(100)] string Name,
    [Required] [EmailAddress] [MaxLength(255)] string Email
);`;
  }

  protected generateUserServiceInterface(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using ${projectName}.DTOs;
using ${projectName}.Models;

namespace ${projectName}.Services;

public interface IUserService
{
    Task<IEnumerable<UserDto>> GetAllUsersAsync();
    Task<UserDto?> GetUserByIdAsync(int id);
    Task<UserDto> CreateUserAsync(CreateUserDto createUserDto);
    Task<UserDto?> UpdateUserAsync(int id, CreateUserDto updateUserDto);
    Task<bool> DeleteUserAsync(int id);
}`;
  }

  protected generateUserService(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using ${projectName}.DTOs;
using ${projectName}.Models;

namespace ${projectName}.Services;

public class UserService : IUserService
{
    private readonly List<User> _users = new();
    private int _nextId = 1;

    public Task<IEnumerable<UserDto>> GetAllUsersAsync()
    {
        var userDtos = _users.Select(user => new UserDto(
            user.Id,
            user.Name,
            user.Email,
            user.CreatedAt,
            user.UpdatedAt
        ));
        
        return Task.FromResult(userDtos);
    }

    public Task<UserDto?> GetUserByIdAsync(int id)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        if (user == null)
            return Task.FromResult<UserDto?>(null);

        var userDto = new UserDto(
            user.Id,
            user.Name,
            user.Email,
            user.CreatedAt,
            user.UpdatedAt
        );

        return Task.FromResult<UserDto?>(userDto);
    }

    public Task<UserDto> CreateUserAsync(CreateUserDto createUserDto)
    {
        var user = new User
        {
            Id = _nextId++,
            Name = createUserDto.Name,
            Email = createUserDto.Email,
            CreatedAt = DateTime.UtcNow
        };

        _users.Add(user);

        var userDto = new UserDto(
            user.Id,
            user.Name,
            user.Email,
            user.CreatedAt,
            user.UpdatedAt
        );

        return Task.FromResult(userDto);
    }

    public Task<UserDto?> UpdateUserAsync(int id, CreateUserDto updateUserDto)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        if (user == null)
            return Task.FromResult<UserDto?>(null);

        user.Name = updateUserDto.Name;
        user.Email = updateUserDto.Email;
        user.UpdatedAt = DateTime.UtcNow;

        var userDto = new UserDto(
            user.Id,
            user.Name,
            user.Email,
            user.CreatedAt,
            user.UpdatedAt
        );

        return Task.FromResult<UserDto?>(userDto);
    }

    public Task<bool> DeleteUserAsync(int id)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        if (user == null)
            return Task.FromResult(false);

        _users.Remove(user);
        return Task.FromResult(true);
    }
}`;
  }

  protected generateUserController(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.AspNetCore.Mvc;
using ${projectName}.DTOs;
using ${projectName}.Services;

namespace ${projectName}.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    /// <summary>
    /// Get all users
    /// </summary>
    /// <returns>List of users</returns>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<UserDto>>> GetUsers()
    {
        var users = await _userService.GetAllUsersAsync();
        return Ok(users);
    }

    /// <summary>
    /// Get user by ID
    /// </summary>
    /// <param name="id">User ID</param>
    /// <returns>User details</returns>
    [HttpGet("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserDto>> GetUser(int id)
    {
        var user = await _userService.GetUserByIdAsync(id);
        if (user == null)
            return NotFound();

        return Ok(user);
    }

    /// <summary>
    /// Create a new user
    /// </summary>
    /// <param name="createUserDto">User creation data</param>
    /// <returns>Created user</returns>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<UserDto>> CreateUser([FromBody] CreateUserDto createUserDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _userService.CreateUserAsync(createUserDto);
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
    }

    /// <summary>
    /// Update an existing user
    /// </summary>
    /// <param name="id">User ID</param>
    /// <param name="updateUserDto">User update data</param>
    /// <returns>Updated user</returns>
    [HttpPut("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserDto>> UpdateUser(int id, [FromBody] CreateUserDto updateUserDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _userService.UpdateUserAsync(id, updateUserDto);
        if (user == null)
            return NotFound();

        return Ok(user);
    }

    /// <summary>
    /// Delete a user
    /// </summary>
    /// <param name="id">User ID</param>
    /// <returns>No content</returns>
    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> DeleteUser(int id)
    {
        var deleted = await _userService.DeleteUserAsync(id);
        if (!deleted)
            return NotFound();

        return NoContent();
    }
}`;
  }

  protected generateHealthController(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.AspNetCore.Mvc;

namespace ${projectName}.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    /// <summary>
    /// Health check endpoint
    /// </summary>
    /// <returns>Health status</returns>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public ActionResult<object> GetHealth()
    {
        return Ok(new
        {
            Status = "Healthy",
            Timestamp = DateTime.UtcNow,
            Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production",
            Framework = "${this.framework}",
            Version = "1.0.0"
        });
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
                Description = "A ${this.framework} Web API built with Re-Shell CLI"
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

  protected generateErrorHandlingMiddleware(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using System.Net;
using System.Text.Json;

namespace ${projectName}.Middleware;

public class ErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlingMiddleware> _logger;

    public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred");
            await HandleExceptionAsync(context, ex);
        }
    }

    private static async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";
        
        var response = new
        {
            error = new
            {
                message = "An error occurred while processing your request",
                type = exception.GetType().Name,
                timestamp = DateTime.UtcNow
            }
        };

        context.Response.StatusCode = exception switch
        {
            ArgumentException => (int)HttpStatusCode.BadRequest,
            UnauthorizedAccessException => (int)HttpStatusCode.Unauthorized,
            NotImplementedException => (int)HttpStatusCode.NotImplemented,
            _ => (int)HttpStatusCode.InternalServerError
        };

        var jsonResponse = JsonSerializer.Serialize(response, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        await context.Response.WriteAsync(jsonResponse);
    }
}`;
  }

  protected async generateTestFiles(projectPath: string): Promise<void> {
    const projectName = this.options?.name || 'WebApi';

    // Controller tests
    const userControllerTest = this.generateUserControllerTest();
    await fs.writeFile(
      path.join(projectPath, 'tests', `${projectName}.Tests`, 'Controllers', 'UsersControllerTests.cs'),
      userControllerTest
    );

    // Service tests
    const userServiceTest = this.generateUserServiceTest();
    await fs.writeFile(
      path.join(projectPath, 'tests', `${projectName}.Tests`, 'Services', 'UserServiceTests.cs'),
      userServiceTest
    );

    // Integration tests
    const integrationTest = this.generateIntegrationTest();
    await fs.writeFile(
      path.join(projectPath, 'tests', `${projectName}.Tests`, 'IntegrationTests.cs'),
      integrationTest
    );
  }

  protected generateUserControllerTest(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.AspNetCore.Mvc;
using Moq;
using ${projectName}.Controllers;
using ${projectName}.DTOs;
using ${projectName}.Services;
using FluentAssertions;

namespace ${projectName}.Tests.Controllers;

public class UsersControllerTests
{
    private readonly Mock<IUserService> _mockUserService;
    private readonly UsersController _controller;

    public UsersControllerTests()
    {
        _mockUserService = new Mock<IUserService>();
        _controller = new UsersController(_mockUserService.Object);
    }

    [Fact]
    public async Task GetUsers_ShouldReturnOkWithUsers()
    {
        // Arrange
        var users = new List<UserDto>
        {
            new(1, "John Doe", "john@example.com", DateTime.UtcNow, null),
            new(2, "Jane Smith", "jane@example.com", DateTime.UtcNow, null)
        };
        _mockUserService.Setup(s => s.GetAllUsersAsync()).ReturnsAsync(users);

        // Act
        var result = await _controller.GetUsers();

        // Assert
        result.Result.Should().BeOfType<OkObjectResult>();
        var okResult = result.Result as OkObjectResult;
        okResult!.Value.Should().BeEquivalentTo(users);
    }

    [Fact]
    public async Task GetUser_WithValidId_ShouldReturnOkWithUser()
    {
        // Arrange
        var user = new UserDto(1, "John Doe", "john@example.com", DateTime.UtcNow, null);
        _mockUserService.Setup(s => s.GetUserByIdAsync(1)).ReturnsAsync(user);

        // Act
        var result = await _controller.GetUser(1);

        // Assert
        result.Result.Should().BeOfType<OkObjectResult>();
        var okResult = result.Result as OkObjectResult;
        okResult!.Value.Should().BeEquivalentTo(user);
    }

    [Fact]
    public async Task GetUser_WithInvalidId_ShouldReturnNotFound()
    {
        // Arrange
        _mockUserService.Setup(s => s.GetUserByIdAsync(999)).ReturnsAsync((UserDto?)null);

        // Act
        var result = await _controller.GetUser(999);

        // Assert
        result.Result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task CreateUser_WithValidData_ShouldReturnCreated()
    {
        // Arrange
        var createUserDto = new CreateUserDto("John Doe", "john@example.com");
        var createdUser = new UserDto(1, "John Doe", "john@example.com", DateTime.UtcNow, null);
        _mockUserService.Setup(s => s.CreateUserAsync(createUserDto)).ReturnsAsync(createdUser);

        // Act
        var result = await _controller.CreateUser(createUserDto);

        // Assert
        result.Result.Should().BeOfType<CreatedAtActionResult>();
        var createdResult = result.Result as CreatedAtActionResult;
        createdResult!.Value.Should().BeEquivalentTo(createdUser);
    }
}`;
  }

  protected generateUserServiceTest(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using ${projectName}.DTOs;
using ${projectName}.Services;
using FluentAssertions;

namespace ${projectName}.Tests.Services;

public class UserServiceTests
{
    private readonly UserService _userService;

    public UserServiceTests()
    {
        _userService = new UserService();
    }

    [Fact]
    public async Task GetAllUsersAsync_WhenEmpty_ShouldReturnEmptyList()
    {
        // Act
        var result = await _userService.GetAllUsersAsync();

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task CreateUserAsync_ShouldCreateAndReturnUser()
    {
        // Arrange
        var createUserDto = new CreateUserDto("John Doe", "john@example.com");

        // Act
        var result = await _userService.CreateUserAsync(createUserDto);

        // Assert
        result.Should().NotBeNull();
        result.Id.Should().BeGreaterThan(0);
        result.Name.Should().Be("John Doe");
        result.Email.Should().Be("john@example.com");
        result.CreatedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task GetUserByIdAsync_WithValidId_ShouldReturnUser()
    {
        // Arrange
        var createUserDto = new CreateUserDto("John Doe", "john@example.com");
        var createdUser = await _userService.CreateUserAsync(createUserDto);

        // Act
        var result = await _userService.GetUserByIdAsync(createdUser.Id);

        // Assert
        result.Should().NotBeNull();
        result!.Id.Should().Be(createdUser.Id);
        result.Name.Should().Be("John Doe");
        result.Email.Should().Be("john@example.com");
    }

    [Fact]
    public async Task UpdateUserAsync_WithValidId_ShouldUpdateAndReturnUser()
    {
        // Arrange
        var createUserDto = new CreateUserDto("John Doe", "john@example.com");
        var createdUser = await _userService.CreateUserAsync(createUserDto);
        var updateUserDto = new CreateUserDto("Jane Smith", "jane@example.com");

        // Act
        var result = await _userService.UpdateUserAsync(createdUser.Id, updateUserDto);

        // Assert
        result.Should().NotBeNull();
        result!.Id.Should().Be(createdUser.Id);
        result.Name.Should().Be("Jane Smith");
        result.Email.Should().Be("jane@example.com");
        result.UpdatedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task DeleteUserAsync_WithValidId_ShouldReturnTrue()
    {
        // Arrange
        var createUserDto = new CreateUserDto("John Doe", "john@example.com");
        var createdUser = await _userService.CreateUserAsync(createUserDto);

        // Act
        var result = await _userService.DeleteUserAsync(createdUser.Id);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task DeleteUserAsync_WithInvalidId_ShouldReturnFalse()
    {
        // Act
        var result = await _userService.DeleteUserAsync(999);

        // Assert
        result.Should().BeFalse();
    }
}`;
  }

  protected generateIntegrationTest(): string {
    const projectName = this.options?.name || 'WebApi';
    return `using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http.Json;
using ${projectName}.DTOs;
using FluentAssertions;
using System.Net;

namespace ${projectName}.Tests;

public class IntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public IntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task HealthEndpoint_ShouldReturnHealthy()
    {
        // Act
        var response = await _client.GetAsync("/api/health");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("Healthy");
    }

    [Fact]
    public async Task GetUsers_ShouldReturnEmptyList()
    {
        // Act
        var response = await _client.GetAsync("/api/users");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var users = await response.Content.ReadFromJsonAsync<List<UserDto>>();
        users.Should().BeEmpty();
    }

    [Fact]
    public async Task CreateUser_ShouldReturnCreatedUser()
    {
        // Arrange
        var createUserDto = new CreateUserDto("John Doe", "john@example.com");

        // Act
        var response = await _client.PostAsJsonAsync("/api/users", createUserDto);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var user = await response.Content.ReadFromJsonAsync<UserDto>();
        user.Should().NotBeNull();
        user!.Name.Should().Be("John Doe");
        user.Email.Should().Be("john@example.com");
    }

    [Fact]
    public async Task GetUser_WithValidId_ShouldReturnUser()
    {
        // Arrange - Create a user first
        var createUserDto = new CreateUserDto("Jane Smith", "jane@example.com");
        var createResponse = await _client.PostAsJsonAsync("/api/users", createUserDto);
        var createdUser = await createResponse.Content.ReadFromJsonAsync<UserDto>();

        // Act
        var response = await _client.GetAsync($"/api/users/{createdUser!.Id}");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var user = await response.Content.ReadFromJsonAsync<UserDto>();
        user.Should().NotBeNull();
        user!.Id.Should().Be(createdUser.Id);
        user.Name.Should().Be("Jane Smith");
        user.Email.Should().Be("jane@example.com");
    }
}`;
  }

  protected generateGuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16).toUpperCase();
    });
  }

  protected generateDockerfile(): string {
    const projectName = this.options?.name || 'WebApi';
    return `# See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER app
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["src/${projectName}/${projectName}.csproj", "src/${projectName}/"]
RUN dotnet restore "./src/${projectName}/${projectName}.csproj"
COPY . .
WORKDIR "/src/src/${projectName}"
RUN dotnet build "./${projectName}.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./${projectName}.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "${projectName}.dll"]`;
  }

  protected generateDockerignore(): string {
    return `# Directories
**/bin/
**/obj/
**/out/
**/TestResults/

# Files
Dockerfile*
**/.dockerignore
**/.env
**/.git
**/.gitignore
**/.project
**/.settings
**/.toolstarget
**/.vs
**/.vscode
**/.idea
**/*.*proj.user
**/*.dbmdl
**/*.jfm
**/azds.yaml
**/bin
**/charts
**/docker-compose*
**/Dockerfile*
**/node_modules
**/npm-debug.log
**/obj
**/secrets.dev.yaml
**/values.dev.yaml
LICENSE
README.md`;
  }
}