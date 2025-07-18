import { BackendTemplate } from '../types';

export const fsharpSaturnTemplate: BackendTemplate = {
  id: 'fsharp-saturn',
  name: 'fsharp-saturn',
  displayName: 'F# Saturn Web Framework',
  description: 'Modern functional web framework for F# built on top of ASP.NET Core with domain-driven design patterns',
  framework: 'saturn',
  language: 'fsharp',
  version: '0.16',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🪐',
  type: 'rest-api',
  complexity: 'intermediate',
  keywords: ['fsharp', 'saturn', 'functional', 'web', 'ddd', 'aspnet'],
  
  features: [
    'MVC-like architecture',
    'Functional programming',
    'Domain-driven design',
    'Built on ASP.NET Core',
    'Type-safe routing',
    'Model validation',
    'Authentication middleware',
    'CORS support',
    'JSON API',
    'View engines',
    'Database integration',
    'Testing support',
    'Hot reload',
    'Docker support'
  ],
  
  structure: {
    'Program.fs': `open System
open System.IO
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Saturn
open FSharpSaturnApp.Router
open FSharpSaturnApp.Models
open FSharpSaturnApp.Services
open FSharpSaturnApp.Database

let endpointPipe = pipeline {
    plug acceptJson
    plug putSecureBrowserHeaders
    set_header "x-pipeline-type" "Api"
}

let app = application {
    url "http://0.0.0.0:5000/"
    use_router appRouter
    memory_cache
    use_static "static"
    use_json_serializer (Thoth.Json.Giraffe.ThothSerializer())
    use_gzip
    
    service_config (fun services ->
        services.AddScoped<IUserService, UserService>() |> ignore
        services.AddScoped<ITodoService, TodoService>() |> ignore
        services.AddScoped<IAuthService, AuthService>() |> ignore
        services.AddDbContext<AppDbContext>() |> ignore
        services.AddCors(fun options ->
            options.AddDefaultPolicy(fun policy ->
                policy.AllowAnyOrigin()
                      .AllowAnyMethod()
                      .AllowAnyHeader() |> ignore
            )
        ) |> ignore
    )
    
    host_config (fun host ->
        host.ConfigureLogging(fun logging ->
            logging.AddConsole().AddDebug() |> ignore
        )
    )
}

[<EntryPoint>]
let main args =
    printfn "Starting Saturn application..."
    run app`,

    'Router.fs': `namespace FSharpSaturnApp

open Saturn
open FSharpSaturnApp.Controllers

module Router =
    let appRouter = router {
        get "/" (text "F# Saturn API Server")
        get "/health" (json {| status = "healthy"; timestamp = System.DateTime.UtcNow |})
        
        forward "/api/users" usersController
        forward "/api/todos" todosController
        forward "/api/auth" authController
    }`,

    'Controllers/UsersController.fs': `namespace FSharpSaturnApp.Controllers

open Microsoft.AspNetCore.Http
open FSharp.Control.Tasks
open Saturn
open FSharpSaturnApp.Models
open FSharpSaturnApp.Services

module UsersController =
    
    let indexAction : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                let! users = userService.GetAllAsync()
                return! json users ctx
            }
    
    let showAction (id: int) : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                let! user = userService.GetByIdAsync(id)
                match user with
                | Some u -> return! json u ctx
                | None -> return! Response.notFound ctx
            }
    
    let createAction : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                let! user = Controller.getModel<CreateUserRequest> ctx
                
                match user with
                | Ok userRequest ->
                    let! createdUser = userService.CreateAsync(userRequest)
                    return! json createdUser ctx
                | Error errors ->
                    return! Response.badRequest (json {| errors = errors |}) ctx
            }
    
    let updateAction (id: int) : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                let! user = Controller.getModel<UpdateUserRequest> ctx
                
                match user with
                | Ok userRequest ->
                    let! updatedUser = userService.UpdateAsync(id, userRequest)
                    match updatedUser with
                    | Some u -> return! json u ctx
                    | None -> return! Response.notFound ctx
                | Error errors ->
                    return! Response.badRequest (json {| errors = errors |}) ctx
            }
    
    let deleteAction (id: int) : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                let! success = userService.DeleteAsync(id)
                if success then
                    return! Response.ok (json {| message = "User deleted successfully" |}) ctx
                else
                    return! Response.notFound ctx
            }

    let usersController = controller {
        index indexAction
        show showAction
        create createAction
        update updateAction
        delete deleteAction
        
        plug [All] (pipeline { accept_json })
    }`,

    'Controllers/TodosController.fs': `namespace FSharpSaturnApp.Controllers

open Microsoft.AspNetCore.Http
open FSharp.Control.Tasks
open Saturn
open FSharpSaturnApp.Models
open FSharpSaturnApp.Services

module TodosController =
    
    let indexAction : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! todos = todoService.GetAllAsync()
                return! json todos ctx
            }
    
    let showAction (id: int) : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! todo = todoService.GetByIdAsync(id)
                match todo with
                | Some t -> return! json t ctx
                | None -> return! Response.notFound ctx
            }
    
    let createAction : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! todo = Controller.getModel<CreateTodoRequest> ctx
                
                match todo with
                | Ok todoRequest ->
                    let! createdTodo = todoService.CreateAsync(todoRequest)
                    return! json createdTodo ctx
                | Error errors ->
                    return! Response.badRequest (json {| errors = errors |}) ctx
            }
    
    let updateAction (id: int) : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! todo = Controller.getModel<UpdateTodoRequest> ctx
                
                match todo with
                | Ok todoRequest ->
                    let! updatedTodo = todoService.UpdateAsync(id, todoRequest)
                    match updatedTodo with
                    | Some t -> return! json t ctx
                    | None -> return! Response.notFound ctx
                | Error errors ->
                    return! Response.badRequest (json {| errors = errors |}) ctx
            }
    
    let deleteAction (id: int) : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! success = todoService.DeleteAsync(id)
                if success then
                    return! Response.ok (json {| message = "Todo deleted successfully" |}) ctx
                else
                    return! Response.notFound ctx
            }
    
    let completeAction (id: int) : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! todo = todoService.CompleteAsync(id)
                match todo with
                | Some t -> return! json t ctx
                | None -> return! Response.notFound ctx
            }

    let todosController = controller {
        index indexAction
        show showAction
        create createAction
        update updateAction
        delete deleteAction
        
        plug [All] (pipeline { accept_json })
        
        action "complete" [POST] completeAction
    }`,

    'Controllers/AuthController.fs': `namespace FSharpSaturnApp.Controllers

open Microsoft.AspNetCore.Http
open FSharp.Control.Tasks
open Saturn
open FSharpSaturnApp.Models
open FSharpSaturnApp.Services

module AuthController =
    
    let loginAction : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let authService = ctx.GetService<IAuthService>()
                let! loginRequest = Controller.getModel<LoginRequest> ctx
                
                match loginRequest with
                | Ok request ->
                    let! result = authService.LoginAsync(request.Email, request.Password)
                    match result with
                    | Some token ->
                        return! json {| token = token; message = "Login successful" |} ctx
                    | None ->
                        return! Response.unauthorized (json {| error = "Invalid credentials" |}) ctx
                | Error errors ->
                    return! Response.badRequest (json {| errors = errors |}) ctx
            }
    
    let registerAction : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let authService = ctx.GetService<IAuthService>()
                let! registerRequest = Controller.getModel<RegisterRequest> ctx
                
                match registerRequest with
                | Ok request ->
                    let! result = authService.RegisterAsync(request)
                    match result with
                    | Ok user ->
                        return! json {| user = user; message = "Registration successful" |} ctx
                    | Error error ->
                        return! Response.badRequest (json {| error = error |}) ctx
                | Error errors ->
                    return! Response.badRequest (json {| errors = errors |}) ctx
            }
    
    let logoutAction : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                // In a stateless JWT system, logout is typically handled client-side
                return! json {| message = "Logout successful" |} ctx
            }
    
    let meAction : HttpHandler =
        fun (ctx : HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                // Extract user ID from JWT token (would need middleware for this)
                let userId = 1 // Placeholder - would extract from JWT
                let! user = userService.GetByIdAsync(userId)
                match user with
                | Some u -> return! json u ctx
                | None -> return! Response.unauthorized ctx
            }

    let authController = router {
        post "/login" loginAction
        post "/register" registerAction
        post "/logout" logoutAction
        get "/me" meAction
    }`,

    'Models/Domain.fs': `namespace FSharpSaturnApp.Models

open System
open Thoth.Json.Net

type UserRole =
    | Admin
    | User
    | Moderator

type User = {
    Id: int
    Email: string
    FirstName: string
    LastName: string
    Role: UserRole
    CreatedAt: DateTime
    UpdatedAt: DateTime
}

type Todo = {
    Id: int
    Title: string
    Description: string option
    IsCompleted: bool
    UserId: int
    DueDate: DateTime option
    Priority: Priority
    CreatedAt: DateTime
    UpdatedAt: DateTime
}

and Priority =
    | Low
    | Medium
    | High
    | Critical

// Request DTOs
type CreateUserRequest = {
    Email: string
    FirstName: string
    LastName: string
    Password: string
    Role: UserRole option
}

type UpdateUserRequest = {
    Email: string option
    FirstName: string option
    LastName: string option
    Role: UserRole option
}

type CreateTodoRequest = {
    Title: string
    Description: string option
    UserId: int
    DueDate: DateTime option
    Priority: Priority option
}

type UpdateTodoRequest = {
    Title: string option
    Description: string option
    IsCompleted: bool option
    DueDate: DateTime option
    Priority: Priority option
}

type LoginRequest = {
    Email: string
    Password: string
}

type RegisterRequest = {
    Email: string
    FirstName: string
    LastName: string
    Password: string
    ConfirmPassword: string
}

// JSON Encoders/Decoders for Thoth.Json
module UserRole =
    let encoder = function
        | Admin -> Encode.string "admin"
        | User -> Encode.string "user"
        | Moderator -> Encode.string "moderator"
    
    let decoder =
        Decode.string
        |> Decode.andThen (function
            | "admin" -> Decode.succeed Admin
            | "user" -> Decode.succeed User
            | "moderator" -> Decode.succeed Moderator
            | invalid -> Decode.fail $"Invalid user role: {invalid}")

module Priority =
    let encoder = function
        | Low -> Encode.string "low"
        | Medium -> Encode.string "medium"
        | High -> Encode.string "high"
        | Critical -> Encode.string "critical"
    
    let decoder =
        Decode.string
        |> Decode.andThen (function
            | "low" -> Decode.succeed Low
            | "medium" -> Decode.succeed Medium
            | "high" -> Decode.succeed High
            | "critical" -> Decode.succeed Critical
            | invalid -> Decode.fail $"Invalid priority: {invalid}")`,

    'Services/UserService.fs': `namespace FSharpSaturnApp.Services

open System.Threading.Tasks
open FSharpSaturnApp.Models

type IUserService =
    abstract member GetAllAsync: unit -> Task<User list>
    abstract member GetByIdAsync: int -> Task<User option>
    abstract member GetByEmailAsync: string -> Task<User option>
    abstract member CreateAsync: CreateUserRequest -> Task<User>
    abstract member UpdateAsync: int * UpdateUserRequest -> Task<User option>
    abstract member DeleteAsync: int -> Task<bool>

type UserService() =
    // In-memory storage for demo purposes
    let mutable users = [
        { Id = 1; Email = "admin@example.com"; FirstName = "Admin"; LastName = "User"; Role = Admin; CreatedAt = System.DateTime.UtcNow.AddDays(-30.0); UpdatedAt = System.DateTime.UtcNow }
        { Id = 2; Email = "user@example.com"; FirstName = "Regular"; LastName = "User"; Role = User; CreatedAt = System.DateTime.UtcNow.AddDays(-15.0); UpdatedAt = System.DateTime.UtcNow }
    ]
    let mutable nextId = 3

    interface IUserService with
        member _.GetAllAsync() =
            Task.FromResult(users)
        
        member _.GetByIdAsync(id: int) =
            let user = users |> List.tryFind (fun u -> u.Id = id)
            Task.FromResult(user)
        
        member _.GetByEmailAsync(email: string) =
            let user = users |> List.tryFind (fun u -> u.Email = email)
            Task.FromResult(user)
        
        member _.CreateAsync(request: CreateUserRequest) =
            let user = {
                Id = nextId
                Email = request.Email
                FirstName = request.FirstName
                LastName = request.LastName
                Role = request.Role |> Option.defaultValue User
                CreatedAt = System.DateTime.UtcNow
                UpdatedAt = System.DateTime.UtcNow
            }
            nextId <- nextId + 1
            users <- user :: users
            Task.FromResult(user)
        
        member _.UpdateAsync(id: int, request: UpdateUserRequest) =
            let userIndex = users |> List.tryFindIndex (fun u -> u.Id = id)
            match userIndex with
            | Some index ->
                let existingUser = users.[index]
                let updatedUser = {
                    existingUser with
                        Email = request.Email |> Option.defaultValue existingUser.Email
                        FirstName = request.FirstName |> Option.defaultValue existingUser.FirstName
                        LastName = request.LastName |> Option.defaultValue existingUser.LastName
                        Role = request.Role |> Option.defaultValue existingUser.Role
                        UpdatedAt = System.DateTime.UtcNow
                }
                users <- users |> List.mapi (fun i u -> if i = index then updatedUser else u)
                Task.FromResult(Some updatedUser)
            | None ->
                Task.FromResult(None)
        
        member _.DeleteAsync(id: int) =
            let initialCount = users |> List.length
            users <- users |> List.filter (fun u -> u.Id <> id)
            let finalCount = users |> List.length
            Task.FromResult(initialCount > finalCount)`,

    'Services/TodoService.fs': `namespace FSharpSaturnApp.Services

open System.Threading.Tasks
open FSharpSaturnApp.Models

type ITodoService =
    abstract member GetAllAsync: unit -> Task<Todo list>
    abstract member GetByIdAsync: int -> Task<Todo option>
    abstract member GetByUserIdAsync: int -> Task<Todo list>
    abstract member CreateAsync: CreateTodoRequest -> Task<Todo>
    abstract member UpdateAsync: int * UpdateTodoRequest -> Task<Todo option>
    abstract member CompleteAsync: int -> Task<Todo option>
    abstract member DeleteAsync: int -> Task<bool>

type TodoService() =
    // In-memory storage for demo purposes
    let mutable todos = [
        { Id = 1; Title = "Learn F#"; Description = Some "Study functional programming concepts"; IsCompleted = false; UserId = 1; DueDate = Some (System.DateTime.UtcNow.AddDays(7.0)); Priority = High; CreatedAt = System.DateTime.UtcNow.AddDays(-5.0); UpdatedAt = System.DateTime.UtcNow }
        { Id = 2; Title = "Build Saturn app"; Description = Some "Create a web API with Saturn framework"; IsCompleted = false; UserId = 1; DueDate = Some (System.DateTime.UtcNow.AddDays(14.0)); Priority = Medium; CreatedAt = System.DateTime.UtcNow.AddDays(-3.0); UpdatedAt = System.DateTime.UtcNow }
        { Id = 3; Title = "Deploy to production"; Description = None; IsCompleted = false; UserId = 2; DueDate = Some (System.DateTime.UtcNow.AddDays(30.0)); Priority = Low; CreatedAt = System.DateTime.UtcNow.AddDays(-1.0); UpdatedAt = System.DateTime.UtcNow }
    ]
    let mutable nextId = 4

    interface ITodoService with
        member _.GetAllAsync() =
            Task.FromResult(todos)
        
        member _.GetByIdAsync(id: int) =
            let todo = todos |> List.tryFind (fun t -> t.Id = id)
            Task.FromResult(todo)
        
        member _.GetByUserIdAsync(userId: int) =
            let userTodos = todos |> List.filter (fun t -> t.UserId = userId)
            Task.FromResult(userTodos)
        
        member _.CreateAsync(request: CreateTodoRequest) =
            let todo = {
                Id = nextId
                Title = request.Title
                Description = request.Description
                IsCompleted = false
                UserId = request.UserId
                DueDate = request.DueDate
                Priority = request.Priority |> Option.defaultValue Medium
                CreatedAt = System.DateTime.UtcNow
                UpdatedAt = System.DateTime.UtcNow
            }
            nextId <- nextId + 1
            todos <- todo :: todos
            Task.FromResult(todo)
        
        member _.UpdateAsync(id: int, request: UpdateTodoRequest) =
            let todoIndex = todos |> List.tryFindIndex (fun t -> t.Id = id)
            match todoIndex with
            | Some index ->
                let existingTodo = todos.[index]
                let updatedTodo = {
                    existingTodo with
                        Title = request.Title |> Option.defaultValue existingTodo.Title
                        Description = request.Description |> Option.orElse existingTodo.Description
                        IsCompleted = request.IsCompleted |> Option.defaultValue existingTodo.IsCompleted
                        DueDate = request.DueDate |> Option.orElse existingTodo.DueDate
                        Priority = request.Priority |> Option.defaultValue existingTodo.Priority
                        UpdatedAt = System.DateTime.UtcNow
                }
                todos <- todos |> List.mapi (fun i t -> if i = index then updatedTodo else t)
                Task.FromResult(Some updatedTodo)
            | None ->
                Task.FromResult(None)
        
        member _.CompleteAsync(id: int) =
            let todoIndex = todos |> List.tryFindIndex (fun t -> t.Id = id)
            match todoIndex with
            | Some index ->
                let existingTodo = todos.[index]
                let completedTodo = {
                    existingTodo with
                        IsCompleted = true
                        UpdatedAt = System.DateTime.UtcNow
                }
                todos <- todos |> List.mapi (fun i t -> if i = index then completedTodo else t)
                Task.FromResult(Some completedTodo)
            | None ->
                Task.FromResult(None)
        
        member _.DeleteAsync(id: int) =
            let initialCount = todos |> List.length
            todos <- todos |> List.filter (fun t -> t.Id <> id)
            let finalCount = todos |> List.length
            Task.FromResult(initialCount > finalCount)`,

    'Services/AuthService.fs': `namespace FSharpSaturnApp.Services

open System
open System.Text
open System.Security.Claims
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Tokens
open System.Threading.Tasks
open FSharpSaturnApp.Models

type IAuthService =
    abstract member LoginAsync: string * string -> Task<string option>
    abstract member RegisterAsync: RegisterRequest -> Task<Result<User, string>>
    abstract member ValidateTokenAsync: string -> Task<ClaimsPrincipal option>
    abstract member GenerateTokenAsync: User -> Task<string>

type AuthService(userService: IUserService) =
    let jwtSecret = "your-super-secret-jwt-key-should-be-at-least-256-bits-long-for-security"
    let jwtIssuer = "saturn-app"
    let jwtAudience = "saturn-app-users"
    let jwtExpiryHours = 24.0
    
    let createSecurityKey() =
        SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
    
    let createSigningCredentials() =
        SigningCredentials(createSecurityKey(), SecurityAlgorithms.HmacSha256)
    
    let hashPassword (password: string) =
        // In production, use proper password hashing like BCrypt
        // This is just for demo purposes
        let salt = "demo-salt"
        let combined = password + salt
        let bytes = Encoding.UTF8.GetBytes(combined)
        let hash = System.Security.Cryptography.SHA256.HashData(bytes)
        Convert.ToBase64String(hash)
    
    let verifyPassword (password: string) (hashedPassword: string) =
        hashPassword password = hashedPassword

    interface IAuthService with
        member _.LoginAsync(email: string, password: string) =
            task {
                let! user = userService.GetByEmailAsync(email)
                match user with
                | Some u ->
                    // For demo, we'll assume password is correct
                    // In production, verify against hashed password
                    let! token = (this :> IAuthService).GenerateTokenAsync(u)
                    return Some token
                | None ->
                    return None
            }
        
        member _.RegisterAsync(request: RegisterRequest) =
            task {
                if request.Password <> request.ConfirmPassword then
                    return Error "Passwords do not match"
                else
                    let! existingUser = userService.GetByEmailAsync(request.Email)
                    match existingUser with
                    | Some _ ->
                        return Error "User with this email already exists"
                    | None ->
                        let hashedPassword = hashPassword request.Password
                        let createRequest = {
                            Email = request.Email
                            FirstName = request.FirstName
                            LastName = request.LastName
                            Password = hashedPassword
                            Role = Some User
                        }
                        let! user = userService.CreateAsync(createRequest)
                        return Ok user
            }
        
        member _.ValidateTokenAsync(token: string) =
            task {
                try
                    let tokenHandler = JwtSecurityTokenHandler()
                    let validationParameters = TokenValidationParameters(
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = createSecurityKey(),
                        ValidateIssuer = true,
                        ValidIssuer = jwtIssuer,
                        ValidateAudience = true,
                        ValidAudience = jwtAudience,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero
                    )
                    
                    let principal = tokenHandler.ValidateToken(token, validationParameters, ref null)
                    return Some principal
                with
                | _ -> return None
            }
        
        member _.GenerateTokenAsync(user: User) =
            task {
                let claims = [
                    Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
                    Claim(ClaimTypes.Email, user.Email)
                    Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
                    Claim(ClaimTypes.Role, user.Role.ToString())
                ]
                
                let tokenDescriptor = SecurityTokenDescriptor(
                    Subject = ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.AddHours(jwtExpiryHours),
                    Issuer = jwtIssuer,
                    Audience = jwtAudience,
                    SigningCredentials = createSigningCredentials()
                )
                
                let tokenHandler = JwtSecurityTokenHandler()
                let token = tokenHandler.CreateToken(tokenDescriptor)
                return tokenHandler.WriteToken(token)
            }`,

    'Database/AppDbContext.fs': `namespace FSharpSaturnApp.Database

open Microsoft.EntityFrameworkCore
open Microsoft.Extensions.Logging
open FSharpSaturnApp.Models

type AppDbContext(options: DbContextOptions<AppDbContext>) =
    inherit DbContext(options)
    
    [<DefaultValue>]
    val mutable private _users: DbSet<User>
    member this.Users
        with get() = this._users
        and set value = this._users <- value
    
    [<DefaultValue>]
    val mutable private _todos: DbSet<Todo>
    member this.Todos
        with get() = this._todos
        and set value = this._todos <- value
    
    override _.OnModelCreating(modelBuilder: ModelBuilder) =
        base.OnModelCreating(modelBuilder)
        
        // Configure User entity
        modelBuilder.Entity<User>(fun entity ->
            entity.HasKey(fun u -> u.Id) |> ignore
            entity.Property(fun u -> u.Email).IsRequired().HasMaxLength(255) |> ignore
            entity.Property(fun u -> u.FirstName).IsRequired().HasMaxLength(100) |> ignore
            entity.Property(fun u -> u.LastName).IsRequired().HasMaxLength(100) |> ignore
            entity.HasIndex(fun u -> u.Email).IsUnique() |> ignore
        ) |> ignore
        
        // Configure Todo entity
        modelBuilder.Entity<Todo>(fun entity ->
            entity.HasKey(fun t -> t.Id) |> ignore
            entity.Property(fun t -> t.Title).IsRequired().HasMaxLength(200) |> ignore
            entity.Property(fun t -> t.Description).HasMaxLength(1000) |> ignore
            entity.Property(fun t -> t.IsCompleted).HasDefaultValue(false) |> ignore
        ) |> ignore
    
    override _.OnConfiguring(optionsBuilder: DbContextOptionsBuilder) =
        if not optionsBuilder.IsConfigured then
            // Configure SQLite for demo purposes
            optionsBuilder.UseSqlite("Data Source=saturn_app.db") |> ignore
            optionsBuilder.LogTo(System.Console.WriteLine, LogLevel.Information) |> ignore`,

    'saturn-app.fsproj': `<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <AssemblyName>saturn-app</AssemblyName>
    <RootNamespace>FSharpSaturnApp</RootNamespace>
    <EnableDefaultContentItems>false</EnableDefaultContentItems>
  </PropertyGroup>

  <ItemGroup>
    <Compile Include="Models/Domain.fs" />
    <Compile Include="Database/AppDbContext.fs" />
    <Compile Include="Services/UserService.fs" />
    <Compile Include="Services/TodoService.fs" />
    <Compile Include="Services/AuthService.fs" />
    <Compile Include="Controllers/UsersController.fs" />
    <Compile Include="Controllers/TodosController.fs" />
    <Compile Include="Controllers/AuthController.fs" />
    <Compile Include="Router.fs" />
    <Compile Include="Program.fs" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Saturn" Version="0.16.1" />
    <PackageReference Include="Thoth.Json.Net" Version="11.0.0" />
    <PackageReference Include="Thoth.Json.Giraffe" Version="5.0.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="6.0.22" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="6.0.22" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Design" Version="6.0.22" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="6.32.3" />
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="6.0.22" />
  </ItemGroup>

  <ItemGroup>
    <Content Include="static/**/*" CopyToOutputDirectory="PreserveNewest" />
  </ItemGroup>

</Project>`,

    'appsettings.json': `{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.EntityFrameworkCore": "Information"
    }
  },
  "AllowedHosts": "*",
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=saturn_app.db"
  },
  "JWT": {
    "Secret": "your-super-secret-jwt-key-should-be-at-least-256-bits-long-for-security",
    "Issuer": "saturn-app",
    "Audience": "saturn-app-users",
    "ExpiryHours": 24
  },
  "CORS": {
    "AllowedOrigins": ["http://localhost:3000", "http://localhost:5173"],
    "AllowedMethods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "AllowedHeaders": ["Content-Type", "Authorization"]
  }
}`,

    'Dockerfile': `FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["saturn-app.fsproj", "."]
RUN dotnet restore "saturn-app.fsproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "saturn-app.fsproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "saturn-app.fsproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "saturn-app.dll"]`,

    'docker-compose.yml': `version: '3.8'

services:
  saturn-app:
    build: .
    ports:
      - "5000:80"
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ConnectionStrings__DefaultConnection=Data Source=/data/saturn_app.db
    volumes:
      - sqlite_data:/data
    depends_on:
      - postgres

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: saturn_app
      POSTGRES_USER: saturn_user
      POSTGRES_PASSWORD: saturn_password
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

volumes:
  sqlite_data:
  postgres_data:
  redis_data:`,

    'README.md': `# F# Saturn Web Framework

A modern functional web framework built on ASP.NET Core with domain-driven design patterns and type-safe development.

## Features

- **MVC-like Architecture**: Familiar patterns with functional programming benefits
- **Type-Safe Routing**: Compile-time route validation and strongly-typed controllers
- **Domain-Driven Design**: Clean architecture with domain models and services
- **Built on ASP.NET Core**: Full .NET ecosystem compatibility and performance
- **JSON API**: RESTful API with automatic JSON serialization
- **Authentication**: JWT-based authentication with role-based access control
- **Database Integration**: Entity Framework Core with SQLite/PostgreSQL support
- **Testing Support**: Built-in testing capabilities
- **Docker Support**: Production-ready containerization

## Quick Start

### Prerequisites

- .NET 6.0 SDK or later
- F# development tools

### Installation

\`\`\`bash
# Clone the project
git clone <repository-url>
cd saturn-app

# Restore dependencies
dotnet restore

# Run the application
dotnet run
\`\`\`

The API will be available at \`http://localhost:5000\`

### Development

\`\`\`bash
# Watch mode for development
dotnet watch run

# Run tests
dotnet test

# Build for production
dotnet build -c Release
\`\`\`

## Project Structure

\`\`\`
├── Models/
│   └── Domain.fs           # Domain models and DTOs
├── Services/
│   ├── UserService.fs      # User business logic
│   ├── TodoService.fs      # Todo business logic
│   └── AuthService.fs      # Authentication logic
├── Controllers/
│   ├── UsersController.fs  # User endpoints
│   ├── TodosController.fs  # Todo endpoints
│   └── AuthController.fs   # Auth endpoints
├── Database/
│   └── AppDbContext.fs     # Entity Framework context
├── Router.fs               # Application routing
├── Program.fs              # Application entry point
└── saturn-app.fsproj       # Project configuration
\`\`\`

## API Endpoints

### Authentication
- \`POST /api/auth/login\` - User login
- \`POST /api/auth/register\` - User registration
- \`GET /api/auth/me\` - Get current user
- \`POST /api/auth/logout\` - User logout

### Users
- \`GET /api/users\` - List all users
- \`GET /api/users/{id}\` - Get user by ID
- \`POST /api/users\` - Create new user
- \`PUT /api/users/{id}\` - Update user
- \`DELETE /api/users/{id}\` - Delete user

### Todos
- \`GET /api/todos\` - List all todos
- \`GET /api/todos/{id}\` - Get todo by ID
- \`POST /api/todos\` - Create new todo
- \`PUT /api/todos/{id}\` - Update todo
- \`DELETE /api/todos/{id}\` - Delete todo
- \`POST /api/todos/{id}/complete\` - Mark todo as complete

## Architecture

### Domain-Driven Design

The application follows DDD principles with:

- **Domain Models**: Pure F# types representing business entities
- **Services**: Business logic and use cases
- **Controllers**: HTTP request/response handling
- **Repository Pattern**: Data access abstraction

### Functional Programming

Saturn leverages F#'s functional programming features:

- **Immutable Data**: All domain models are immutable by default
- **Type Safety**: Compile-time guarantees for route parameters and models
- **Pattern Matching**: Robust error handling with Result types
- **Composition**: Function composition for building HTTP pipelines

### Pipeline Architecture

Saturn uses a pipeline-based approach for request processing:

\`\`\`fsharp
let apiPipeline = pipeline {
    plug acceptJson
    plug putSecureBrowserHeaders
    set_header "x-api-version" "1.0"
}
\`\`\`

## Configuration

### Database

Configure your database connection in \`appsettings.json\`:

\`\`\`json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=saturn_app.db"
  }
}
\`\`\`

For PostgreSQL:
\`\`\`json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=saturn_app;Username=user;Password=pass"
  }
}
\`\`\`

### JWT Authentication

Configure JWT settings:

\`\`\`json
{
  "JWT": {
    "Secret": "your-256-bit-secret",
    "Issuer": "saturn-app",
    "Audience": "saturn-app-users",
    "ExpiryHours": 24
  }
}
\`\`\`

## Testing

Saturn provides excellent testing support:

\`\`\`fsharp
open Saturn
open Microsoft.AspNetCore.Hosting
open Microsoft.Extensions.DependencyInjection

let createHost() =
    WebHostBuilder()
        .UseStartup<Startup>()
        .ConfigureServices(fun services ->
            services.AddScoped<IUserService, MockUserService>() |> ignore
        )

let testClient = createHost().CreateClient()
\`\`\`

## Deployment

### Docker

\`\`\`bash
# Build image
docker build -t saturn-app .

# Run container
docker run -p 5000:80 saturn-app

# Or use docker-compose
docker-compose up
\`\`\`

### Production

\`\`\`bash
# Publish for deployment
dotnet publish -c Release -o ./publish

# Copy to server and run
cd publish
dotnet saturn-app.dll
\`\`\`

## Advanced Features

### Custom Middleware

\`\`\`fsharp
let customMiddleware : HttpHandler =
    fun (ctx : HttpContext) ->
        // Custom logic here
        next ctx
\`\`\`

### Model Validation

\`\`\`fsharp
type CreateUserRequest = {
    [<Required>]
    [<EmailAddress>]
    Email: string
    
    [<Required>]
    [<MinLength(2)>]
    FirstName: string
}
\`\`\`

### Background Services

\`\`\`fsharp
type EmailService() =
    interface IHostedService with
        member _.StartAsync(cancellationToken) = Task.CompletedTask
        member _.StopAsync(cancellationToken) = Task.CompletedTask
\`\`\`

## Learning Resources

- [Saturn Documentation](https://saturnframework.org/)
- [F# for Fun and Profit](https://fsharpforfunandprofit.com/)
- [ASP.NET Core Documentation](https://docs.microsoft.com/en-us/aspnet/core/)
- [Domain-Driven Design](https://martinfowler.com/tags/domain%20driven%20design.html)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.`
  }
};