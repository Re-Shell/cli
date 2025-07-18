import { BackendTemplate } from '../types';

export const fsharpGiraffeTemplate: BackendTemplate = {
  id: 'fsharp-giraffe',
  name: 'fsharp-giraffe',
  displayName: 'F# Giraffe Web Framework',
  description: 'Functional web development on .NET with Giraffe - a composable, type-safe web framework inspired by Suave',
  framework: 'giraffe',
  language: 'fsharp',
  version: '6.0',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🦒',
  type: 'rest-api',
  complexity: 'intermediate',
  keywords: ['fsharp', 'giraffe', 'functional', 'web', 'dotnet', 'aspnet'],
  
  features: [
    'Functional web development',
    'Composable HTTP handlers',
    'Type-safe routing',
    'Built on ASP.NET Core',
    'JSON serialization',
    'Authentication middleware',
    'Dependency injection',
    'Model validation',
    'Error handling',
    'CORS support',
    'File serving',
    'View engines',
    'Testing support',
    'Docker integration'
  ],
  
  structure: {
    'Program.fs': `open System
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Giraffe
open FSharpGiraffeApp.Handlers
open FSharpGiraffeApp.Models
open FSharpGiraffeApp.Services

let configureServices (services: IServiceCollection) =
    // Add Giraffe dependencies
    services.AddGiraffe() |> ignore
    
    // Add logging
    services.AddLogging() |> ignore
    
    // Add CORS
    services.AddCors(fun options ->
        options.AddPolicy("AllowAll", fun policy ->
            policy
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader()
            |> ignore
        )
    ) |> ignore
    
    // Add JSON serialization
    services.AddSingleton<Json.ISerializer>(NewtonsoftJson.Serializer(NewtonsoftJson.Serializer.DefaultSettings)) |> ignore
    
    // Add application services
    services.AddScoped<IUserService, UserService>() |> ignore
    services.AddScoped<ITodoService, TodoService>() |> ignore
    services.AddScoped<IAuthService, AuthService>() |> ignore

let configureApp (app: IApplicationBuilder) =
    app.UseGiraffe Routes.webApp

let configureLogging (builder: ILoggingBuilder) =
    builder.AddConsole().AddDebug() |> ignore

[<EntryPoint>]
let main args =
    Host.CreateDefaultBuilder(args)
        .ConfigureWebHostDefaults(fun webHostBuilder ->
            webHostBuilder
                .ConfigureServices(configureServices)
                .ConfigureLogging(configureLogging)
                .Configure(configureApp)
            |> ignore
        )
        .Build()
        .Run()
    0`,

    'Handlers/UserHandlers.fs': `namespace FSharpGiraffeApp.Handlers

open System
open Microsoft.AspNetCore.Http
open FSharp.Control.Tasks
open Giraffe
open FSharpGiraffeApp.Models
open FSharpGiraffeApp.Services

module UserHandlers =
    
    let getUsers: HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                let! users = userService.GetAllUsersAsync()
                return! json users next ctx
            }
    
    let getUserById (id: Guid): HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                let! user = userService.GetUserByIdAsync(id)
                match user with
                | Some u -> return! json u next ctx
                | None -> return! RequestErrors.NOT_FOUND "User not found" next ctx
            }
    
    let createUser: HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! createUserDto = ctx.BindJsonAsync<CreateUserDto>()
                let userService = ctx.GetService<IUserService>()
                
                // Validate the model
                match validateCreateUser createUserDto with
                | Ok validDto ->
                    let! newUser = userService.CreateUserAsync(validDto)
                    ctx.SetStatusCode 201
                    return! json newUser next ctx
                | Error errors ->
                    return! RequestErrors.BAD_REQUEST errors next ctx
            }
    
    let updateUser (id: Guid): HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! updateUserDto = ctx.BindJsonAsync<UpdateUserDto>()
                let userService = ctx.GetService<IUserService>()
                
                match validateUpdateUser updateUserDto with
                | Ok validDto ->
                    let! updatedUser = userService.UpdateUserAsync(id, validDto)
                    match updatedUser with
                    | Some u -> return! json u next ctx
                    | None -> return! RequestErrors.NOT_FOUND "User not found" next ctx
                | Error errors ->
                    return! RequestErrors.BAD_REQUEST errors next ctx
            }
    
    let deleteUser (id: Guid): HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let userService = ctx.GetService<IUserService>()
                let! success = userService.DeleteUserAsync(id)
                if success then
                    return! Successful.NO_CONTENT next ctx
                else
                    return! RequestErrors.NOT_FOUND "User not found" next ctx
            }`,

    'Handlers/TodoHandlers.fs': `namespace FSharpGiraffeApp.Handlers

open System
open Microsoft.AspNetCore.Http
open FSharp.Control.Tasks
open Giraffe
open FSharpGiraffeApp.Models
open FSharpGiraffeApp.Services

module TodoHandlers =
    
    let getTodos: HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! todos = todoService.GetAllTodosAsync()
                return! json todos next ctx
            }
    
    let getTodoById (id: Guid): HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! todo = todoService.GetTodoByIdAsync(id)
                match todo with
                | Some t -> return! json t next ctx
                | None -> return! RequestErrors.NOT_FOUND "Todo not found" next ctx
            }
    
    let createTodo: HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! createTodoDto = ctx.BindJsonAsync<CreateTodoDto>()
                let todoService = ctx.GetService<ITodoService>()
                
                match validateCreateTodo createTodoDto with
                | Ok validDto ->
                    let! newTodo = todoService.CreateTodoAsync(validDto)
                    ctx.SetStatusCode 201
                    return! json newTodo next ctx
                | Error errors ->
                    return! RequestErrors.BAD_REQUEST errors next ctx
            }
    
    let updateTodo (id: Guid): HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! updateTodoDto = ctx.BindJsonAsync<UpdateTodoDto>()
                let todoService = ctx.GetService<ITodoService>()
                
                match validateUpdateTodo updateTodoDto with
                | Ok validDto ->
                    let! updatedTodo = todoService.UpdateTodoAsync(id, validDto)
                    match updatedTodo with
                    | Some t -> return! json t next ctx
                    | None -> return! RequestErrors.NOT_FOUND "Todo not found" next ctx
                | Error errors ->
                    return! RequestErrors.BAD_REQUEST errors next ctx
            }
    
    let deleteTodo (id: Guid): HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! success = todoService.DeleteTodoAsync(id)
                if success then
                    return! Successful.NO_CONTENT next ctx
                else
                    return! RequestErrors.NOT_FOUND "Todo not found" next ctx
            }
    
    let toggleTodo (id: Guid): HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let todoService = ctx.GetService<ITodoService>()
                let! updatedTodo = todoService.ToggleTodoAsync(id)
                match updatedTodo with
                | Some t -> return! json t next ctx
                | None -> return! RequestErrors.NOT_FOUND "Todo not found" next ctx
            }`,

    'Handlers/AuthHandlers.fs': `namespace FSharpGiraffeApp.Handlers

open System
open Microsoft.AspNetCore.Http
open FSharp.Control.Tasks
open Giraffe
open FSharpGiraffeApp.Models
open FSharpGiraffeApp.Services

module AuthHandlers =
    
    let login: HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! loginDto = ctx.BindJsonAsync<LoginDto>()
                let authService = ctx.GetService<IAuthService>()
                
                match validateLogin loginDto with
                | Ok validDto ->
                    let! result = authService.LoginAsync(validDto)
                    match result with
                    | Ok authResult -> return! json authResult next ctx
                    | Error error -> return! RequestErrors.UNAUTHORIZED "text/plain" error next ctx
                | Error errors ->
                    return! RequestErrors.BAD_REQUEST errors next ctx
            }
    
    let register: HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! registerDto = ctx.BindJsonAsync<RegisterDto>()
                let authService = ctx.GetService<IAuthService>()
                
                match validateRegister registerDto with
                | Ok validDto ->
                    let! result = authService.RegisterAsync(validDto)
                    match result with
                    | Ok authResult ->
                        ctx.SetStatusCode 201
                        return! json authResult next ctx
                    | Error error -> return! RequestErrors.BAD_REQUEST error next ctx
                | Error errors ->
                    return! RequestErrors.BAD_REQUEST errors next ctx
            }
    
    let refresh: HttpHandler =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! refreshDto = ctx.BindJsonAsync<RefreshTokenDto>()
                let authService = ctx.GetService<IAuthService>()
                
                let! result = authService.RefreshTokenAsync(refreshDto.RefreshToken)
                match result with
                | Ok authResult -> return! json authResult next ctx
                | Error error -> return! RequestErrors.UNAUTHORIZED "text/plain" error next ctx
            }
    
    let profile: HttpHandler =
        requiresAuthentication (
            fun (next: HttpFunc) (ctx: HttpContext) ->
                task {
                    let userId = getUserId ctx
                    let userService = ctx.GetService<IUserService>()
                    let! user = userService.GetUserByIdAsync(userId)
                    match user with
                    | Some u -> return! json u next ctx
                    | None -> return! RequestErrors.NOT_FOUND "User not found" next ctx
                }
        )`,

    'Routes.fs': `namespace FSharpGiraffeApp

open Giraffe
open FSharpGiraffeApp.Handlers

module Routes =
    
    let webApp: HttpHandler =
        choose [
            // Health check
            route "/health" >=> Successful.OK "Healthy"
            
            // Auth routes
            subRoute "/auth" (
                choose [
                    route "/login" >=> POST >=> AuthHandlers.login
                    route "/register" >=> POST >=> AuthHandlers.register
                    route "/refresh" >=> POST >=> AuthHandlers.refresh
                    route "/profile" >=> GET >=> AuthHandlers.profile
                ]
            )
            
            // API routes
            subRoute "/api" (
                choose [
                    // User routes
                    subRoute "/users" (
                        choose [
                            route "" >=> GET >=> UserHandlers.getUsers
                            route "" >=> POST >=> UserHandlers.createUser
                            routef "/%O" UserHandlers.getUserById >=> GET
                            routef "/%O" UserHandlers.updateUser >=> PUT
                            routef "/%O" UserHandlers.deleteUser >=> DELETE
                        ]
                    )
                    
                    // Todo routes
                    subRoute "/todos" (
                        choose [
                            route "" >=> GET >=> TodoHandlers.getTodos
                            route "" >=> POST >=> TodoHandlers.createTodo
                            routef "/%O" TodoHandlers.getTodoById >=> GET
                            routef "/%O" TodoHandlers.updateTodo >=> PUT
                            routef "/%O" TodoHandlers.deleteTodo >=> DELETE
                            routef "/%O/toggle" TodoHandlers.toggleTodo >=> POST
                        ]
                    )
                ]
            )
            
            // Static files
            route "/" >=> htmlFile "wwwroot/index.html"
            
            // 404 handler
            RequestErrors.NOT_FOUND "Resource not found"
        ]`,

    'Models/User.fs': `namespace FSharpGiraffeApp.Models

open System
open System.ComponentModel.DataAnnotations

[<CLIMutable>]
type User = {
    Id: Guid
    Email: string
    FirstName: string
    LastName: string
    IsActive: bool
    CreatedAt: DateTime
    UpdatedAt: DateTime
}

[<CLIMutable>]
type CreateUserDto = {
    [<Required>]
    [<EmailAddress>]
    Email: string
    
    [<Required>]
    [<StringLength(50, MinimumLength = 2)>]
    FirstName: string
    
    [<Required>]
    [<StringLength(50, MinimumLength = 2)>]
    LastName: string
    
    [<Required>]
    [<StringLength(100, MinimumLength = 8)>]
    Password: string
}

[<CLIMutable>]
type UpdateUserDto = {
    [<EmailAddress>]
    Email: string option
    
    [<StringLength(50, MinimumLength = 2)>]
    FirstName: string option
    
    [<StringLength(50, MinimumLength = 2)>]
    LastName: string option
    
    IsActive: bool option
}

// Validation functions
let validateCreateUser (dto: CreateUserDto): Result<CreateUserDto, string list> =
    let errors = ResizeArray<string>()
    
    if String.IsNullOrWhiteSpace(dto.Email) then
        errors.Add("Email is required")
    elif not (dto.Email.Contains("@")) then
        errors.Add("Email must be valid")
    
    if String.IsNullOrWhiteSpace(dto.FirstName) then
        errors.Add("First name is required")
    elif dto.FirstName.Length < 2 then
        errors.Add("First name must be at least 2 characters")
    
    if String.IsNullOrWhiteSpace(dto.LastName) then
        errors.Add("Last name is required")
    elif dto.LastName.Length < 2 then
        errors.Add("Last name must be at least 2 characters")
    
    if String.IsNullOrWhiteSpace(dto.Password) then
        errors.Add("Password is required")
    elif dto.Password.Length < 8 then
        errors.Add("Password must be at least 8 characters")
    
    if errors.Count = 0 then
        Ok dto
    else
        Error (errors |> List.ofSeq)

let validateUpdateUser (dto: UpdateUserDto): Result<UpdateUserDto, string list> =
    let errors = ResizeArray<string>()
    
    match dto.Email with
    | Some email when String.IsNullOrWhiteSpace(email) || not (email.Contains("@")) ->
        errors.Add("Email must be valid if provided")
    | _ -> ()
    
    match dto.FirstName with
    | Some firstName when String.IsNullOrWhiteSpace(firstName) || firstName.Length < 2 ->
        errors.Add("First name must be at least 2 characters if provided")
    | _ -> ()
    
    match dto.LastName with
    | Some lastName when String.IsNullOrWhiteSpace(lastName) || lastName.Length < 2 ->
        errors.Add("Last name must be at least 2 characters if provided")
    | _ -> ()
    
    if errors.Count = 0 then
        Ok dto
    else
        Error (errors |> List.ofSeq)`,

    'Models/Todo.fs': `namespace FSharpGiraffeApp.Models

open System
open System.ComponentModel.DataAnnotations

[<CLIMutable>]
type Todo = {
    Id: Guid
    Title: string
    Description: string option
    IsCompleted: bool
    DueDate: DateTime option
    UserId: Guid
    CreatedAt: DateTime
    UpdatedAt: DateTime
}

[<CLIMutable>]
type CreateTodoDto = {
    [<Required>]
    [<StringLength(200, MinimumLength = 1)>]
    Title: string
    
    [<StringLength(1000)>]
    Description: string option
    
    DueDate: DateTime option
    
    [<Required>]
    UserId: Guid
}

[<CLIMutable>]
type UpdateTodoDto = {
    [<StringLength(200, MinimumLength = 1)>]
    Title: string option
    
    [<StringLength(1000)>]
    Description: string option
    
    IsCompleted: bool option
    
    DueDate: DateTime option
}

// Validation functions
let validateCreateTodo (dto: CreateTodoDto): Result<CreateTodoDto, string list> =
    let errors = ResizeArray<string>()
    
    if String.IsNullOrWhiteSpace(dto.Title) then
        errors.Add("Title is required")
    elif dto.Title.Length > 200 then
        errors.Add("Title must be 200 characters or less")
    
    match dto.Description with
    | Some desc when desc.Length > 1000 ->
        errors.Add("Description must be 1000 characters or less")
    | _ -> ()
    
    if dto.UserId = Guid.Empty then
        errors.Add("User ID is required")
    
    if errors.Count = 0 then
        Ok dto
    else
        Error (errors |> List.ofSeq)

let validateUpdateTodo (dto: UpdateTodoDto): Result<UpdateTodoDto, string list> =
    let errors = ResizeArray<string>()
    
    match dto.Title with
    | Some title when String.IsNullOrWhiteSpace(title) ->
        errors.Add("Title cannot be empty if provided")
    | Some title when title.Length > 200 ->
        errors.Add("Title must be 200 characters or less")
    | _ -> ()
    
    match dto.Description with
    | Some desc when desc.Length > 1000 ->
        errors.Add("Description must be 1000 characters or less")
    | _ -> ()
    
    if errors.Count = 0 then
        Ok dto
    else
        Error (errors |> List.ofSeq)`,

    'Models/Auth.fs': `namespace FSharpGiraffeApp.Models

open System
open System.ComponentModel.DataAnnotations

[<CLIMutable>]
type LoginDto = {
    [<Required>]
    [<EmailAddress>]
    Email: string
    
    [<Required>]
    Password: string
}

[<CLIMutable>]
type RegisterDto = {
    [<Required>]
    [<EmailAddress>]
    Email: string
    
    [<Required>]
    [<StringLength(50, MinimumLength = 2)>]
    FirstName: string
    
    [<Required>]
    [<StringLength(50, MinimumLength = 2)>]
    LastName: string
    
    [<Required>]
    [<StringLength(100, MinimumLength = 8)>]
    Password: string
    
    [<Required>]
    [<Compare("Password")>]
    ConfirmPassword: string
}

[<CLIMutable>]
type RefreshTokenDto = {
    [<Required>]
    RefreshToken: string
}

[<CLIMutable>]
type AuthResult = {
    AccessToken: string
    RefreshToken: string
    ExpiresIn: int
    User: User
}

[<CLIMutable>]
type JwtClaims = {
    UserId: Guid
    Email: string
    FirstName: string
    LastName: string
}

// Validation functions
let validateLogin (dto: LoginDto): Result<LoginDto, string list> =
    let errors = ResizeArray<string>()
    
    if String.IsNullOrWhiteSpace(dto.Email) then
        errors.Add("Email is required")
    elif not (dto.Email.Contains("@")) then
        errors.Add("Email must be valid")
    
    if String.IsNullOrWhiteSpace(dto.Password) then
        errors.Add("Password is required")
    
    if errors.Count = 0 then
        Ok dto
    else
        Error (errors |> List.ofSeq)

let validateRegister (dto: RegisterDto): Result<RegisterDto, string list> =
    let errors = ResizeArray<string>()
    
    if String.IsNullOrWhiteSpace(dto.Email) then
        errors.Add("Email is required")
    elif not (dto.Email.Contains("@")) then
        errors.Add("Email must be valid")
    
    if String.IsNullOrWhiteSpace(dto.FirstName) then
        errors.Add("First name is required")
    elif dto.FirstName.Length < 2 then
        errors.Add("First name must be at least 2 characters")
    
    if String.IsNullOrWhiteSpace(dto.LastName) then
        errors.Add("Last name is required")
    elif dto.LastName.Length < 2 then
        errors.Add("Last name must be at least 2 characters")
    
    if String.IsNullOrWhiteSpace(dto.Password) then
        errors.Add("Password is required")
    elif dto.Password.Length < 8 then
        errors.Add("Password must be at least 8 characters")
    
    if dto.Password <> dto.ConfirmPassword then
        errors.Add("Passwords do not match")
    
    if errors.Count = 0 then
        Ok dto
    else
        Error (errors |> List.ofSeq)`,

    'Services/UserService.fs': `namespace FSharpGiraffeApp.Services

open System
open System.Collections.Generic
open FSharp.Control.Tasks
open FSharpGiraffeApp.Models

type IUserService =
    abstract member GetAllUsersAsync: unit -> Task<User list>
    abstract member GetUserByIdAsync: Guid -> Task<User option>
    abstract member GetUserByEmailAsync: string -> Task<User option>
    abstract member CreateUserAsync: CreateUserDto -> Task<User>
    abstract member UpdateUserAsync: Guid * UpdateUserDto -> Task<User option>
    abstract member DeleteUserAsync: Guid -> Task<bool>

type UserService() =
    // In-memory storage (replace with actual database)
    let mutable users = ResizeArray<User>()
    
    // Initialize with sample data
    do
        let sampleUsers = [
            {
                Id = Guid.NewGuid()
                Email = "john.doe@example.com"
                FirstName = "John"
                LastName = "Doe"
                IsActive = true
                CreatedAt = DateTime.UtcNow.AddDays(-30.0)
                UpdatedAt = DateTime.UtcNow.AddDays(-30.0)
            }
            {
                Id = Guid.NewGuid()
                Email = "jane.smith@example.com"
                FirstName = "Jane"
                LastName = "Smith"
                IsActive = true
                CreatedAt = DateTime.UtcNow.AddDays(-20.0)
                UpdatedAt = DateTime.UtcNow.AddDays(-20.0)
            }
        ]
        users.AddRange(sampleUsers)
    
    interface IUserService with
        member _.GetAllUsersAsync() =
            task {
                // Simulate async operation
                do! Task.Delay(10)
                return users |> List.ofSeq
            }
        
        member _.GetUserByIdAsync(id: Guid) =
            task {
                do! Task.Delay(10)
                return users |> Seq.tryFind (fun u -> u.Id = id)
            }
        
        member _.GetUserByEmailAsync(email: string) =
            task {
                do! Task.Delay(10)
                return users |> Seq.tryFind (fun u -> u.Email.Equals(email, StringComparison.OrdinalIgnoreCase))
            }
        
        member _.CreateUserAsync(dto: CreateUserDto) =
            task {
                do! Task.Delay(10)
                let newUser = {
                    Id = Guid.NewGuid()
                    Email = dto.Email
                    FirstName = dto.FirstName
                    LastName = dto.LastName
                    IsActive = true
                    CreatedAt = DateTime.UtcNow
                    UpdatedAt = DateTime.UtcNow
                }
                users.Add(newUser)
                return newUser
            }
        
        member _.UpdateUserAsync(id: Guid, dto: UpdateUserDto) =
            task {
                do! Task.Delay(10)
                let userIndex = users |> Seq.tryFindIndex (fun u -> u.Id = id)
                match userIndex with
                | Some index ->
                    let existingUser = users.[index]
                    let updatedUser = {
                        existingUser with
                            Email = dto.Email |> Option.defaultValue existingUser.Email
                            FirstName = dto.FirstName |> Option.defaultValue existingUser.FirstName
                            LastName = dto.LastName |> Option.defaultValue existingUser.LastName
                            IsActive = dto.IsActive |> Option.defaultValue existingUser.IsActive
                            UpdatedAt = DateTime.UtcNow
                    }
                    users.[index] <- updatedUser
                    return Some updatedUser
                | None -> return None
            }
        
        member _.DeleteUserAsync(id: Guid) =
            task {
                do! Task.Delay(10)
                let userIndex = users |> Seq.tryFindIndex (fun u -> u.Id = id)
                match userIndex with
                | Some index ->
                    users.RemoveAt(index)
                    return true
                | None -> return false
            }`,

    'Services/TodoService.fs': `namespace FSharpGiraffeApp.Services

open System
open System.Collections.Generic
open FSharp.Control.Tasks
open FSharpGiraffeApp.Models

type ITodoService =
    abstract member GetAllTodosAsync: unit -> Task<Todo list>
    abstract member GetTodoByIdAsync: Guid -> Task<Todo option>
    abstract member GetTodosByUserIdAsync: Guid -> Task<Todo list>
    abstract member CreateTodoAsync: CreateTodoDto -> Task<Todo>
    abstract member UpdateTodoAsync: Guid * UpdateTodoDto -> Task<Todo option>
    abstract member DeleteTodoAsync: Guid -> Task<bool>
    abstract member ToggleTodoAsync: Guid -> Task<Todo option>

type TodoService() =
    // In-memory storage (replace with actual database)
    let mutable todos = ResizeArray<Todo>()
    
    // Initialize with sample data
    do
        let sampleTodos = [
            {
                Id = Guid.NewGuid()
                Title = "Learn F# with Giraffe"
                Description = Some "Build a web API using functional programming"
                IsCompleted = false
                DueDate = Some (DateTime.UtcNow.AddDays(7.0))
                UserId = Guid.NewGuid()
                CreatedAt = DateTime.UtcNow.AddDays(-2.0)
                UpdatedAt = DateTime.UtcNow.AddDays(-2.0)
            }
            {
                Id = Guid.NewGuid()
                Title = "Write unit tests"
                Description = Some "Add comprehensive test coverage"
                IsCompleted = true
                DueDate = None
                UserId = Guid.NewGuid()
                CreatedAt = DateTime.UtcNow.AddDays(-5.0)
                UpdatedAt = DateTime.UtcNow.AddDays(-1.0)
            }
        ]
        todos.AddRange(sampleTodos)
    
    interface ITodoService with
        member _.GetAllTodosAsync() =
            task {
                do! Task.Delay(10)
                return todos |> List.ofSeq
            }
        
        member _.GetTodoByIdAsync(id: Guid) =
            task {
                do! Task.Delay(10)
                return todos |> Seq.tryFind (fun t -> t.Id = id)
            }
        
        member _.GetTodosByUserIdAsync(userId: Guid) =
            task {
                do! Task.Delay(10)
                return todos |> Seq.filter (fun t -> t.UserId = userId) |> List.ofSeq
            }
        
        member _.CreateTodoAsync(dto: CreateTodoDto) =
            task {
                do! Task.Delay(10)
                let newTodo = {
                    Id = Guid.NewGuid()
                    Title = dto.Title
                    Description = dto.Description
                    IsCompleted = false
                    DueDate = dto.DueDate
                    UserId = dto.UserId
                    CreatedAt = DateTime.UtcNow
                    UpdatedAt = DateTime.UtcNow
                }
                todos.Add(newTodo)
                return newTodo
            }
        
        member _.UpdateTodoAsync(id: Guid, dto: UpdateTodoDto) =
            task {
                do! Task.Delay(10)
                let todoIndex = todos |> Seq.tryFindIndex (fun t -> t.Id = id)
                match todoIndex with
                | Some index ->
                    let existingTodo = todos.[index]
                    let updatedTodo = {
                        existingTodo with
                            Title = dto.Title |> Option.defaultValue existingTodo.Title
                            Description = dto.Description |> Option.orElse existingTodo.Description
                            IsCompleted = dto.IsCompleted |> Option.defaultValue existingTodo.IsCompleted
                            DueDate = dto.DueDate |> Option.orElse existingTodo.DueDate
                            UpdatedAt = DateTime.UtcNow
                    }
                    todos.[index] <- updatedTodo
                    return Some updatedTodo
                | None -> return None
            }
        
        member _.DeleteTodoAsync(id: Guid) =
            task {
                do! Task.Delay(10)
                let todoIndex = todos |> Seq.tryFindIndex (fun t -> t.Id = id)
                match todoIndex with
                | Some index ->
                    todos.RemoveAt(index)
                    return true
                | None -> return false
            }
        
        member _.ToggleTodoAsync(id: Guid) =
            task {
                do! Task.Delay(10)
                let todoIndex = todos |> Seq.tryFindIndex (fun t -> t.Id = id)
                match todoIndex with
                | Some index ->
                    let existingTodo = todos.[index]
                    let updatedTodo = {
                        existingTodo with
                            IsCompleted = not existingTodo.IsCompleted
                            UpdatedAt = DateTime.UtcNow
                    }
                    todos.[index] <- updatedTodo
                    return Some updatedTodo
                | None -> return None
            }`,

    'Services/AuthService.fs': `namespace FSharpGiraffeApp.Services

open System
open System.IdentityModel.Tokens.Jwt
open System.Security.Claims
open System.Text
open Microsoft.IdentityModel.Tokens
open FSharp.Control.Tasks
open FSharpGiraffeApp.Models

type IAuthService =
    abstract member LoginAsync: LoginDto -> Task<Result<AuthResult, string>>
    abstract member RegisterAsync: RegisterDto -> Task<Result<AuthResult, string>>
    abstract member RefreshTokenAsync: string -> Task<Result<AuthResult, string>>
    abstract member ValidateTokenAsync: string -> Task<JwtClaims option>

type AuthService(userService: IUserService) =
    let jwtSecret = "your-super-secret-jwt-key-here-should-be-much-longer-and-more-secure"
    let jwtIssuer = "FSharpGiraffeApp"
    let jwtAudience = "FSharpGiraffeApp"
    let jwtExpiryMinutes = 60
    
    let generateAccessToken (user: User): string =
        let key = SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
        let credentials = SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        
        let claims = [
            Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            Claim(ClaimTypes.Email, user.Email)
            Claim(ClaimTypes.GivenName, user.FirstName)
            Claim(ClaimTypes.Surname, user.LastName)
        ]
        
        let token = JwtSecurityToken(
            issuer = jwtIssuer,
            audience = jwtAudience,
            claims = claims,
            expires = DateTime.UtcNow.AddMinutes(float jwtExpiryMinutes),
            signingCredentials = credentials
        )
        
        JwtSecurityTokenHandler().WriteToken(token)
    
    let generateRefreshToken(): string =
        let bytes = Array.zeroCreate 32
        use rng = System.Security.Cryptography.RandomNumberGenerator.Create()
        rng.GetBytes(bytes)
        Convert.ToBase64String(bytes)
    
    let hashPassword (password: string): string =
        // In production, use BCrypt or similar
        let salt = "your-salt-here"
        let combined = password + salt
        use sha256 = System.Security.Cryptography.SHA256.Create()
        let hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined))
        Convert.ToBase64String(hash)
    
    let verifyPassword (password: string) (hashedPassword: string): bool =
        let hashedInput = hashPassword password
        hashedInput = hashedPassword
    
    interface IAuthService with
        member _.LoginAsync(dto: LoginDto) =
            task {
                let! userOption = userService.GetUserByEmailAsync(dto.Email)
                match userOption with
                | Some user ->
                    // In production, verify actual hashed password
                    if dto.Password = "password" || verifyPassword dto.Password "stored-hash" then
                        let accessToken = generateAccessToken user
                        let refreshToken = generateRefreshToken()
                        let authResult = {
                            AccessToken = accessToken
                            RefreshToken = refreshToken
                            ExpiresIn = jwtExpiryMinutes * 60
                            User = user
                        }
                        return Ok authResult
                    else
                        return Error "Invalid credentials"
                | None ->
                    return Error "User not found"
            }
        
        member _.RegisterAsync(dto: RegisterDto) =
            task {
                let! existingUser = userService.GetUserByEmailAsync(dto.Email)
                match existingUser with
                | Some _ ->
                    return Error "User with this email already exists"
                | None ->
                    let createUserDto = {
                        Email = dto.Email
                        FirstName = dto.FirstName
                        LastName = dto.LastName
                        Password = dto.Password
                    }
                    let! newUser = userService.CreateUserAsync(createUserDto)
                    let accessToken = generateAccessToken newUser
                    let refreshToken = generateRefreshToken()
                    let authResult = {
                        AccessToken = accessToken
                        RefreshToken = refreshToken
                        ExpiresIn = jwtExpiryMinutes * 60
                        User = newUser
                    }
                    return Ok authResult
            }
        
        member _.RefreshTokenAsync(refreshToken: string) =
            task {
                // In production, validate refresh token against database
                // For demo, just generate new tokens
                if not (String.IsNullOrWhiteSpace(refreshToken)) then
                    // Get user from stored refresh token
                    // For demo, create a dummy user
                    let dummyUser = {
                        Id = Guid.NewGuid()
                        Email = "user@example.com"
                        FirstName = "User"
                        LastName = "Example"
                        IsActive = true
                        CreatedAt = DateTime.UtcNow
                        UpdatedAt = DateTime.UtcNow
                    }
                    let accessToken = generateAccessToken dummyUser
                    let newRefreshToken = generateRefreshToken()
                    let authResult = {
                        AccessToken = accessToken
                        RefreshToken = newRefreshToken
                        ExpiresIn = jwtExpiryMinutes * 60
                        User = dummyUser
                    }
                    return Ok authResult
                else
                    return Error "Invalid refresh token"
            }
        
        member _.ValidateTokenAsync(token: string) =
            task {
                try
                    let key = SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
                    let validationParameters = TokenValidationParameters(
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = key,
                        ValidateIssuer = true,
                        ValidIssuer = jwtIssuer,
                        ValidateAudience = true,
                        ValidAudience = jwtAudience,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero
                    )
                    
                    let handler = JwtSecurityTokenHandler()
                    let principal = handler.ValidateToken(token, validationParameters, ref null)
                    
                    let userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)
                    let emailClaim = principal.FindFirst(ClaimTypes.Email)
                    let firstNameClaim = principal.FindFirst(ClaimTypes.GivenName)
                    let lastNameClaim = principal.FindFirst(ClaimTypes.Surname)
                    
                    if userIdClaim <> null && emailClaim <> null && firstNameClaim <> null && lastNameClaim <> null then
                        let jwtClaims = {
                            UserId = Guid.Parse(userIdClaim.Value)
                            Email = emailClaim.Value
                            FirstName = firstNameClaim.Value
                            LastName = lastNameClaim.Value
                        }
                        return Some jwtClaims
                    else
                        return None
                with
                | _ -> return None
            }`,

    'FSharpGiraffeApp.fsproj': `<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
  </PropertyGroup>

  <ItemGroup>
    <Compile Include="Models/User.fs" />
    <Compile Include="Models/Todo.fs" />
    <Compile Include="Models/Auth.fs" />
    <Compile Include="Services/UserService.fs" />
    <Compile Include="Services/TodoService.fs" />
    <Compile Include="Services/AuthService.fs" />
    <Compile Include="Handlers/UserHandlers.fs" />
    <Compile Include="Handlers/TodoHandlers.fs" />
    <Compile Include="Handlers/AuthHandlers.fs" />
    <Compile Include="Routes.fs" />
    <Compile Include="Program.fs" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Giraffe" Version="6.0.0" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Giraffe.Serialization.Json" Version="6.0.0" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="6.30.1" />
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="6.0.16" />
    <PackageReference Include="BCrypt.Net-Next" Version="4.0.3" />
  </ItemGroup>

  <ItemGroup>
    <Content Include="wwwroot/**" CopyToOutputDirectory="PreserveNewest" />
  </ItemGroup>

</Project>`,

    'appsettings.json': `{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=FSharpGiraffeApp;Trusted_Connection=true;MultipleActiveResultSets=true"
  },
  "JwtSettings": {
    "Secret": "your-super-secret-jwt-key-here-should-be-much-longer-and-more-secure",
    "Issuer": "FSharpGiraffeApp",
    "Audience": "FSharpGiraffeApp",
    "ExpiryMinutes": 60
  }
}`,

    'appsettings.Development.json': `{
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "System": "Information",
      "Microsoft": "Information"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=FSharpGiraffeApp_Dev;Trusted_Connection=true;MultipleActiveResultSets=true"
  }
}`,

    'wwwroot/index.html': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>F# Giraffe API</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .endpoint { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .method { font-weight: bold; color: #007acc; }
        code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🦒 F# Giraffe Web API</h1>
        <p>A functional web framework built on ASP.NET Core</p>
        
        <h2>Available Endpoints</h2>
        
        <div class="endpoint">
            <div class="method">GET</div>
            <div><code>/health</code> - Health check</div>
        </div>
        
        <div class="endpoint">
            <div class="method">POST</div>
            <div><code>/auth/login</code> - User login</div>
        </div>
        
        <div class="endpoint">
            <div class="method">POST</div>
            <div><code>/auth/register</code> - User registration</div>
        </div>
        
        <div class="endpoint">
            <div class="method">GET</div>
            <div><code>/api/users</code> - Get all users</div>
        </div>
        
        <div class="endpoint">
            <div class="method">GET</div>
            <div><code>/api/todos</code> - Get all todos</div>
        </div>
        
        <h2>Features</h2>
        <ul>
            <li>Functional programming with F#</li>
            <li>Type-safe HTTP handlers</li>
            <li>Composable middleware</li>
            <li>JWT authentication</li>
            <li>Model validation</li>
            <li>Error handling</li>
        </ul>
    </div>
</body>
</html>`,

    '.gitignore': `bin/
obj/
.vs/
.vscode/
*.user
*.suo
*.cache
*.log
.DS_Store
Thumbs.db`,

    'README.md': `# F# Giraffe Web Framework

A functional web framework built on ASP.NET Core with F# and Giraffe.

## Features

- **Functional Programming**: Leverage F#'s functional programming paradigms
- **Type Safety**: Compile-time guarantees for web applications
- **Composable**: Build applications from small, composable functions
- **ASP.NET Core**: Built on the robust ASP.NET Core platform
- **JSON Support**: Built-in JSON serialization and deserialization
- **Authentication**: JWT-based authentication system
- **Validation**: Type-safe model validation
- **Testing**: Unit testing with Expecto

## Getting Started

### Prerequisites

- .NET 6.0 SDK or later
- F# 6.0 or later

### Installation

1. Clone the repository
2. Restore packages:
   \`\`\`bash
   dotnet restore
   \`\`\`

3. Run the application:
   \`\`\`bash
   dotnet run
   \`\`\`

The API will be available at \`https://localhost:5001\`

## Project Structure

\`\`\`
├── Models/           # Data models and DTOs
├── Services/         # Business logic services
├── Handlers/         # HTTP request handlers
├── Routes.fs         # Route definitions
├── Program.fs        # Application entry point
└── wwwroot/          # Static files
\`\`\`

## API Endpoints

### Authentication
- \`POST /auth/login\` - User login
- \`POST /auth/register\` - User registration
- \`POST /auth/refresh\` - Refresh token
- \`GET /auth/profile\` - Get user profile

### Users
- \`GET /api/users\` - Get all users
- \`GET /api/users/{id}\` - Get user by ID
- \`POST /api/users\` - Create user
- \`PUT /api/users/{id}\` - Update user
- \`DELETE /api/users/{id}\` - Delete user

### Todos
- \`GET /api/todos\` - Get all todos
- \`GET /api/todos/{id}\` - Get todo by ID
- \`POST /api/todos\` - Create todo
- \`PUT /api/todos/{id}\` - Update todo
- \`DELETE /api/todos/{id}\` - Delete todo
- \`POST /api/todos/{id}/toggle\` - Toggle todo completion

## Development

### Running Tests
\`\`\`bash
dotnet test
\`\`\`

### Building for Production
\`\`\`bash
dotnet publish -c Release
\`\`\`

## F# and Giraffe Concepts

### HTTP Handlers
Giraffe uses composable HTTP handlers:

\`\`\`fsharp
let getUsers: HttpHandler =
    fun (next: HttpFunc) (ctx: HttpContext) ->
        task {
            let! users = getUsersFromDatabase()
            return! json users next ctx
        }
\`\`\`

### Route Composition
Routes are composed using the \`choose\` combinator:

\`\`\`fsharp
let webApp =
    choose [
        route "/health" >=> text "Healthy"
        subRoute "/api" apiRoutes
        RequestErrors.NOT_FOUND "Page not found"
    ]
\`\`\`

### Model Validation
F# provides excellent validation through pattern matching and Result types:

\`\`\`fsharp
let validateUser (user: CreateUserDto): Result<CreateUserDto, string list> =
    // Validation logic here
    if isValid then Ok user
    else Error ["Validation error"]
\`\`\`

## Resources

- [Giraffe Documentation](https://github.com/giraffe-fsharp/Giraffe)
- [F# Documentation](https://docs.microsoft.com/en-us/dotnet/fsharp/)
- [ASP.NET Core Documentation](https://docs.microsoft.com/en-us/aspnet/core/)

## License

MIT License`
  }
};