import { BackendTemplate } from '../types';

export const fsharpSuaveTemplate: BackendTemplate = {
  id: 'fsharp-suave',
  name: 'fsharp-suave',
  displayName: 'F# Suave Web Framework',
  description: 'Lightweight functional web server library for F# with composable web parts and minimal dependencies',
  framework: 'suave',
  language: 'fsharp',
  version: '2.6',
  author: 'Re-Shell Team',
  featured: true,
  recommended: false,
  icon: '🌊',
  type: 'rest-api',
  complexity: 'beginner',
  keywords: ['fsharp', 'suave', 'functional', 'lightweight', 'web', 'minimal'],
  
  features: [
    'Lightweight and fast',
    'Composable web parts',
    'Functional programming',
    'Minimal dependencies',
    'HTTP/HTTPS support',
    'WebSocket support',
    'Static file serving',
    'JSON API',
    'Authentication filters',
    'CORS support',
    'Async/await support',
    'Custom routing',
    'Middleware pipeline',
    'Testing friendly'
  ],
  
  structure: {
    'Program.fs': `open System
open System.Net
open Suave
open Suave.Operators
open Suave.Filters
open Suave.Successful
open Suave.Json
open Suave.RequestErrors
open SuaveApp.Models
open SuaveApp.Handlers
open SuaveApp.Services

let app =
    choose [
        GET >=> choose [
            path "/" >=> OK "F# Suave Web Server"
            path "/health" >=> JSON {| status = "healthy"; timestamp = DateTime.UtcNow |}
        ]
        
        pathScan "/api/%s" (fun resource ->
            match resource with
            | "users" -> UserHandlers.userRoutes
            | "todos" -> TodoHandlers.todoRoutes
            | "auth" -> AuthHandlers.authRoutes
            | _ -> NOT_FOUND "Resource not found"
        )
        
        NOT_FOUND "Page not found"
    ]

// CORS middleware
let corsHeaders =
    Writers.setHeader "Access-Control-Allow-Origin" "*"
    >=> Writers.setHeader "Access-Control-Allow-Methods" "GET, POST, PUT, DELETE, OPTIONS"
    >=> Writers.setHeader "Access-Control-Allow-Headers" "Content-Type, Authorization"

let config =
    { defaultConfig with
        bindings = [ HttpBinding.createSimple HTTP "0.0.0.0" 8080 ]
        listenTimeout = TimeSpan.FromMilliseconds 3000.0
        cancellationToken = Async.DefaultCancellationToken }

[<EntryPoint>]
let main argv =
    printfn "Starting Suave server on http://localhost:8080"
    startWebServer config (corsHeaders >=> app)
    0`,

    'Models/Domain.fs': `namespace SuaveApp.Models

open System
open Newtonsoft.Json

[<JsonConverter(typeof<Newtonsoft.Json.Converters.StringEnumConverter>)>]
type UserRole =
    | Admin = 0
    | User = 1
    | Moderator = 2

[<JsonConverter(typeof<Newtonsoft.Json.Converters.StringEnumConverter>)>]
type Priority =
    | Low = 0
    | Medium = 1
    | High = 2
    | Critical = 3

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

// Request DTOs
type CreateUserRequest = {
    Email: string
    FirstName: string
    LastName: string
    Password: string
}

type UpdateUserRequest = {
    Email: string option
    FirstName: string option
    LastName: string option
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

// Response DTOs
type ApiResponse<'T> = {
    Success: bool
    Data: 'T option
    Message: string
    Errors: string list
}

type LoginResponse = {
    Token: string
    User: User
    ExpiresAt: DateTime
}

// Helper functions for API responses
module ApiResponse =
    let success data message =
        { Success = true; Data = Some data; Message = message; Errors = [] }
    
    let successNoData message =
        { Success = true; Data = None; Message = message; Errors = [] }
    
    let error message errors =
        { Success = false; Data = None; Message = message; Errors = errors }
    
    let errorSingle message error =
        { Success = false; Data = None; Message = message; Errors = [error] }`,

    'Services/UserService.fs': `namespace SuaveApp.Services

open System
open SuaveApp.Models

type IUserService =
    abstract member GetAll: unit -> User list
    abstract member GetById: int -> User option
    abstract member GetByEmail: string -> User option
    abstract member Create: CreateUserRequest -> User
    abstract member Update: int * UpdateUserRequest -> User option
    abstract member Delete: int -> bool

type UserService() =
    // In-memory storage for demo purposes
    let mutable users = [
        { Id = 1; Email = "admin@example.com"; FirstName = "Admin"; LastName = "User"; Role = UserRole.Admin; CreatedAt = DateTime.UtcNow.AddDays(-30.0); UpdatedAt = DateTime.UtcNow }
        { Id = 2; Email = "user@example.com"; FirstName = "Regular"; LastName = "User"; Role = UserRole.User; CreatedAt = DateTime.UtcNow.AddDays(-15.0); UpdatedAt = DateTime.UtcNow }
        { Id = 3; Email = "mod@example.com"; FirstName = "Moderator"; LastName = "User"; Role = UserRole.Moderator; CreatedAt = DateTime.UtcNow.AddDays(-10.0); UpdatedAt = DateTime.UtcNow }
    ]
    let mutable nextId = 4

    interface IUserService with
        member _.GetAll() = users
        
        member _.GetById(id: int) =
            users |> List.tryFind (fun u -> u.Id = id)
        
        member _.GetByEmail(email: string) =
            users |> List.tryFind (fun u -> u.Email = email)
        
        member _.Create(request: CreateUserRequest) =
            let user = {
                Id = nextId
                Email = request.Email
                FirstName = request.FirstName
                LastName = request.LastName
                Role = UserRole.User
                CreatedAt = DateTime.UtcNow
                UpdatedAt = DateTime.UtcNow
            }
            nextId <- nextId + 1
            users <- user :: users
            user
        
        member _.Update(id: int, request: UpdateUserRequest) =
            let userIndex = users |> List.tryFindIndex (fun u -> u.Id = id)
            match userIndex with
            | Some index ->
                let existingUser = users.[index]
                let updatedUser = {
                    existingUser with
                        Email = request.Email |> Option.defaultValue existingUser.Email
                        FirstName = request.FirstName |> Option.defaultValue existingUser.FirstName
                        LastName = request.LastName |> Option.defaultValue existingUser.LastName
                        UpdatedAt = DateTime.UtcNow
                }
                users <- users |> List.mapi (fun i u -> if i = index then updatedUser else u)
                Some updatedUser
            | None -> None
        
        member _.Delete(id: int) =
            let initialCount = users |> List.length
            users <- users |> List.filter (fun u -> u.Id <> id)
            let finalCount = users |> List.length
            initialCount > finalCount`,

    'Services/TodoService.fs': `namespace SuaveApp.Services

open System
open SuaveApp.Models

type ITodoService =
    abstract member GetAll: unit -> Todo list
    abstract member GetById: int -> Todo option
    abstract member GetByUserId: int -> Todo list
    abstract member Create: CreateTodoRequest -> Todo
    abstract member Update: int * UpdateTodoRequest -> Todo option
    abstract member Complete: int -> Todo option
    abstract member Delete: int -> bool

type TodoService() =
    // In-memory storage for demo purposes
    let mutable todos = [
        { Id = 1; Title = "Learn F#"; Description = Some "Study functional programming concepts"; IsCompleted = false; UserId = 1; DueDate = Some (DateTime.UtcNow.AddDays(7.0)); Priority = Priority.High; CreatedAt = DateTime.UtcNow.AddDays(-5.0); UpdatedAt = DateTime.UtcNow }
        { Id = 2; Title = "Build Suave app"; Description = Some "Create a web API with Suave framework"; IsCompleted = false; UserId = 1; DueDate = Some (DateTime.UtcNow.AddDays(14.0)); Priority = Priority.Medium; CreatedAt = DateTime.UtcNow.AddDays(-3.0); UpdatedAt = DateTime.UtcNow }
        { Id = 3; Title = "Deploy to production"; Description = None; IsCompleted = false; UserId = 2; DueDate = Some (DateTime.UtcNow.AddDays(30.0)); Priority = Priority.Low; CreatedAt = DateTime.UtcNow.AddDays(-1.0); UpdatedAt = DateTime.UtcNow }
        { Id = 4; Title = "Write documentation"; Description = Some "Document the API endpoints"; IsCompleted = true; UserId = 1; DueDate = None; Priority = Priority.Medium; CreatedAt = DateTime.UtcNow.AddDays(-7.0); UpdatedAt = DateTime.UtcNow.AddDays(-2.0) }
    ]
    let mutable nextId = 5

    interface ITodoService with
        member _.GetAll() = todos
        
        member _.GetById(id: int) =
            todos |> List.tryFind (fun t -> t.Id = id)
        
        member _.GetByUserId(userId: int) =
            todos |> List.filter (fun t -> t.UserId = userId)
        
        member _.Create(request: CreateTodoRequest) =
            let todo = {
                Id = nextId
                Title = request.Title
                Description = request.Description
                IsCompleted = false
                UserId = request.UserId
                DueDate = request.DueDate
                Priority = request.Priority |> Option.defaultValue Priority.Medium
                CreatedAt = DateTime.UtcNow
                UpdatedAt = DateTime.UtcNow
            }
            nextId <- nextId + 1
            todos <- todo :: todos
            todo
        
        member _.Update(id: int, request: UpdateTodoRequest) =
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
                        UpdatedAt = DateTime.UtcNow
                }
                todos <- todos |> List.mapi (fun i t -> if i = index then updatedTodo else t)
                Some updatedTodo
            | None -> None
        
        member _.Complete(id: int) =
            let todoIndex = todos |> List.tryFindIndex (fun t -> t.Id = id)
            match todoIndex with
            | Some index ->
                let existingTodo = todos.[index]
                let completedTodo = {
                    existingTodo with
                        IsCompleted = true
                        UpdatedAt = DateTime.UtcNow
                }
                todos <- todos |> List.mapi (fun i t -> if i = index then completedTodo else t)
                Some completedTodo
            | None -> None
        
        member _.Delete(id: int) =
            let initialCount = todos |> List.length
            todos <- todos |> List.filter (fun t -> t.Id <> id)
            let finalCount = todos |> List.length
            initialCount > finalCount`,

    'Services/AuthService.fs': `namespace SuaveApp.Services

open System
open System.Text
open System.Security.Claims
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Tokens
open SuaveApp.Models

type IAuthService =
    abstract member Login: string * string -> LoginResponse option
    abstract member Register: RegisterRequest -> Result<User, string>
    abstract member ValidateToken: string -> ClaimsPrincipal option
    abstract member GenerateToken: User -> string

type AuthService(userService: IUserService) =
    let jwtSecret = "your-super-secret-jwt-key-should-be-at-least-256-bits-long-for-security"
    let jwtIssuer = "suave-app"
    let jwtAudience = "suave-app-users"
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
        member _.Login(email: string, password: string) =
            let user = userService.GetByEmail(email)
            match user with
            | Some u ->
                // For demo, we'll assume password is correct
                // In production, verify against hashed password
                let token = (this :> IAuthService).GenerateToken(u)
                let expiresAt = DateTime.UtcNow.AddHours(jwtExpiryHours)
                Some { Token = token; User = u; ExpiresAt = expiresAt }
            | None -> None
        
        member _.Register(request: RegisterRequest) =
            if request.Password <> request.ConfirmPassword then
                Error "Passwords do not match"
            else
                let existingUser = userService.GetByEmail(request.Email)
                match existingUser with
                | Some _ -> Error "User with this email already exists"
                | None ->
                    let hashedPassword = hashPassword request.Password
                    let createRequest = {
                        Email = request.Email
                        FirstName = request.FirstName
                        LastName = request.LastName
                        Password = hashedPassword
                    }
                    let user = userService.Create(createRequest)
                    Ok user
        
        member _.ValidateToken(token: string) =
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
                
                let mutable securityToken : SecurityToken = null
                let principal = tokenHandler.ValidateToken(token, validationParameters, &securityToken)
                Some principal
            with
            | _ -> None
        
        member _.GenerateToken(user: User) =
            let claims = [
                Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
                Claim(ClaimTypes.Email, user.Email)
                Claim(ClaimTypes.Name, sprintf "%s %s" user.FirstName user.LastName)
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
            tokenHandler.WriteToken(token)`,

    'Handlers/UserHandlers.fs': `namespace SuaveApp.Handlers

open System
open Suave
open Suave.Operators
open Suave.Filters
open Suave.Successful
open Suave.RequestErrors
open Suave.Json
open SuaveApp.Models
open SuaveApp.Services

module UserHandlers =
    let userService = UserService() :> IUserService

    let getUsers : WebPart =
        fun ctx ->
            try
                let users = userService.GetAll()
                let response = ApiResponse.success users "Users retrieved successfully"
                JSON response ctx
            with
            | ex -> 
                let response = ApiResponse.errorSingle "Failed to retrieve users" ex.Message
                JSON response ctx

    let getUserById id : WebPart =
        fun ctx ->
            try
                match userService.GetById(id) with
                | Some user ->
                    let response = ApiResponse.success user "User retrieved successfully"
                    JSON response ctx
                | None ->
                    let response = ApiResponse.errorSingle "User not found" "No user found with the specified ID"
                    NOT_FOUND (JSON response) ctx
            with
            | ex ->
                let response = ApiResponse.errorSingle "Failed to retrieve user" ex.Message
                JSON response ctx

    let createUser : WebPart =
        fun ctx ->
            async {
                try
                    let! requestBody = Suave.Utils.UTF8.toString ctx.request.rawForm
                    let userRequest = Newtonsoft.Json.JsonConvert.DeserializeObject<CreateUserRequest>(requestBody)
                    
                    // Basic validation
                    if String.IsNullOrWhiteSpace(userRequest.Email) then
                        let response = ApiResponse.errorSingle "Validation failed" "Email is required"
                        return! BAD_REQUEST (JSON response) ctx
                    elif String.IsNullOrWhiteSpace(userRequest.FirstName) then
                        let response = ApiResponse.errorSingle "Validation failed" "First name is required"
                        return! BAD_REQUEST (JSON response) ctx
                    elif String.IsNullOrWhiteSpace(userRequest.LastName) then
                        let response = ApiResponse.errorSingle "Validation failed" "Last name is required"
                        return! BAD_REQUEST (JSON response) ctx
                    else
                        let user = userService.Create(userRequest)
                        let response = ApiResponse.success user "User created successfully"
                        return! CREATED (JSON response) ctx
                with
                | ex ->
                    let response = ApiResponse.errorSingle "Failed to create user" ex.Message
                    return! BAD_REQUEST (JSON response) ctx
            }

    let updateUser id : WebPart =
        fun ctx ->
            async {
                try
                    let! requestBody = Suave.Utils.UTF8.toString ctx.request.rawForm
                    let userRequest = Newtonsoft.Json.JsonConvert.DeserializeObject<UpdateUserRequest>(requestBody)
                    
                    match userService.Update(id, userRequest) with
                    | Some user ->
                        let response = ApiResponse.success user "User updated successfully"
                        return! OK (JSON response) ctx
                    | None ->
                        let response = ApiResponse.errorSingle "User not found" "No user found with the specified ID"
                        return! NOT_FOUND (JSON response) ctx
                with
                | ex ->
                    let response = ApiResponse.errorSingle "Failed to update user" ex.Message
                    return! BAD_REQUEST (JSON response) ctx
            }

    let deleteUser id : WebPart =
        fun ctx ->
            try
                if userService.Delete(id) then
                    let response = ApiResponse.successNoData "User deleted successfully"
                    OK (JSON response) ctx
                else
                    let response = ApiResponse.errorSingle "User not found" "No user found with the specified ID"
                    NOT_FOUND (JSON response) ctx
            with
            | ex ->
                let response = ApiResponse.errorSingle "Failed to delete user" ex.Message
                JSON response ctx

    let userRoutes =
        choose [
            GET >=> choose [
                path "" >=> getUsers
                pathScan "/%d" getUserById
            ]
            POST >=> path "" >=> createUser
            PUT >=> pathScan "/%d" updateUser
            DELETE >=> pathScan "/%d" deleteUser
        ]`,

    'Handlers/TodoHandlers.fs': `namespace SuaveApp.Handlers

open System
open Suave
open Suave.Operators
open Suave.Filters
open Suave.Successful
open Suave.RequestErrors
open Suave.Json
open SuaveApp.Models
open SuaveApp.Services

module TodoHandlers =
    let todoService = TodoService() :> ITodoService

    let getTodos : WebPart =
        fun ctx ->
            try
                let todos = todoService.GetAll()
                let response = ApiResponse.success todos "Todos retrieved successfully"
                JSON response ctx
            with
            | ex -> 
                let response = ApiResponse.errorSingle "Failed to retrieve todos" ex.Message
                JSON response ctx

    let getTodoById id : WebPart =
        fun ctx ->
            try
                match todoService.GetById(id) with
                | Some todo ->
                    let response = ApiResponse.success todo "Todo retrieved successfully"
                    JSON response ctx
                | None ->
                    let response = ApiResponse.errorSingle "Todo not found" "No todo found with the specified ID"
                    NOT_FOUND (JSON response) ctx
            with
            | ex ->
                let response = ApiResponse.errorSingle "Failed to retrieve todo" ex.Message
                JSON response ctx

    let getTodosByUserId userId : WebPart =
        fun ctx ->
            try
                let todos = todoService.GetByUserId(userId)
                let response = ApiResponse.success todos "User todos retrieved successfully"
                JSON response ctx
            with
            | ex ->
                let response = ApiResponse.errorSingle "Failed to retrieve user todos" ex.Message
                JSON response ctx

    let createTodo : WebPart =
        fun ctx ->
            async {
                try
                    let! requestBody = Suave.Utils.UTF8.toString ctx.request.rawForm
                    let todoRequest = Newtonsoft.Json.JsonConvert.DeserializeObject<CreateTodoRequest>(requestBody)
                    
                    // Basic validation
                    if String.IsNullOrWhiteSpace(todoRequest.Title) then
                        let response = ApiResponse.errorSingle "Validation failed" "Title is required"
                        return! BAD_REQUEST (JSON response) ctx
                    elif todoRequest.UserId <= 0 then
                        let response = ApiResponse.errorSingle "Validation failed" "Valid user ID is required"
                        return! BAD_REQUEST (JSON response) ctx
                    else
                        let todo = todoService.Create(todoRequest)
                        let response = ApiResponse.success todo "Todo created successfully"
                        return! CREATED (JSON response) ctx
                with
                | ex ->
                    let response = ApiResponse.errorSingle "Failed to create todo" ex.Message
                    return! BAD_REQUEST (JSON response) ctx
            }

    let updateTodo id : WebPart =
        fun ctx ->
            async {
                try
                    let! requestBody = Suave.Utils.UTF8.toString ctx.request.rawForm
                    let todoRequest = Newtonsoft.Json.JsonConvert.DeserializeObject<UpdateTodoRequest>(requestBody)
                    
                    match todoService.Update(id, todoRequest) with
                    | Some todo ->
                        let response = ApiResponse.success todo "Todo updated successfully"
                        return! OK (JSON response) ctx
                    | None ->
                        let response = ApiResponse.errorSingle "Todo not found" "No todo found with the specified ID"
                        return! NOT_FOUND (JSON response) ctx
                with
                | ex ->
                    let response = ApiResponse.errorSingle "Failed to update todo" ex.Message
                    return! BAD_REQUEST (JSON response) ctx
            }

    let completeTodo id : WebPart =
        fun ctx ->
            try
                match todoService.Complete(id) with
                | Some todo ->
                    let response = ApiResponse.success todo "Todo completed successfully"
                    OK (JSON response) ctx
                | None ->
                    let response = ApiResponse.errorSingle "Todo not found" "No todo found with the specified ID"
                    NOT_FOUND (JSON response) ctx
            with
            | ex ->
                let response = ApiResponse.errorSingle "Failed to complete todo" ex.Message
                JSON response ctx

    let deleteTodo id : WebPart =
        fun ctx ->
            try
                if todoService.Delete(id) then
                    let response = ApiResponse.successNoData "Todo deleted successfully"
                    OK (JSON response) ctx
                else
                    let response = ApiResponse.errorSingle "Todo not found" "No todo found with the specified ID"
                    NOT_FOUND (JSON response) ctx
            with
            | ex ->
                let response = ApiResponse.errorSingle "Failed to delete todo" ex.Message
                JSON response ctx

    let todoRoutes =
        choose [
            GET >=> choose [
                path "" >=> getTodos
                pathScan "/%d" getTodoById
                pathScan "/user/%d" getTodosByUserId
            ]
            POST >=> choose [
                path "" >=> createTodo
                pathScan "/%d/complete" completeTodo
            ]
            PUT >=> pathScan "/%d" updateTodo
            DELETE >=> pathScan "/%d" deleteTodo
        ]`,

    'Handlers/AuthHandlers.fs': `namespace SuaveApp.Handlers

open System
open Suave
open Suave.Operators
open Suave.Filters
open Suave.Successful
open Suave.RequestErrors
open Suave.Json
open SuaveApp.Models
open SuaveApp.Services

module AuthHandlers =
    let userService = UserService() :> IUserService
    let authService = AuthService(userService) :> IAuthService

    let login : WebPart =
        fun ctx ->
            async {
                try
                    let! requestBody = Suave.Utils.UTF8.toString ctx.request.rawForm
                    let loginRequest = Newtonsoft.Json.JsonConvert.DeserializeObject<LoginRequest>(requestBody)
                    
                    // Basic validation
                    if String.IsNullOrWhiteSpace(loginRequest.Email) then
                        let response = ApiResponse.errorSingle "Validation failed" "Email is required"
                        return! BAD_REQUEST (JSON response) ctx
                    elif String.IsNullOrWhiteSpace(loginRequest.Password) then
                        let response = ApiResponse.errorSingle "Validation failed" "Password is required"
                        return! BAD_REQUEST (JSON response) ctx
                    else
                        match authService.Login(loginRequest.Email, loginRequest.Password) with
                        | Some loginResponse ->
                            let response = ApiResponse.success loginResponse "Login successful"
                            return! OK (JSON response) ctx
                        | None ->
                            let response = ApiResponse.errorSingle "Authentication failed" "Invalid email or password"
                            return! UNAUTHORIZED (JSON response) ctx
                with
                | ex ->
                    let response = ApiResponse.errorSingle "Login failed" ex.Message
                    return! BAD_REQUEST (JSON response) ctx
            }

    let register : WebPart =
        fun ctx ->
            async {
                try
                    let! requestBody = Suave.Utils.UTF8.toString ctx.request.rawForm
                    let registerRequest = Newtonsoft.Json.JsonConvert.DeserializeObject<RegisterRequest>(requestBody)
                    
                    // Basic validation
                    if String.IsNullOrWhiteSpace(registerRequest.Email) then
                        let response = ApiResponse.errorSingle "Validation failed" "Email is required"
                        return! BAD_REQUEST (JSON response) ctx
                    elif String.IsNullOrWhiteSpace(registerRequest.Password) then
                        let response = ApiResponse.errorSingle "Validation failed" "Password is required"
                        return! BAD_REQUEST (JSON response) ctx
                    elif registerRequest.Password.Length < 6 then
                        let response = ApiResponse.errorSingle "Validation failed" "Password must be at least 6 characters long"
                        return! BAD_REQUEST (JSON response) ctx
                    else
                        match authService.Register(registerRequest) with
                        | Ok user ->
                            let response = ApiResponse.success user "Registration successful"
                            return! CREATED (JSON response) ctx
                        | Error error ->
                            let response = ApiResponse.errorSingle "Registration failed" error
                            return! BAD_REQUEST (JSON response) ctx
                with
                | ex ->
                    let response = ApiResponse.errorSingle "Registration failed" ex.Message
                    return! BAD_REQUEST (JSON response) ctx
            }

    let logout : WebPart =
        fun ctx ->
            // In a stateless JWT system, logout is typically handled client-side
            let response = ApiResponse.successNoData "Logout successful"
            OK (JSON response) ctx

    let me : WebPart =
        fun ctx ->
            try
                // Extract Authorization header
                match ctx.request.header "authorization" with
                | Choice1Of2 authHeader when authHeader.StartsWith("Bearer ") ->
                    let token = authHeader.Substring(7)
                    match authService.ValidateToken(token) with
                    | Some principal ->
                        let userIdClaim = principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)
                        if userIdClaim <> null then
                            let userId = Int32.Parse(userIdClaim.Value)
                            match userService.GetById(userId) with
                            | Some user ->
                                let response = ApiResponse.success user "User profile retrieved successfully"
                                OK (JSON response) ctx
                            | None ->
                                let response = ApiResponse.errorSingle "User not found" "User profile not found"
                                NOT_FOUND (JSON response) ctx
                        else
                            let response = ApiResponse.errorSingle "Invalid token" "User ID not found in token"
                            UNAUTHORIZED (JSON response) ctx
                    | None ->
                        let response = ApiResponse.errorSingle "Invalid token" "Token validation failed"
                        UNAUTHORIZED (JSON response) ctx
                | _ ->
                    let response = ApiResponse.errorSingle "Authorization required" "Bearer token required"
                    UNAUTHORIZED (JSON response) ctx
            with
            | ex ->
                let response = ApiResponse.errorSingle "Authentication failed" ex.Message
                UNAUTHORIZED (JSON response) ctx

    let authRoutes =
        choose [
            POST >=> choose [
                path "/login" >=> login
                path "/register" >=> register
                path "/logout" >=> logout
            ]
            GET >=> path "/me" >=> me
        ]`,

    'suave-app.fsproj': `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <AssemblyName>suave-app</AssemblyName>
    <RootNamespace>SuaveApp</RootNamespace>
  </PropertyGroup>

  <ItemGroup>
    <Compile Include="Models/Domain.fs" />
    <Compile Include="Services/UserService.fs" />
    <Compile Include="Services/TodoService.fs" />
    <Compile Include="Services/AuthService.fs" />
    <Compile Include="Handlers/UserHandlers.fs" />
    <Compile Include="Handlers/TodoHandlers.fs" />
    <Compile Include="Handlers/AuthHandlers.fs" />
    <Compile Include="Program.fs" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Suave" Version="2.6.2" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="6.32.3" />
  </ItemGroup>

</Project>`,

    'Dockerfile': `FROM mcr.microsoft.com/dotnet/runtime:6.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["suave-app.fsproj", "."]
RUN dotnet restore "suave-app.fsproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "suave-app.fsproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "suave-app.fsproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "suave-app.dll"]`,

    'README.md': `# F# Suave Web Framework

A lightweight functional web server library for F# with composable web parts and minimal dependencies.

## Features

- **Lightweight & Fast**: Minimal overhead and dependencies
- **Composable Web Parts**: Build complex applications by composing simple functions
- **Functional Programming**: Leverage F#'s functional programming capabilities
- **Async Support**: Built-in support for asynchronous operations
- **HTTP/HTTPS**: Support for both HTTP and HTTPS protocols
- **WebSocket Support**: Real-time communication capabilities
- **Static File Serving**: Serve static files efficiently
- **JSON API**: RESTful API with JSON serialization
- **Authentication**: JWT-based authentication
- **CORS Support**: Cross-origin resource sharing
- **Testing Friendly**: Easy to test with functional composition

## Quick Start

### Prerequisites

- .NET 6.0 SDK or later
- F# development tools

### Installation

\`\`\`bash
# Clone the project
git clone <repository-url>
cd suave-app

# Restore dependencies
dotnet restore

# Run the application
dotnet run
\`\`\`

The API will be available at \`http://localhost:8080\`

### Development

\`\`\`bash
# Watch mode for development
dotnet watch run

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
├── Handlers/
│   ├── UserHandlers.fs     # User HTTP handlers
│   ├── TodoHandlers.fs     # Todo HTTP handlers
│   └── AuthHandlers.fs     # Auth HTTP handlers
├── Program.fs              # Application entry point
└── suave-app.fsproj        # Project configuration
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
- \`GET /api/todos/user/{userId}\` - Get todos by user
- \`POST /api/todos\` - Create new todo
- \`PUT /api/todos/{id}\` - Update todo
- \`DELETE /api/todos/{id}\` - Delete todo
- \`POST /api/todos/{id}/complete\` - Mark todo as complete

## Architecture

### Functional Web Parts

Suave uses composable web parts to build HTTP applications:

\`\`\`fsharp
let app =
    choose [
        GET >=> path "/" >=> OK "Hello World"
        POST >=> path "/api/data" >=> handleData
        NOT_FOUND "Page not found"
    ]
\`\`\`

### Composition Operators

- \`>=>\` - Compose web parts sequentially
- \`choose\` - Try multiple web parts, use first successful
- \`>>>\` - Forward composition
- \`<<<\` - Backward composition

### Request Processing

\`\`\`fsharp
let pipeline =
    corsHeaders
    >=> logRequest
    >=> authenticate
    >=> handleRequest
\`\`\`

## Configuration

### Server Configuration

\`\`\`fsharp
let config =
    { defaultConfig with
        bindings = [ HttpBinding.createSimple HTTP "0.0.0.0" 8080 ]
        listenTimeout = TimeSpan.FromMilliseconds 3000.0
        cancellationToken = Async.DefaultCancellationToken }
\`\`\`

### HTTPS Configuration

\`\`\`fsharp
let httpsBinding = HttpBinding.createSimple HTTPS "0.0.0.0" 8443
let config = { defaultConfig with bindings = [httpsBinding] }
\`\`\`

## Error Handling

Suave provides built-in error handling:

\`\`\`fsharp
let safeHandler handler =
    fun ctx ->
        try
            handler ctx
        with
        | ex ->
            let errorResponse = { error = ex.Message }
            INTERNAL_ERROR (JSON errorResponse) ctx
\`\`\`

## Testing

Suave applications are easy to test:

\`\`\`fsharp
open Suave
open Suave.Testing

[<Test>]
let testEndpoint() =
    runWithConfig defaultConfig app
    |> req HttpMethod.GET "/" None
    |> fun response ->
        Assert.AreEqual(HttpStatusCode.OK, response.statusCode)
\`\`\`

## Middleware

Create custom middleware using web parts:

\`\`\`fsharp
let requestLogger : WebPart =
    fun ctx ->
        printfn "Request: %s %s" ctx.request.method.ToString() ctx.request.url.AbsolutePath
        succeed ctx

let app = requestLogger >=> routes
\`\`\`

## JSON Handling

Suave provides JSON support:

\`\`\`fsharp
open Suave.Json
open Newtonsoft.Json

let getUser id =
    let user = getUserById id
    JSON user

let createUser =
    request (fun req ->
        let user = JsonConvert.DeserializeObject<User>(UTF8.toString req.rawForm)
        // Process user...
        JSON user
    )
\`\`\`

## Authentication

JWT authentication example:

\`\`\`fsharp
let authenticate : WebPart =
    request (fun req ->
        match req.header "authorization" with
        | Choice1Of2 token when token.StartsWith("Bearer ") ->
            let jwt = token.Substring(7)
            if validateJwtToken jwt then
                succeed
            else
                UNAUTHORIZED "Invalid token"
        | _ -> UNAUTHORIZED "Authorization required"
    )
\`\`\`

## WebSocket Support

\`\`\`fsharp
open Suave.Sockets
open Suave.WebSocket

let ws (webSocket : WebSocket) (context: HttpContext) =
    socket {
        let loop = true
        while loop do
            let! msg = webSocket.read()
            match msg with
            | Text, data, true ->
                let str = UTF8.toString data
                do! webSocket.send Text (UTF8.bytes ("Echo: " + str)) true
            | _ -> ()
    }

let app =
    choose [
        path "/websocket" >=> handShake ws
        // Other routes...
    ]
\`\`\`

## Deployment

### Docker

\`\`\`bash
# Build image
docker build -t suave-app .

# Run container
docker run -p 8080:8080 suave-app
\`\`\`

### Production

\`\`\`bash
# Publish for deployment
dotnet publish -c Release -o ./publish

# Copy to server and run
cd publish
dotnet suave-app.dll
\`\`\`

## Performance Tips

1. **Use Async**: Leverage F#'s async workflows
2. **Connection Pooling**: Reuse database connections
3. **Caching**: Cache frequently accessed data
4. **Minimal Allocations**: Avoid unnecessary object creation
5. **Profiling**: Use .NET profiling tools

## Best Practices

1. **Composition**: Build complex logic by composing simple web parts
2. **Immutability**: Use immutable data structures
3. **Error Handling**: Handle errors explicitly with Result types
4. **Testing**: Write unit tests for individual web parts
5. **Documentation**: Document your API endpoints

## Learning Resources

- [Suave Documentation](https://suave.io/)
- [F# for Fun and Profit](https://fsharpforfunandprofit.com/)
- [Functional Web Development](https://pragprog.com/titles/swdddf/web-development-with-clojure/)

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