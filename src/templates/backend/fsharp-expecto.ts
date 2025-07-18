import { BackendTemplate } from '../types';

export const fsharpExpectoTemplate: BackendTemplate = {
  id: 'fsharp-expecto',
  name: 'fsharp-expecto',
  displayName: 'F# Expecto Testing Framework',
  description: 'Smooth testing framework for F# with powerful assertions, property-based testing, and performance testing',
  framework: 'expecto',
  language: 'fsharp',
  version: '10.2',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🧪',
  type: 'testing',
  complexity: 'intermediate',
  keywords: ['fsharp', 'expecto', 'testing', 'unit-tests', 'property-based', 'performance'],
  
  features: [
    'Smooth testing API',
    'Property-based testing',
    'Performance testing',
    'Parallel test execution',
    'Custom test filters',
    'Test generators',
    'BDD-style testing',
    'Stress testing',
    'Visual Studio integration',
    'CLI test runner',
    'Code coverage',
    'Test reporting',
    'Parameterized tests',
    'Setup/teardown'
  ],
  
  structure: {
    'Tests/BasicTests.fs': `module BasicTests

open Expecto

[<Tests>]
let basicTests =
    testList "Basic Tests" [
        test "Simple test" {
            let result = 2 + 2
            Expect.equal result 4 "2 + 2 should equal 4"
        }
        
        test "String test" {
            let str = "Hello World"
            Expect.stringContains str "World" "String should contain 'World'"
        }
        
        test "Boolean test" {
            let condition = true
            Expect.isTrue condition "Condition should be true"
        }
        
        test "Collection test" {
            let numbers = [1; 2; 3; 4; 5]
            Expect.hasLength numbers 5 "List should have 5 elements"
            Expect.contains numbers 3 "List should contain 3"
        }
        
        test "Exception test" {
            let throwsException() = failwith "This always fails"
            Expect.throws throwsException "Function should throw exception"
        }
        
        testAsync "Async test" {
            let! result = async { return 42 }
            Expect.equal result 42 "Async operation should return 42"
        }
    ]`,

    'Tests/ParameterizedTests.fs': `module ParameterizedTests

open Expecto

let additionData = [
    (1, 2, 3)
    (5, 7, 12)
    (10, -5, 5)
    (0, 0, 0)
]

let multiplicationData = [
    (2, 3, 6)
    (4, 5, 20)
    (0, 100, 0)
    (-2, 3, -6)
]

[<Tests>]
let parameterizedTests =
    testList "Parameterized Tests" [
        testList "Addition tests" [
            for (a, b, expected) in additionData ->
                test $"Adding {a} + {b} should equal {expected}" {
                    let result = a + b
                    Expect.equal result expected $"{a} + {b} should equal {expected}"
                }
        ]
        
        testList "Multiplication tests" [
            for (a, b, expected) in multiplicationData ->
                test $"Multiplying {a} * {b} should equal {expected}" {
                    let result = a * b
                    Expect.equal result expected $"{a} * {b} should equal {expected}"
                }
        ]
        
        testTheory "Theory-based addition" additionData <| fun (a, b, expected) ->
            let result = a + b
            Expect.equal result expected $"{a} + {b} should equal {expected}"
        
        testProperty "Property: addition is commutative" <| fun (a: int) (b: int) ->
            let result1 = a + b
            let result2 = b + a
            Expect.equal result1 result2 "Addition should be commutative"
        
        testProperty "Property: multiplication by zero" <| fun (a: int) ->
            let result = a * 0
            Expect.equal result 0 "Any number multiplied by zero should be zero"
    ]`,

    'Tests/PropertyBasedTests.fs': `module PropertyBasedTests

open Expecto
open FsCheck

// Custom generators
let positiveIntGen = Gen.choose(1, 1000)
let nonEmptyStringGen = 
    Gen.elements ['a'..'z']
    |> Gen.listOfLength 10
    |> Gen.map (List.toArray >> System.String)

let emailGen =
    gen {
        let! username = Gen.elements ['a'..'z'] |> Gen.listOfLength 8 |> Gen.map (List.toArray >> System.String)
        let! domain = Gen.elements ["gmail.com"; "yahoo.com"; "test.com"]
        return $"{username}@{domain}"
    }

type User = {
    Id: int
    Name: string
    Email: string
    Age: int
}

let userGen =
    gen {
        let! id = positiveIntGen
        let! name = nonEmptyStringGen
        let! email = emailGen
        let! age = Gen.choose(18, 100)
        return { Id = id; Name = name; Email = email; Age = age }
    }

// Business logic to test
module BusinessLogic =
    let isValidEmail (email: string) =
        email.Contains("@") && email.Contains(".")
    
    let calculateDiscount age =
        if age >= 65 then 0.2
        elif age >= 18 then 0.1
        else 0.0
    
    let processUsers users =
        users
        |> List.filter (fun u -> u.Age >= 18)
        |> List.sortBy (fun u -> u.Name)

[<Tests>]
let propertyBasedTests =
    testList "Property-Based Tests" [
        testProperty "String concatenation length" <| fun (s1: string) (s2: string) ->
            let result = s1 + s2
            result.Length = s1.Length + s2.Length
        
        testProperty "List reverse is involutive" <| fun (lst: int list) ->
            let reversed = List.rev lst
            let doubleReversed = List.rev reversed
            doubleReversed = lst
        
        testProperty "Adding zero is identity" <| fun (x: int) ->
            x + 0 = x && 0 + x = x
        
        testProperty "Absolute value is non-negative" <| fun (x: int) ->
            abs x >= 0
        
        testPropertyWithConfig { FsCheckConfig.defaultConfig with maxTest = 1000 } 
            "List length after filter is <= original" <| fun (lst: int list) ->
            let filtered = lst |> List.filter (fun x -> x > 0)
            filtered.Length <= lst.Length
        
        testProperty "Valid email generation" <| 
            Prop.forAll (Arb.fromGen emailGen) BusinessLogic.isValidEmail
        
        testProperty "User discount calculation" <|
            Prop.forAll (Arb.fromGen userGen) (fun user ->
                let discount = BusinessLogic.calculateDiscount user.Age
                discount >= 0.0 && discount <= 1.0
            )
        
        testProperty "Adult users processing" <|
            Prop.forAll (Arb.fromGen (Gen.listOf userGen)) (fun users ->
                let processed = BusinessLogic.processUsers users
                processed |> List.forall (fun u -> u.Age >= 18)
            )
        
        // Shrinking example
        testProperty "Non-empty list has positive length" <| fun (NonEmptyArray arr) ->
            arr.Length > 0
        
        // Custom arbitraries
        testProperty "Business logic with custom data" <|
            Prop.forAll (Arb.fromGen userGen) (fun user ->
                classify (user.Age >= 65) "Senior" <|
                classify (user.Age >= 18 && user.Age < 65) "Adult" <|
                classify (user.Age < 18) "Minor" <|
                let discount = BusinessLogic.calculateDiscount user.Age
                match user.Age with
                | age when age >= 65 -> discount = 0.2
                | age when age >= 18 -> discount = 0.1
                | _ -> discount = 0.0
            )
    ]`,

    'Tests/PerformanceTests.fs': `module PerformanceTests

open Expecto
open System
open System.Diagnostics

// Functions to test performance
module Algorithm =
    let fibonacciNaive n =
        let rec fib x =
            if x <= 1 then x
            else fib (x - 1) + fib (x - 2)
        fib n
    
    let fibonacciOptimal n =
        let rec fib a b i =
            if i = 0 then a
            else fib b (a + b) (i - 1)
        fib 0 1 n
    
    let bubbleSort arr =
        let mutable swapped = true
        let mutable n = Array.length arr
        while swapped do
            swapped <- false
            for i in 1 to n - 1 do
                if arr.[i-1] > arr.[i] then
                    let temp = arr.[i]
                    arr.[i] <- arr.[i-1]
                    arr.[i-1] <- temp
                    swapped <- true
            n <- n - 1
        arr
    
    let quickSort arr =
        let rec sort arr =
            match arr with
            | [] -> []
            | head :: tail ->
                let smaller = tail |> List.filter (fun x -> x <= head)
                let larger = tail |> List.filter (fun x -> x > head)
                sort smaller @ [head] @ sort larger
        sort (Array.toList arr) |> List.toArray

let measureTime f =
    let sw = Stopwatch.StartNew()
    let result = f()
    sw.Stop()
    (result, sw.ElapsedMilliseconds)

[<Tests>]
let performanceTests =
    testList "Performance Tests" [
        test "Fibonacci performance comparison" {
            let n = 30
            
            let (result1, time1) = measureTime (fun () -> Algorithm.fibonacciNaive n)
            let (result2, time2) = measureTime (fun () -> Algorithm.fibonacciOptimal n)
            
            printfn $"Naive fibonacci({n}): {result1} in {time1}ms"
            printfn $"Optimal fibonacci({n}): {result2} in {time2}ms"
            
            Expect.equal result1 result2 "Both algorithms should produce same result"
            Expect.isLessThan time2 (time1 / 2L) "Optimal should be significantly faster"
        }
        
        testSequenced <| testList "Concurrent performance tests" [
            test "Bubble sort vs Quick sort" {
                let random = Random(42)
                let arr1 = Array.init 1000 (fun _ -> random.Next(1000))
                let arr2 = Array.copy arr1
                
                let (sorted1, time1) = measureTime (fun () -> Algorithm.bubbleSort arr1)
                let (sorted2, time2) = measureTime (fun () -> Algorithm.quickSort arr2)
                
                printfn $"Bubble sort (1000 elements): {time1}ms"
                printfn $"Quick sort (1000 elements): {time2}ms"
                
                Expect.equal (Array.sort sorted1) (Array.sort sorted2) "Both should sort correctly"
                Expect.isLessThan time2 time1 "Quick sort should be faster"
            }
        ]
        
        // Performance test with custom timeout
        testCaseWithTimeout 5000 "Memory allocation test" <| fun () ->
            let mutable list = []
            for i in 1 to 100000 do
                list <- i :: list
            Expect.hasLength list 100000 "List should have 100000 elements"
        
        // Stress test
        test "Stress test - Large data processing" {
            let largeData = Array.init 1000000 (fun i -> i * 2)
            
            let (sum, time) = measureTime (fun () ->
                largeData
                |> Array.filter (fun x -> x % 3 = 0)
                |> Array.map (fun x -> x * 2)
                |> Array.sum
            )
            
            printfn $"Processed 1M elements in {time}ms, sum: {sum}"
            Expect.isLessThan time 1000L "Should process 1M elements in under 1 second"
        }
        
        // Benchmark with multiple iterations
        test "String concatenation benchmark" {
            let iterations = 10000
            let testString = "Hello"
            
            let (result1, time1) = measureTime (fun () ->
                let mutable result = ""
                for i in 1 to iterations do
                    result <- result + testString
                result
            )
            
            let (result2, time2) = measureTime (fun () ->
                let sb = System.Text.StringBuilder()
                for i in 1 to iterations do
                    sb.Append(testString) |> ignore
                sb.ToString()
            )
            
            printfn $"String concatenation: {time1}ms"
            printfn $"StringBuilder: {time2}ms"
            
            Expect.equal result1 result2 "Both methods should produce same result"
            Expect.isLessThan time2 (time1 / 2L) "StringBuilder should be much faster"
        }
    ]`,

    'Tests/BDDTests.fs': `module BDDTests

open Expecto

// Domain model for BDD testing
type ShoppingCart = {
    Items: (string * decimal * int) list  // (product, price, quantity)
    DiscountPercentage: decimal
}

type PaymentMethod = 
    | CreditCard of string
    | PayPal of string
    | Cash

type Order = {
    Cart: ShoppingCart
    PaymentMethod: PaymentMethod
    Total: decimal
    Status: string
}

// Business logic
module ShoppingLogic =
    let createEmptyCart() = { Items = []; DiscountPercentage = 0m }
    
    let addItem cart product price quantity =
        let newItem = (product, price, quantity)
        { cart with Items = newItem :: cart.Items }
    
    let calculateSubtotal cart =
        cart.Items
        |> List.sumBy (fun (_, price, qty) -> price * decimal qty)
    
    let applyDiscount cart =
        let subtotal = calculateSubtotal cart
        subtotal * (1m - cart.DiscountPercentage / 100m)
    
    let createOrder cart paymentMethod =
        let total = applyDiscount cart
        { Cart = cart; PaymentMethod = paymentMethod; Total = total; Status = "Pending" }
    
    let processPayment order =
        match order.PaymentMethod with
        | CreditCard _ when order.Total > 0m -> { order with Status = "Paid" }
        | PayPal _ when order.Total > 0m -> { order with Status = "Paid" }
        | Cash when order.Total > 0m -> { order with Status = "Paid" }
        | _ -> { order with Status = "Failed" }

[<Tests>]
let bddTests =
    testList "BDD Style Tests" [
        testList "Shopping Cart Feature" [
            testList "Scenario: Adding items to cart" [
                test "Given an empty cart" {
                    let cart = ShoppingLogic.createEmptyCart()
                    Expect.isEmpty cart.Items "Cart should be empty initially"
                }
                
                test "When I add a product" {
                    let cart = ShoppingLogic.createEmptyCart()
                    let updatedCart = ShoppingLogic.addItem cart "Laptop" 999.99m 1
                    Expect.hasLength updatedCart.Items 1 "Cart should have one item"
                }
                
                test "Then the cart contains the product" {
                    let cart = ShoppingLogic.createEmptyCart()
                    let updatedCart = ShoppingLogic.addItem cart "Laptop" 999.99m 1
                    let (product, price, qty) = updatedCart.Items.[0]
                    Expect.equal product "Laptop" "Product should be Laptop"
                    Expect.equal price 999.99m "Price should be 999.99"
                    Expect.equal qty 1 "Quantity should be 1"
                }
            ]
            
            testList "Scenario: Calculating cart total" [
                test "Given a cart with multiple items" {
                    let cart = ShoppingLogic.createEmptyCart()
                    let cart = ShoppingLogic.addItem cart "Laptop" 999.99m 1
                    let cart = ShoppingLogic.addItem cart "Mouse" 29.99m 2
                    
                    let subtotal = ShoppingLogic.calculateSubtotal cart
                    Expect.equal subtotal 1059.97m "Subtotal should be 1059.97"
                }
                
                test "When I apply a discount" {
                    let cart = ShoppingLogic.createEmptyCart()
                    let cart = ShoppingLogic.addItem cart "Laptop" 1000m 1
                    let cart = { cart with DiscountPercentage = 10m }
                    
                    let total = ShoppingLogic.applyDiscount cart
                    Expect.equal total 900m "Total with 10% discount should be 900"
                }
            ]
        ]
        
        testList "Order Processing Feature" [
            testList "Scenario: Successful payment" [
                test "Given a valid order with credit card" {
                    let cart = ShoppingLogic.createEmptyCart()
                    let cart = ShoppingLogic.addItem cart "Book" 19.99m 1
                    let order = ShoppingLogic.createOrder cart (CreditCard "1234-5678-9012-3456")
                    
                    Expect.equal order.Status "Pending" "Order should be pending initially"
                    Expect.equal order.Total 19.99m "Order total should be 19.99"
                }
                
                test "When payment is processed" {
                    let cart = ShoppingLogic.createEmptyCart()
                    let cart = ShoppingLogic.addItem cart "Book" 19.99m 1
                    let order = ShoppingLogic.createOrder cart (CreditCard "1234-5678-9012-3456")
                    let processedOrder = ShoppingLogic.processPayment order
                    
                    Expect.equal processedOrder.Status "Paid" "Order should be paid after processing"
                }
            ]
            
            testList "Scenario: Failed payment" [
                test "Given an order with zero total" {
                    let cart = ShoppingLogic.createEmptyCart()
                    let order = ShoppingLogic.createOrder cart (CreditCard "1234-5678-9012-3456")
                    let processedOrder = ShoppingLogic.processPayment order
                    
                    Expect.equal processedOrder.Status "Failed" "Order with zero total should fail"
                }
            ]
        ]
        
        testList "Integration Scenarios" [
            test "Complete shopping flow" {
                // Given: A customer starts shopping
                let cart = ShoppingLogic.createEmptyCart()
                
                // When: Customer adds items
                let cart = ShoppingLogic.addItem cart "Laptop" 1000m 1
                let cart = ShoppingLogic.addItem cart "Mouse" 50m 1
                
                // And: Applies a discount
                let cart = { cart with DiscountPercentage = 15m }
                
                // And: Creates an order
                let order = ShoppingLogic.createOrder cart (PayPal "customer@email.com")
                
                // And: Processes payment
                let finalOrder = ShoppingLogic.processPayment order
                
                // Then: Order is completed successfully
                Expect.equal finalOrder.Status "Paid" "Order should be paid"
                Expect.equal finalOrder.Total 892.5m "Total should be 1050 - 15% = 892.5"
                
                // And: Cart contains expected items
                Expect.hasLength finalOrder.Cart.Items 2 "Cart should have 2 items"
            }
        ]
    ]`,

    'Tests/SetupTeardownTests.fs': `module SetupTeardownTests

open Expecto
open System.IO

// Test fixtures and setup/teardown
module TestFixtures =
    let mutable testCounter = 0
    let mutable tempFiles = []
    
    let createTempFile content =
        let tempPath = Path.GetTempFileName()
        File.WriteAllText(tempPath, content)
        tempFiles <- tempPath :: tempFiles
        tempPath
    
    let cleanup() =
        tempFiles
        |> List.iter (fun file ->
            if File.Exists(file) then
                File.Delete(file)
        )
        tempFiles <- []

// Database simulation for testing
type Database = {
    Users: Map<int, string>
    LastId: int
}

module DatabaseSim =
    let mutable database = { Users = Map.empty; LastId = 0 }
    
    let reset() =
        database <- { Users = Map.empty; LastId = 0 }
    
    let addUser name =
        let newId = database.LastId + 1
        database <- { 
            Users = database.Users |> Map.add newId name
            LastId = newId 
        }
        newId
    
    let getUser id =
        database.Users |> Map.tryFind id
    
    let getAllUsers() =
        database.Users |> Map.toList

[<Tests>]
let setupTeardownTests =
    testList "Setup/Teardown Tests" [
        testList "File operations" [
            // Test with setup for each test
            yield! [
                "Test file creation", fun () ->
                    let tempFile = TestFixtures.createTempFile "test content"
                    Expect.isTrue (File.Exists(tempFile)) "Temp file should exist"
                    let content = File.ReadAllText(tempFile)
                    Expect.equal content "test content" "File should contain test content"
                
                "Test file modification", fun () ->
                    let tempFile = TestFixtures.createTempFile "original"
                    File.WriteAllText(tempFile, "modified")
                    let content = File.ReadAllText(tempFile)
                    Expect.equal content "modified" "File should be modified"
            ] |> List.map (fun (name, test) ->
                testCase name test
            )
            
            // Cleanup after all file tests
            testCase "Cleanup temp files" (fun () ->
                TestFixtures.cleanup()
                Expect.isEmpty TestFixtures.tempFiles "All temp files should be cleaned up"
            )
        ]
        
        testList "Database simulation tests" [
            // Setup before each test
            testCase "Reset database" (fun () ->
                DatabaseSim.reset()
                let users = DatabaseSim.getAllUsers()
                Expect.isEmpty users "Database should be empty after reset"
            )
            
            testCase "Add user to database" (fun () ->
                let userId = DatabaseSim.addUser "John Doe"
                Expect.equal userId 1 "First user should have ID 1"
                
                let user = DatabaseSim.getUser userId
                Expect.equal user (Some "John Doe") "Should retrieve added user"
            )
            
            testCase "Add multiple users" (fun () ->
                let id1 = DatabaseSim.addUser "Alice"
                let id2 = DatabaseSim.addUser "Bob"
                
                Expect.equal id1 1 "First user should have ID 1"
                Expect.equal id2 2 "Second user should have ID 2"
                
                let users = DatabaseSim.getAllUsers()
                Expect.hasLength users 2 "Should have 2 users"
            )
            
            // Reset after tests
            testCase "Final cleanup" (fun () ->
                DatabaseSim.reset()
            )
        ]
        
        // Test sequence with shared state
        testSequenced <| testList "Sequenced tests with shared state" [
            testCase "Initialize counter" (fun () ->
                TestFixtures.testCounter <- 0
                Expect.equal TestFixtures.testCounter 0 "Counter should start at 0"
            )
            
            testCase "Increment counter" (fun () ->
                TestFixtures.testCounter <- TestFixtures.testCounter + 1
                Expect.equal TestFixtures.testCounter 1 "Counter should be 1"
            )
            
            testCase "Increment counter again" (fun () ->
                TestFixtures.testCounter <- TestFixtures.testCounter + 1
                Expect.equal TestFixtures.testCounter 2 "Counter should be 2"
            )
        ]
        
        // Tests with custom setup/teardown
        testList "Custom setup/teardown pattern" [
            let runWithSetup setup teardown test =
                testCase "Setup/Test/Teardown" (fun () ->
                    let context = setup()
                    try
                        test context
                    finally
                        teardown context
                )
            
            runWithSetup
                (fun () -> 
                    let tempDir = Path.Combine(Path.GetTempPath(), System.Guid.NewGuid().ToString())
                    Directory.CreateDirectory(tempDir) |> ignore
                    tempDir
                )
                (fun tempDir -> 
                    if Directory.Exists(tempDir) then
                        Directory.Delete(tempDir, true)
                )
                (fun tempDir ->
                    Expect.isTrue (Directory.Exists(tempDir)) "Temp directory should exist"
                    let testFile = Path.Combine(tempDir, "test.txt")
                    File.WriteAllText(testFile, "test")
                    Expect.isTrue (File.Exists(testFile)) "Test file should be created"
                )
        ]
    ]`,

    'Tests/Program.fs': `module Program

open Expecto

[<EntryPoint>]
let main argv =
    Tests.runTestsInAssemblyWithCLIArgs [] argv`,

    'expecto-tests.fsproj': `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <AssemblyName>expecto-tests</AssemblyName>
    <GenerateProgramFile>false</GenerateProgramFile>
  </PropertyGroup>

  <ItemGroup>
    <Compile Include="Tests/BasicTests.fs" />
    <Compile Include="Tests/ParameterizedTests.fs" />
    <Compile Include="Tests/PropertyBasedTests.fs" />
    <Compile Include="Tests/PerformanceTests.fs" />
    <Compile Include="Tests/BDDTests.fs" />
    <Compile Include="Tests/SetupTeardownTests.fs" />
    <Compile Include="Tests/Program.fs" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Expecto" Version="10.2.1" />
    <PackageReference Include="FsCheck" Version="2.16.5" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.6.3" />
  </ItemGroup>

</Project>`,

    'test-config.json': `{
  "filter": {
    "include": [],
    "exclude": ["Stress", "Manual"]
  },
  "parallel": true,
  "parallelWorkers": 4,
  "summary": true,
  "verbosity": "Normal",
  "failOnFocusedTests": true,
  "printer": "Default",
  "colours": 256,
  "appendSummaryHandler": true,
  "stress": {
    "iterations": 1000,
    "timeout": 30000
  },
  "property": {
    "maxTest": 100,
    "maxFail": 1000,
    "replay": null,
    "seed": null,
    "verbosity": "Normal"
  }
}`,

    'Dockerfile': `FROM mcr.microsoft.com/dotnet/runtime:6.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["expecto-tests.fsproj", "."]
RUN dotnet restore "expecto-tests.fsproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "expecto-tests.fsproj" -c Release -o /app/build

FROM build AS test
RUN dotnet test "expecto-tests.fsproj" --no-build --verbosity normal --configuration Release

FROM build AS publish
RUN dotnet publish "expecto-tests.fsproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "expecto-tests.dll"]`,

    'scripts/run-tests.sh': `#!/bin/bash

# Run all tests
echo "Running all tests..."
dotnet run

# Run specific test
echo "Running specific test pattern..."
dotnet run -- --filter "Basic"

# Run tests with parallel execution
echo "Running tests in parallel..."
dotnet run -- --parallel

# Run property-based tests only
echo "Running property-based tests..."
dotnet run -- --filter "Property"

# Run performance tests
echo "Running performance tests..."
dotnet run -- --filter "Performance"

# Generate test report
echo "Running tests with detailed output..."
dotnet run -- --summary --verbosity Detailed

# Run stress tests (if any)
echo "Running stress tests..."
dotnet run -- --stress 1000`,

    'scripts/coverage.sh': `#!/bin/bash

# Install coverage tools if not already installed
dotnet tool install --global dotnet-reportgenerator-globaltool
dotnet tool install --global coverlet.console

# Run tests with coverage
dotnet test --collect:"XPlat Code Coverage" --results-directory ./coverage

# Generate HTML report
reportgenerator \\
  -reports:"./coverage/**/coverage.cobertura.xml" \\
  -targetdir:"./coverage/html" \\
  -reporttypes:Html

echo "Coverage report generated in ./coverage/html/index.html"`,

    'README.md': `# F# Expecto Testing Framework

A smooth testing framework for F# with powerful assertions, property-based testing, and performance testing capabilities.

## Features

- **Smooth Testing API**: Intuitive and expressive test syntax
- **Property-Based Testing**: Integrated FsCheck for property-based testing
- **Performance Testing**: Built-in performance and stress testing
- **Parallel Execution**: Run tests in parallel for faster feedback
- **BDD Support**: Behavior-driven development style testing
- **Custom Filters**: Filter tests by name, category, or custom criteria
- **Visual Studio Integration**: Full IDE support and test explorer integration
- **CLI Test Runner**: Powerful command-line interface
- **Test Reports**: Detailed test reporting and output formatting

## Quick Start

### Prerequisites

- .NET 6.0 SDK or later
- F# development tools

### Installation

\`\`\`bash
# Clone the project
git clone <repository-url>
cd expecto-tests

# Restore dependencies
dotnet restore

# Run all tests
dotnet run

# Or run tests with specific options
dotnet run -- --parallel --summary
\`\`\`

## Project Structure

\`\`\`
├── Tests/
│   ├── BasicTests.fs           # Simple unit tests
│   ├── ParameterizedTests.fs   # Data-driven tests
│   ├── PropertyBasedTests.fs   # Property-based tests
│   ├── PerformanceTests.fs     # Performance and benchmark tests
│   ├── BDDTests.fs            # Behavior-driven tests
│   ├── SetupTeardownTests.fs  # Tests with setup/cleanup
│   └── Program.fs             # Test runner entry point
├── scripts/
│   ├── run-tests.sh           # Test execution scripts
│   └── coverage.sh            # Code coverage scripts
├── test-config.json           # Test configuration
└── expecto-tests.fsproj       # Project file
\`\`\`

## Test Categories

### 1. Basic Tests

Simple unit tests with assertions:

\`\`\`fsharp
test "Simple test" {
    let result = 2 + 2
    Expect.equal result 4 "2 + 2 should equal 4"
}
\`\`\`

### 2. Parameterized Tests

Data-driven tests with multiple inputs:

\`\`\`fsharp
let testData = [(1, 2, 3); (5, 7, 12); (10, -5, 5)]

testList "Addition tests" [
    for (a, b, expected) in testData ->
        test $"Adding {a} + {b} should equal {expected}" {
            let result = a + b
            Expect.equal result expected $"{a} + {b} should equal {expected}"
        }
]
\`\`\`

### 3. Property-Based Tests

Generative testing with FsCheck:

\`\`\`fsharp
testProperty "List reverse is involutive" <| fun (lst: int list) ->
    let reversed = List.rev lst
    let doubleReversed = List.rev reversed
    doubleReversed = lst
\`\`\`

### 4. Performance Tests

Benchmark and performance testing:

\`\`\`fsharp
test "Algorithm performance" {
    let (result, time) = measureTime (fun () -> expensiveOperation())
    Expect.isLessThan time 1000L "Should complete in under 1 second"
}
\`\`\`

### 5. BDD Tests

Behavior-driven development style:

\`\`\`fsharp
testList "Shopping Cart Feature" [
    testList "Scenario: Adding items to cart" [
        test "Given an empty cart" { /* ... */ }
        test "When I add a product" { /* ... */ }
        test "Then the cart contains the product" { /* ... */ }
    ]
]
\`\`\`

## Running Tests

### Command Line Options

\`\`\`bash
# Run all tests
dotnet run

# Run tests in parallel
dotnet run -- --parallel

# Filter tests by name
dotnet run -- --filter "Basic"

# Run with summary
dotnet run -- --summary

# Set verbosity level
dotnet run -- --verbosity Detailed

# Run stress tests
dotnet run -- --stress 1000

# List available tests
dotnet run -- --list

# Run specific test assembly
dotnet run -- --sequenced
\`\`\`

### Test Filtering

\`\`\`bash
# Include specific tests
dotnet run -- --filter-test-name "Addition"

# Exclude tests
dotnet run -- --filter-test-name "Performance" --exclude

# Run tests by category
dotnet run -- --filter-test-case "BDD"
\`\`\`

### Configuration

Use \`test-config.json\` for persistent settings:

\`\`\`json
{
  "parallel": true,
  "parallelWorkers": 4,
  "summary": true,
  "verbosity": "Normal",
  "filter": {
    "exclude": ["Stress", "Manual"]
  }
}
\`\`\`

## Assertions

Expecto provides rich assertion methods:

\`\`\`fsharp
// Equality
Expect.equal actual expected "message"
Expect.notEqual actual expected "message"

// Comparisons
Expect.isLessThan actual expected "message"
Expect.isGreaterThan actual expected "message"
Expect.isLessThanOrEqual actual expected "message"

// Boolean
Expect.isTrue condition "message"
Expect.isFalse condition "message"

// Strings
Expect.stringContains str substring "message"
Expect.stringStarts str prefix "message"
Expect.stringEnds str suffix "message"

// Collections
Expect.hasLength collection expectedLength "message"
Expect.isEmpty collection "message"
Expect.contains collection item "message"
Expect.containsAll collection items "message"

// Exceptions
Expect.throws operation "message"
Expect.throwsT<ExceptionType> operation "message"

// Floating point
Expect.floatClose accuracy actual expected "message"

// Async
testAsync "Async test" {
    let! result = asyncOperation()
    Expect.equal result expected "message"
}
\`\`\`

## Property-Based Testing

### Basic Properties

\`\`\`fsharp
testProperty "Addition is commutative" <| fun (a: int) (b: int) ->
    a + b = b + a
\`\`\`

### Custom Generators

\`\`\`fsharp
let positiveIntGen = Gen.choose(1, 1000)

testProperty "Custom generator" <|
    Prop.forAll (Arb.fromGen positiveIntGen) (fun x ->
        x > 0
    )
\`\`\`

### Configuration

\`\`\`fsharp
testPropertyWithConfig 
    { FsCheckConfig.defaultConfig with maxTest = 1000 }
    "Property with custom config" <| fun (x: int) ->
        abs x >= 0
\`\`\`

## Performance Testing

### Measuring Time

\`\`\`fsharp
let measureTime f =
    let sw = Stopwatch.StartNew()
    let result = f()
    sw.Stop()
    (result, sw.ElapsedMilliseconds)

test "Performance test" {
    let (result, time) = measureTime (fun () -> heavyComputation())
    Expect.isLessThan time 5000L "Should complete in under 5 seconds"
}
\`\`\`

### Stress Testing

\`\`\`fsharp
testCaseWithTimeout 10000 "Stress test" <| fun () ->
    for i in 1 to 1000000 do
        // Perform operation
        ()
\`\`\`

## Setup and Teardown

### Per-Test Setup

\`\`\`fsharp
let runWithSetup setup teardown test =
    testCase "Test with setup" (fun () ->
        let context = setup()
        try
            test context
        finally
            teardown context
    )
\`\`\`

### Test Sequencing

\`\`\`fsharp
testSequenced <| testList "Sequenced tests" [
    testCase "First test" (fun () -> (* ... *))
    testCase "Second test" (fun () -> (* ... *))
]
\`\`\`

## Code Coverage

### Install Tools

\`\`\`bash
dotnet tool install --global dotnet-reportgenerator-globaltool
dotnet tool install --global coverlet.console
\`\`\`

### Generate Coverage

\`\`\`bash
# Run tests with coverage
dotnet test --collect:"XPlat Code Coverage"

# Generate HTML report
reportgenerator \\
  -reports:"./coverage/**/coverage.cobertura.xml" \\
  -targetdir:"./coverage/html" \\
  -reporttypes:Html
\`\`\`

## Advanced Features

### Custom Test Runners

\`\`\`fsharp
[<EntryPoint>]
let main argv =
    Tests.runTestsInAssemblyWithCLIArgs 
        [ CLIArguments.Parallel
          CLIArguments.Summary ] argv
\`\`\`

### Test Attributes

\`\`\`fsharp
[<Tests>]
let tests = testList "My tests" [ (* ... *) ]

[<PTests>]  // Property tests
let propertyTests = testList "Property tests" [ (* ... *) ]
\`\`\`

### Custom Expectations

\`\`\`fsharp
module CustomExpect =
    let isEven x message =
        if x % 2 <> 0 then
            failtestf "%s. Expected %d to be even" message x
\`\`\`

## Integration with CI/CD

### GitHub Actions

\`\`\`yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup .NET
      uses: actions/setup-dotnet@v1
      with:
        dotnet-version: 6.0.x
    - name: Run tests
      run: dotnet run -- --summary
\`\`\`

### Docker

\`\`\`bash
# Build and run tests in Docker
docker build -t expecto-tests .
docker run expecto-tests
\`\`\`

## Best Practices

1. **Descriptive Test Names**: Use clear, descriptive test names
2. **Arrange-Act-Assert**: Follow the AAA pattern
3. **Independent Tests**: Make tests independent of each other
4. **Fast Tests**: Keep unit tests fast and focused
5. **Property Testing**: Use property-based testing for business logic
6. **Performance Baselines**: Set performance baselines and monitor regression
7. **Test Categories**: Organize tests into logical categories
8. **Parallel Execution**: Use parallel execution for faster feedback

## Learning Resources

- [Expecto Documentation](https://github.com/haf/expecto)
- [FsCheck Documentation](https://fscheck.github.io/FsCheck/)
- [F# Testing Guide](https://fsharp.org/guides/testing/)
- [Property-Based Testing](https://hypothesis.works/articles/what-is-property-based-testing/)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License.`
  }
};