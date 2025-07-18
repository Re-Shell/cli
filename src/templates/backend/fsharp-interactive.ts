import { BackendTemplate } from '../types';

export const fsharpInteractiveTemplate: BackendTemplate = {
  id: 'fsharp-interactive',
  name: 'fsharp-interactive',
  displayName: 'F# Interactive (FSI) Environment',
  description: 'Interactive F# development environment with REPL, scripting, data analysis, and rapid prototyping capabilities',
  framework: 'fsi',
  language: 'fsharp',
  version: '6.0',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🔬',
  type: 'interactive',
  complexity: 'beginner',
  keywords: ['fsharp', 'fsi', 'interactive', 'repl', 'scripting', 'data-analysis', 'prototyping'],
  
  features: [
    'Interactive REPL environment',
    'Script execution',
    'Data analysis and visualization',
    'Rapid prototyping',
    'Package loading',
    'Type exploration',
    'Performance profiling',
    'Multi-line editing',
    'History and persistence',
    'Integration with IDEs',
    'Jupyter notebook support',
    'Live documentation',
    'Hot reload development',
    'Educational programming'
  ],
  
  structure: {
    'scripts/basic-examples.fsx': `// Basic F# Interactive Examples
// Run with: dotnet fsi basic-examples.fsx

#r "nuget: Newtonsoft.Json"
#r "nuget: FSharp.Data"

open System
open Newtonsoft.Json
open FSharp.Data

// Simple expressions
printfn "Hello from F# Interactive!"
let greeting = "Welcome to FSI"
printfn "%s" greeting

// Basic arithmetic
let add x y = x + y
let result = add 5 3
printfn "5 + 3 = %d" result

// List operations
let numbers = [1..10]
let squares = numbers |> List.map (fun x -> x * x)
printfn "Squares: %A" squares

let evenSquares = 
    squares 
    |> List.filter (fun x -> x % 2 = 0)
    |> List.take 3
printfn "First 3 even squares: %A" evenSquares

// String manipulation
let text = "F# Interactive is powerful"
let words = text.Split(' ')
let wordLengths = words |> Array.map (fun w -> w.Length)
printfn "Word lengths: %A" wordLengths

// Date and time
let now = DateTime.Now
printfn "Current time: %s" (now.ToString("yyyy-MM-dd HH:mm:ss"))

let tomorrow = now.AddDays(1.0)
printfn "Tomorrow: %s" (tomorrow.ToString("yyyy-MM-dd"))

// Pattern matching
type Shape =
    | Circle of radius: float
    | Rectangle of width: float * height: float
    | Triangle of base: float * height: float

let calculateArea shape =
    match shape with
    | Circle radius -> Math.PI * radius * radius
    | Rectangle (width, height) -> width * height
    | Triangle (base, height) -> 0.5 * base * height

let shapes = [
    Circle 5.0
    Rectangle (4.0, 6.0)
    Triangle (3.0, 8.0)
]

shapes 
|> List.iter (fun shape ->
    let area = calculateArea shape
    printfn "Shape: %A, Area: %.2f" shape area
)

// Working with JSON
type Person = {
    Name: string
    Age: int
    Email: string
}

let person = { Name = "Alice"; Age = 30; Email = "alice@example.com" }
let json = JsonConvert.SerializeObject(person, Formatting.Indented)
printfn "JSON: %s" json

// Async operations
let downloadAsync url =
    async {
        use client = new System.Net.Http.HttpClient()
        let! response = client.GetStringAsync(url) |> Async.AwaitTask
        return response.Length
    }

// Example usage (commented out to avoid network dependency)
// let contentLength = downloadAsync "https://httpbin.org/json" |> Async.RunSynchronously
// printfn "Content length: %d" contentLength

printfn "Basic examples completed!"`,

    'scripts/data-analysis.fsx': `// Data Analysis with F# Interactive
// Run with: dotnet fsi data-analysis.fsx

#r "nuget: FSharp.Data"
#r "nuget: FSharp.Stats"
#r "nuget: Newtonsoft.Json"

open System
open System.IO
open FSharp.Data
open Newtonsoft.Json

// Sample data for analysis
type SalesRecord = {
    Date: DateTime
    Product: string
    Category: string
    Quantity: int
    Price: decimal
    CustomerAge: int
    Region: string
}

// Generate sample sales data
let random = Random(42) // Fixed seed for reproducibility

let products = ["Laptop"; "Mouse"; "Keyboard"; "Monitor"; "Tablet"; "Phone"]
let categories = ["Electronics"; "Accessories"; "Computing"]
let regions = ["North"; "South"; "East"; "West"]

let generateSalesRecord () =
    {
        Date = DateTime.Now.AddDays(-random.Next(365))
        Product = products.[random.Next(products.Length)]
        Category = categories.[random.Next(categories.Length)]
        Quantity = random.Next(1, 11)
        Price = decimal (random.Next(100, 2000))
        CustomerAge = random.Next(18, 80)
        Region = regions.[random.Next(regions.Length)]
    }

let salesData = List.init 1000 (fun _ -> generateSalesRecord())

printfn "Generated %d sales records" salesData.Length

// Basic statistics
let totalRevenue = 
    salesData 
    |> List.sumBy (fun r -> r.Price * decimal r.Quantity)

printfn "Total Revenue: $%.2f" totalRevenue

let averageOrderValue = 
    salesData 
    |> List.averageBy (fun r -> float (r.Price * decimal r.Quantity))

printfn "Average Order Value: $%.2f" averageOrderValue

// Sales by product
let salesByProduct = 
    salesData
    |> List.groupBy (fun r -> r.Product)
    |> List.map (fun (product, records) ->
        let totalSales = records |> List.sumBy (fun r -> r.Price * decimal r.Quantity)
        (product, totalSales)
    )
    |> List.sortByDescending snd

printfn "\nSales by Product:"
salesByProduct
|> List.iter (fun (product, sales) ->
    printfn "  %s: $%.2f" product sales
)

// Sales by region
let salesByRegion = 
    salesData
    |> List.groupBy (fun r -> r.Region)
    |> List.map (fun (region, records) ->
        let totalSales = records |> List.sumBy (fun r -> r.Price * decimal r.Quantity)
        let avgAge = records |> List.averageBy (fun r -> float r.CustomerAge)
        (region, totalSales, avgAge)
    )

printfn "\nSales by Region:"
salesByRegion
|> List.iter (fun (region, sales, avgAge) ->
    printfn "  %s: $%.2f (Avg Age: %.1f)" region sales avgAge
)

// Monthly sales trend
let monthlySales = 
    salesData
    |> List.groupBy (fun r -> r.Date.ToString("yyyy-MM"))
    |> List.map (fun (month, records) ->
        let totalSales = records |> List.sumBy (fun r -> r.Price * decimal r.Quantity)
        (month, totalSales)
    )
    |> List.sortBy fst

printfn "\nMonthly Sales Trend:"
monthlySales
|> List.iter (fun (month, sales) ->
    printfn "  %s: $%.2f" month sales
)

// Customer age analysis
let ageGroups = 
    salesData
    |> List.groupBy (fun r -> 
        match r.CustomerAge with
        | age when age < 25 -> "18-24"
        | age when age < 35 -> "25-34"
        | age when age < 45 -> "35-44"
        | age when age < 55 -> "45-54"
        | age when age < 65 -> "55-64"
        | _ -> "65+"
    )
    |> List.map (fun (group, records) ->
        let totalSales = records |> List.sumBy (fun r -> r.Price * decimal r.Quantity)
        let count = records.Length
        (group, totalSales, count)
    )
    |> List.sortBy (fun (group, _, _) -> group)

printfn "\nSales by Age Group:"
ageGroups
|> List.iter (fun (group, sales, count) ->
    printfn "  %s: $%.2f (%d customers)" group sales count
)

// Statistical analysis functions
module Statistics =
    let mean (data: float list) =
        data |> List.average
    
    let median (data: float list) =
        let sorted = data |> List.sort
        let n = sorted.Length
        if n % 2 = 0 then
            (sorted.[n/2 - 1] + sorted.[n/2]) / 2.0
        else
            sorted.[n/2]
    
    let standardDeviation (data: float list) =
        let avg = mean data
        let variance = data |> List.averageBy (fun x -> (x - avg) ** 2.0)
        sqrt variance
    
    let percentile (data: float list) (p: float) =
        let sorted = data |> List.sort
        let index = (p / 100.0) * float (sorted.Length - 1)
        let lower = int (floor index)
        let upper = int (ceil index)
        if lower = upper then
            sorted.[lower]
        else
            let weight = index - float lower
            sorted.[lower] * (1.0 - weight) + sorted.[upper] * weight

// Analyze order values
let orderValues = 
    salesData 
    |> List.map (fun r -> float (r.Price * decimal r.Quantity))

let stats = {|
    Mean = Statistics.mean orderValues
    Median = Statistics.median orderValues
    StdDev = Statistics.standardDeviation orderValues
    P25 = Statistics.percentile orderValues 25.0
    P75 = Statistics.percentile orderValues 75.0
    P95 = Statistics.percentile orderValues 95.0
|}

printfn "\nOrder Value Statistics:"
printfn "  Mean: $%.2f" stats.Mean
printfn "  Median: $%.2f" stats.Median
printfn "  Std Dev: $%.2f" stats.StdDev
printfn "  25th Percentile: $%.2f" stats.P25
printfn "  75th Percentile: $%.2f" stats.P75
printfn "  95th Percentile: $%.2f" stats.P95

// Export data for visualization
let exportToJson data filename =
    let json = JsonConvert.SerializeObject(data, Formatting.Indented)
    File.WriteAllText(filename, json)
    printfn "Data exported to %s" filename

// Export analysis results
let analysisResults = {|
    TotalRevenue = totalRevenue
    AverageOrderValue = averageOrderValue
    SalesByProduct = salesByProduct
    SalesByRegion = salesByRegion
    MonthlySales = monthlySales
    AgeGroups = ageGroups
    Statistics = stats
|}

exportToJson analysisResults "sales-analysis.json"

printfn "\nData analysis completed!"`,

    'scripts/web-scraping.fsx': `// Web Scraping and API Integration with F# Interactive
// Run with: dotnet fsi web-scraping.fsx

#r "nuget: FSharp.Data"
#r "nuget: HtmlAgilityPack"
#r "nuget: Newtonsoft.Json"

open System
open System.Net.Http
open System.Threading.Tasks
open FSharp.Data
open HtmlAgilityPack
open Newtonsoft.Json

// Type providers for external data
type JsonPlaceholder = JsonProvider<"https://jsonplaceholder.typicode.com/users">
type GitHubUser = JsonProvider<"https://api.github.com/users/octocat">

// HTTP utilities
module Http =
    let private client = new HttpClient()
    
    let getStringAsync url =
        async {
            try
                let! response = client.GetStringAsync(url) |> Async.AwaitTask
                return Ok response
            with
            | ex -> return Error ex.Message
        }
    
    let getJsonAsync<'T> url =
        async {
            let! result = getStringAsync url
            match result with
            | Ok json ->
                try
                    let data = JsonConvert.DeserializeObject<'T>(json)
                    return Ok data
                | ex -> return Error ex.Message
            | Error err -> return Error err
        }

// Web scraping utilities
module WebScraping =
    let loadHtml url =
        async {
            let! result = Http.getStringAsync url
            match result with
            | Ok html ->
                let doc = HtmlDocument()
                doc.LoadHtml(html)
                return Ok doc
            | Error err -> return Error err
        }
    
    let extractText selector (doc: HtmlDocument) =
        doc.DocumentNode.SelectNodes(selector)
        |> Option.ofObj
        |> Option.map (fun nodes -> 
            nodes 
            |> Seq.map (fun node -> node.InnerText.Trim())
            |> Seq.toList
        )
        |> Option.defaultValue []

// Example 1: Working with JSONPlaceholder API
printfn "=== JSONPlaceholder API Example ==="

let loadUsers () =
    async {
        try
            let! users = JsonPlaceholder.AsyncLoad("https://jsonplaceholder.typicode.com/users")
            return Ok users
        with
        | ex -> return Error ex.Message
    }

match loadUsers() |> Async.RunSynchronously with
| Ok users ->
    printfn "Loaded %d users from JSONPlaceholder" users.Length
    users
    |> Array.take 3
    |> Array.iter (fun user ->
        printfn "  User: %s (%s) - %s" user.Name user.Username user.Email
    )
| Error err ->
    printfn "Error loading users: %s" err

// Example 2: GitHub API integration
printfn "\n=== GitHub API Example ==="

let getGitHubUser username =
    async {
        let url = $"https://api.github.com/users/{username}"
        try
            let! user = GitHubUser.AsyncLoad(url)
            return Ok user
        with
        | ex -> return Error ex.Message
    }

let githubUsers = ["octocat"; "torvalds"; "gaearon"]

for username in githubUsers do
    match getGitHubUser username |> Async.RunSynchronously with
    | Ok user ->
        printfn "  %s: %d repos, %d followers" user.Login user.PublicRepos user.Followers
    | Error err ->
        printfn "  Error loading %s: %s" username err

// Example 3: Custom API data structures
type WeatherData = {
    Temperature: float
    Humidity: int
    Description: string
    WindSpeed: float
}

type CryptoPrice = {
    Symbol: string
    Price: decimal
    Change24h: decimal
    Volume: decimal
}

// Mock weather API simulation
let getWeatherData city =
    async {
        let random = Random()
        await (Task.Delay(100)) // Simulate network delay
        return {
            Temperature = 15.0 + random.NextDouble() * 20.0
            Humidity = random.Next(30, 90)
            Description = ["Sunny"; "Cloudy"; "Rainy"; "Windy"].[random.Next(4)]
            WindSpeed = random.NextDouble() * 15.0
        }
    }

printfn "\n=== Weather Data Example ==="
let cities = ["New York"; "London"; "Tokyo"; "Sydney"]

for city in cities do
    let weather = getWeatherData city |> Async.RunSynchronously
    printfn "  %s: %.1f°C, %d%% humidity, %s, Wind: %.1f km/h" 
        city weather.Temperature weather.Humidity weather.Description weather.WindSpeed

// Example 4: Data aggregation and analysis
type NewsArticle = {
    Title: string
    Source: string
    PublishedAt: DateTime
    Category: string
}

// Mock news data
let generateNewsData () =
    let random = Random(42)
    let sources = ["BBC"; "CNN"; "Reuters"; "TechCrunch"; "Ars Technica"]
    let categories = ["Technology"; "Politics"; "Science"; "Business"; "Sports"]
    
    List.init 50 (fun i ->
        {
            Title = $"News Article {i + 1}"
            Source = sources.[random.Next(sources.Length)]
            PublishedAt = DateTime.Now.AddHours(-random.NextDouble() * 24.0 * 7.0)
            Category = categories.[random.Next(categories.Length)]
        }
    )

printfn "\n=== News Data Analysis ==="
let newsData = generateNewsData()

// Analyze news by source
let newsBySource = 
    newsData
    |> List.groupBy (fun article -> article.Source)
    |> List.map (fun (source, articles) -> (source, articles.Length))
    |> List.sortByDescending snd

printfn "Articles by Source:"
newsBySource
|> List.iter (fun (source, count) ->
    printfn "  %s: %d articles" source count
)

// Analyze news by category
let newsByCategory = 
    newsData
    |> List.groupBy (fun article -> article.Category)
    |> List.map (fun (category, articles) -> (category, articles.Length))
    |> List.sortByDescending snd

printfn "\nArticles by Category:"
newsByCategory
|> List.iter (fun (category, count) ->
    printfn "  %s: %d articles" category count
)

// Recent articles (last 24 hours)
let recentArticles = 
    newsData
    |> List.filter (fun article -> article.PublishedAt > DateTime.Now.AddDays(-1.0))
    |> List.sortByDescending (fun article -> article.PublishedAt)

printfn "\nRecent Articles (last 24h): %d" recentArticles.Length

// Example 5: CSV data processing
let csvData = """
Date,Product,Sales,Region
2024-01-01,Laptop,1200,North
2024-01-02,Mouse,25,South
2024-01-03,Keyboard,75,East
2024-01-04,Monitor,300,West
2024-01-05,Tablet,450,North
"""

type CsvSales = CsvProvider<Schema="Date(Date),Product(string),Sales(int),Region(string)", HasHeaders=true>

printfn "\n=== CSV Data Processing ==="
let salesData = CsvSales.Parse(csvData)

let totalSales = salesData.Rows |> Seq.sumBy (fun row -> row.Sales)
printfn "Total Sales: $%d" totalSales

let salesByRegion = 
    salesData.Rows
    |> Seq.groupBy (fun row -> row.Region)
    |> Seq.map (fun (region, rows) -> (region, rows |> Seq.sumBy (fun r -> r.Sales)))
    |> Seq.sortByDescending snd
    |> Seq.toList

printfn "Sales by Region:"
salesByRegion
|> List.iter (fun (region, sales) ->
    printfn "  %s: $%d" region sales
)

// Example 6: Error handling and resilience
let fetchWithRetry url maxRetries =
    let rec attempt remainingTries =
        async {
            if remainingTries <= 0 then
                return Error "Max retries exceeded"
            else
                let! result = Http.getStringAsync url
                match result with
                | Ok data -> return Ok data
                | Error _ when remainingTries > 1 ->
                    do! Async.Sleep(1000) // Wait 1 second before retry
                    return! attempt (remainingTries - 1)
                | Error err -> return Error err
        }
    attempt maxRetries

printfn "\n=== Error Handling Example ==="
let testUrls = [
    "https://httpbin.org/status/200"  // Should succeed
    "https://httpbin.org/status/500"  // Should fail
    "https://invalid-url-that-does-not-exist.com"  // Should fail
]

for url in testUrls do
    match fetchWithRetry url 3 |> Async.RunSynchronously with
    | Ok _ -> printfn "  ✓ %s - Success" url
    | Error err -> printfn "  ✗ %s - Failed: %s" url err

printfn "\nWeb scraping and API examples completed!"`,

    'scripts/performance-analysis.fsx': `// Performance Analysis and Benchmarking with F# Interactive
// Run with: dotnet fsi performance-analysis.fsx

#r "nuget: BenchmarkDotNet"
#time "on"  // Enable FSI timing

open System
open System.Collections.Generic
open System.Diagnostics
open System.Threading.Tasks

// Performance measurement utilities
module Performance =
    let measureTime f =
        let sw = Stopwatch.StartNew()
        let result = f()
        sw.Stop()
        (result, sw.ElapsedMilliseconds)
    
    let measureTimeAsync f =
        async {
            let sw = Stopwatch.StartNew()
            let! result = f()
            sw.Stop()
            return (result, sw.ElapsedMilliseconds)
        }
    
    let benchmark name iterations f =
        printfn "Benchmarking: %s (%d iterations)" name iterations
        let times = ResizeArray<int64>()
        
        for i in 1..iterations do
            let (_, time) = measureTime f
            times.Add(time)
        
        let totalTime = times |> Seq.sum
        let avgTime = totalTime / int64 iterations
        let minTime = times |> Seq.min
        let maxTime = times |> Seq.max
        
        printfn "  Total: %dms, Avg: %dms, Min: %dms, Max: %dms" totalTime avgTime minTime maxTime
        (totalTime, avgTime, minTime, maxTime)

// Algorithm performance comparisons
module Algorithms =
    
    // Sorting algorithms
    let bubbleSort (arr: int[]) =
        let mutable swapped = true
        let mutable n = arr.Length
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
        let rec sort = function
            | [] -> []
            | head :: tail ->
                let smaller = tail |> List.filter (fun x -> x <= head)
                let larger = tail |> List.filter (fun x -> x > head)
                sort smaller @ [head] @ sort larger
        sort (Array.toList arr) |> List.toArray
    
    // Search algorithms
    let linearSearch (arr: int[]) target =
        let mutable found = false
        let mutable index = -1
        for i in 0 to arr.Length - 1 do
            if not found && arr.[i] = target then
                found <- true
                index <- i
        index
    
    let binarySearch (arr: int[]) target =
        let rec search low high =
            if low > high then -1
            else
                let mid = (low + high) / 2
                if arr.[mid] = target then mid
                elif arr.[mid] > target then search low (mid - 1)
                else search (mid + 1) high
        search 0 (arr.Length - 1)
    
    // Fibonacci implementations
    let fibonacciRecursive n =
        let rec fib x =
            if x <= 1 then x
            else fib (x - 1) + fib (x - 2)
        fib n
    
    let fibonacciIterative n =
        if n <= 1 then n
        else
            let mutable a, b = 0, 1
            for _ in 2 to n do
                let temp = a + b
                a <- b
                b <- temp
            b
    
    let fibonacciMemoized =
        let cache = Dictionary<int, int>()
        let rec fib n =
            if cache.ContainsKey(n) then
                cache.[n]
            else
                let result = 
                    if n <= 1 then n
                    else fib (n - 1) + fib (n - 2)
                cache.[n] <- result
                result
        fib

// Data structure performance
module DataStructures =
    
    let testListOperations size =
        // List operations
        let list = [1..size]
        let (_, timeMap) = Performance.measureTime (fun () -> list |> List.map (fun x -> x * 2))
        let (_, timeFilter) = Performance.measureTime (fun () -> list |> List.filter (fun x -> x % 2 = 0))
        let (_, timeSum) = Performance.measureTime (fun () -> list |> List.sum)
        (timeMap, timeFilter, timeSum)
    
    let testArrayOperations size =
        // Array operations
        let array = [|1..size|]
        let (_, timeMap) = Performance.measureTime (fun () -> array |> Array.map (fun x -> x * 2))
        let (_, timeFilter) = Performance.measureTime (fun () -> array |> Array.filter (fun x -> x % 2 = 0))
        let (_, timeSum) = Performance.measureTime (fun () -> array |> Array.sum)
        (timeMap, timeFilter, timeSum)
    
    let testSequenceOperations size =
        // Sequence operations (lazy)
        let sequence = seq { 1..size }
        let (_, timeMap) = Performance.measureTime (fun () -> sequence |> Seq.map (fun x -> x * 2) |> Seq.toArray)
        let (_, timeFilter) = Performance.measureTime (fun () -> sequence |> Seq.filter (fun x -> x % 2 = 0) |> Seq.toArray)
        let (_, timeSum) = Performance.measureTime (fun () -> sequence |> Seq.sum)
        (timeMap, timeFilter, timeSum)

// Memory usage analysis
module Memory =
    let getCurrentMemoryUsage () =
        GC.Collect()
        GC.WaitForPendingFinalizers()
        GC.Collect()
        GC.GetTotalMemory(false)
    
    let measureMemoryUsage f =
        let memoryBefore = getCurrentMemoryUsage()
        let result = f()
        let memoryAfter = getCurrentMemoryUsage()
        let memoryUsed = memoryAfter - memoryBefore
        (result, memoryUsed)

printfn "=== Performance Analysis with F# Interactive ==="

// 1. Sorting Algorithm Comparison
printfn "\n1. Sorting Algorithm Performance"
let sizes = [100; 1000; 5000]

for size in sizes do
    printfn "\nArray size: %d" size
    let random = Random(42)
    let data = Array.init size (fun _ -> random.Next(1000))
    
    // Bubble sort
    let bubbleData = Array.copy data
    let (_, bubbleTime) = Performance.measureTime (fun () -> Algorithms.bubbleSort bubbleData)
    printfn "  Bubble Sort: %dms" bubbleTime
    
    // Quick sort
    let quickData = Array.copy data
    let (_, quickTime) = Performance.measureTime (fun () -> Algorithms.quickSort quickData)
    printfn "  Quick Sort: %dms" quickTime
    
    // Built-in sort
    let builtinData = Array.copy data
    let (_, builtinTime) = Performance.measureTime (fun () -> Array.sort builtinData)
    printfn "  Built-in Sort: %dms" builtinTime

// 2. Search Algorithm Comparison
printfn "\n2. Search Algorithm Performance"
let searchSize = 100000
let searchData = [|1..searchSize|]
let target = searchSize / 2

let (_, linearTime) = Performance.measureTime (fun () -> Algorithms.linearSearch searchData target)
let (_, binaryTime) = Performance.measureTime (fun () -> Algorithms.binarySearch searchData target)

printfn "Searching for %d in array of %d elements:" target searchSize
printfn "  Linear Search: %dms" linearTime
printfn "  Binary Search: %dms" binaryTime

// 3. Fibonacci Performance
printfn "\n3. Fibonacci Algorithm Performance"
let fibNumbers = [20; 25; 30; 35]

for n in fibNumbers do
    printfn "\nFibonacci(%d):" n
    
    let (result1, time1) = Performance.measureTime (fun () -> Algorithms.fibonacciIterative n)
    printfn "  Iterative: %dms (result: %d)" time1 result1
    
    let (result2, time2) = Performance.measureTime (fun () -> Algorithms.fibonacciMemoized n)
    printfn "  Memoized: %dms (result: %d)" time2 result2
    
    if n <= 30 then // Recursive is too slow for larger numbers
        let (result3, time3) = Performance.measureTime (fun () -> Algorithms.fibonacciRecursive n)
        printfn "  Recursive: %dms (result: %d)" time3 result3

// 4. Data Structure Performance
printfn "\n4. Data Structure Performance"
let dataSizes = [10000; 50000; 100000]

for size in dataSizes do
    printfn "\nData size: %d" size
    
    let (listMap, listFilter, listSum) = DataStructures.testListOperations size
    printfn "  List - Map: %dms, Filter: %dms, Sum: %dms" listMap listFilter listSum
    
    let (arrayMap, arrayFilter, arraySum) = DataStructures.testArrayOperations size
    printfn "  Array - Map: %dms, Filter: %dms, Sum: %dms" arrayMap arrayFilter arraySum
    
    let (seqMap, seqFilter, seqSum) = DataStructures.testSequenceOperations size
    printfn "  Sequence - Map: %dms, Filter: %dms, Sum: %dms" seqMap seqFilter seqSum

// 5. Memory Usage Analysis
printfn "\n5. Memory Usage Analysis"

let (listData, listMemory) = Memory.measureMemoryUsage (fun () -> List.init 100000 id)
printfn "List creation (100k elements): %d bytes" listMemory

let (arrayData, arrayMemory) = Memory.measureMemoryUsage (fun () -> Array.init 100000 id)
printfn "Array creation (100k elements): %d bytes" arrayMemory

let (stringData, stringMemory) = Memory.measureMemoryUsage (fun () -> String.replicate 100000 "a")
printfn "String creation (100k chars): %d bytes" stringMemory

// 6. Async Performance
printfn "\n6. Async Performance"

let syncOperation n =
    let mutable sum = 0
    for i in 1 to n do
        sum <- sum + i
    sum

let asyncOperation n =
    async {
        let mutable sum = 0
        for i in 1 to n do
            sum <- sum + i
            if i % 10000 = 0 then
                do! Async.Sleep(0) // Yield control
        return sum
    }

let parallelAsyncOperation n =
    let chunkSize = n / 4
    [
        async { return syncOperation chunkSize }
        async { return syncOperation chunkSize }
        async { return syncOperation chunkSize }
        async { return syncOperation (n - 3 * chunkSize) }
    ]
    |> Async.Parallel
    |> Async.map Array.sum

let n = 1000000
printfn "Computing sum 1 to %d:" n

let (syncResult, syncTime) = Performance.measureTime (fun () -> syncOperation n)
printfn "  Synchronous: %dms (result: %d)" syncTime syncResult

let (asyncResult, asyncTime) = 
    Performance.measureTimeAsync (fun () -> asyncOperation n)
    |> Async.RunSynchronously
printfn "  Asynchronous: %dms (result: %d)" asyncTime asyncResult

let (parallelResult, parallelTime) = 
    Performance.measureTimeAsync (fun () -> parallelAsyncOperation n)
    |> Async.RunSynchronously
printfn "  Parallel Async: %dms (result: %d)" parallelTime parallelResult

// 7. String Operations Performance
printfn "\n7. String Operations Performance"

let testStringConcatenation iterations =
    let (_, concatTime) = Performance.measureTime (fun () ->
        let mutable result = ""
        for i in 1 to iterations do
            result <- result + "a"
        result
    )
    
    let (_, builderTime) = Performance.measureTime (fun () ->
        let builder = System.Text.StringBuilder()
        for i in 1 to iterations do
            builder.Append("a") |> ignore
        builder.ToString()
    )
    
    (concatTime, builderTime)

let stringIterations = [1000; 5000; 10000]
for iterations in stringIterations do
    let (concatTime, builderTime) = testStringConcatenation iterations
    printfn "String concatenation (%d iterations):" iterations
    printfn "  String concat: %dms" concatTime
    printfn "  StringBuilder: %dms" builderTime

// 8. Parallel Processing Performance
printfn "\n8. Parallel Processing Performance"

let computeIntensive n =
    let mutable sum = 0.0
    for i in 1 to n do
        sum <- sum + sin(float i) * cos(float i)
    sum

let data = [1..1000000]

let (seqResult, seqTime) = Performance.measureTime (fun () ->
    data |> List.map (fun x -> computeIntensive (x % 100)) |> List.sum
)

let (parallelResult, parallelTime) = Performance.measureTime (fun () ->
    data |> List.toArray |> Array.Parallel.map (fun x -> computeIntensive (x % 100)) |> Array.sum
)

printfn "Compute-intensive operations on %d elements:" data.Length
printfn "  Sequential: %dms (result: %.2f)" seqTime seqResult
printfn "  Parallel: %dms (result: %.2f)" parallelTime parallelResult
printfn "  Speedup: %.2fx" (float seqTime / float parallelTime)

printfn "\nPerformance analysis completed!"
printfn "Note: #time \"on\" shows timing for each FSI evaluation"`,

    'scripts/machine-learning.fsx': `// Machine Learning and Data Science with F# Interactive
// Run with: dotnet fsi machine-learning.fsx

#r "nuget: FSharp.Stats"
#r "nuget: Accord.MachineLearning"
#r "nuget: Accord.Statistics"
#r "nuget: MathNet.Numerics"
#r "nuget: MathNet.Numerics.FSharp"

open System
open MathNet.Numerics.LinearAlgebra
open FSharp.Stats

// Sample data generation
module DataGeneration =
    let generateLinearData n noise =
        let random = Random(42)
        [1..n]
        |> List.map (fun i ->
            let x = float i / 10.0
            let y = 2.0 * x + 3.0 + random.NextGaussian() * noise
            (x, y)
        )
    
    let generateClassificationData n =
        let random = Random(42)
        [1..n]
        |> List.map (fun _ ->
            let x1 = random.NextGaussian() * 2.0
            let x2 = random.NextGaussian() * 2.0
            let label = if x1 + x2 > 0.0 then 1 else 0
            ([|x1; x2|], label)
        )
    
    let generateClusterData n centers =
        let random = Random(42)
        centers
        |> List.collect (fun (cx, cy) ->
            [1..n/centers.Length]
            |> List.map (fun _ ->
                let x = cx + random.NextGaussian() * 0.5
                let y = cy + random.NextGaussian() * 0.5
                (x, y)
            )
        )

// Statistics and descriptive analytics
module Statistics =
    let summary data =
        let values = data |> List.map snd
        {|
            Count = List.length values
            Mean = FSharp.Stats.Seq.mean values
            Median = FSharp.Stats.Seq.median values
            StandardDeviation = FSharp.Stats.Seq.stDev values
            Min = List.min values
            Max = List.max values
            Q1 = FSharp.Stats.Seq.percentile 25.0 values
            Q3 = FSharp.Stats.Seq.percentile 75.0 values
        |}
    
    let correlation data =
        let xs = data |> List.map fst
        let ys = data |> List.map snd
        FSharp.Stats.Correlation.Seq.pearson xs ys

// Linear regression implementation
module LinearRegression =
    type Model = {
        Slope: float
        Intercept: float
        RSquared: float
    }
    
    let fit data =
        let xs = data |> List.map fst
        let ys = data |> List.map snd
        
        let n = float (List.length data)
        let sumX = List.sum xs
        let sumY = List.sum ys
        let sumXY = List.zip xs ys |> List.sumBy (fun (x, y) -> x * y)
        let sumXX = xs |> List.sumBy (fun x -> x * x)
        
        let slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX)
        let intercept = (sumY - slope * sumX) / n
        
        // Calculate R-squared
        let meanY = sumY / n
        let predictions = xs |> List.map (fun x -> slope * x + intercept)
        let ssRes = List.zip ys predictions |> List.sumBy (fun (y, pred) -> (y - pred) ** 2.0)
        let ssTot = ys |> List.sumBy (fun y -> (y - meanY) ** 2.0)
        let rSquared = 1.0 - ssRes / ssTot
        
        { Slope = slope; Intercept = intercept; RSquared = rSquared }
    
    let predict model x =
        model.Slope * x + model.Intercept

// K-means clustering
module KMeans =
    type Cluster = {
        Center: float * float
        Points: (float * float) list
    }
    
    let distance (x1, y1) (x2, y2) =
        sqrt ((x1 - x2) ** 2.0 + (y1 - y2) ** 2.0)
    
    let findClosestCenter point centers =
        centers
        |> List.mapi (fun i center -> (i, distance point center))
        |> List.minBy snd
        |> fst
    
    let updateCenter points =
        if List.isEmpty points then (0.0, 0.0)
        else
            let xs = points |> List.map fst
            let ys = points |> List.map snd
            (List.average xs, List.average ys)
    
    let cluster data k maxIterations =
        let random = Random(42)
        let initialCenters = 
            [1..k] |> List.map (fun _ -> 
                let x = random.NextDouble() * 10.0 - 5.0
                let y = random.NextDouble() * 10.0 - 5.0
                (x, y)
            )
        
        let rec iterate centers iteration =
            if iteration >= maxIterations then centers
            else
                // Assign points to clusters
                let assignments = 
                    data |> List.map (fun point ->
                        let clusterIndex = findClosestCenter point centers
                        (point, clusterIndex)
                    )
                
                // Update centers
                let newCenters = 
                    [0..k-1] |> List.map (fun i ->
                        let clusterPoints = 
                            assignments 
                            |> List.filter (fun (_, clusterIndex) -> clusterIndex = i)
                            |> List.map fst
                        updateCenter clusterPoints
                    )
                
                // Check for convergence
                let converged = 
                    List.zip centers newCenters
                    |> List.forall (fun (old, new_) -> distance old new_ < 0.01)
                
                if converged then newCenters
                else iterate newCenters (iteration + 1)
        
        let finalCenters = iterate initialCenters 0
        
        // Create final clusters
        finalCenters |> List.mapi (fun i center ->
            let clusterPoints = 
                data 
                |> List.filter (fun point -> findClosestCenter point finalCenters = i)
            { Center = center; Points = clusterPoints }
        )

// Classification with logistic regression
module LogisticRegression =
    let sigmoid x = 1.0 / (1.0 + exp(-x))
    
    let predict weights features =
        let score = Array.zip weights features |> Array.sumBy (fun (w, f) -> w * f)
        sigmoid score
    
    let train data learningRate iterations =
        let features = data |> List.map fst
        let labels = data |> List.map (fun (_, label) -> float label)
        let featureCount = (List.head features).Length
        
        let mutable weights = Array.init featureCount (fun _ -> 0.1)
        
        for _ in 1..iterations do
            let totalError = Array.zeroCreate featureCount
            
            for i in 0..features.Length-1 do
                let prediction = predict weights features.[i]
                let error = prediction - labels.[i]
                
                for j in 0..featureCount-1 do
                    totalError.[j] <- totalError.[j] + error * features.[i].[j]
            
            for j in 0..featureCount-1 do
                weights.[j] <- weights.[j] - learningRate * totalError.[j] / float features.Length
        
        weights

printfn "=== Machine Learning with F# Interactive ==="

// 1. Linear Regression Example
printfn "\n1. Linear Regression Analysis"
let linearData = DataGeneration.generateLinearData 100 0.5
let stats = Statistics.summary linearData
let correlation = Statistics.correlation linearData

printfn "Dataset Statistics:"
printfn "  Count: %d" stats.Count
printfn "  Mean Y: %.3f" stats.Mean
printfn "  Std Dev: %.3f" stats.StandardDeviation
printfn "  Correlation: %.3f" correlation

let model = LinearRegression.fit linearData
printfn "\nLinear Regression Model:"
printfn "  Equation: y = %.3fx + %.3f" model.Slope model.Intercept
printfn "  R-squared: %.3f" model.RSquared

// Make predictions
let testX = [1.0; 5.0; 10.0]
printfn "\nPredictions:"
testX |> List.iter (fun x ->
    let prediction = LinearRegression.predict model x
    printfn "  x=%.1f -> y=%.3f" x prediction
)

// 2. K-Means Clustering
printfn "\n2. K-Means Clustering"
let clusterCenters = [(2.0, 2.0); (-2.0, 2.0); (0.0, -2.0)]
let clusterData = DataGeneration.generateClusterData 150 clusterCenters

let clusters = KMeans.cluster clusterData 3 100

printfn "K-Means Results (%d clusters):" clusters.Length
clusters |> List.iteri (fun i cluster ->
    let (cx, cy) = cluster.Center
    printfn "  Cluster %d: Center (%.2f, %.2f), %d points" i cx cy cluster.Points.Length
)

// Calculate within-cluster sum of squares
let wcss = 
    clusters 
    |> List.sumBy (fun cluster ->
        cluster.Points 
        |> List.sumBy (fun point -> KMeans.distance point cluster.Center ** 2.0)
    )
printfn "  Total WCSS: %.3f" wcss

// 3. Classification with Logistic Regression
printfn "\n3. Logistic Regression Classification"
let classificationData = DataGeneration.generateClassificationData 200

let weights = LogisticRegression.train classificationData 0.1 1000

printfn "Trained Logistic Regression:"
printfn "  Weights: [%.3f, %.3f]" weights.[0] weights.[1]

// Test accuracy
let predictions = 
    classificationData 
    |> List.map (fun (features, actualLabel) ->
        let prediction = LogisticRegression.predict weights features
        let predictedLabel = if prediction > 0.5 then 1 else 0
        (actualLabel, predictedLabel, prediction)
    )

let accuracy = 
    predictions 
    |> List.map (fun (actual, predicted, _) -> if actual = predicted then 1.0 else 0.0)
    |> List.average

printfn "  Accuracy: %.3f" accuracy

// Show some predictions
printfn "\nSample Predictions:"
predictions 
|> List.take 10
|> List.iteri (fun i (actual, predicted, prob) ->
    printfn "  Sample %d: Actual=%d, Predicted=%d, Probability=%.3f" i actual predicted prob
)

// 4. Time Series Analysis
printfn "\n4. Time Series Analysis"

let generateTimeSeries n =
    let random = Random(42)
    [0..n-1]
    |> List.map (fun t ->
        let trend = 0.1 * float t
        let seasonal = 2.0 * sin(2.0 * Math.PI * float t / 12.0)
        let noise = random.NextGaussian() * 0.5
        trend + seasonal + noise
    )

let timeSeries = generateTimeSeries 100

// Simple moving average
let movingAverage window data =
    data
    |> List.windowed window
    |> List.map List.average

let ma5 = movingAverage 5 timeSeries
let ma10 = movingAverage 10 timeSeries

printfn "Time Series Statistics:"
printfn "  Original series: %d points" timeSeries.Length
printfn "  MA(5): %d points" ma5.Length
printfn "  MA(10): %d points" ma10.Length

// Calculate trend
let timePoints = [0.0 .. float (timeSeries.Length - 1)]
let trendData = List.zip timePoints timeSeries
let trendModel = LinearRegression.fit trendData

printfn "  Trend: %.4f per period" trendModel.Slope

// 5. Anomaly Detection
printfn "\n5. Anomaly Detection"

let detectAnomalies data threshold =
    let mean = List.average data
    let stdDev = FSharp.Stats.Seq.stDev data
    
    data
    |> List.mapi (fun i value ->
        let zScore = abs (value - mean) / stdDev
        (i, value, zScore, zScore > threshold)
    )

let anomalies = detectAnomalies timeSeries 2.0
let anomalyCount = anomalies |> List.countBy (fun (_, _, _, isAnomaly) -> isAnomaly) |> List.find fst |> snd

printfn "Anomaly Detection (Z-score > 2.0):"
printfn "  Total anomalies: %d out of %d points" anomalyCount timeSeries.Length

anomalies
|> List.filter (fun (_, _, _, isAnomaly) -> isAnomaly)
|> List.take 5
|> List.iter (fun (index, value, zScore, _) ->
    printfn "  Point %d: Value=%.3f, Z-score=%.3f" index value zScore
)

// 6. Feature Engineering
printfn "\n6. Feature Engineering"

// Polynomial features
let addPolynomialFeatures degree data =
    data |> List.map (fun (x, y) ->
        let features = [1.0..float degree] |> List.map (fun d -> x ** d) |> List.toArray
        (features, y)
    )

let polyData = addPolynomialFeatures 3 (linearData |> List.take 50)

printfn "Polynomial Feature Engineering:"
printfn "  Original features: 1"
printfn "  Polynomial features: 3 (x, x², x³)"

// Feature scaling
let scaleFeatures data =
    let features = data |> List.map fst
    let featureCount = (List.head features).Length
    
    let means = [0..featureCount-1] |> List.map (fun i ->
        features |> List.averageBy (fun f -> f.[i])
    )
    
    let stds = [0..featureCount-1] |> List.map (fun i ->
        let mean = means.[i]
        features |> List.map (fun f -> (f.[i] - mean) ** 2.0) |> List.average |> sqrt
    )
    
    data |> List.map (fun (features, label) ->
        let scaledFeatures = 
            features |> Array.mapi (fun i f -> (f - means.[i]) / stds.[i])
        (scaledFeatures, label)
    )

let scaledData = scaleFeatures classificationData

printfn "Feature Scaling Applied:"
printfn "  Features normalized to zero mean and unit variance"

// 7. Model Evaluation
printfn "\n7. Model Evaluation"

// Cross-validation
let crossValidate data folds trainFunc predictFunc =
    let shuffled = data |> List.sortBy (fun _ -> System.Guid.NewGuid())
    let foldSize = shuffled.Length / folds
    
    [0..folds-1] |> List.map (fun fold ->
        let testStart = fold * foldSize
        let testEnd = min (testStart + foldSize) shuffled.Length
        
        let testData = shuffled |> List.skip testStart |> List.take (testEnd - testStart)
        let trainData = 
            (shuffled |> List.take testStart) @ 
            (shuffled |> List.skip testEnd)
        
        let model = trainFunc trainData
        let accuracy = 
            testData 
            |> List.map (fun (features, actual) ->
                let predicted = predictFunc model features
                if actual = predicted then 1.0 else 0.0
            )
            |> List.average
        
        accuracy
    )

let trainLogistic data = LogisticRegression.train data 0.1 1000
let predictLogistic weights features = 
    let prob = LogisticRegression.predict weights features
    if prob > 0.5 then 1 else 0

let cvScores = crossValidate classificationData 5 trainLogistic predictLogistic
let meanCvScore = List.average cvScores
let stdCvScore = FSharp.Stats.Seq.stDev cvScores

printfn "5-Fold Cross-Validation Results:"
printfn "  Mean Accuracy: %.3f (±%.3f)" meanCvScore stdCvScore
cvScores |> List.iteri (fun i score ->
    printfn "  Fold %d: %.3f" (i + 1) score
)

printfn "\nMachine learning analysis completed!"`,

    'notebooks/fsharp-examples.ipynb': `{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# F# Interactive Examples in Jupyter\n",
    "\n",
    "This notebook demonstrates F# Interactive capabilities in Jupyter notebooks."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "// Install packages\n",
    "#r \"nuget: FSharp.Data\"\n",
    "#r \"nuget: Plotly.NET\"\n",
    "#r \"nuget: Plotly.NET.Interactive\"\n",
    "\n",
    "open FSharp.Data\n",
    "open Plotly.NET"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Basic F# Syntax"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "// Variables and functions\n",
    "let greeting = \"Hello, Jupyter!\"\n",
    "let add x y = x + y\n",
    "\n",
    "printfn \"%s\" greeting\n",
    "printfn \"2 + 3 = %d\" (add 2 3)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Data Processing"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "// Generate sample data\n",
    "let data = \n",
    "    [1..100]\n",
    "    |> List.map (fun x -> \n",
    "        let y = float x * 2.0 + System.Random().NextDouble() * 10.0\n",
    "        (x, y)\n",
    "    )\n",
    "\n",
    "// Display first 10 items\n",
    "data |> List.take 10"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Data Visualization"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "// Create a scatter plot\n",
    "let xs = data |> List.map fst |> List.map float\n",
    "let ys = data |> List.map snd\n",
    "\n",
    "Chart.Scatter(xs, ys)\n",
    "|> Chart.withTitle \"Sample Data\"\n",
    "|> Chart.withXAxisStyle \"X Values\"\n",
    "|> Chart.withYAxisStyle \"Y Values\""
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Working with JSON"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "// Define JSON type provider\n",
    "type JsonData = JsonProvider<\"\"\"{\n",
    "    \"name\": \"John\",\n",
    "    \"age\": 30,\n",
    "    \"skills\": [\"F#\", \"JavaScript\", \"Python\"]\n",
    "}\"\"\">\n",
    "\n",
    "// Parse JSON\n",
    "let json = \"\"\"{\n",
    "    \"name\": \"Alice\",\n",
    "    \"age\": 25,\n",
    "    \"skills\": [\"C#\", \"F#\", \"SQL\"]\n",
    "}\"\"\"\n",
    "\n",
    "let person = JsonData.Parse(json)\n",
    "printfn \"Name: %s, Age: %d\" person.Name person.Age\n",
    "printfn \"Skills: %s\" (String.concat \", \" person.Skills)"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": ".NET (F#)",
   "language": "F#",
   "name": ".net-fsharp"
  },
  "language_info": {
   "file_extension": ".fs",
   "mimetype": "text/x-fsharp",
   "name": "F#",
   "pygments_lexer": "fsharp",
   "version": "6.0"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 4
}`,

    'fsi-project.fsproj': `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <OutputType>Library</OutputType>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
  </PropertyGroup>

  <ItemGroup>
    <Compile Include="Library.fs" />
  </ItemGroup>

  <ItemGroup>
    <None Include="scripts/*.fsx" />
    <None Include="notebooks/*.ipynb" />
    <None Include="README.md" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="FSharp.Data" Version="6.3.0" />
    <PackageReference Include="FSharp.Stats" Version="0.5.0" />
    <PackageReference Include="BenchmarkDotNet" Version="0.13.7" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="HtmlAgilityPack" Version="1.11.54" />
    <PackageReference Include="MathNet.Numerics" Version="5.0.0" />
    <PackageReference Include="MathNet.Numerics.FSharp" Version="5.0.0" />
  </ItemGroup>

</Project>`,

    'Library.fs': `namespace FSharpInteractive

/// Core utilities for F# Interactive development
module Interactive =
    
    open System
    open System.IO
    
    /// Load and execute an F# script file
    let loadScript scriptPath =
        if File.Exists(scriptPath) then
            let content = File.ReadAllText(scriptPath)
            printfn "Loading script: %s" scriptPath
            printfn "Content preview: %s..." (content.Substring(0, min 100 content.Length))
        else
            printfn "Script file not found: %s" scriptPath
    
    /// Time execution of a function
    let time f =
        let sw = System.Diagnostics.Stopwatch.StartNew()
        let result = f()
        sw.Stop()
        printfn "Execution time: %dms" sw.ElapsedMilliseconds
        result
    
    /// Pretty print any value
    let pretty value =
        sprintf "%A" value
    
    /// Clear console (when supported)
    let clear() =
        try
            Console.Clear()
        with
        | _ -> printfn "Clear not supported in this environment"
    
    /// Show help for common FSI commands
    let help() =
        printfn """
F# Interactive Help:

Core Commands:
  #help;;                    - Show FSI help
  #quit;;                    - Exit FSI
  #time "on";;               - Enable timing
  #time "off";;              - Disable timing

References:
  #r "assembly.dll";;        - Reference assembly
  #r "nuget: PackageName";;  - Reference NuGet package
  #I "path";;                - Add include path
  #load "script.fsx";;       - Load F# script

Useful Functions:
  Interactive.time (fun () -> expr)  - Time expression
  Interactive.pretty value           - Pretty print value
  Interactive.clear()                - Clear console
        """

/// Educational utilities for learning F#
module Education =
    
    /// Show F# syntax examples
    let syntaxExamples() =
        printfn """
F# Syntax Examples:

// Variables
let x = 42
let mutable y = 10

// Functions
let add a b = a + b
let multiply = fun a b -> a * b

// Pattern Matching
match x with
| 0 -> "zero"
| n when n > 0 -> "positive"
| _ -> "negative"

// Lists and Arrays
let list = [1; 2; 3]
let array = [|1; 2; 3|]

// Pipes and Composition
[1..10] |> List.map ((*) 2) |> List.sum

// Records
type Person = { Name: string; Age: int }
let john = { Name = "John"; Age = 30 }

// Discriminated Unions
type Shape =
    | Circle of radius: float
    | Rectangle of width: float * height: float
        """
    
    /// Show common F# idioms
    let idioms() =
        printfn """
F# Idioms:

1. Use |> for data transformation:
   data |> List.filter predicate |> List.map transform

2. Pattern matching for control flow:
   match option with | Some x -> x | None -> default

3. Use Option instead of null:
   let tryDivide a b = if b = 0 then None else Some(a / b)

4. Composition over inheritance:
   let pipeline = filter >> map >> reduce

5. Use active patterns for parsing:
   let (|Int|_|) str = match Int32.TryParse(str) with
                       | true, i -> Some i | _ -> None
        """
    
    /// Interactive exercises
    let exercises() =
        printfn """
F# Exercises:

1. List Processing:
   // Create a function that filters even numbers and squares them
   let processNumbers nums = // Your code here
   
2. String Manipulation:
   // Count words in a string
   let countWords text = // Your code here
   
3. Data Transformation:
   // Convert list of tuples to record list
   let tuplesToRecords tuples = // Your code here
   
4. Pattern Matching:
   // Implement FizzBuzz using pattern matching
   let fizzBuzz n = // Your code here
        """`,

    'config/fsi-config.fsx': `// F# Interactive Configuration Script
// Load this with: #load "config/fsi-config.fsx"

// Set up common references
#r "nuget: FSharp.Data"
#r "nuget: Newtonsoft.Json"
#r "nuget: FSharp.Stats"

// Enable timing by default
#time "on"

// Import common namespaces
open System
open System.IO
open System.Collections.Generic
open FSharp.Data
open Newtonsoft.Json

// Define common utilities
let time f =
    let sw = System.Diagnostics.Stopwatch.StartNew()
    let result = f()
    sw.Stop()
    printfn "Execution time: %dms" sw.ElapsedMilliseconds
    result

let pretty value = sprintf "%A" value |> printfn "%s"

let saveToFile filename content =
    File.WriteAllText(filename, content)
    printfn "Saved to: %s" filename

let loadFromFile filename =
    if File.Exists(filename) then
        File.ReadAllText(filename)
    else
        failwithf "File not found: %s" filename

// Set up sample data
let sampleNumbers = [1..100]
let sampleData = List.zip sampleNumbers (List.map (fun x -> x * x) sampleNumbers)

// Greeting
printfn "F# Interactive environment configured!"
printfn "Available utilities: time, pretty, saveToFile, loadFromFile"
printfn "Sample data: sampleNumbers, sampleData"
printfn "Use Interactive.help() for more information"`,

    'README.md': `# F# Interactive (FSI) Environment

Interactive F# development environment with REPL capabilities, scripting support, data analysis tools, and rapid prototyping features.

## Features

- **Interactive REPL**: Real-time F# code evaluation and exploration
- **Script Execution**: Run F# scripts (.fsx files) for automation and analysis
- **Data Analysis**: Built-in data processing and visualization capabilities
- **Rapid Prototyping**: Quick testing and development of F# code
- **Package Integration**: Easy NuGet package loading and management
- **Educational Tools**: Learning resources and interactive tutorials
- **Notebook Support**: Jupyter notebook integration
- **Performance Profiling**: Built-in timing and performance analysis

## Quick Start

### Prerequisites

- .NET 6.0 SDK or later
- F# development tools

### Starting F# Interactive

\`\`\`bash
# Start FSI from command line
dotnet fsi

# Load a script
dotnet fsi script.fsx

# Run in interactive mode
dotnet fsi --gui  # On Windows with GUI support
\`\`\`

### Basic Usage

\`\`\`fsharp
// Enable timing
#time "on";;

// Reference packages
#r "nuget: FSharp.Data";;
#r "nuget: Newtonsoft.Json";;

// Load scripts
#load "scripts/basic-examples.fsx";;

// Define and test functions
let add x y = x + y;;
add 5 3;;

// Work with collections
[1..10] |> List.map (fun x -> x * x);;
\`\`\`

## Project Structure

\`\`\`
├── scripts/
│   ├── basic-examples.fsx        # Basic F# examples
│   ├── data-analysis.fsx         # Data analysis examples
│   ├── web-scraping.fsx          # Web scraping and APIs
│   ├── performance-analysis.fsx  # Performance benchmarking
│   └── machine-learning.fsx      # ML and data science
├── notebooks/
│   └── fsharp-examples.ipynb     # Jupyter notebook examples
├── config/
│   └── fsi-config.fsx            # FSI configuration
├── Library.fs                    # Common utilities
└── fsi-project.fsproj            # Project file
\`\`\`

## FSI Commands

### Core Commands

\`\`\`fsharp
#help;;                    // Show FSI help
#quit;;                    // Exit FSI
#time "on";;               // Enable timing
#time "off";;              // Disable timing
#clear;;                   // Clear definitions (if supported)
\`\`\`

### Loading and References

\`\`\`fsharp
// Reference assemblies
#r "System.Net.Http";;
#r "assembly.dll";;

// Reference NuGet packages
#r "nuget: FSharp.Data";;
#r "nuget: Newtonsoft.Json, 13.0.3";;

// Add include paths
#I "path/to/assemblies";;

// Load F# scripts
#load "script.fsx";;
#load "folder/script1.fsx" "folder/script2.fsx";;
\`\`\`

### Directives

\`\`\`fsharp
// Conditional compilation
#if INTERACTIVE
printfn "Running in FSI"
#endif

// Line directives
#line 100 "filename.fs"
\`\`\`

## Script Examples

### 1. Basic Data Processing

\`\`\`fsharp
// Load the basic examples script
#load "scripts/basic-examples.fsx"

// Or run inline
let data = [1..100]
let result = 
    data 
    |> List.filter (fun x -> x % 2 = 0)
    |> List.map (fun x -> x * x)
    |> List.sum

printfn "Sum of squares of even numbers: %d" result
\`\`\`

### 2. Data Analysis

\`\`\`fsharp
// Load data analysis examples
#load "scripts/data-analysis.fsx"

// Generate and analyze sales data
// (See script for complete implementation)
\`\`\`

### 3. Web Scraping and APIs

\`\`\`fsharp
// Load web scraping examples
#load "scripts/web-scraping.fsx"

// Work with JSON APIs
#r "nuget: FSharp.Data";;
open FSharp.Data

type Users = JsonProvider<"https://jsonplaceholder.typicode.com/users">
let users = Users.Load("https://jsonplaceholder.typicode.com/users")
users |> Array.iter (fun u -> printfn "%s - %s" u.Name u.Email)
\`\`\`

### 4. Performance Analysis

\`\`\`fsharp
// Load performance examples
#load "scripts/performance-analysis.fsx"

// Benchmark algorithms
let measureTime f =
    let sw = System.Diagnostics.Stopwatch.StartNew()
    let result = f()
    sw.Stop()
    (result, sw.ElapsedMilliseconds)

let (result, time) = measureTime (fun () -> [1..1000000] |> List.sum)
printfn "Sum calculated in %dms: %d" time result
\`\`\`

### 5. Machine Learning

\`\`\`fsharp
// Load ML examples
#load "scripts/machine-learning.fsx"

// Simple linear regression
// (See script for complete implementation)
\`\`\`

## Jupyter Notebook Integration

### Setup

\`\`\`bash
# Install .NET Interactive
dotnet tool install -g Microsoft.dotnet-interactive

# Install Jupyter kernels
dotnet interactive jupyter install

# Start Jupyter
jupyter lab
\`\`\`

### Usage

Create notebooks with F# cells:

\`\`\`fsharp
// Install packages in notebook
#r "nuget: FSharp.Data"
#r "nuget: Plotly.NET"

// Create visualizations
open Plotly.NET

let data = [1..10] |> List.map (fun x -> (x, x * x))
Chart.Scatter(data) |> Chart.show
\`\`\`

## IDE Integration

### Visual Studio Code

1. Install F# extension
2. Use "F#: Send Selection to FSI" command
3. Interactive window integration

### Visual Studio

1. F# Interactive window available
2. Send code to FSI with shortcuts
3. IntelliSense support

### JetBrains Rider

1. F# Interactive tool window
2. Send selection to REPL
3. Script file support

## Advanced Features

### Custom Configuration

Create \`fsi-config.fsx\`:

\`\`\`fsharp
// Auto-load common packages
#r "nuget: FSharp.Data"
#r "nuget: Newtonsoft.Json"

// Enable timing
#time "on"

// Define utilities
let time f =
    let sw = System.Diagnostics.Stopwatch.StartNew()
    let result = f()
    sw.Stop()
    printfn "Time: %dms" sw.ElapsedMilliseconds
    result

// Load with: #load "fsi-config.fsx"
\`\`\`

### Package Management

\`\`\`fsharp
// Load specific versions
#r "nuget: FSharp.Data, 6.3.0"

// Load with dependencies
#r "nuget: FSharp.Stats"  // Automatically loads dependencies

// Local packages
#I "packages/MyLibrary/lib/net6.0"
#r "MyLibrary.dll"
\`\`\`

### Multi-file Projects

\`\`\`fsharp
// Load multiple files in order
#load "Models.fs" "Services.fs" "Main.fs"

// Or use a loader script
#load "LoadProject.fsx"
\`\`\`

## Educational Use

### Learning F#

\`\`\`fsharp
// Load educational utilities
open Education

// Show syntax examples
Education.syntaxExamples()

// Show common idioms
Education.idioms()

// Interactive exercises
Education.exercises()
\`\`\`

### Exploration and Discovery

\`\`\`fsharp
// Explore type information
typeof<List<int>>
typeof<string>.GetMethods() |> Array.map (fun m -> m.Name)

// Inspect values
let value = [1; 2; 3]
value.GetType()
value.Length
\`\`\`

## Debugging and Profiling

### Error Handling

\`\`\`fsharp
// Show stack traces
#r "nuget: FSharp.Core"
open System

try
    1 / 0
with
| ex -> printfn "Error: %s\\nStack: %s" ex.Message ex.StackTrace
\`\`\`

### Performance Profiling

\`\`\`fsharp
// Use built-in timing
#time "on"
[1..1000000] |> List.sum;;

// Custom profiling
let profile name f =
    let sw = System.Diagnostics.Stopwatch.StartNew()
    let result = f()
    sw.Stop()
    printfn "%s: %dms" name sw.ElapsedMilliseconds
    result

profile "List sum" (fun () -> [1..1000000] |> List.sum)
\`\`\`

## Best Practices

### Script Organization

1. **Modular Scripts**: Break complex logic into smaller scripts
2. **Configuration**: Use config scripts for common setup
3. **Documentation**: Comment scripts thoroughly
4. **Error Handling**: Include proper error handling

### Performance

1. **Lazy Evaluation**: Use sequences for large datasets
2. **Mutable Collections**: Use when performance critical
3. **Parallel Processing**: Leverage \`Array.Parallel\` operations
4. **Memory Management**: Be aware of GC pressure

### Development Workflow

1. **Rapid Prototyping**: Test ideas quickly in FSI
2. **Incremental Development**: Build up solutions step by step
3. **Interactive Testing**: Test functions as you write them
4. **Data Exploration**: Use FSI for data analysis

## Common Issues and Solutions

### Package Loading

\`\`\`fsharp
// If package fails to load
#I "nuget: PackageName"  // Add package path first
#r "nuget: PackageName"  // Then reference

// Clear and reload
#quit
dotnet fsi
#load "script.fsx"
\`\`\`

### Memory Issues

\`\`\`fsharp
// Force garbage collection
System.GC.Collect()
System.GC.WaitForPendingFinalizers()

// Monitor memory usage
let memBefore = System.GC.GetTotalMemory(false)
// ... run code ...
let memAfter = System.GC.GetTotalMemory(false)
printfn "Memory used: %d bytes" (memAfter - memBefore)
\`\`\`

### Script Dependencies

\`\`\`fsharp
// Load dependencies in correct order
#load "Utilities.fs"    // Load dependencies first
#load "Business.fs"     // Then dependent modules
#load "Main.fs"         // Finally main module
\`\`\`

## Learning Resources

- [F# for Fun and Profit](https://fsharpforfunandprofit.com/)
- [F# Interactive Documentation](https://docs.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/)
- [F# Data Science](https://fsharp.org/guides/data-science/)
- [Try F# Online](https://try.fsharp.org/)

## Contributing

1. Fork the repository
2. Add new script examples
3. Improve documentation
4. Share your FSI tips and tricks
5. Submit a pull request

## License

This project is licensed under the MIT License.`
  }
};