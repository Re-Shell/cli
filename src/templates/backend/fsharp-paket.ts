import { BackendTemplate } from '../types';

export const fsharpPaketTemplate: BackendTemplate = {
  id: 'fsharp-paket',
  name: 'fsharp-paket',
  displayName: 'F# Paket Dependency Manager',
  description: 'Modern dependency manager for F# and .NET projects with precise dependency resolution and reproducible builds',
  framework: 'paket',
  language: 'fsharp',
  version: '8.0',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '📦',
  type: 'build-system',
  complexity: 'intermediate',
  keywords: ['fsharp', 'paket', 'dependency', 'package-manager', 'build', 'dotnet'],
  
  features: [
    'Precise dependency resolution',
    'Reproducible builds',
    'Lock file support',
    'Group-based dependencies',
    'Framework restrictions',
    'Source code dependencies',
    'Git dependencies',
    'NuGet package management',
    'Dependency groups',
    'Version constraints',
    'Transitive dependency control',
    'Integration with MSBuild',
    'Cross-platform support',
    'Dependency analysis'
  ],
  
  structure: {
    'paket.dependencies': `// Paket dependency specification file
// Framework restrictions and source specifications

framework: net6.0, netstandard2.0

// Main NuGet source
source https://api.nuget.org/v3/index.json

// Package dependencies
nuget FSharp.Core >= 6.0.0
nuget Newtonsoft.Json >= 13.0.0
nuget Microsoft.AspNetCore.App >= 6.0.0

// Web framework dependencies
group Web
    source https://api.nuget.org/v3/index.json
    framework: net6.0
    
    nuget Giraffe >= 6.0.0
    nuget Saturn >= 0.16.0
    nuget Suave >= 2.6.0
    nuget Microsoft.AspNetCore.Authentication.JwtBearer >= 6.0.0
    nuget Microsoft.EntityFrameworkCore >= 6.0.0
    nuget Microsoft.EntityFrameworkCore.Sqlite >= 6.0.0

// Testing dependencies
group Test
    source https://api.nuget.org/v3/index.json
    framework: net6.0
    
    nuget Expecto >= 10.0.0
    nuget FsCheck >= 2.16.0
    nuget Microsoft.NET.Test.Sdk >= 17.0.0
    nuget NUnit >= 3.13.0
    nuget NUnit3TestAdapter >= 4.0.0

// Build and development tools
group Build
    source https://api.nuget.org/v3/index.json
    framework: net6.0
    
    nuget FAKE.Core.Target >= 5.23.0
    nuget FAKE.IO.FileSystem >= 5.23.0
    nuget FAKE.DotNet.Cli >= 5.23.0
    nuget FAKE.DotNet.MSBuild >= 5.23.0
    nuget FAKE.DotNet.Testing.Expecto >= 5.23.0

// Documentation tools
group Docs
    source https://api.nuget.org/v3/index.json
    framework: net6.0
    
    nuget FSharp.Formatting >= 14.0.0
    nuget FSharp.Compiler.Service >= 41.0.0

// Performance and profiling
group Performance
    source https://api.nuget.org/v3/index.json
    framework: net6.0
    
    nuget BenchmarkDotNet >= 0.13.0
    nuget BenchmarkDotNet.Diagnostics.Windows
    nuget Microsoft.Diagnostics.Tracing.TraceEvent >= 3.0.0

// Source code dependencies from GitHub
github fsprojects/FSharpx.Collections src/FSharpx.Collections/Collections.fs
github fsharp/FAKE modules/Octokit/Octokit.fsx

// HTTP file dependency
http https://raw.githubusercontent.com/fsprojects/Paket/master/src/Paket.Core/AssemblyInfo.fs src/AssemblyInfo.fs

// Git dependencies
git https://github.com/fsprojects/FSharp.Data.git master src/FSharp.Data/
git https://github.com/fsprojects/Argu.git 6.0.0 src/Argu/

// Copy local settings
copy_local: false
copy_content_to_output_dir: never
import_targets: false

// Dependency restrictions
restrictions: >= net6.0
content: none
storage: none`,

    'paket.lock': `RESTRICTION: >= net6.0
NUGET
  remote: https://api.nuget.org/v3/index.json
    FSharp.Core (6.0.7)
    Microsoft.AspNetCore.App (6.0.22)
      Microsoft.AspNetCore (>= 6.0.22)
      Microsoft.AspNetCore.Authorization (>= 6.0.22)
      Microsoft.AspNetCore.Components (>= 6.0.22)
      Microsoft.AspNetCore.DataProtection (>= 6.0.22)
      Microsoft.AspNetCore.Diagnostics (>= 6.0.22)
      Microsoft.AspNetCore.Http (>= 6.0.22)
      Microsoft.AspNetCore.Routing (>= 6.0.22)
      Microsoft.Extensions.Configuration (>= 6.0.22)
      Microsoft.Extensions.DependencyInjection (>= 6.0.22)
      Microsoft.Extensions.Logging (>= 6.0.22)
    Newtonsoft.Json (13.0.3)

GROUP Build
RESTRICTION: >= net6.0
NUGET
  remote: https://api.nuget.org/v3/index.json
    FAKE.Core.Target (5.23.1)
      FAKE.Core.Context (>= 5.23.1)
      FSharp.Control.Reactive (>= 5.0.2)
      FSharp.Core (>= 6.0.1)
    FAKE.DotNet.Cli (5.23.1)
      FAKE.Core.Environment (>= 5.23.1)
      FAKE.Core.Process (>= 5.23.1)
      FAKE.Core.String (>= 5.23.1)
      FAKE.Core.Trace (>= 5.23.1)
      FAKE.DotNet.MSBuild (>= 5.23.1)
      FAKE.IO.FileSystem (>= 5.23.1)
      Mono.Posix.NETStandard (>= 1.0)
      Newtonsoft.Json (>= 13.0.1)
    FAKE.DotNet.MSBuild (5.23.1)
      FAKE.Core.Environment (>= 5.23.1)
      FAKE.Core.Process (>= 5.23.1)
      FAKE.Core.String (>= 5.23.1)
      FAKE.Core.Trace (>= 5.23.1)
      FAKE.IO.FileSystem (>= 5.23.1)
      MSBuild.StructuredLogger (>= 2.1.758)
    FAKE.DotNet.Testing.Expecto (5.23.1)
      FAKE.Core.Process (>= 5.23.1)
      FAKE.Core.String (>= 5.23.1)
      FAKE.Core.Trace (>= 5.23.1)
      FAKE.DotNet.Cli (>= 5.23.1)
    FAKE.IO.FileSystem (5.23.1)
      FAKE.Core.String (>= 5.23.1)
      FSharp.Core (>= 6.0.1)

GROUP Docs
RESTRICTION: >= net6.0
NUGET
  remote: https://api.nuget.org/v3/index.json
    FSharp.Compiler.Service (41.0.8)
      FSharp.Core (>= 6.0.2)
      System.Collections.Immutable (>= 6.0)
      System.Memory (>= 4.5.4)
      System.Reflection.Metadata (>= 6.0.1)
    FSharp.Formatting (14.0.1)
      FSharp.Compiler.Service (>= 41.0.3)
      FSharp.Core (>= 6.0.0)
      Newtonsoft.Json (>= 13.0.1)

GROUP Performance
RESTRICTION: >= net6.0
NUGET
  remote: https://api.nuget.org/v3/index.json
    BenchmarkDotNet (0.13.7)
      BenchmarkDotNet.Annotations (>= 0.13.7)
      CommandLineParser (>= 2.9.1)
      Iced (>= 1.17.0)
      Microsoft.CodeAnalysis.CSharp (>= 4.5.0)
      Microsoft.DotNet.PlatformAbstractions (>= 3.1.6)
      Microsoft.Win32.Registry (>= 5.0)
      Perfolizer (>= 0.2.1)
      System.Management (>= 6.0)
      System.Text.Json (>= 6.0.5)
    BenchmarkDotNet.Diagnostics.Windows (0.13.7)
      BenchmarkDotNet (>= 0.13.7)
      Microsoft.Diagnostics.Tracing.TraceEvent (>= 3.0.2)
    Microsoft.Diagnostics.Tracing.TraceEvent (3.0.8)
      Microsoft.Win32.Registry (>= 4.7)
      System.Security.Principal.Windows (>= 4.7)

GROUP Test
RESTRICTION: >= net6.0
NUGET
  remote: https://api.nuget.org/v3/index.json
    Expecto (10.2.1)
      FSharp.Core (>= 6.0.1)
      Mono.Posix.NETStandard (>= 1.0)
    FsCheck (2.16.5)
      FSharp.Core (>= 6.0.1)
    Microsoft.NET.Test.Sdk (17.7.2)
      Microsoft.CodeCoverage (>= 17.7.2)
      Microsoft.TestPlatform.TestHost (>= 17.7.2)
    NUnit (3.13.3)
      NETStandard.Library (>= 2.0)
    NUnit3TestAdapter (4.5.0)

GROUP Web
RESTRICTION: >= net6.0
NUGET
  remote: https://api.nuget.org/v3/index.json
    Giraffe (6.2.0)
      FSharp.Core (>= 6.0.3)
      Microsoft.AspNetCore.Http.Abstractions (>= 2.1)
      Microsoft.IO.RecyclableMemoryStream (>= 2.2.1)
      Newtonsoft.Json (>= 13.0.3)
      TaskBuilder.fs (>= 2.1)
      Utf8Json (>= 1.3.7)
    Microsoft.AspNetCore.Authentication.JwtBearer (6.0.22)
      Microsoft.IdentityModel.Protocols.OpenIdConnect (>= 6.15.1)
    Microsoft.EntityFrameworkCore (6.0.22)
      Microsoft.EntityFrameworkCore.Abstractions (>= 6.0.22)
      Microsoft.EntityFrameworkCore.Analyzers (>= 6.0.22)
      Microsoft.Extensions.Caching.Memory (>= 6.0.1)
      Microsoft.Extensions.DependencyInjection (>= 6.0.1)
      Microsoft.Extensions.Logging (>= 6.0.1)
      System.Collections.Immutable (>= 6.0)
      System.Diagnostics.DiagnosticSource (>= 6.0.1)
    Microsoft.EntityFrameworkCore.Sqlite (6.0.22)
      Microsoft.EntityFrameworkCore.Relational (>= 6.0.22)
      SQLitePCLRaw.bundle_e_sqlite3 (>= 2.1.2)
    Saturn (0.16.1)
      FSharp.Core (>= 6.0.1)
      Giraffe (>= 6.0.0)
      Microsoft.AspNetCore.Authentication.Cookies (>= 6.0.4)
      Microsoft.AspNetCore.Authentication.OpenIdConnect (>= 6.0.4)
      Microsoft.AspNetCore.Mvc.Razor.RuntimeCompilation (>= 6.0.4)
      Microsoft.AspNetCore.Session (>= 2.2.0)
      Microsoft.Extensions.DependencyInjection (>= 6.0.0)
    Suave (2.6.2)
      FSharp.Core (>= 6.0.1)

GITHUB
  remote: fsprojects/FSharpx.Collections
  specs:
    src/FSharpx.Collections/Collections.fs (a1b69514a64c94ec46b37e7fd0f471b8c63e2a5b)
  remote: fsharp/FAKE
  specs:
    modules/Octokit/Octokit.fsx (8af10ad6bfcc1b6e68e1f2c725c8b5a2b6a2b4b8)

HTTP
  remote: https://raw.githubusercontent.com/fsprojects/Paket/master/src/Paket.Core/AssemblyInfo.fs
  specs:
    src/AssemblyInfo.fs

GIT
  remote: https://github.com/fsprojects/FSharp.Data.git
  specs:
    src/FSharp.Data/ (master)
  remote: https://github.com/fsprojects/Argu.git
  specs:
    src/Argu/ (6.0.0)`,

    'paket.local': `// Local overrides for paket.dependencies
// This file is used for local development overrides
// and should not be committed to version control

// Override package versions for local development
nuget FSharp.Core 6.0.7
nuget Newtonsoft.Json 13.0.3

// Local source for testing
source C:\\Local\\MyPackages

// Disable specific packages temporarily
// nuget SomePackage disable

// Use local git repository
// git file:///c:/dev/MyLibrary main src/MyLibrary/

// Development-specific settings
storage: packages
content: once
copy_local: true`,

    'paket.template': `type project
id MyFSharpProject
version 1.0.0
authors Your Name
owners Your Name
description
    A comprehensive F# project template with Paket dependency management
tags
    fsharp, paket, template, dotnet
summary A template for F# projects using Paket
licenseUrl https://github.com/yourname/yourproject/blob/master/LICENSE
projectUrl https://github.com/yourname/yourproject
iconUrl https://raw.githubusercontent.com/yourname/yourproject/master/icon.png
releaseNotes
    Initial release with Paket integration
copyright Copyright 2024
requireLicenseAcceptance false
files
    bin/Release/net6.0/MyFSharpProject.dll ==> lib/net6.0
    bin/Release/net6.0/MyFSharpProject.xml ==> lib/net6.0
dependencies
    FSharp.Core >= LOCKEDVERSION
excludedgroups
    Build
    Test`,

    'src/Library.fs': `namespace MyFSharpProject

/// Core library module demonstrating Paket dependency management
module Core =
    
    open System
    open Newtonsoft.Json
    
    /// Sample data type for JSON serialization
    type Person = {
        Id: int
        Name: string
        Email: string
        BirthDate: DateTime
    }
    
    /// Create a sample person
    let createPerson id name email birthDate =
        { Id = id; Name = name; Email = email; BirthDate = birthDate }
    
    /// Serialize person to JSON using Newtonsoft.Json
    let personToJson (person: Person) =
        JsonConvert.SerializeObject(person, Formatting.Indented)
    
    /// Deserialize person from JSON
    let personFromJson (json: string) =
        try
            JsonConvert.DeserializeObject<Person>(json) |> Ok
        with
        | ex -> Error ex.Message
    
    /// Example using FSharp.Core features
    let processPersons persons =
        persons
        |> List.map (fun p -> { p with Name = p.Name.ToUpper() })
        |> List.sortBy (fun p -> p.BirthDate)
        |> List.filter (fun p -> p.BirthDate.Year >= 1990)

/// HTTP utilities module
module Http =
    
    open System.Net.Http
    open System.Threading.Tasks
    open System.Text
    
    /// Simple HTTP client wrapper
    type HttpClient with
        member this.GetStringAsync(url: string) =
            task {
                let! response = this.GetAsync(url)
                response.EnsureSuccessStatusCode() |> ignore
                let! content = response.Content.ReadAsStringAsync()
                return content
            }
        
        member this.PostJsonAsync(url: string, json: string) =
            task {
                let content = new StringContent(json, Encoding.UTF8, "application/json")
                let! response = this.PostAsync(url, content)
                response.EnsureSuccessStatusCode() |> ignore
                let! responseContent = response.Content.ReadAsStringAsync()
                return responseContent
            }

/// Configuration module
module Config =
    
    open System
    open System.IO
    open Newtonsoft.Json
    
    /// Application configuration
    type AppConfig = {
        DatabaseConnection: string
        ApiKey: string
        Debug: bool
        Port: int
        AllowedOrigins: string list
    }
    
    /// Default configuration
    let defaultConfig = {
        DatabaseConnection = "Data Source=app.db"
        ApiKey = "your-api-key"
        Debug = true
        Port = 8080
        AllowedOrigins = ["http://localhost:3000"]
    }
    
    /// Load configuration from file
    let loadConfig (filePath: string) =
        if File.Exists(filePath) then
            try
                let json = File.ReadAllText(filePath)
                JsonConvert.DeserializeObject<AppConfig>(json) |> Ok
            with
            | ex -> Error $"Failed to load config: {ex.Message}"
        else
            Error "Configuration file not found"
    
    /// Save configuration to file
    let saveConfig (config: AppConfig) (filePath: string) =
        try
            let json = JsonConvert.SerializeObject(config, Formatting.Indented)
            File.WriteAllText(filePath, json)
            Ok ()
        with
        | ex -> Error $"Failed to save config: {ex.Message}"`,

    'src/MyFSharpProject.fsproj': `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <WarningsNotAsErrors>FS0025</WarningsNotAsErrors>
  </PropertyGroup>

  <ItemGroup>
    <Compile Include="Library.fs" />
  </ItemGroup>

  <Import Project="..\\..\\paket.targets" />

</Project>`,

    'tests/Tests.fs': `module Tests

open Expecto
open MyFSharpProject.Core
open MyFSharpProject.Config
open System

let configTests =
    testList "Configuration Tests" [
        test "Default config should have correct values" {
            let config = defaultConfig
            Expect.equal config.Port 8080 "Default port should be 8080"
            Expect.isTrue config.Debug "Debug should be enabled by default"
            Expect.hasLength config.AllowedOrigins 1 "Should have one allowed origin"
        }
        
        test "Config serialization should work" {
            let config = defaultConfig
            let result = saveConfig config "test-config.json"
            Expect.isOk result "Should save config successfully"
            
            let loadResult = loadConfig "test-config.json"
            Expect.isOk loadResult "Should load config successfully"
            
            match loadResult with
            | Ok loadedConfig ->
                Expect.equal loadedConfig.Port config.Port "Port should match"
                Expect.equal loadedConfig.Debug config.Debug "Debug should match"
            | Error _ -> failtest "Failed to load config"
        }
    ]

let coreTests =
    testList "Core Tests" [
        test "Person creation should work" {
            let person = createPerson 1 "John Doe" "john@example.com" (DateTime(1990, 1, 1))
            Expect.equal person.Id 1 "ID should be 1"
            Expect.equal person.Name "John Doe" "Name should match"
            Expect.equal person.Email "john@example.com" "Email should match"
        }
        
        test "JSON serialization should work" {
            let person = createPerson 1 "John Doe" "john@example.com" (DateTime(1990, 1, 1))
            let json = personToJson person
            Expect.stringContains json "John Doe" "JSON should contain name"
            Expect.stringContains json "john@example.com" "JSON should contain email"
        }
        
        test "JSON deserialization should work" {
            let person = createPerson 1 "John Doe" "john@example.com" (DateTime(1990, 1, 1))
            let json = personToJson person
            let result = personFromJson json
            
            Expect.isOk result "Deserialization should succeed"
            
            match result with
            | Ok deserializedPerson ->
                Expect.equal deserializedPerson.Name person.Name "Names should match"
                Expect.equal deserializedPerson.Email person.Email "Emails should match"
            | Error _ -> failtest "Deserialization failed"
        }
        
        test "Process persons should filter and sort correctly" {
            let persons = [
                createPerson 1 "alice" "alice@example.com" (DateTime(1985, 1, 1))
                createPerson 2 "bob" "bob@example.com" (DateTime(1995, 1, 1))
                createPerson 3 "charlie" "charlie@example.com" (DateTime(2000, 1, 1))
            ]
            
            let processed = processPersons persons
            
            Expect.hasLength processed 2 "Should filter out person born before 1990"
            Expect.equal processed.[0].Name "BOB" "Names should be uppercase"
            Expect.equal processed.[1].Name "CHARLIE" "Names should be uppercase"
            Expect.isTrue (processed.[0].BirthDate <= processed.[1].BirthDate) "Should be sorted by birth date"
        }
    ]

[<Tests>]
let allTests =
    testList "All Tests" [
        configTests
        coreTests
    ]`,

    'tests/Tests.fsproj': `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <IsPackable>false</IsPackable>
    <GenerateProgramFile>false</GenerateProgramFile>
  </PropertyGroup>

  <ItemGroup>
    <Compile Include="Tests.fs" />
    <Compile Include="Program.fs" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="../src/MyFSharpProject.fsproj" />
  </ItemGroup>

  <Import Project="..\\paket.targets" />

</Project>`,

    'tests/Program.fs': `module Program

open Expecto

[<EntryPoint>]
let main argv =
    Tests.runTestsInAssemblyWithCLIArgs [] argv`,

    'build.fsx': `#r "paket: groupref Build //"
#load ".fake/build.fsx/intellisense.fsx"

open Fake.Core
open Fake.DotNet
open Fake.IO
open Fake.IO.FileSystemOperators
open Fake.IO.Globbing.Operators
open Fake.Core.TargetOperators
open Fake.DotNet.Testing.Expecto

// Build configuration
let buildDir = "./build/"
let deployDir = "./deploy/"
let srcGlob = "src/**/*.fsproj"
let testsGlob = "tests/**/*.fsproj"

// Paket targets
Target.create "RestorePackages" (fun _ ->
    Paket.restore (fun p ->
        { p with ToolType = ToolType.CreateLocalTool() }
    )
)

Target.create "UpdatePackages" (fun _ ->
    Paket.update (fun p ->
        { p with ToolType = ToolType.CreateLocalTool() }
    )
)

Target.create "InstallPackages" (fun _ ->
    Paket.install (fun p ->
        { p with ToolType = ToolType.CreateLocalTool() }
    )
)

// Build targets
Target.create "Clean" (fun _ ->
    !! "src/**/bin"
    ++ "src/**/obj"
    ++ "tests/**/bin"
    ++ "tests/**/obj"
    ++ buildDir
    ++ deployDir
    |> Shell.cleanDirs
)

Target.create "AssemblyInfo" (fun _ ->
    let getAssemblyInfoAttributes projectName =
        [ AssemblyInfo.Title (projectName)
          AssemblyInfo.Product projectName
          AssemblyInfo.Version "1.0.0"
          AssemblyInfo.Metadata("githash", Git.Information.getCurrentSHA1 ".") ]

    let getProjectDetails projectPath =
        let projectName = System.IO.Path.GetFileNameWithoutExtension(projectPath)
        ( projectPath,
          projectName,
          System.IO.Path.GetDirectoryName(projectPath),
          (getAssemblyInfoAttributes projectName)
        )

    !! srcGlob
    |> Seq.map getProjectDetails
    |> Seq.iter (fun (projFileName, _, folderName, attributes) ->
        AssemblyInfoFile.createFSharp (folderName </> "AssemblyInfo.fs") attributes
    )
)

Target.create "Build" (fun _ ->
    !! srcGlob
    |> Seq.iter (DotNet.build (fun p ->
        { p with
            Configuration = DotNet.BuildConfiguration.Release
            OutputPath = Some buildDir }))
)

Target.create "BuildTests" (fun _ ->
    !! testsGlob
    |> Seq.iter (DotNet.build (fun p ->
        { p with
            Configuration = DotNet.BuildConfiguration.Debug }))
)

Target.create "RunTests" (fun _ ->
    !! testsGlob
    |> Seq.iter (fun proj ->
        DotNet.exec id "run" (sprintf "--project %s" proj)
        |> fun result ->
            if not result.OK then
                failwithf "Tests failed for project %s" proj
    )
)

Target.create "GenerateDocs" (fun _ ->
    let source = "./docs"
    let template = "./docs/template"
    let output = "./docs/output"
    
    Shell.cleanDir output
    
    // Use FSharp.Formatting to generate documentation
    DotNet.exec id "fsdocs" (sprintf "build --input %s --output %s" source output)
    |> ignore
)

Target.create "Pack" (fun _ ->
    Paket.pack (fun p ->
        { p with
            ToolType = ToolType.CreateLocalTool()
            OutputPath = deployDir
            Version = "1.0.0"
            ReleaseNotes = "Initial release"
        }
    )
)

Target.create "Deploy" (fun _ ->
    !! (deployDir + "/*.nupkg")
    |> Seq.iter (fun pkg ->
        Paket.push (fun p ->
            { p with
                ToolType = ToolType.CreateLocalTool()
                WorkingDir = deployDir
                PublishUrl = "https://www.nuget.org/api/v2/package"
                ApiKey = Environment.environVarOrDefault "NUGET_API_KEY" ""
            }
        ) pkg
    )
)

// Build order
"Clean"
  ==> "RestorePackages"
  ==> "AssemblyInfo"
  ==> "Build"
  ==> "BuildTests"
  ==> "RunTests"
  ==> "GenerateDocs"
  ==> "Pack"

"Pack" ==> "Deploy"

Target.runOrDefault "RunTests"`,

    '.paket/paket.bootstrapper.exe.config': `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="System.Net.Http" publicKeyToken="b03f5f7f11d50a3a" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-4.3.4.0" newVersion="4.3.4.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2" />
  </startup>
</configuration>`,

    'scripts/paket-commands.sh': `#!/bin/bash

# Paket command reference and automation scripts

echo "Paket Dependency Manager Commands"
echo "=================================="

# Initialize Paket in a new project
init_paket() {
    echo "Initializing Paket..."
    dotnet tool install paket --tool-path .paket
    .paket/paket init
    echo "Paket initialized successfully!"
}

# Install dependencies
install_deps() {
    echo "Installing dependencies..."
    .paket/paket install
    echo "Dependencies installed!"
}

# Update dependencies
update_deps() {
    echo "Updating dependencies..."
    .paket/paket update
    echo "Dependencies updated!"
}

# Add a new package
add_package() {
    if [ -z "$1" ]; then
        echo "Usage: add_package <package-name> [version] [group]"
        return 1
    fi
    
    local package=$1
    local version=${2:-""}
    local group=${3:-""}
    
    local cmd=".paket/paket add nuget $package"
    
    if [ ! -z "$version" ]; then
        cmd="$cmd --version $version"
    fi
    
    if [ ! -z "$group" ]; then
        cmd="$cmd --group $group"
    fi
    
    echo "Adding package: $package"
    eval $cmd
    echo "Package added successfully!"
}

# Remove a package
remove_package() {
    if [ -z "$1" ]; then
        echo "Usage: remove_package <package-name> [group]"
        return 1
    fi
    
    local package=$1
    local group=${2:-""}
    
    local cmd=".paket/paket remove nuget $package"
    
    if [ ! -z "$group" ]; then
        cmd="$cmd --group $group"
    fi
    
    echo "Removing package: $package"
    eval $cmd
    echo "Package removed successfully!"
}

# Show outdated packages
show_outdated() {
    echo "Checking for outdated packages..."
    .paket/paket outdated
}

# Show dependency tree
show_deps() {
    echo "Dependency tree:"
    .paket/paket show-groups
    echo ""
    .paket/paket show-installed-packages
}

# Restore packages
restore() {
    echo "Restoring packages..."
    .paket/paket restore
    echo "Packages restored!"
}

# Generate include scripts
generate_includes() {
    echo "Generating include scripts..."
    .paket/paket generate-include-scripts
    echo "Include scripts generated!"
}

# Find packages
find_package() {
    if [ -z "$1" ]; then
        echo "Usage: find_package <search-term>"
        return 1
    fi
    
    echo "Searching for packages containing: $1"
    .paket/paket find-packages --search-term "$1"
}

# Validate paket files
validate() {
    echo "Validating Paket files..."
    .paket/paket check
    echo "Validation complete!"
}

# Clean paket cache
clean_cache() {
    echo "Cleaning Paket cache..."
    .paket/paket clear-cache
    echo "Cache cleared!"
}

# Pack for NuGet
pack_nuget() {
    echo "Packing for NuGet..."
    .paket/paket pack ./nuget
    echo "NuGet packages created in ./nuget/"
}

# Push to NuGet
push_nuget() {
    if [ -z "$1" ]; then
        echo "Usage: push_nuget <api-key>"
        return 1
    fi
    
    echo "Pushing packages to NuGet..."
    .paket/paket push --api-key "$1" ./nuget
    echo "Packages pushed to NuGet!"
}

# Convert from packages.config
convert_from_nuget() {
    echo "Converting from packages.config..."
    .paket/paket convert-from-nuget
    echo "Conversion complete!"
}

# Auto-restore setup
setup_auto_restore() {
    echo "Setting up auto-restore..."
    .paket/paket auto-restore on
    echo "Auto-restore enabled!"
}

# Simplify dependencies
simplify() {
    echo "Simplifying dependencies..."
    .paket/paket simplify
    echo "Dependencies simplified!"
}

# Show help
show_help() {
    echo "Available commands:"
    echo "  init_paket              - Initialize Paket in current directory"
    echo "  install_deps            - Install all dependencies"
    echo "  update_deps             - Update all dependencies"
    echo "  add_package <name>      - Add a new package"
    echo "  remove_package <name>   - Remove a package"
    echo "  show_outdated           - Show outdated packages"
    echo "  show_deps               - Show dependency tree"
    echo "  restore                 - Restore packages"
    echo "  generate_includes       - Generate include scripts"
    echo "  find_package <term>     - Search for packages"
    echo "  validate                - Validate Paket files"
    echo "  clean_cache             - Clean Paket cache"
    echo "  pack_nuget              - Pack for NuGet"
    echo "  push_nuget <api-key>    - Push to NuGet"
    echo "  convert_from_nuget      - Convert from packages.config"
    echo "  setup_auto_restore      - Enable auto-restore"
    echo "  simplify                - Simplify dependencies"
    echo "  show_help               - Show this help"
}

# Main command dispatcher
case "$1" in
    "init") init_paket ;;
    "install") install_deps ;;
    "update") update_deps ;;
    "add") add_package "$2" "$3" "$4" ;;
    "remove") remove_package "$2" "$3" ;;
    "outdated") show_outdated ;;
    "deps") show_deps ;;
    "restore") restore ;;
    "includes") generate_includes ;;
    "find") find_package "$2" ;;
    "validate") validate ;;
    "clean") clean_cache ;;
    "pack") pack_nuget ;;
    "push") push_nuget "$2" ;;
    "convert") convert_from_nuget ;;
    "auto-restore") setup_auto_restore ;;
    "simplify") simplify ;;
    "help"|"") show_help ;;
    *) echo "Unknown command: $1"; show_help ;;
esac`,

    'README.md': `# F# Paket Dependency Manager

A modern dependency manager for F# and .NET projects providing precise dependency resolution, reproducible builds, and powerful package management capabilities.

## Features

- **Precise Dependency Resolution**: Deterministic dependency resolution with conflict detection
- **Reproducible Builds**: Lock files ensure consistent builds across environments
- **Group-Based Dependencies**: Organize dependencies into logical groups
- **Multiple Sources**: Support for NuGet, Git, GitHub, and HTTP sources
- **Framework Restrictions**: Target specific .NET frameworks
- **Transitive Control**: Fine-grained control over transitive dependencies
- **Source Code Dependencies**: Include source files directly from repositories
- **Integration**: Seamless MSBuild and .NET CLI integration

## Quick Start

### Prerequisites

- .NET 6.0 SDK or later
- F# development tools

### Installation

\`\`\`bash
# Install Paket as a local tool
dotnet tool install paket --tool-path .paket

# Initialize Paket in your project
.paket/paket init

# Install dependencies
.paket/paket install
\`\`\`

### Basic Usage

\`\`\`bash
# Add a package
.paket/paket add nuget Newtonsoft.Json

# Update dependencies
.paket/paket update

# Restore packages
.paket/paket restore
\`\`\`

## Project Structure

\`\`\`
├── .paket/
│   ├── paket.bootstrapper.exe     # Paket bootstrapper
│   └── paket.targets              # MSBuild targets
├── src/
│   ├── Library.fs                 # Main library code
│   └── MyFSharpProject.fsproj     # Project file
├── tests/
│   ├── Tests.fs                   # Unit tests
│   ├── Program.fs                 # Test runner
│   └── Tests.fsproj               # Test project file
├── scripts/
│   └── paket-commands.sh          # Helper scripts
├── paket.dependencies             # Dependency specification
├── paket.lock                     # Lock file (auto-generated)
├── paket.local                    # Local overrides
├── paket.template                 # NuGet package template
└── build.fsx                      # Build script
\`\`\`

## Configuration Files

### paket.dependencies

Main dependency specification file:

\`\`\`
// Framework restrictions
framework: net6.0, netstandard2.0

// Main NuGet source
source https://api.nuget.org/v3/index.json

// Dependencies
nuget FSharp.Core >= 6.0.0
nuget Newtonsoft.Json >= 13.0.0

// Group-based dependencies
group Test
    source https://api.nuget.org/v3/index.json
    framework: net6.0
    
    nuget Expecto >= 10.0.0
    nuget FsCheck >= 2.16.0

// Git dependencies
git https://github.com/fsprojects/FSharp.Data.git master src/FSharp.Data/

// HTTP dependencies
http https://raw.githubusercontent.com/fsprojects/Paket/master/src/Paket.Core/AssemblyInfo.fs src/AssemblyInfo.fs
\`\`\`

### paket.lock

Auto-generated lock file ensuring reproducible builds:

\`\`\`
RESTRICTION: >= net6.0
NUGET
  remote: https://api.nuget.org/v3/index.json
    FSharp.Core (6.0.7)
    Newtonsoft.Json (13.0.3)

GROUP Test
RESTRICTION: >= net6.0
NUGET
  remote: https://api.nuget.org/v3/index.json
    Expecto (10.2.1)
    FsCheck (2.16.5)
\`\`\`

## Dependency Groups

Organize dependencies into logical groups:

\`\`\`
// Main dependencies
nuget FSharp.Core
nuget Microsoft.AspNetCore.App

// Web development group
group Web
    nuget Giraffe
    nuget Saturn
    nuget Suave

// Testing group
group Test
    nuget Expecto
    nuget FsCheck
    nuget NUnit

// Build tools group
group Build
    nuget FAKE.Core.Target
    nuget FAKE.DotNet.Cli
\`\`\`

## Advanced Features

### Framework Restrictions

Target specific .NET frameworks:

\`\`\`
framework: net6.0, netstandard2.0, netframework461

// Per-group restrictions
group Web
    framework: net6.0
    nuget Giraffe
\`\`\`

### Version Constraints

Specify version requirements:

\`\`\`
nuget FSharp.Core >= 6.0.0         // Minimum version
nuget Newtonsoft.Json ~> 13.0      // Compatible version
nuget Microsoft.AspNetCore.App == 6.0.22  // Exact version
nuget SomePackage >= 1.0 < 2.0      // Version range
\`\`\`

### Source Code Dependencies

Include source files directly:

\`\`\`
// GitHub files
github fsprojects/FSharpx.Collections src/FSharpx.Collections/Collections.fs

// Git repositories
git https://github.com/fsprojects/FSharp.Data.git master src/FSharp.Data/

// HTTP files
http https://raw.githubusercontent.com/fsprojects/Paket/master/src/Paket.Core/AssemblyInfo.fs src/AssemblyInfo.fs
\`\`\`

### Local Development

Use \`paket.local\` for local overrides:

\`\`\`
// Override versions
nuget FSharp.Core 6.0.7

// Add local sources
source C:\\Local\\MyPackages

// Use local git repositories
git file:///c:/dev/MyLibrary main src/MyLibrary/
\`\`\`

## Commands

### Package Management

\`\`\`bash
# Add packages
.paket/paket add nuget FSharp.Core
.paket/paket add nuget Expecto --group Test

# Remove packages
.paket/paket remove nuget Expecto --group Test

# Update packages
.paket/paket update
.paket/paket update nuget FSharp.Core

# Install packages
.paket/paket install
\`\`\`

### Information Commands

\`\`\`bash
# Show outdated packages
.paket/paket outdated

# Show installed packages
.paket/paket show-installed-packages

# Show dependency groups
.paket/paket show-groups

# Find packages
.paket/paket find-packages --search-term "json"
\`\`\`

### Project Commands

\`\`\`bash
# Initialize Paket
.paket/paket init

# Convert from packages.config
.paket/paket convert-from-nuget

# Simplify dependencies
.paket/paket simplify

# Auto-restore setup
.paket/paket auto-restore on
\`\`\`

### Validation and Cleanup

\`\`\`bash
# Validate dependencies
.paket/paket check

# Clear cache
.paket/paket clear-cache

# Generate include scripts
.paket/paket generate-include-scripts
\`\`\`

## NuGet Package Creation

### paket.template

Define package metadata:

\`\`\`
type project
id MyFSharpProject
version 1.0.0
authors Your Name
description A comprehensive F# project
tags fsharp, paket, template
licenseUrl https://github.com/yourname/yourproject/blob/master/LICENSE
projectUrl https://github.com/yourname/yourproject
files
    bin/Release/net6.0/MyFSharpProject.dll ==> lib/net6.0
dependencies
    FSharp.Core >= LOCKEDVERSION
\`\`\`

### Creating Packages

\`\`\`bash
# Pack packages
.paket/paket pack ./nuget

# Push to NuGet
.paket/paket push --api-key YOUR_API_KEY ./nuget
\`\`\`

## Integration with Build Tools

### FAKE Integration

\`\`\`fsharp
#r "paket: groupref Build //"
open Fake.DotNet

Target.create "RestorePackages" (fun _ ->
    Paket.restore (fun p ->
        { p with ToolType = ToolType.CreateLocalTool() }
    )
)

Target.create "UpdatePackages" (fun _ ->
    Paket.update (fun p ->
        { p with ToolType = ToolType.CreateLocalTool() }
    )
)
\`\`\`

### MSBuild Integration

Projects automatically reference \`paket.targets\`:

\`\`\`xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
  <Import Project="..\\paket.targets" />
</Project>
\`\`\`

## CI/CD Integration

### GitHub Actions

\`\`\`yaml
name: Build and Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup .NET
      uses: actions/setup-dotnet@v1
      with:
        dotnet-version: 6.0.x
    - name: Restore Paket
      run: .paket/paket restore
    - name: Build
      run: dotnet build
    - name: Test
      run: dotnet test
\`\`\`

### Docker

\`\`\`dockerfile
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY paket.dependencies paket.lock ./
COPY .paket .paket/
RUN .paket/paket restore
COPY . .
RUN dotnet build -c Release
\`\`\`

## Best Practices

### Dependency Management

1. **Use Lock Files**: Always commit \`paket.lock\` for reproducible builds
2. **Group Dependencies**: Organize dependencies into logical groups
3. **Specify Constraints**: Use appropriate version constraints
4. **Regular Updates**: Keep dependencies up to date
5. **Local Overrides**: Use \`paket.local\` for development

### Performance

1. **Parallel Restore**: Use \`--parallel\` for faster operations
2. **Cache Management**: Clear cache when experiencing issues
3. **Selective Updates**: Update specific packages when needed
4. **Framework Targeting**: Use framework restrictions to reduce conflicts

### Security

1. **Source Verification**: Use trusted package sources
2. **Version Pinning**: Pin sensitive dependencies to specific versions
3. **Audit Dependencies**: Regular security audits
4. **Local Sources**: Validate local package sources

## Troubleshooting

### Common Issues

\`\`\`bash
# Clear cache and reinstall
.paket/paket clear-cache
.paket/paket install

# Force update
.paket/paket update --force

# Validate configuration
.paket/paket check

# Regenerate lock file
rm paket.lock
.paket/paket install
\`\`\`

### Conflict Resolution

1. **Version Conflicts**: Use version overrides in \`paket.dependencies\`
2. **Framework Issues**: Adjust framework restrictions
3. **Source Problems**: Verify source URLs and credentials
4. **Dependency Loops**: Use \`simplify\` to reduce complexity

## Migration

### From NuGet

\`\`\`bash
# Convert existing projects
.paket/paket convert-from-nuget

# Manual cleanup
rm packages.config
rm -rf packages/
\`\`\`

### From Other Tools

1. **NPM/Yarn**: Map dependencies manually
2. **pip/conda**: Use .NET equivalents where available
3. **Maven/Gradle**: Convert Java libraries to .NET equivalents

## Learning Resources

- [Paket Documentation](https://fsprojects.github.io/Paket/)
- [F# Dependency Management](https://fsharp.org/guides/package-management/)
- [.NET Package Management](https://docs.microsoft.com/en-us/nuget/)
- [Paket vs NuGet](https://fsprojects.github.io/Paket/paket-vs-nuget.html)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Update documentation
5. Submit a pull request

## License

This project is licensed under the MIT License.`
  }
};