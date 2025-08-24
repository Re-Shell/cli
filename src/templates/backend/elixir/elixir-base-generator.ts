import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export abstract class ElixirBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor() {
    super({
      language: 'Elixir',
      framework: 'Elixir Framework',
      packageManager: 'mix',
      buildTool: 'mix',
      testFramework: 'ExUnit',
      features: [
        'OTP Application with Supervision Trees',
        'Fault tolerance with supervisor hierarchies',
        'GenServer for stateful processes',
        'Actor model with lightweight processes',
        'Let it crash philosophy',
        'ExUnit testing framework',
        'Custom Mix tasks',
        'ExDoc documentation generation',
        'Hot code reloading',
        'Docker support with multi-stage builds',
        'Telemetry and monitoring',
        'Credo code quality analysis',
        'Dialyzer type checking'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'start': 'mix run --no-halt',
        'dev': 'iex -S mix',
        'test': 'mix test',
        'format': 'mix format',
        'lint': 'mix credo --strict',
        'docs': 'mix docs',
        'compile': 'mix compile',
        'release': 'mix release',
        'dialyzer': 'mix dialyzer'
      }
    });
  }

  protected abstract getFrameworkDependencies(): any[];
  protected abstract generateMainApplicationFile(): string;
  protected abstract generateSupervisorFile(): string;
  protected abstract generateGenServerFiles(): { path: string; content: string }[];
  protected abstract generateRouterFile(): string;
  protected abstract generateControllerFiles(): { path: string; content: string }[];
  protected abstract generateServiceFiles(): { path: string; content: string }[];
  protected abstract generateConfigFiles(): { path: string; content: string }[];
  protected abstract generateTestFiles(): { path: string; content: string }[];

  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate mix.exs (Elixir project file)
    await fs.writeFile(
      path.join(projectPath, 'mix.exs'),
      this.generateMixFile(options)
    );

    // Generate formatter configuration
    await fs.writeFile(
      path.join(projectPath, '.formatter.exs'),
      this.generateFormatterConfig()
    );

    // Generate .tool-versions for asdf
    await fs.writeFile(
      path.join(projectPath, '.tool-versions'),
      'elixir 1.15.7\nerlang 26.1.2\n'
    );

    // Generate lib directory structure
    const appName = this.getAppName(options);
    await fs.mkdir(path.join(projectPath, 'lib', appName), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'application'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'supervisors'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'workers'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'services'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'models'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'utils'), { recursive: true });

    // Generate the main application file
    await fs.writeFile(
      path.join(projectPath, 'lib', `${appName}.ex`),
      this.generateMainModule(options)
    );

    // Generate application.ex
    await fs.writeFile(
      path.join(projectPath, 'lib', appName, 'application.ex'),
      this.generateApplicationFile(options)
    );

    // Generate mix tasks directory
    await fs.mkdir(path.join(projectPath, 'lib', 'mix', 'tasks'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'lib', 'mix', 'tasks', `${appName}.seed.ex`),
      this.generateSeedTask(options)
    );

    // Generate development scripts
    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'scripts', 'setup.sh'),
      this.generateSetupScript()
    );
    await fs.writeFile(
      path.join(projectPath, 'scripts', 'release.sh'),
      this.generateReleaseScript()
    );

    // Make scripts executable
    await fs.chmod(path.join(projectPath, 'scripts', 'setup.sh'), 0o755);
    await fs.chmod(path.join(projectPath, 'scripts', 'release.sh'), 0o755);

    // Generate environment files
    await fs.writeFile(
      path.join(projectPath, '.env'),
      this.generateEnvFile(options)
    );
    await fs.writeFile(
      path.join(projectPath, '.env.example'),
      this.generateEnvExample(options)
    );

    // Generate credo configuration
    await fs.writeFile(
      path.join(projectPath, '.credo.exs'),
      this.generateCredoConfig()
    );

    // Generate dialyzer ignore file
    await fs.writeFile(
      path.join(projectPath, '.dialyzer_ignore.exs'),
      '[\n  # Add dialyzer warnings to ignore here\n]\n'
    );
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const appName = this.getAppName(options);

    // Generate supervisor files
    await fs.writeFile(
      path.join(projectPath, 'lib', appName, 'supervisors', 'main_supervisor.ex'),
      this.generateMainSupervisor(options)
    );

    // Generate GenServer examples
    const genServerFiles = this.generateGenServerExamples(options);
    for (const file of genServerFiles) {
      const fullPath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }

    // Generate sample workers demonstrating actor model
    await fs.writeFile(
      path.join(projectPath, 'lib', appName, 'workers', 'task_worker.ex'),
      this.generateTaskWorker(options)
    );

    await fs.writeFile(
      path.join(projectPath, 'lib', appName, 'workers', 'async_processor.ex'),
      this.generateAsyncProcessor(options)
    );

    // Generate Registry example
    await fs.writeFile(
      path.join(projectPath, 'lib', appName, 'services', 'process_registry.ex'),
      this.generateProcessRegistry(options)
    );

    // Generate error handling examples
    await fs.writeFile(
      path.join(projectPath, 'lib', appName, 'utils', 'error_handler.ex'),
      this.generateErrorHandler(options)
    );

    // Generate Telemetry module
    await fs.writeFile(
      path.join(projectPath, 'lib', appName, 'telemetry.ex'),
      this.generateTelemetryModule(options)
    );

    // Generate service files
    const serviceFiles = this.generateServiceFiles();
    for (const file of serviceFiles) {
      const fullPath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }

    // Generate config files
    const configFiles = this.generateConfigFiles();
    for (const file of configFiles) {
      const fullPath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    const appName = this.getAppName(options);

    // Create test directories
    await fs.mkdir(path.join(projectPath, 'test', appName), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'test', 'support'), { recursive: true });

    // Generate test helper
    await fs.writeFile(
      path.join(projectPath, 'test', 'test_helper.exs'),
      'ExUnit.start()\n'
    );

    // Generate test files
    const testFiles = this.generateTestFiles();
    for (const file of testFiles) {
      const fullPath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }

    // Create test directory structure
    await fs.mkdir(path.join(projectPath, 'test', appName), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'test', appName, 'workers'), { recursive: true });

    // Generate example test for main module
    await fs.writeFile(
      path.join(projectPath, 'test', appName, `${appName}_test.exs`),
      this.generateMainModuleTest(options)
    );

    // Generate GenServer test example
    await fs.writeFile(
      path.join(projectPath, 'test', appName, 'workers', 'counter_server_test.exs'),
      this.generateGenServerTest(options)
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check will be implemented in the web framework layer
    // For base Elixir, we'll include telemetry
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocs = `# API Documentation

## Overview
This Elixir application demonstrates OTP principles and best practices.

## Architecture

### Supervision Tree
- MainSupervisor: Root supervisor
  - ProcessRegistry: Named process registry
  - CounterServer: Example GenServer
  - TaskWorker: Async task processor
  - AsyncProcessor: Parallel processing example

### Key Patterns
- Let it crash philosophy
- Process isolation
- Fault tolerance through supervision
- Hot code reloading

## API Endpoints
API endpoints will be defined by the specific web framework (Phoenix, Plug, etc.)

## Mix Tasks
- \`mix ${this.options?.name || 'app'}.seed\` - Seed initial data
- \`mix docs\` - Generate documentation
- \`mix test\` - Run tests
- \`mix format\` - Format code
- \`mix credo\` - Run static analysis
- \`mix dialyzer\` - Run type checking
`;

    await fs.writeFile(path.join(projectPath, 'docs/api.md'), apiDocs);
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    // Generate Dockerfile with multi-stage build
    await fs.writeFile(
      path.join(projectPath, 'Dockerfile'),
      this.generateDockerfile(options)
    );

    // Generate docker-compose.yml
    await fs.writeFile(
      path.join(projectPath, 'docker-compose.yml'),
      this.generateDockerCompose(options)
    );

    // Generate .dockerignore
    await fs.writeFile(
      path.join(projectPath, '.dockerignore'),
      this.generateDockerIgnore()
    );
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // Generate architecture documentation
    const architectureDocs = this.generateArchitectureDocs(options);
    await fs.writeFile(path.join(projectPath, 'docs/architecture.md'), architectureDocs);

    // Generate OTP principles guide
    const otpGuide = this.generateOTPGuide();
    await fs.writeFile(path.join(projectPath, 'docs/otp-guide.md'), otpGuide);

    // Generate deployment guide
    const deploymentGuide = this.generateDeploymentGuide(options);
    await fs.writeFile(path.join(projectPath, 'docs/deployment.md'), deploymentGuide);
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '# Elixir',
      '/_build/',
      '/cover/',
      '/deps/',
      '/doc/',
      '/.fetch',
      'erl_crash.dump',
      '*.ez',
      '*.beam',
      '/config/*.secret.exs',
      '.elixir_ls/',
      '',
      '# Mix artifacts',
      '*.tar',
      '/tmp/',
      '',
      '# Dialyzer',
      '/priv/plts/*.plt',
      '/priv/plts/*.plt.hash',
      '',
      '# Releases',
      '/rel/',
      '_build/',
      '',
      '# Test coverage',
      '/cover/',
      '/coverage/',
    ];
  }

  protected getLanguagePrerequisites(): string {
    return `- Elixir 1.15+
- Erlang/OTP 26+
- PostgreSQL 15+ (optional)
- Redis 7+ (optional)`;
  }

  protected getInstallCommand(): string {
    return 'mix deps.get';
  }

  protected getDevCommand(): string {
    return 'iex -S mix';
  }

  protected getProdCommand(): string {
    return 'mix run --no-halt';
  }

  protected getTestCommand(): string {
    return 'mix test';
  }

  protected getCoverageCommand(): string {
    return 'mix test --cover';
  }

  protected getLintCommand(): string {
    return 'mix credo --strict';
  }

  protected getBuildCommand(): string {
    return 'mix release';
  }

  protected getSetupAction(): string {
    return 'uses: erlef/setup-beam@v1\n      with:\n        elixir-version: "1.15.7"\n        otp-version: "26.1.2"';
  }

  // Helper methods specific to Elixir

  protected getAppName(options: any): string {
    return (options.name || 'elixir_app').replace(/-/g, '_');
  }

  protected generateMixFile(options: any): string {
    const appName = this.getAppName(options);
    const deps = this.getFrameworkDependencies();
    
    const depsString = deps.map(dep => {
      if (typeof dep === 'object' && dep.name) {
        let depStr = `{:${dep.name}, "${dep.version}"`;
        if (dep.only) {
          const only = Array.isArray(dep.only) ? dep.only : [dep.only];
          depStr += `, only: ${only.length === 1 ? `:${only[0]}` : `[${only.map(o => `:${o}`).join(', ')}]`}`;
        }
        if (dep.runtime === false) {
          depStr += `, runtime: false`;
        }
        if (dep.github) {
          depStr = `{:${dep.name}, github: "${dep.github}"`;
          if (dep.version) {
            depStr += `, branch: "${dep.version}"`;
          }
        }
        depStr += `}`;
        return `      ${depStr}`;
      }
      return '';
    }).filter(Boolean).join(',\n');

    return `defmodule ${this.toPascalCase(appName)}.MixProject do
  use Mix.Project

  def project do
    [
      app: :${appName},
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
        ignore_warnings: ".dialyzer_ignore.exs"
      ],
      docs: [
        main: "${this.toPascalCase(appName)}",
        extras: ["README.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {${this.toPascalCase(appName)}.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
${depsString}
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Aliases are shortcuts or tasks specific to the current project.
  defp aliases do
    [
      setup: ["deps.get", "deps.compile"],
      test: ["test"],
      "test.watch": ["test.watch"],
      quality: ["format", "credo --strict", "dialyzer"],
      "quality.ci": ["format --check-formatted", "credo --strict", "dialyzer"]
    ]
  end
end
`;
  }

  protected generateFormatterConfig(): string {
    return `[
  import_deps: [:plug, :phoenix],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  line_length: 120
]
`;
  }

  protected generateMainModule(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName} do
  @moduledoc """
  ${moduleName} is the main module for the ${options.name || 'Elixir'} application.
  
  This module serves as the entry point and provides core functionality
  demonstrating Elixir's OTP principles and best practices.
  """

  @doc """
  Hello world function demonstrating pattern matching and pipe operator.
  
  ## Examples
  
      iex> ${moduleName}.hello("World")
      "Hello, World!"
      
      iex> ${moduleName}.hello()
      "Hello, Anonymous!"
  """
  def hello(name \\\\ "Anonymous") do
    name
    |> String.trim()
    |> greeting()
  end

  @doc """
  Demonstrates pattern matching with multiple function clauses.
  """
  def process_data({:ok, data}) do
    {:success, transform_data(data)}
  end

  def process_data({:error, reason}) do
    {:failure, "Error: #{reason}"}
  end

  def process_data(_) do
    {:failure, "Invalid data format"}
  end

  @doc """
  Example of using the pipe operator for data transformation.
  """
  def transform_pipeline(data) do
    data
    |> validate()
    |> normalize()
    |> enrich()
    |> format_output()
  end

  # Private functions

  defp greeting(name) do
    "Hello, #{name}!"
  end

  defp transform_data(data) do
    Map.put(data, :processed_at, DateTime.utc_now())
  end

  defp validate(data) do
    case data do
      nil -> {:error, :invalid_data}
      "" -> {:error, :empty_data}
      _ -> {:ok, data}
    end
  end

  defp normalize({:ok, data}) do
    {:ok, String.downcase(data)}
  end

  defp normalize(error), do: error

  defp enrich({:ok, data}) do
    {:ok, %{
      data: data,
      timestamp: DateTime.utc_now(),
      version: "1.0.0"
    }}
  end

  defp enrich(error), do: error

  defp format_output({:ok, result}) do
    {:ok, Jason.encode!(result)}
  end

  defp format_output({:error, reason}) do
    {:error, "Processing failed: #{reason}"}
  end
end
`;
  }

  protected generateApplicationFile(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Application do
  @moduledoc """
  The OTP Application module for ${moduleName}.
  
  This module defines the supervision tree and starts all necessary processes
  when the application boots.
  """
  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    Logger.info("Starting ${moduleName} application...")

    # List all child processes to be supervised
    children = [
      # Process Registry
      {Registry, keys: :unique, name: ${moduleName}.Registry},
      
      # Main Supervisor
      ${moduleName}.Supervisors.MainSupervisor,
      
      # Task Supervisor for async operations
      {Task.Supervisor, name: ${moduleName}.TaskSupervisor},
      
      # Dynamic Supervisor for runtime process spawning
      {DynamicSupervisor, name: ${moduleName}.DynamicSupervisor, strategy: :one_for_one}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ${moduleName}.Supervisor]
    
    case Supervisor.start_link(children, opts) do
      {:ok, pid} ->
        Logger.info("${moduleName} application started successfully")
        {:ok, pid}
      
      {:error, reason} ->
        Logger.error("Failed to start ${moduleName} application: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @impl true
  def stop(_state) do
    Logger.info("Stopping ${moduleName} application...")
    :ok
  end
end
`;
  }

  protected generateMainSupervisor(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Supervisors.MainSupervisor do
  @moduledoc """
  Main supervisor demonstrating OTP supervision tree patterns.
  
  This supervisor manages core application processes with different
  restart strategies based on process criticality.
  """
  use Supervisor
  require Logger

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    Logger.info("Starting MainSupervisor...")

    children = [
      # Permanent workers - always restart
      {${moduleName}.Workers.CounterServer, []},
      
      # Transient workers - restart only on abnormal termination
      %{
        id: ${moduleName}.Workers.TaskWorker,
        start: {${moduleName}.Workers.TaskWorker, :start_link, [[]]},
        restart: :transient
      },
      
      # Temporary workers - never restart
      %{
        id: ${moduleName}.Workers.AsyncProcessor,
        start: {${moduleName}.Workers.AsyncProcessor, :start_link, [[]]},
        restart: :temporary
      }
    ]

    # :one_for_one - If a child process terminates, only that process is restarted
    # :one_for_all - If any child process terminates, all are terminated and restarted
    # :rest_for_one - If a child process terminates, it and any child processes started after it are terminated and restarted
    Supervisor.init(children, strategy: :one_for_one)
  end
end
`;
  }

  protected generateTaskWorker(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Workers.TaskWorker do
  @moduledoc """
  Example of a worker that processes tasks asynchronously using the Actor model.
  
  Demonstrates:
  - Lightweight process creation
  - Message passing
  - Process linking and monitoring
  """
  use GenServer
  require Logger

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process a task asynchronously.
  """
  def process_async(task, callback_pid \\\\ self()) do
    GenServer.cast(__MODULE__, {:process, task, callback_pid})
  end

  @doc """
  Process multiple tasks in parallel.
  """
  def process_batch(tasks) do
    tasks
    |> Enum.map(&Task.async(fn -> process_task(&1) end))
    |> Enum.map(&Task.await(&1, 5000))
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("TaskWorker started")
    {:ok, %{active_tasks: %{}}}
  end

  @impl true
  def handle_cast({:process, task, callback_pid}, state) do
    # Spawn a monitored process for the task
    task_ref = make_ref()
    
    {:ok, pid} = Task.Supervisor.start_child(
      ${moduleName}.TaskSupervisor,
      fn -> 
        result = process_task(task)
        send(callback_pid, {:task_completed, task_ref, result})
      end
    )
    
    new_state = put_in(state.active_tasks[task_ref], {pid, task, callback_pid})
    {:noreply, new_state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    # Handle crashed task processes
    case find_task_by_pid(state.active_tasks, pid) do
      {task_ref, {_pid, task, callback_pid}} ->
        Logger.error("Task process #{inspect(pid)} crashed: #{inspect(reason)}")
        send(callback_pid, {:task_failed, task_ref, reason})
        new_state = %{state | active_tasks: Map.delete(state.active_tasks, task_ref)}
        {:noreply, new_state}
      
      nil ->
        {:noreply, state}
    end
  end

  # Private functions

  defp process_task(task) do
    Logger.info("Processing task: #{inspect(task)}")
    
    # Simulate task processing
    Process.sleep(Enum.random(100..1000))
    
    # Demonstrate error handling
    case Enum.random(1..10) do
      1 -> raise "Simulated task failure"
      _ -> {:ok, "Task #{inspect(task)} completed"}
    end
  end

  defp find_task_by_pid(active_tasks, pid) do
    Enum.find(active_tasks, fn {_ref, {task_pid, _task, _callback}} ->
      task_pid == pid
    end)
  end
end
`;
  }

  protected generateAsyncProcessor(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Workers.AsyncProcessor do
  @moduledoc """
  Demonstrates concurrent processing using Elixir's lightweight processes.
  
  Shows how to:
  - Spawn thousands of processes efficiently
  - Use message passing for coordination
  - Implement scatter-gather patterns
  """
  use GenServer
  require Logger

  @process_timeout 5000

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process items concurrently with a specified concurrency limit.
  """
  def process_concurrent(items, processor_fn, max_concurrency \\\\ 10) do
    GenServer.call(__MODULE__, {:process_concurrent, items, processor_fn, max_concurrency}, 30_000)
  end

  @doc """
  Map-reduce operation across multiple processes.
  """
  def map_reduce(items, map_fn, reduce_fn, initial_acc) do
    GenServer.call(__MODULE__, {:map_reduce, items, map_fn, reduce_fn, initial_acc}, 30_000)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    {:ok, %{}}
  end

  @impl true
  def handle_call({:process_concurrent, items, processor_fn, max_concurrency}, _from, state) do
    results = 
      items
      |> Task.async_stream(
        processor_fn,
        max_concurrency: max_concurrency,
        timeout: @process_timeout,
        on_timeout: :kill_task
      )
      |> Enum.map(fn
        {:ok, result} -> {:ok, result}
        {:exit, reason} -> {:error, reason}
      end)
    
    {:reply, results, state}
  end

  @impl true
  def handle_call({:map_reduce, items, map_fn, reduce_fn, initial_acc}, _from, state) do
    # Spawn a process for each item
    parent = self()
    ref = make_ref()
    
    items
    |> Enum.each(fn item ->
      spawn_link(fn ->
        result = map_fn.(item)
        send(parent, {ref, result})
      end)
    end)
    
    # Collect results
    results = collect_results(ref, length(items), [])
    
    # Reduce
    final_result = Enum.reduce(results, initial_acc, reduce_fn)
    
    {:reply, {:ok, final_result}, state}
  end

  # Private functions

  defp collect_results(_ref, 0, acc), do: acc
  
  defp collect_results(ref, count, acc) do
    receive do
      {^ref, result} ->
        collect_results(ref, count - 1, [result | acc])
    after
      @process_timeout ->
        Logger.error("Timeout collecting results. Missing #{count} results.")
        acc
    end
  end
end
`;
  }

  protected generateProcessRegistry(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Services.ProcessRegistry do
  @moduledoc """
  Process registry service demonstrating named process management.
  
  Uses Registry for process discovery and provides helper functions
  for process registration and lookup.
  """

  @registry ${moduleName}.Registry

  @doc """
  Register a process with a given name.
  """
  def register(name, pid \\\\ self()) do
    case Registry.register(@registry, name, pid) do
      {:ok, _owner} -> :ok
      {:error, {:already_registered, _pid}} -> {:error, :already_registered}
    end
  end

  @doc """
  Unregister a process.
  """
  def unregister(name) do
    Registry.unregister(@registry, name)
  end

  @doc """
  Look up a process by name.
  """
  def whereis(name) do
    case Registry.lookup(@registry, name) do
      [{pid, _value}] -> {:ok, pid}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Send a message to a named process.
  """
  def send(name, message) do
    case whereis(name) do
      {:ok, pid} -> 
        Kernel.send(pid, message)
        :ok
      {:error, :not_found} -> 
        {:error, :process_not_found}
    end
  end

  @doc """
  Call a named process (synchronous).
  """
  def call(name, request, timeout \\\\ 5000) do
    case whereis(name) do
      {:ok, pid} ->
        try do
          GenServer.call(pid, request, timeout)
        catch
          :exit, reason -> {:error, {:exit, reason}}
        end
      {:error, :not_found} ->
        {:error, :process_not_found}
    end
  end

  @doc """
  Cast to a named process (asynchronous).
  """
  def cast(name, request) do
    case whereis(name) do
      {:ok, pid} ->
        GenServer.cast(pid, request)
        :ok
      {:error, :not_found} ->
        {:error, :process_not_found}
    end
  end

  @doc """
  List all registered processes.
  """
  def list_registered() do
    Registry.select(@registry, [{{:"$1", :"$2", :"$3"}, [], [{{:"$1", :"$3"}}]}])
  end

  @doc """
  Monitor a named process.
  """
  def monitor(name) do
    case whereis(name) do
      {:ok, pid} ->
        ref = Process.monitor(pid)
        {:ok, ref}
      {:error, :not_found} ->
        {:error, :process_not_found}
    end
  end
end
`;
  }

  protected generateErrorHandler(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Utils.ErrorHandler do
  @moduledoc """
  Error handling utilities demonstrating Elixir's "let it crash" philosophy
  and proper error handling patterns.
  """
  require Logger

  @doc """
  Execute a function with error handling and retry logic.
  
  ## Options
  - :retries - Number of retry attempts (default: 3)
  - :delay - Delay between retries in milliseconds (default: 1000)
  - :backoff - Backoff multiplier for delays (default: 2)
  """
  def with_retry(fun, opts \\\\ []) do
    retries = Keyword.get(opts, :retries, 3)
    delay = Keyword.get(opts, :delay, 1000)
    backoff = Keyword.get(opts, :backoff, 2)
    
    do_with_retry(fun, retries, delay, backoff)
  end

  @doc """
  Pattern matching for error handling with custom error types.
  """
  def handle_result({:ok, value}), do: {:ok, value}
  
  def handle_result({:error, :not_found}) do
    Logger.warn("Resource not found")
    {:error, %{type: :not_found, message: "The requested resource was not found"}}
  end
  
  def handle_result({:error, :unauthorized}) do
    Logger.warn("Unauthorized access attempt")
    {:error, %{type: :unauthorized, message: "You are not authorized to perform this action"}}
  end
  
  def handle_result({:error, {:validation, errors}}) do
    Logger.warn("Validation failed: #{inspect(errors)}")
    {:error, %{type: :validation_failed, errors: errors}}
  end
  
  def handle_result({:error, reason}) do
    Logger.error("Unhandled error: #{inspect(reason)}")
    {:error, %{type: :internal_error, message: "An unexpected error occurred"}}
  end

  @doc """
  Safe execution with crash protection.
  """
  def safe_execute(fun) do
    try do
      {:ok, fun.()}
    rescue
      e in RuntimeError ->
        Logger.error("Runtime error: #{e.message}")
        {:error, {:runtime_error, e.message}}
      
      e in ArgumentError ->
        Logger.error("Argument error: #{e.message}")
        {:error, {:argument_error, e.message}}
      
      e ->
        Logger.error("Unexpected error: #{inspect(e)}")
        {:error, {:unexpected_error, inspect(e)}}
    catch
      :exit, reason ->
        Logger.error("Process exited: #{inspect(reason)}")
        {:error, {:exit, reason}}
      
      kind, reason ->
        Logger.error("Caught #{kind}: #{inspect(reason)}")
        {:error, {kind, reason}}
    end
  end

  @doc """
  Pipeline with error handling using the 'with' construct.
  """
  def pipeline_with_errors(data) do
    with {:ok, validated} <- validate(data),
         {:ok, processed} <- process(validated),
         {:ok, stored} <- store(processed) do
      {:ok, stored}
    else
      {:error, :validation_failed} = error ->
        Logger.error("Validation failed in pipeline")
        error
      
      {:error, :processing_failed} = error ->
        Logger.error("Processing failed in pipeline")
        error
      
      {:error, reason} = error ->
        Logger.error("Pipeline failed: #{inspect(reason)}")
        error
    end
  end

  # Private functions

  defp do_with_retry(fun, 0, _delay, _backoff) do
    Logger.error("All retry attempts exhausted")
    {:error, :max_retries_exceeded}
  end
  
  defp do_with_retry(fun, retries, delay, backoff) do
    case safe_execute(fun) do
      {:ok, result} ->
        {:ok, result}
      
      {:error, reason} ->
        Logger.warn("Attempt failed: #{inspect(reason)}. Retries left: #{retries - 1}")
        Process.sleep(delay)
        do_with_retry(fun, retries - 1, delay * backoff, backoff)
    end
  end

  defp validate(data) when is_map(data), do: {:ok, data}
  defp validate(_), do: {:error, :validation_failed}

  defp process(data) do
    # Simulate processing
    {:ok, Map.put(data, :processed, true)}
  end

  defp store(data) do
    # Simulate storage
    {:ok, Map.put(data, :id, System.unique_integer([:positive]))}
  end
end
`;
  }

  protected generateSeedTask(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule Mix.Tasks.${moduleName}.Seed do
  @moduledoc """
  Seeds the application with initial data.
  
  Usage:
      mix ${appName}.seed
      mix ${appName}.seed --env production
  """
  use Mix.Task
  require Logger

  @shortdoc "Seeds the application with initial data"

  @impl Mix.Task
  def run(args) do
    Logger.info("Starting seed task...")
    
    # Parse arguments
    {opts, _, _} = OptionParser.parse(args, switches: [env: :string])
    env = Keyword.get(opts, :env, "dev")
    
    Logger.info("Seeding for environment: #{env}")
    
    # Start the application
    Mix.Task.run("app.start")
    
    # Run seeds
    case seed_data(env) do
      :ok ->
        Logger.info("Seeding completed successfully!")
      {:error, reason} ->
        Logger.error("Seeding failed: #{inspect(reason)}")
        exit({:shutdown, 1})
    end
  end

  defp seed_data("dev") do
    Logger.info("Seeding development data...")
    
    # Add development-specific seed data here
    # Example:
    # - Create test users
    # - Generate sample data
    # - Configure development settings
    
    :ok
  end

  defp seed_data("test") do
    Logger.info("Seeding test data...")
    
    # Add test-specific seed data here
    
    :ok
  end

  defp seed_data("production") do
    Logger.info("Seeding production data...")
    
    # Add production-specific seed data here
    # Example:
    # - Create admin user
    # - Initialize system settings
    # - Set up default configurations
    
    :ok
  end

  defp seed_data(env) do
    Logger.warn("Unknown environment: #{env}")
    {:error, :unknown_environment}
  end
end
`;
  }

  protected generateCredoConfig(): string {
    return `%{
  configs: [
    %{
      name: "default",
      files: %{
        included: [
          "lib/",
          "src/",
          "test/",
          "web/",
          "apps/*/lib/",
          "apps/*/src/",
          "apps/*/test/",
          "apps/*/web/"
        ],
        excluded: [~r"/_build/", ~r"/deps/", ~r"/node_modules/"]
      },
      plugins: [],
      requires: [],
      strict: true,
      parse_timeout: 5000,
      color: true,
      checks: %{
        enabled: [
          #
          ## Consistency Checks
          #
          {Credo.Check.Consistency.ExceptionNames, []},
          {Credo.Check.Consistency.LineEndings, []},
          {Credo.Check.Consistency.ParameterPatternMatching, []},
          {Credo.Check.Consistency.SpaceAroundOperators, []},
          {Credo.Check.Consistency.SpaceInParentheses, []},
          {Credo.Check.Consistency.TabsOrSpaces, []},

          #
          ## Design Checks
          #
          {Credo.Check.Design.AliasUsage,
           [priority: :low, if_nested_deeper_than: 2, if_called_more_often_than: 0]},
          {Credo.Check.Design.TagFIXME, []},
          {Credo.Check.Design.TagTODO, [exit_status: 2]},

          #
          ## Readability Checks
          #
          {Credo.Check.Readability.AliasOrder, []},
          {Credo.Check.Readability.FunctionNames, []},
          {Credo.Check.Readability.LargeNumbers, []},
          {Credo.Check.Readability.MaxLineLength, [priority: :low, max_length: 120]},
          {Credo.Check.Readability.ModuleAttributeNames, []},
          {Credo.Check.Readability.ModuleDoc, []},
          {Credo.Check.Readability.ModuleNames, []},
          {Credo.Check.Readability.ParenthesesInCondition, []},
          {Credo.Check.Readability.ParenthesesOnZeroArityDefs, []},
          {Credo.Check.Readability.PipeIntoAnonymousFunctions, []},
          {Credo.Check.Readability.PredicateFunctionNames, []},
          {Credo.Check.Readability.PreferImplicitTry, []},
          {Credo.Check.Readability.RedundantBlankLines, []},
          {Credo.Check.Readability.Semicolons, []},
          {Credo.Check.Readability.SpaceAfterCommas, []},
          {Credo.Check.Readability.StringSigils, []},
          {Credo.Check.Readability.TrailingBlankLine, []},
          {Credo.Check.Readability.TrailingWhiteSpace, []},
          {Credo.Check.Readability.UnnecessaryAliasExpansion, []},
          {Credo.Check.Readability.VariableNames, []},
          {Credo.Check.Readability.WithSingleClause, []},

          #
          ## Refactoring Opportunities
          #
          {Credo.Check.Refactor.Apply, []},
          {Credo.Check.Refactor.CondStatements, []},
          {Credo.Check.Refactor.CyclomaticComplexity, []},
          {Credo.Check.Refactor.FunctionArity, []},
          {Credo.Check.Refactor.LongQuoteBlocks, []},
          {Credo.Check.Refactor.MatchInCondition, []},
          {Credo.Check.Refactor.MapJoin, []},
          {Credo.Check.Refactor.NegatedConditionsInUnless, []},
          {Credo.Check.Refactor.NegatedConditionsWithElse, []},
          {Credo.Check.Refactor.Nesting, []},
          {Credo.Check.Refactor.UnlessWithElse, []},
          {Credo.Check.Refactor.WithClauses, []},
          {Credo.Check.Refactor.FilterFilter, []},
          {Credo.Check.Refactor.RejectReject, []},
          {Credo.Check.Refactor.RedundantWithClauseResult, []},

          #
          ## Warnings
          #
          {Credo.Check.Warning.ApplicationConfigInModuleAttribute, []},
          {Credo.Check.Warning.BoolOperationOnSameValues, []},
          {Credo.Check.Warning.ExpensiveEmptyEnumCheck, []},
          {Credo.Check.Warning.IExPry, []},
          {Credo.Check.Warning.IoInspect, []},
          {Credo.Check.Warning.LazyLogging, []},
          {Credo.Check.Warning.MixEnv, []},
          {Credo.Check.Warning.OperationOnSameValues, []},
          {Credo.Check.Warning.OperationWithConstantResult, []},
          {Credo.Check.Warning.RaiseInsideRescue, []},
          {Credo.Check.Warning.SpecWithStruct, []},
          {Credo.Check.Warning.WrongTestFileExtension, []},
          {Credo.Check.Warning.UnusedEnumOperation, []},
          {Credo.Check.Warning.UnusedFileOperation, []},
          {Credo.Check.Warning.UnusedKeywordOperation, []},
          {Credo.Check.Warning.UnusedListOperation, []},
          {Credo.Check.Warning.UnusedPathOperation, []},
          {Credo.Check.Warning.UnusedRegexOperation, []},
          {Credo.Check.Warning.UnusedStringOperation, []},
          {Credo.Check.Warning.UnusedTupleOperation, []},
          {Credo.Check.Warning.UnsafeExec, []}
        ],
        disabled: [
          #
          # Checks scheduled for next check update (opt-in for now, just replace \`false\` with \`[]\`)

          #
          # Controversial and experimental checks (opt-in, just move the check to \`:enabled\`
          #   and be sure to use \`mix credo --strict\` to see low priority checks)
          #
          {Credo.Check.Consistency.MultiAliasImportRequireUse, []},
          {Credo.Check.Consistency.UnusedVariableNames, []},
          {Credo.Check.Design.DuplicatedCode, []},
          {Credo.Check.Design.SkipTestWithoutComment, []},
          {Credo.Check.Readability.AliasAs, []},
          {Credo.Check.Readability.BlockPipe, []},
          {Credo.Check.Readability.ImplTrue, []},
          {Credo.Check.Readability.MultiAlias, []},
          {Credo.Check.Readability.NestedFunctionCalls, []},
          {Credo.Check.Readability.SeparateAliasRequire, []},
          {Credo.Check.Readability.SingleFunctionToBlockPipe, []},
          {Credo.Check.Readability.SinglePipe, []},
          {Credo.Check.Readability.Specs, []},
          {Credo.Check.Readability.StrictModuleLayout, []},
          {Credo.Check.Readability.WithCustomTaggedTuple, []},
          {Credo.Check.Refactor.ABCSize, []},
          {Credo.Check.Refactor.AppendSingleItem, []},
          {Credo.Check.Refactor.DoubleBooleanNegation, []},
          {Credo.Check.Refactor.FilterReject, []},
          {Credo.Check.Refactor.IoPuts, []},
          {Credo.Check.Refactor.MapMap, []},
          {Credo.Check.Refactor.ModuleDependencies, []},
          {Credo.Check.Refactor.NegatedIsNil, []},
          {Credo.Check.Refactor.PipeChainStart, []},
          {Credo.Check.Refactor.RejectFilter, []},
          {Credo.Check.Refactor.VariableRebinding, []},
          {Credo.Check.Warning.LeakyEnvironment, []},
          {Credo.Check.Warning.MapGetUnsafePass, []},
          {Credo.Check.Warning.MixEnv, []},
          {Credo.Check.Warning.UnsafeToAtom, []}
        ]
      }
    }
  ]
}
`;
  }

  protected generateMainModuleTest(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}Test do
  use ExUnit.Case
  doctest ${moduleName}

  describe "hello/1" do
    test "greets the world" do
      assert ${moduleName}.hello("World") == "Hello, World!"
    end

    test "greets anonymous when no name provided" do
      assert ${moduleName}.hello() == "Hello, Anonymous!"
    end

    test "trims whitespace from name" do
      assert ${moduleName}.hello("  Alice  ") == "Hello, Alice!"
    end
  end

  describe "process_data/1" do
    test "handles successful data" do
      assert ${moduleName}.process_data({:ok, %{value: 42}}) == 
             {:success, %{value: 42, processed_at: DateTime.utc_now()}}
    end

    test "handles error data" do
      assert ${moduleName}.process_data({:error, "Something went wrong"}) == 
             {:failure, "Error: Something went wrong"}
    end

    test "handles invalid format" do
      assert ${moduleName}.process_data("invalid") == 
             {:failure, "Invalid data format"}
    end
  end

  describe "transform_pipeline/1" do
    test "transforms valid data through pipeline" do
      result = ${moduleName}.transform_pipeline("TEST")
      
      assert {:ok, json} = result
      assert {:ok, decoded} = Jason.decode(json)
      assert decoded["data"] == "test"
      assert decoded["version"] == "1.0.0"
      assert Map.has_key?(decoded, "timestamp")
    end

    test "handles nil input" do
      assert ${moduleName}.transform_pipeline(nil) == 
             {:error, "Processing failed: invalid_data"}
    end

    test "handles empty input" do
      assert ${moduleName}.transform_pipeline("") == 
             {:error, "Processing failed: empty_data"}
    end
  end
end
`;
  }

  protected generateGenServerTest(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Workers.CounterServerTest do
  use ExUnit.Case, async: true

  alias ${moduleName}.Workers.CounterServer

  setup do
    {:ok, pid} = start_supervised(CounterServer)
    %{server: pid}
  end

  describe "increment/0" do
    test "increments the counter", %{server: _server} do
      assert CounterServer.get_count() == 0
      assert CounterServer.increment() == :ok
      assert CounterServer.get_count() == 1
    end

    test "handles multiple increments", %{server: _server} do
      for _ <- 1..10, do: CounterServer.increment()
      assert CounterServer.get_count() == 10
    end
  end

  describe "decrement/0" do
    test "decrements the counter", %{server: _server} do
      CounterServer.increment()
      CounterServer.increment()
      assert CounterServer.get_count() == 2
      
      CounterServer.decrement()
      assert CounterServer.get_count() == 1
    end

    test "doesn't go below zero", %{server: _server} do
      assert CounterServer.get_count() == 0
      CounterServer.decrement()
      assert CounterServer.get_count() == 0
    end
  end

  describe "reset/0" do
    test "resets the counter to zero", %{server: _server} do
      for _ <- 1..5, do: CounterServer.increment()
      assert CounterServer.get_count() == 5
      
      CounterServer.reset()
      assert CounterServer.get_count() == 0
    end
  end

  describe "concurrent operations" do
    test "handles concurrent increments correctly", %{server: _server} do
      tasks = for _ <- 1..100 do
        Task.async(fn -> CounterServer.increment() end)
      end
      
      Task.await_many(tasks)
      assert CounterServer.get_count() == 100
    end
  end
end
`;
  }

  protected generateSetupScript(): string {
    return `#!/bin/bash
set -e

echo "🔧 Setting up Elixir project..."

# Check for required tools
command -v elixir >/dev/null 2>&1 || { echo "❌ Elixir is required but not installed. Aborting." >&2; exit 1; }
command -v mix >/dev/null 2>&1 || { echo "❌ Mix is required but not installed. Aborting." >&2; exit 1; }

echo "📦 Installing dependencies..."
mix deps.get

echo "🔨 Compiling project..."
mix compile

echo "🗄️ Setting up database (if configured)..."
if [ -f "priv/repo/migrations" ]; then
  mix ecto.create
  mix ecto.migrate
fi

echo "🌱 Running seeds (if available)..."
if mix help | grep -q "seed"; then
  mix seed
fi

echo "🧪 Running tests..."
mix test

echo "📝 Generating documentation..."
mix docs

echo "✅ Setup complete! Run 'iex -S mix' to start the interactive shell."
`;
  }

  protected generateReleaseScript(): string {
    return `#!/bin/bash
set -e

echo "🚀 Building release..."

# Check environment
if [ -z "$MIX_ENV" ]; then
  export MIX_ENV=prod
fi

echo "🧹 Cleaning build artifacts..."
mix clean

echo "📦 Getting production dependencies..."
mix deps.get --only prod

echo "🔨 Compiling in production mode..."
mix compile

echo "🧪 Running tests..."
mix test

echo "🔍 Running code quality checks..."
mix format --check-formatted
mix credo --strict
mix dialyzer

echo "📄 Generating documentation..."
mix docs

echo "📦 Building release..."
mix release

echo "✅ Release built successfully!"
echo "📁 Release artifacts are in _build/$MIX_ENV/rel/"
`;
  }

  protected generateEnvFile(options: any): string {
    const port = options.port || 4000;
    const appName = this.getAppName(options);
    
    return `# Application
PORT=${port}
SECRET_KEY_BASE=your-secret-key-base-at-least-64-bytes
MIX_ENV=dev

# Database
DATABASE_URL=ecto://postgres:postgres@localhost/${appName}_dev
POOL_SIZE=10

# Redis
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=debug

# External Services
API_KEY=your-api-key
WEBHOOK_URL=https://example.com/webhook
`;
  }

  protected generateEnvExample(options: any): string {
    const port = options.port || 4000;
    const appName = this.getAppName(options);
    
    return `# Application
PORT=${port}
SECRET_KEY_BASE=generate-with-mix-phx.gen.secret
MIX_ENV=dev

# Database
DATABASE_URL=ecto://username:password@localhost/${appName}_dev
POOL_SIZE=10

# Redis
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=info

# External Services
API_KEY=your-api-key
WEBHOOK_URL=https://example.com/webhook
`;
  }

  protected generateDockerfile(options: any): string {
    const appName = this.getAppName(options);
    
    return `# Build stage
FROM elixir:1.15.7-alpine AS build

# Install build dependencies
RUN apk add --no-cache build-base git python3

# Set environment
ENV MIX_ENV=prod

WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \\
    mix local.rebar --force

# Copy mix files
COPY mix.exs mix.lock ./
COPY config config

# Install dependencies
RUN mix deps.get --only prod && \\
    mix deps.compile

# Copy application files
COPY priv priv
COPY lib lib
COPY rel rel

# Compile and build release
RUN mix compile
RUN mix release

# Runtime stage
FROM alpine:3.18 AS app

RUN apk add --no-cache openssl ncurses-libs libstdc++ ca-certificates

WORKDIR /app

# Create non-root user
RUN addgroup -g 1000 -S elixir && \\
    adduser -u 1000 -S elixir -G elixir

# Copy release from build stage
COPY --from=build --chown=elixir:elixir /app/_build/prod/rel/${appName} ./

USER elixir

# Set environment
ENV HOME=/app
ENV MIX_ENV=prod
ENV PORT=4000

EXPOSE 4000

CMD ["bin/${appName}", "start"]
`;
  }

  protected generateDockerCompose(options: any): string {
    const appName = this.getAppName(options);
    const port = options.port || 4000;
    
    return `version: '3.8'

services:
  ${appName}:
    build: .
    ports:
      - "${port}:4000"
    environment:
      - MIX_ENV=dev
      - DATABASE_URL=ecto://postgres:postgres@postgres:5432/${appName}_dev
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY_BASE=your-secret-key-base-at-least-64-bytes
    depends_on:
      - postgres
      - redis
    volumes:
      - .:/app
      - deps:/app/deps
      - build:/app/_build
    command: mix phx.server

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: ${appName}_dev
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
  deps:
  build:
`;
  }

  protected generateDockerIgnore(): string {
    return `# Dependencies
deps/
_build/

# Static artifacts
node_modules/

# Installer-generated files
/installer/_build/
/installer/tmp/

# Temporary files
*.tmp
*.temp

# Environment files
.env
.env.*
!.env.example

# Test coverage
cover/
coverage/

# Docs
doc/
docs/

# Git
.git/
.gitignore

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs
*.log

# Development tools
.formatter.exs
.credo.exs
.dialyzer_ignore.exs
.tool-versions
`;
  }

  protected generateArchitectureDocs(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);
    
    return `# ${moduleName} Architecture

## Overview

${moduleName} is built on Elixir's OTP (Open Telecom Platform) principles, providing a fault-tolerant, distributed, and scalable application architecture.

## Core Concepts

### 1. Actor Model
- Each process is an independent actor
- Processes communicate via message passing
- No shared state between processes
- Lightweight processes (millions can run concurrently)

### 2. Supervision Trees
\`\`\`
${moduleName}.Supervisor
├── Registry (Process naming)
├── MainSupervisor
│   ├── CounterServer (Permanent)
│   ├── TaskWorker (Transient)
│   └── AsyncProcessor (Temporary)
├── Telemetry
├── TaskSupervisor (For async tasks)
└── DynamicSupervisor (Runtime process spawning)
\`\`\`

### 3. Let It Crash Philosophy
- Processes are isolated; failures don't cascade
- Supervisors restart failed processes
- System self-heals from errors
- Focus on the happy path

## Application Structure

### lib/${appName}/
- **application.ex**: OTP application entry point
- **supervisors/**: Supervision tree definitions
- **workers/**: GenServer and worker processes
- **services/**: Business logic and services
- **models/**: Data structures and schemas
- **utils/**: Utility modules

## Process Types

### 1. GenServers
Stateful processes that handle synchronous and asynchronous calls:
- CounterServer: Example of state management
- TaskWorker: Async task processing

### 2. Supervisors
Manage child processes with restart strategies:
- **one_for_one**: Restart only the failed child
- **one_for_all**: Restart all children if one fails
- **rest_for_one**: Restart failed child and those started after it

### 3. Tasks
For fire-and-forget operations:
- Task.async/await for concurrent operations
- Task.Supervisor for managed async tasks

### 4. Registry
Named process registry for process discovery

## Communication Patterns

### 1. Call (Synchronous)
\`\`\`elixir
GenServer.call(server, {:get_state})
\`\`\`

### 2. Cast (Asynchronous)
\`\`\`elixir
GenServer.cast(server, {:update_state, new_value})
\`\`\`

### 3. Info (Direct Messages)
\`\`\`elixir
send(pid, {:custom_message, data})
\`\`\`

## Error Handling

### 1. Try/Catch/Rescue
For expected errors within a process

### 2. Process Linking
Bidirectional failure propagation

### 3. Process Monitoring
Unidirectional failure notification

### 4. Supervision
Automatic restart policies

## Scaling Strategies

### 1. Vertical Scaling
- Increase BEAM VM resources
- Tune VM flags for performance

### 2. Horizontal Scaling
- Distributed Erlang nodes
- Process distribution across nodes
- Global process registry

### 3. Load Balancing
- Round-robin process selection
- Consistent hashing for stateful processes
- Dynamic process pools

## Performance Considerations

### 1. Process Design
- Keep processes focused (single responsibility)
- Minimize process state
- Use ETS for shared read-heavy data

### 2. Message Passing
- Keep messages small
- Avoid large binary copying
- Use references for large data

### 3. Supervision Strategy
- Choose appropriate restart strategies
- Set proper restart intensity
- Use circuit breakers for external services

## Monitoring and Observability

### 1. Telemetry
- Built-in instrumentation
- Custom event emission
- Metrics collection

### 2. Logger
- Structured logging
- Log levels and filtering
- Custom backends

### 3. Observer
- Live process inspection
- Memory and CPU profiling
- Message queue monitoring

## Best Practices

1. **Fail Fast**: Don't try to handle every error
2. **Isolate State**: Each process owns its state
3. **Think in Processes**: Design around concurrent processes
4. **Embrace Immutability**: Data is immutable
5. **Pattern Match**: Use pattern matching extensively
6. **Supervise Everything**: All processes should be supervised
7. **Name Your Processes**: Use Registry for process discovery
8. **Monitor Don't Link**: Unless you want bidirectional failure
9. **Keep It Simple**: Simple processes are easier to reason about
10. **Document Your Supervisors**: Clear supervision strategies
`;
  }

  protected generateOTPGuide(): string {
    return `# OTP (Open Telecom Platform) Guide

## What is OTP?

OTP is a set of design principles, libraries, and tools for building distributed, fault-tolerant applications in Erlang and Elixir.

## Key OTP Behaviors

### 1. GenServer (Generic Server)
A behavior module for implementing stateful server processes.

\`\`\`elixir
defmodule MyServer do
  use GenServer

  # Client API
  def start_link(init_arg) do
    GenServer.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  def get_state do
    GenServer.call(__MODULE__, :get_state)
  end

  # Server Callbacks
  @impl true
  def init(init_arg) do
    {:ok, init_arg}
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end
end
\`\`\`

### 2. Supervisor
Manages child processes and implements restart strategies.

\`\`\`elixir
defmodule MySupervisor do
  use Supervisor

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    children = [
      {MyWorker, []},
      {MyServer, []}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
\`\`\`

### 3. Application
Defines the application callback module and supervision tree root.

\`\`\`elixir
defmodule MyApp.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      MyApp.Supervisor
    ]

    opts = [strategy: :one_for_one, name: MyApp.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
\`\`\`

## Supervision Strategies

### one_for_one
- If a child process crashes, only that process is restarted
- Use when child processes are independent

### one_for_all
- If any child process crashes, all child processes are terminated and restarted
- Use when child processes depend on each other

### rest_for_one
- If a child process crashes, it and all child processes started after it are restarted
- Use when later children depend on earlier ones

## Process Communication

### Synchronous (call)
- Waits for a response
- Has a timeout (default 5 seconds)
- Use for queries or operations that need confirmation

### Asynchronous (cast)
- Fire and forget
- No response expected
- Use for notifications or state updates

### Direct Messages (send/receive)
- Low-level message passing
- More flexible but less structured
- Use sparingly, prefer GenServer abstractions

## Error Handling Philosophy

### Let It Crash
- Don't try to handle every possible error
- Let processes fail and be restarted by supervisors
- Focus on correct behavior, not error recovery

### Isolation
- Process crashes don't affect other processes
- Each process has its own heap
- No shared memory between processes

### Fail Fast
- Detect errors as early as possible
- Crash immediately on unexpected conditions
- Provide clear error messages

## Best Practices

### 1. Process Naming
\`\`\`elixir
# Use atoms for singleton processes
GenServer.start_link(__MODULE__, arg, name: __MODULE__)

# Use Registry for dynamic processes
{:via, Registry, {MyApp.Registry, "user_123"}}
\`\`\`

### 2. State Management
\`\`\`elixir
# Keep state simple and focused
defstruct [:id, :name, :status, :data]

# Use maps for flexible state
%{id: 123, name: "test", metadata: %{}}
\`\`\`

### 3. Timeouts
\`\`\`elixir
# Set appropriate timeouts for calls
GenServer.call(server, :request, 10_000)  # 10 seconds

# Handle timeouts gracefully
try do
  GenServer.call(server, :request, 5_000)
catch
  :exit, {:timeout, _} -> {:error, :timeout}
end
\`\`\`

### 4. Process Monitoring
\`\`\`elixir
# Monitor for unidirectional failure notification
ref = Process.monitor(pid)

# Link for bidirectional failure propagation
Process.link(pid)
\`\`\`

### 5. Hot Code Reloading
\`\`\`elixir
# Support code upgrades
def code_change(old_vsn, state, _extra) do
  # Migrate state if needed
  {:ok, state}
end
\`\`\`

## Common Patterns

### 1. Worker Pool
\`\`\`elixir
children = for i <- 1..10 do
  %{
    id: {Worker, i},
    start: {Worker, :start_link, [i]}
  }
end
\`\`\`

### 2. Circuit Breaker
\`\`\`elixir
defmodule CircuitBreaker do
  # Track failures and prevent cascading failures
  # Open circuit after threshold
  # Half-open to test recovery
  # Close when service recovers
end
\`\`\`

### 3. Event Manager
\`\`\`elixir
defmodule EventManager do
  # Publish events to multiple handlers
  # Decouple event producers from consumers
  # Handle events asynchronously
end
\`\`\`

## Testing OTP Applications

### 1. Start Under Test Supervision
\`\`\`elixir
{:ok, pid} = start_supervised(MyServer)
\`\`\`

### 2. Test Process State
\`\`\`elixir
assert :sys.get_state(pid) == expected_state
\`\`\`

### 3. Test Process Crashes
\`\`\`elixir
Process.flag(:trap_exit, true)
Process.exit(pid, :kill)
assert_receive {:EXIT, ^pid, :killed}
\`\`\`

## Debugging Tools

### 1. Observer
\`\`\`elixir
:observer.start()
\`\`\`

### 2. Process Info
\`\`\`elixir
Process.info(pid)
Process.info(pid, [:message_queue_len, :memory])
\`\`\`

### 3. Sys Module
\`\`\`elixir
:sys.get_status(pid)
:sys.get_state(pid)
:sys.trace(pid, true)
\`\`\`

## Performance Tips

1. **Message Queue**: Monitor queue length, avoid bottlenecks
2. **Process Memory**: Keep process heap small
3. **ETS Tables**: Use for shared read-heavy data
4. **Binary References**: Avoid copying large binaries
5. **Selective Receive**: Order matters in receive blocks
`;
  }

  protected generateDeploymentGuide(options: any): string {
    const appName = this.getAppName(options);
    
    return `# Deployment Guide

## Development Deployment

### Using Mix
\`\`\`bash
# Start interactive shell
iex -S mix

# Start application
mix run --no-halt
\`\`\`

### Using Docker
\`\`\`bash
# Build and run with docker-compose
docker-compose up

# Run specific commands
docker-compose run ${appName} mix test
\`\`\`

## Production Deployment

### 1. Build Release

\`\`\`bash
# Set production environment
export MIX_ENV=prod

# Get dependencies
mix deps.get --only prod

# Compile
mix compile

# Build release
mix release
\`\`\`

### 2. Release Structure

\`\`\`
_build/prod/rel/${appName}/
├── bin/
│   ├── ${appName}         # Main executable
│   ├── ${appName}.bat     # Windows script
│   └── ...
├── lib/                    # Compiled BEAM files
├── releases/
│   └── 0.1.0/
│       ├── sys.config      # System configuration
│       ├── vm.args         # VM arguments
│       └── ...
└── erts-*/                 # Erlang runtime
\`\`\`

### 3. Running the Release

\`\`\`bash
# Start in foreground
_build/prod/rel/${appName}/bin/${appName} start

# Start as daemon
_build/prod/rel/${appName}/bin/${appName} daemon

# Remote console
_build/prod/rel/${appName}/bin/${appName} remote

# Stop daemon
_build/prod/rel/${appName}/bin/${appName} stop
\`\`\`

### 4. Environment Variables

\`\`\`bash
# Required for production
export SECRET_KEY_BASE=$(mix phx.gen.secret)
export DATABASE_URL=ecto://user:pass@host/db
export PORT=4000
export PHX_HOST=example.com
\`\`\`

## Docker Deployment

### Building Image

\`\`\`bash
# Build production image
docker build -t ${appName}:latest .

# Tag for registry
docker tag ${appName}:latest registry.example.com/${appName}:latest

# Push to registry
docker push registry.example.com/${appName}:latest
\`\`\`

### Running Container

\`\`\`bash
# Run with environment file
docker run -d \\
  --name ${appName} \\
  -p 4000:4000 \\
  --env-file .env.prod \\
  ${appName}:latest

# With specific environment variables
docker run -d \\
  --name ${appName} \\
  -p 4000:4000 \\
  -e SECRET_KEY_BASE=your-secret \\
  -e DATABASE_URL=ecto://... \\
  ${appName}:latest
\`\`\`

## Kubernetes Deployment

### Deployment Manifest

\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${appName}
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ${appName}
  template:
    metadata:
      labels:
        app: ${appName}
    spec:
      containers:
      - name: ${appName}
        image: registry.example.com/${appName}:latest
        ports:
        - containerPort: 4000
        env:
        - name: SECRET_KEY_BASE
          valueFrom:
            secretKeyRef:
              name: ${appName}-secrets
              key: secret-key-base
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: ${appName}-secrets
              key: database-url
        livenessProbe:
          httpGet:
            path: /health
            port: 4000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 4000
          initialDelaySeconds: 5
          periodSeconds: 5
\`\`\`

### Service Manifest

\`\`\`yaml
apiVersion: v1
kind: Service
metadata:
  name: ${appName}
spec:
  selector:
    app: ${appName}
  ports:
  - protocol: TCP
    port: 80
    targetPort: 4000
  type: LoadBalancer
\`\`\`

## Systemd Service

### Service File

\`\`\`ini
[Unit]
Description=${appName} service
After=network.target

[Service]
Type=simple
User=${appName}
Group=${appName}
WorkingDirectory=/opt/${appName}
Environment="MIX_ENV=prod"
Environment="PORT=4000"
EnvironmentFile=/opt/${appName}/.env
ExecStart=/opt/${appName}/bin/${appName} start
ExecStop=/opt/${appName}/bin/${appName} stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
\`\`\`

### Installation

\`\`\`bash
# Copy release to server
scp -r _build/prod/rel/${appName} server:/opt/

# Create user
sudo useradd -r -s /bin/false ${appName}

# Set permissions
sudo chown -R ${appName}:${appName} /opt/${appName}

# Install service
sudo cp ${appName}.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ${appName}
sudo systemctl start ${appName}
\`\`\`

## Hot Code Upgrades

### 1. Build Upgrade Release

\`\`\`bash
# Update version in mix.exs
# Build new release
mix release

# Create upgrade package
mix release --upgrade
\`\`\`

### 2. Apply Upgrade

\`\`\`bash
# Copy upgrade to release
cp _build/prod/${appName}-0.2.0.tar.gz /opt/${appName}/releases/

# Apply upgrade
/opt/${appName}/bin/${appName} upgrade 0.2.0
\`\`\`

## Monitoring

### Health Checks

\`\`\`elixir
# Add health endpoint
get "/health" do
  send_resp(conn, 200, "OK")
end

# Add readiness check
get "/ready" do
  # Check database, external services
  if all_services_ready?() do
    send_resp(conn, 200, "Ready")
  else
    send_resp(conn, 503, "Not Ready")
  end
end
\`\`\`

### Metrics

\`\`\`elixir
# Use Telemetry for metrics
:telemetry.execute(
  [:${appName}, :request],
  %{duration: duration},
  %{path: path, method: method}
)
\`\`\`

### Logging

\`\`\`elixir
# Configure production logging
config :logger,
  level: :info,
  format: "$time $metadata[$level] $message\\n",
  metadata: [:request_id, :user_id]
\`\`\`

## Security Considerations

1. **Environment Variables**: Never commit secrets
2. **HTTPS**: Always use TLS in production
3. **CORS**: Configure allowed origins
4. **Rate Limiting**: Implement request limits
5. **Input Validation**: Validate all user input
6. **SQL Injection**: Use Ecto parameterized queries
7. **CSRF Protection**: Enable CSRF tokens
8. **Content Security Policy**: Set appropriate headers

## Performance Tuning

### BEAM VM Flags

\`\`\`bash
# Increase schedulers
+S 4:4

# Increase process limit
+P 1000000

# Enable kernel poll
+K true

# Set memory allocators
+MBas aobf +MBacul 0
\`\`\`

### Application Tuning

\`\`\`elixir
# Connection pool size
pool_size: 20

# Request timeout
timeout: 30_000

# Concurrent requests
max_concurrency: 100
\`\`\`

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   - Check: \`lsof -i :4000\`
   - Kill: \`kill -9 <PID>\`

2. **Database Connection Failed**
   - Check DATABASE_URL
   - Verify database is running
   - Check network connectivity

3. **Memory Issues**
   - Monitor with \`:observer.start()\`
   - Check for memory leaks
   - Tune VM memory settings

4. **High CPU Usage**
   - Profile with \`:fprof\`
   - Check for infinite loops
   - Optimize algorithms

### Debug Mode

\`\`\`bash
# Start with debug logging
LOG_LEVEL=debug _build/prod/rel/${appName}/bin/${appName} start

# Remote shell
_build/prod/rel/${appName}/bin/${appName} remote

# Run observer
:observer.start()
\`\`\`
`;
  }

  protected toPascalCase(str: string): string {
    return str
      .split(/[-_]/)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join('');
  }

  // Method to generate example GenServer files
  protected generateGenServerExamples(options: any): { path: string; content: string }[] {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);
    
    return [
      {
        path: `lib/${appName}/workers/counter_server.ex`,
        content: this.generateCounterServer(options)
      },
      {
        path: `lib/${appName}/workers/cache_server.ex`, 
        content: this.generateCacheServer(options)
      },
      {
        path: `lib/${appName}/workers/state_manager.ex`,
        content: this.generateStateManager(options)
      }
    ];
  }

  protected generateCounterServer(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Workers.CounterServer do
  @moduledoc """
  A simple counter GenServer demonstrating basic state management.
  
  This server maintains a counter that can be incremented, decremented,
  and reset. It demonstrates:
  - GenServer callbacks
  - Synchronous calls
  - State management
  - Process naming
  """
  use GenServer
  require Logger

  # Client API

  @doc """
  Starts the counter server.
  """
  def start_link(opts \\\\ []) do
    initial_value = Keyword.get(opts, :initial_value, 0)
    GenServer.start_link(__MODULE__, initial_value, name: __MODULE__)
  end

  @doc """
  Gets the current counter value.
  """
  def get_count do
    GenServer.call(__MODULE__, :get_count)
  end

  @doc """
  Increments the counter.
  """
  def increment do
    GenServer.cast(__MODULE__, :increment)
  end

  @doc """
  Decrements the counter.
  """
  def decrement do
    GenServer.cast(__MODULE__, :decrement)
  end

  @doc """
  Resets the counter to zero.
  """
  def reset do
    GenServer.cast(__MODULE__, :reset)
  end

  @doc """
  Sets the counter to a specific value.
  """
  def set_count(value) when is_integer(value) do
    GenServer.call(__MODULE__, {:set_count, value})
  end

  # Server Callbacks

  @impl true
  def init(initial_value) do
    Logger.info("CounterServer starting with initial value: #{initial_value}")
    {:ok, initial_value}
  end

  @impl true
  def handle_call(:get_count, _from, count) do
    {:reply, count, count}
  end

  @impl true
  def handle_call({:set_count, value}, _from, _count) do
    Logger.info("Setting counter to #{value}")
    {:reply, :ok, value}
  end

  @impl true
  def handle_cast(:increment, count) do
    new_count = count + 1
    Logger.debug("Counter incremented to #{new_count}")
    {:noreply, new_count}
  end

  @impl true
  def handle_cast(:decrement, count) do
    new_count = max(0, count - 1)  # Don't go below zero
    Logger.debug("Counter decremented to #{new_count}")
    {:noreply, new_count}
  end

  @impl true
  def handle_cast(:reset, _count) do
    Logger.info("Counter reset to 0")
    {:noreply, 0}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end
end
`;
  }

  protected generateCacheServer(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Workers.CacheServer do
  @moduledoc """
  A GenServer implementing a simple in-memory cache with TTL support.
  
  Features:
  - Key-value storage
  - TTL (time to live) for entries
  - Automatic cleanup of expired entries
  - Size limits
  """
  use GenServer
  require Logger

  @cleanup_interval :timer.minutes(5)
  @default_ttl :timer.hours(1)
  @max_entries 10_000

  # Client API

  def start_link(opts \\\\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Stores a value in the cache with optional TTL.
  """
  def put(key, value, ttl \\\\ @default_ttl) do
    GenServer.cast(__MODULE__, {:put, key, value, ttl})
  end

  @doc """
  Retrieves a value from the cache.
  """
  def get(key) do
    GenServer.call(__MODULE__, {:get, key})
  end

  @doc """
  Deletes a value from the cache.
  """
  def delete(key) do
    GenServer.cast(__MODULE__, {:delete, key})
  end

  @doc """
  Clears all entries from the cache.
  """
  def clear do
    GenServer.cast(__MODULE__, :clear)
  end

  @doc """
  Returns the current size of the cache.
  """
  def size do
    GenServer.call(__MODULE__, :size)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Schedule periodic cleanup
    schedule_cleanup()
    
    state = %{
      entries: %{},
      access_count: %{},
      created_at: DateTime.utc_now()
    }
    
    {:ok, state}
  end

  @impl true
  def handle_call({:get, key}, _from, state) do
    case Map.get(state.entries, key) do
      nil ->
        {:reply, {:error, :not_found}, state}
      
      {value, expiry} ->
        if DateTime.compare(DateTime.utc_now(), expiry) == :lt do
          # Update access count
          new_state = update_in(state.access_count[key], &((&1 || 0) + 1))
          {:reply, {:ok, value}, new_state}
        else
          # Entry expired, remove it
          new_state = %{state | 
            entries: Map.delete(state.entries, key),
            access_count: Map.delete(state.access_count, key)
          }
          {:reply, {:error, :expired}, new_state}
        end
    end
  end

  @impl true
  def handle_call(:size, _from, state) do
    {:reply, map_size(state.entries), state}
  end

  @impl true
  def handle_cast({:put, key, value, ttl}, state) do
    # Check size limit
    if map_size(state.entries) >= @max_entries do
      Logger.warn("Cache is full (#{@max_entries} entries), evicting LRU entry")
      state = evict_lru(state)
    end
    
    expiry = DateTime.add(DateTime.utc_now(), ttl, :millisecond)
    new_entries = Map.put(state.entries, key, {value, expiry})
    
    {:noreply, %{state | entries: new_entries}}
  end

  @impl true
  def handle_cast({:delete, key}, state) do
    new_state = %{state |
      entries: Map.delete(state.entries, key),
      access_count: Map.delete(state.access_count, key)
    }
    {:noreply, new_state}
  end

  @impl true
  def handle_cast(:clear, state) do
    {:noreply, %{state | entries: %{}, access_count: %{}}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    Logger.debug("Running cache cleanup")
    new_state = cleanup_expired_entries(state)
    schedule_cleanup()
    {:noreply, new_state}
  end

  # Private functions

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_expired_entries(state) do
    now = DateTime.utc_now()
    
    expired_keys = 
      state.entries
      |> Enum.filter(fn {_key, {_value, expiry}} ->
        DateTime.compare(now, expiry) != :lt
      end)
      |> Enum.map(fn {key, _} -> key end)
    
    if length(expired_keys) > 0 do
      Logger.info("Cleaning up #{length(expired_keys)} expired entries")
    end
    
    new_entries = Map.drop(state.entries, expired_keys)
    new_access_count = Map.drop(state.access_count, expired_keys)
    
    %{state | entries: new_entries, access_count: new_access_count}
  end

  defp evict_lru(state) do
    # Find least recently used entry
    lru_key = 
      state.entries
      |> Map.keys()
      |> Enum.min_by(fn key -> Map.get(state.access_count, key, 0) end)
    
    %{state |
      entries: Map.delete(state.entries, lru_key),
      access_count: Map.delete(state.access_count, lru_key)
    }
  end
end
`;
  }

  protected generateStateManager(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Workers.StateManager do
  @moduledoc """
  A GenServer that manages application state with event sourcing patterns.
  
  Features:
  - Event-driven state updates
  - State snapshots
  - Event history
  - Undo/redo functionality
  """
  use GenServer
  require Logger

  @max_history 100

  # Client API

  def start_link(opts \\\\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Applies an event to the state.
  """
  def apply_event(event) do
    GenServer.call(__MODULE__, {:apply_event, event})
  end

  @doc """
  Gets the current state.
  """
  def get_state do
    GenServer.call(__MODULE__, :get_state)
  end

  @doc """
  Gets the event history.
  """
  def get_history do
    GenServer.call(__MODULE__, :get_history)
  end

  @doc """
  Undoes the last event.
  """
  def undo do
    GenServer.call(__MODULE__, :undo)
  end

  @doc """
  Redoes the last undone event.
  """
  def redo do
    GenServer.call(__MODULE__, :redo)
  end

  @doc """
  Creates a snapshot of the current state.
  """
  def snapshot do
    GenServer.call(__MODULE__, :snapshot)
  end

  @doc """
  Restores state from a snapshot.
  """
  def restore_snapshot(snapshot_id) do
    GenServer.call(__MODULE__, {:restore_snapshot, snapshot_id})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %{
      current_state: %{},
      events: [],
      undo_stack: [],
      redo_stack: [],
      snapshots: %{},
      event_handlers: %{
        user_created: &handle_user_created/2,
        user_updated: &handle_user_updated/2,
        user_deleted: &handle_user_deleted/2,
        setting_changed: &handle_setting_changed/2
      }
    }
    
    {:ok, state}
  end

  @impl true
  def handle_call({:apply_event, event}, _from, state) do
    case apply_event_to_state(event, state) do
      {:ok, new_state} ->
        # Clear redo stack when new event is applied
        new_state = %{new_state | redo_stack: []}
        {:reply, :ok, new_state}
      
      {:error, reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, {:ok, state.current_state}, state}
  end

  @impl true
  def handle_call(:get_history, _from, state) do
    {:reply, {:ok, Enum.reverse(state.events)}, state}
  end

  @impl true
  def handle_call(:undo, _from, state) do
    case state.events do
      [] ->
        {:reply, {:error, :no_events_to_undo}, state}
      
      [last_event | rest_events] ->
        # Rebuild state from remaining events
        new_current_state = rebuild_state(rest_events, %{}, state.event_handlers)
        
        new_state = %{state |
          current_state: new_current_state,
          events: rest_events,
          undo_stack: [last_event | state.undo_stack],
          redo_stack: [last_event | state.redo_stack]
        }
        
        {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_call(:redo, _from, state) do
    case state.redo_stack do
      [] ->
        {:reply, {:error, :no_events_to_redo}, state}
      
      [event | rest_redo] ->
        case apply_event_to_state(event, state) do
          {:ok, new_state} ->
            new_state = %{new_state | redo_stack: rest_redo}
            {:reply, :ok, new_state}
          
          error ->
            {:reply, error, state}
        end
    end
  end

  @impl true
  def handle_call(:snapshot, _from, state) do
    snapshot_id = generate_snapshot_id()
    snapshot = %{
      id: snapshot_id,
      state: state.current_state,
      events_count: length(state.events),
      created_at: DateTime.utc_now()
    }
    
    new_snapshots = Map.put(state.snapshots, snapshot_id, snapshot)
    {:reply, {:ok, snapshot_id}, %{state | snapshots: new_snapshots}}
  end

  @impl true
  def handle_call({:restore_snapshot, snapshot_id}, _from, state) do
    case Map.get(state.snapshots, snapshot_id) do
      nil ->
        {:reply, {:error, :snapshot_not_found}, state}
      
      snapshot ->
        new_state = %{state |
          current_state: snapshot.state,
          events: [],
          undo_stack: [],
          redo_stack: []
        }
        {:reply, :ok, new_state}
    end
  end

  # Private functions

  defp apply_event_to_state(event, state) do
    handler = Map.get(state.event_handlers, event.type)
    
    if handler do
      try do
        new_current_state = handler.(event, state.current_state)
        
        # Add event to history (maintain max size)
        new_events = [event | state.events] |> Enum.take(@max_history)
        
        {:ok, %{state | 
          current_state: new_current_state,
          events: new_events
        }}
      rescue
        e ->
          Logger.error("Error applying event: #{inspect(e)}")
          {:error, :event_handler_error}
      end
    else
      {:error, :unknown_event_type}
    end
  end

  defp rebuild_state(events, initial_state, event_handlers) do
    Enum.reduce(events, initial_state, fn event, acc_state ->
      handler = Map.get(event_handlers, event.type)
      if handler, do: handler.(event, acc_state), else: acc_state
    end)
  end

  defp generate_snapshot_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16()
  end

  # Event handlers

  defp handle_user_created(event, state) do
    Map.put(state, {:user, event.user_id}, event.user_data)
  end

  defp handle_user_updated(event, state) do
    Map.update(state, {:user, event.user_id}, event.user_data, fn existing ->
      Map.merge(existing, event.changes)
    end)
  end

  defp handle_user_deleted(event, state) do
    Map.delete(state, {:user, event.user_id})
  end

  defp handle_setting_changed(event, state) do
    put_in(state, [:settings, event.key], event.value)
  end
end
`;
  }

  // Add telemetry module generation
  protected generateTelemetryModule(options: any): string {
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Telemetry do
  @moduledoc """
  Telemetry integration for application monitoring and metrics.
  """
  use Supervisor
  import Telemetry.Metrics

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    children = [
      # Add telemetry reporters here
      # {Telemetry.Metrics.ConsoleReporter, metrics: metrics()},
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    [
      # Application metrics
      counter("${appName}.request.count"),
      summary("${appName}.request.duration",
        unit: {:native, :millisecond}
      ),
      
      # VM metrics
      summary("vm.memory.total", unit: {:byte, :kilobyte}),
      summary("vm.total_run_queue_lengths.total"),
      summary("vm.total_run_queue_lengths.cpu"),
      summary("vm.total_run_queue_lengths.io"),
      
      # Process metrics
      summary("${appName}.repo.query.total_time", unit: {:native, :millisecond}),
      summary("${appName}.repo.query.decode_time", unit: {:native, :millisecond}),
      summary("${appName}.repo.query.query_time", unit: {:native, :millisecond}),
      summary("${appName}.repo.query.queue_time", unit: {:native, :millisecond}),
      summary("${appName}.repo.query.idle_time", unit: {:native, :millisecond})
    ]
  end

  @doc """
  Emit a telemetry event.
  """
  def emit(event, measurements, metadata \\\\ %{}) do
    :telemetry.execute([:${appName} | event], measurements, metadata)
  end
end
`;
  }
}