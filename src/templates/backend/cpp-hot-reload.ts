/**
 * C++ Hot-Reload Development Generator
 * Generates file watching and hot-reload configuration for C++ projects
 */

export interface CppHotReloadConfig {
  projectName: string;
  watcherTool?: 'entr' | 'watchman' | 'inotify' | 'fswatch';
  buildTool?: 'cmake' | 'make' | 'ninja' | 'bazel';
  reloadStrategy?: 'rebuild' | 'incremental' | 'module';
  enableTests?: boolean;
  enableBenchmarks?: boolean;
  enableDebugger?: boolean;
  customWatchPaths?: string[];
}

export class CppHotReloadGenerator {
  static generate(config: CppHotReloadConfig): Record<string, string> {
    const {
      projectName,
      watcherTool = 'entr',
      buildTool = 'cmake',
      reloadStrategy = 'incremental',
      enableTests = true,
      enableBenchmarks = false,
      enableDebugger = false,
      customWatchPaths = []
    } = config;

    return {
      'scripts/hot-reload.sh': this.generateHotReloadScript(projectName, {
        watcherTool,
        buildTool,
        reloadStrategy,
        enableTests,
        enableBenchmarks,
        enableDebugger,
        customWatchPaths
      }),
      'scripts/watch-and-build.py': this.generateWatchAndBuildScript(),
      'hot-reload/entr-setup.sh': this.generateEntrSetup(),
      'hot-reload/watchman-config.json': this.generateWatchmanConfig(projectName),
      'hot-reload/inotify-setup.sh': this.generateInotifySetup(),
      'hot-reload/fswatch-setup.sh': this.generateFswatchSetup(),
      '.watchmanconfig': this.generateWatchmanProjectConfig(),
      'hot-reload/README.md': this.generateHotReloadReadme(projectName),
      'cmake/HotReload.cmake': this.generateHotReloadCMake(),
      'hot-reload/ccache.conf': this.generateCcacheConfig(),
      'hot-reload/distcc.conf': this.generateDistccConfig(),
      '.clangd': this.generateClangdConfig(),
      'scripts/development-server.sh': this.generateDevelopmentServer(projectName),
      'docker/Dockerfile.dev': this.generateDevDockerfile(projectName),
      'docker-compose.dev.yml': this.generateDevDockerCompose(projectName),
      '.vscode/tasks.json': this.generateVSCodeTasks(),
      '.vscode/launch.json': this.generateVSCodeLaunch(projectName)
    };
  }

  private static generateHotReloadScript(projectName: string, options: any): string {
    return `#!/bin/bash
# Hot-Reload Development Script for ${projectName}
# Automatically rebuilds and reloads on file changes

set -euo pipefail

# Configuration
PROJECT_NAME="${projectName}"
BUILD_DIR="build"
SOURCE_DIR="src"
INCLUDE_DIR="include"
TEST_DIR="tests"
WATCHER_TOOL="${options.watcherTool}"
BUILD_TOOL="${options.buildTool}"
RELOAD_STRATEGY="${options.reloadStrategy}"
ENABLE_TESTS=${options.enableTests}
ENABLE_BENCHMARKS=${options.enableBenchmarks}
ENABLE_DEBUGGER=${options.enableDebugger}

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
BLUE='\\033[0;34m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

# Default watch paths
WATCH_PATHS=(
    "\\${SOURCE_DIR}"
    "\\${INCLUDE_DIR}"
    "CMakeLists.txt"
)

# Add test directory if enabled
if [[ "\\${ENABLE_TESTS}" == "true" ]]; then
    WATCH_PATHS+=("\\${TEST_DIR}")
fi

# Add custom watch paths
CUSTOM_PATHS=(${options.customWatchPaths.map(p => `"${p}"`).join(' ')})
WATCH_PATHS+=("\\${CUSTOM_PATHS[@]}")

echo -e "\\${BLUE}=== C++ Hot-Reload Development Server ===\\${NC}"
echo "Project: \\${PROJECT_NAME}"
echo "Watcher: \\${WATCHER_TOOL}"
echo "Build Tool: \\${BUILD_TOOL}"
echo "Strategy: \\${RELOAD_STRATEGY}"
echo ""

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check watcher tool
    case "\\${WATCHER_TOOL}" in
        entr)
            if ! command -v entr &> /dev/null; then
                missing_deps+=("entr")
            fi
            ;;
        watchman)
            if ! command -v watchman &> /dev/null; then
                missing_deps+=("watchman")
            fi
            ;;
        inotify)
            if ! command -v inotifywait &> /dev/null; then
                missing_deps+=("inotify-tools")
            fi
            ;;
        fswatch)
            if ! command -v fswatch &> /dev/null; then
                missing_deps+=("fswatch")
            fi
            ;;
    esac
    
    # Check build tool
    case "\\${BUILD_TOOL}" in
        cmake)
            if ! command -v cmake &> /dev/null; then
                missing_deps+=("cmake")
            fi
            ;;
        make)
            if ! command -v make &> /dev/null; then
                missing_deps+=("make")
            fi
            ;;
        ninja)
            if ! command -v ninja &> /dev/null; then
                missing_deps+=("ninja")
            fi
            ;;
        bazel)
            if ! command -v bazel &> /dev/null; then
                missing_deps+=("bazel")
            fi
            ;;
    esac
    
    # Check optional tools
    if command -v ccache &> /dev/null; then
        echo -e "\\${GREEN}✓ ccache detected - build caching enabled\\${NC}"
        export CC="ccache gcc"
        export CXX="ccache g++"
    fi
    
    if command -v distcc &> /dev/null; then
        echo -e "\\${GREEN}✓ distcc detected - distributed compilation available\\${NC}"
    fi
    
    if [ \\${#missing_deps[@]} -gt 0 ]; then
        echo -e "\\${RED}Missing dependencies: \\${missing_deps[*]}\\${NC}"
        echo "Please install missing dependencies and try again."
        exit 1
    fi
}

# Initial build
initial_build() {
    echo -e "\\${YELLOW}Performing initial build...\\${NC}"
    
    case "\\${BUILD_TOOL}" in
        cmake)
            if [ ! -d "\\${BUILD_DIR}" ]; then
                cmake -B "\\${BUILD_DIR}" \\
                    -DCMAKE_BUILD_TYPE=Debug \\
                    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \\
                    -DENABLE_HOT_RELOAD=ON
            fi
            cmake --build "\\${BUILD_DIR}" --parallel
            ;;
        make)
            make -j\\$(nproc)
            ;;
        ninja)
            ninja -C "\\${BUILD_DIR}"
            ;;
        bazel)
            bazel build //:all
            ;;
    esac
    
    echo -e "\\${GREEN}✓ Initial build complete\\${NC}"
}

# Incremental build function
incremental_build() {
    local changed_file="\\$1"
    echo -e "\\${YELLOW}File changed: \\${changed_file}\\${NC}"
    
    local start_time=\\$(date +%s.%N)
    
    case "\\${RELOAD_STRATEGY}" in
        rebuild)
            # Full rebuild
            case "\\${BUILD_TOOL}" in
                cmake)
                    cmake --build "\\${BUILD_DIR}" --parallel
                    ;;
                make)
                    make -j\\$(nproc)
                    ;;
                ninja)
                    ninja -C "\\${BUILD_DIR}"
                    ;;
                bazel)
                    bazel build //:all
                    ;;
            esac
            ;;
        incremental)
            # Incremental build (default for most build tools)
            case "\\${BUILD_TOOL}" in
                cmake)
                    cmake --build "\\${BUILD_DIR}" --parallel --target \\${PROJECT_NAME}
                    ;;
                make)
                    make -j\\$(nproc) \\${PROJECT_NAME}
                    ;;
                ninja)
                    ninja -C "\\${BUILD_DIR}" \\${PROJECT_NAME}
                    ;;
                bazel)
                    bazel build //:${projectName}
                    ;;
            esac
            ;;
        module)
            # Module-specific rebuild
            local module=\\$(determine_module "\\${changed_file}")
            case "\\${BUILD_TOOL}" in
                cmake)
                    cmake --build "\\${BUILD_DIR}" --parallel --target "\\${module}"
                    ;;
                *)
                    # Fallback to incremental
                    incremental_build "\\${changed_file}"
                    ;;
            esac
            ;;
    esac
    
    local end_time=\\$(date +%s.%N)
    local build_time=\\$(echo "\\${end_time} - \\${start_time}" | bc)
    
    echo -e "\\${GREEN}✓ Build completed in \\${build_time}s\\${NC}"
    
    # Run tests if enabled
    if [[ "\\${ENABLE_TESTS}" == "true" ]]; then
        run_tests
    fi
    
    # Run benchmarks if enabled
    if [[ "\\${ENABLE_BENCHMARKS}" == "true" ]]; then
        run_benchmarks
    fi
}

# Determine module from file path
determine_module() {
    local file="\\$1"
    # Simple heuristic - can be customized
    basename "\\${file%.*}"
}

# Run tests
run_tests() {
    echo -e "\\${YELLOW}Running tests...\\${NC}"
    
    case "\\${BUILD_TOOL}" in
        cmake)
            cd "\\${BUILD_DIR}" && ctest --output-on-failure || true
            cd ..
            ;;
        make)
            make test || true
            ;;
        bazel)
            bazel test //:all || true
            ;;
    esac
}

# Run benchmarks
run_benchmarks() {
    echo -e "\\${YELLOW}Running benchmarks...\\${NC}"
    
    if [ -f "\\${BUILD_DIR}/benchmarks/\\${PROJECT_NAME}_benchmark" ]; then
        "\\${BUILD_DIR}/benchmarks/\\${PROJECT_NAME}_benchmark" --benchmark_format=json || true
    fi
}

# File watcher functions
watch_with_entr() {
    echo -e "\\${BLUE}Starting entr file watcher...\\${NC}"
    
    while true; do
        find \\${WATCH_PATHS[@]} \\
            \\( -name "*.cpp" -o -name "*.cc" -o -name "*.cxx" \\
            -o -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \\
            -o -name "CMakeLists.txt" -o -name "*.cmake" \\) \\
            2>/dev/null | \\
        entr -d -c bash -c "incremental_build \\$0"
        
        # entr exits when directory structure changes
        echo -e "\\${YELLOW}Directory structure changed, restarting watcher...\\${NC}"
        sleep 1
    done
}

watch_with_watchman() {
    echo -e "\\${BLUE}Starting watchman file watcher...\\${NC}"
    
    # Start watchman
    watchman watch .
    
    # Subscribe to file changes
    watchman -j <<-EOT
    ["subscribe", ".", "hot-reload", {
        "expression": ["anyof",
            ["suffix", "cpp"],
            ["suffix", "cc"],
            ["suffix", "cxx"],
            ["suffix", "h"],
            ["suffix", "hpp"],
            ["suffix", "hxx"],
            ["name", "CMakeLists.txt"],
            ["suffix", "cmake"]
        ],
        "fields": ["name", "type"]
    }]
EOT
    
    # Process watchman events
    watchman --json-command <<< '["since", ".", "c:0:0"]' | \\
    while IFS= read -r line; do
        if echo "\\${line}" | jq -e '.files[]' > /dev/null 2>&1; then
            changed_file=\\$(echo "\\${line}" | jq -r '.files[0].name')
            incremental_build "\\${changed_file}"
        fi
    done
}

watch_with_inotify() {
    echo -e "\\${BLUE}Starting inotify file watcher...\\${NC}"
    
    inotifywait -mr --timefmt '%Y-%m-%d %H:%M:%S' --format '%T %w %f %e' \\
        -e modify,create,delete,move \\
        --include '.*\\.(cpp|cc|cxx|h|hpp|hxx|cmake)$|CMakeLists\\.txt$' \\
        \\${WATCH_PATHS[@]} |
    while read date time dir file event; do
        if [[ "\\${event}" =~ (MODIFY|CREATE|MOVED_TO) ]]; then
            incremental_build "\\${dir}\\${file}"
        fi
    done
}

watch_with_fswatch() {
    echo -e "\\${BLUE}Starting fswatch file watcher...\\${NC}"
    
    fswatch -r -e ".*" -i "\\\\.cpp$" -i "\\\\.cc$" -i "\\\\.cxx$" \\
            -i "\\\\.h$" -i "\\\\.hpp$" -i "\\\\.hxx$" \\
            -i "CMakeLists\\\\.txt$" -i "\\\\.cmake$" \\
            \\${WATCH_PATHS[@]} |
    while read changed_file; do
        incremental_build "\\${changed_file}"
    done
}

# Signal handlers
cleanup() {
    echo -e "\\n\\${YELLOW}Shutting down hot-reload server...\\${NC}"
    
    # Stop watchman if running
    if [[ "\\${WATCHER_TOOL}" == "watchman" ]]; then
        watchman shutdown-server 2>/dev/null || true
    fi
    
    exit 0
}

trap cleanup SIGINT SIGTERM

# Main execution
main() {
    check_dependencies
    initial_build
    
    # Start appropriate watcher
    case "\\${WATCHER_TOOL}" in
        entr)
            watch_with_entr
            ;;
        watchman)
            watch_with_watchman
            ;;
        inotify)
            watch_with_inotify
            ;;
        fswatch)
            watch_with_fswatch
            ;;
        *)
            echo -e "\\${RED}Unknown watcher tool: \\${WATCHER_TOOL}\\${NC}"
            exit 1
            ;;
    esac
}

# Run main function
main`;
  }

  private static generateWatchAndBuildScript(): string {
    return `#!/usr/bin/env python3
"""
Advanced Watch and Build Script for C++ Projects
Provides intelligent file watching and incremental building
"""

import os
import sys
import time
import subprocess
import hashlib
import json
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import Dict, Set, List, Optional, Tuple
import argparse

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
except ImportError:
    print("Please install watchdog: pip install watchdog")
    sys.exit(1)

class BuildCache:
    """Manages build cache for incremental compilation."""
    
    def __init__(self, cache_file: str = ".build_cache.json"):
        self.cache_file = cache_file
        self.cache = self.load_cache()
    
    def load_cache(self) -> Dict[str, str]:
        """Load build cache from file."""
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def save_cache(self):
        """Save build cache to file."""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def get_file_hash(self, filepath: str) -> str:
        """Calculate hash of file contents."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            return ""
    
    def has_changed(self, filepath: str) -> bool:
        """Check if file has changed since last build."""
        current_hash = self.get_file_hash(filepath)
        cached_hash = self.cache.get(filepath, "")
        
        if current_hash != cached_hash:
            self.cache[filepath] = current_hash
            return True
        return False
    
    def update_file(self, filepath: str):
        """Update cache for a file."""
        self.cache[filepath] = self.get_file_hash(filepath)
    
    def remove_file(self, filepath: str):
        """Remove file from cache."""
        self.cache.pop(filepath, None)

class DependencyGraph:
    """Manages C++ file dependencies."""
    
    def __init__(self, build_dir: str = "build"):
        self.build_dir = build_dir
        self.dependencies = {}
        self.load_compile_commands()
    
    def load_compile_commands(self):
        """Load compile_commands.json for dependency analysis."""
        compile_commands_path = os.path.join(self.build_dir, "compile_commands.json")
        try:
            with open(compile_commands_path, 'r') as f:
                self.compile_commands = json.load(f)
        except FileNotFoundError:
            self.compile_commands = []
    
    def analyze_dependencies(self, source_file: str) -> Set[str]:
        """Analyze dependencies for a source file."""
        dependencies = set()
        
        # Use compiler to get dependencies
        for command in self.compile_commands:
            if command.get('file') == source_file:
                # Extract include paths
                cmd_parts = command['command'].split()
                include_paths = []
                
                for i, part in enumerate(cmd_parts):
                    if part == '-I' and i + 1 < len(cmd_parts):
                        include_paths.append(cmd_parts[i + 1])
                    elif part.startswith('-I'):
                        include_paths.append(part[2:])
                
                # Get dependencies using compiler
                try:
                    result = subprocess.run(
                        ['g++', '-MM', '-MG'] + [f'-I{path}' for path in include_paths] + [source_file],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode == 0:
                        # Parse dependency output
                        deps = result.stdout.replace('\\\\', '').replace('\\n', ' ').split()[1:]
                        dependencies.update(deps)
                except subprocess.SubprocessError:
                    pass
                
                break
        
        return dependencies
    
    def get_affected_files(self, changed_file: str) -> Set[str]:
        """Get all files affected by a change."""
        affected = {changed_file}
        
        # Find all files that depend on the changed file
        for source_file in self.compile_commands:
            deps = self.analyze_dependencies(source_file.get('file', ''))
            if changed_file in deps:
                affected.add(source_file.get('file', ''))
        
        return affected

class BuildQueue:
    """Manages build tasks with deduplication."""
    
    def __init__(self):
        self.queue = queue.Queue()
        self.pending = set()
        self.lock = threading.Lock()
    
    def add_task(self, task: str):
        """Add a build task if not already pending."""
        with self.lock:
            if task not in self.pending:
                self.pending.add(task)
                self.queue.put(task)
    
    def get_task(self) -> Optional[str]:
        """Get next build task."""
        try:
            task = self.queue.get(timeout=0.1)
            with self.lock:
                self.pending.discard(task)
            return task
        except queue.Empty:
            return None
    
    def clear(self):
        """Clear all pending tasks."""
        with self.lock:
            while not self.queue.empty():
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    break
            self.pending.clear()

class CppFileHandler(FileSystemEventHandler):
    """Handles file system events for C++ files."""
    
    def __init__(self, build_queue: BuildQueue, cache: BuildCache, dependency_graph: DependencyGraph):
        self.build_queue = build_queue
        self.cache = cache
        self.dependency_graph = dependency_graph
        self.last_event_time = {}
        self.debounce_delay = 0.5  # seconds
    
    def should_process_file(self, filepath: str) -> bool:
        """Check if file should trigger a build."""
        if not filepath:
            return False
        
        # Check file extensions
        extensions = {'.cpp', '.cc', '.cxx', '.c', '.h', '.hpp', '.hxx', '.cmake'}
        if Path(filepath).suffix not in extensions and not filepath.endswith('CMakeLists.txt'):
            return False
        
        # Debounce rapid events
        current_time = time.time()
        last_time = self.last_event_time.get(filepath, 0)
        
        if current_time - last_time < self.debounce_delay:
            return False
        
        self.last_event_time[filepath] = current_time
        return True
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory and self.should_process_file(event.src_path):
            if self.cache.has_changed(event.src_path):
                # Get affected files
                affected = self.dependency_graph.get_affected_files(event.src_path)
                
                for file in affected:
                    self.build_queue.add_task(file)
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] File modified: {event.src_path}")
                print(f"  Affected files: {len(affected)}")

class IncrementalBuilder:
    """Manages incremental C++ builds."""
    
    def __init__(self, project_name: str, build_dir: str = "build", build_tool: str = "cmake"):
        self.project_name = project_name
        self.build_dir = build_dir
        self.build_tool = build_tool
        self.build_times = []
        self.success_count = 0
        self.failure_count = 0
    
    def build(self, target: Optional[str] = None) -> bool:
        """Perform incremental build."""
        start_time = time.time()
        
        try:
            if self.build_tool == "cmake":
                cmd = ["cmake", "--build", self.build_dir]
                if target:
                    cmd.extend(["--target", os.path.splitext(os.path.basename(target))[0]])
                cmd.append("--parallel")
            elif self.build_tool == "make":
                cmd = ["make", "-C", self.build_dir, f"-j{os.cpu_count()}"]
                if target:
                    cmd.append(os.path.splitext(os.path.basename(target))[0])
            elif self.build_tool == "ninja":
                cmd = ["ninja", "-C", self.build_dir]
                if target:
                    cmd.append(os.path.splitext(os.path.basename(target))[0])
            else:
                print(f"Unsupported build tool: {self.build_tool}")
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            build_time = time.time() - start_time
            self.build_times.append(build_time)
            
            if result.returncode == 0:
                self.success_count += 1
                print(f"✓ Build successful in {build_time:.2f}s")
                return True
            else:
                self.failure_count += 1
                print(f"✗ Build failed in {build_time:.2f}s")
                print("Error output:")
                print(result.stderr)
                return False
                
        except subprocess.SubprocessError as e:
            self.failure_count += 1
            print(f"✗ Build error: {e}")
            return False
    
    def print_statistics(self):
        """Print build statistics."""
        if self.build_times:
            avg_time = sum(self.build_times) / len(self.build_times)
            total_builds = self.success_count + self.failure_count
            success_rate = (self.success_count / total_builds * 100) if total_builds > 0 else 0
            
            print("\\n=== Build Statistics ===")
            print(f"Total builds: {total_builds}")
            print(f"Successful: {self.success_count}")
            print(f"Failed: {self.failure_count}")
            print(f"Success rate: {success_rate:.1f}%")
            print(f"Average build time: {avg_time:.2f}s")
            print(f"Fastest build: {min(self.build_times):.2f}s")
            print(f"Slowest build: {max(self.build_times):.2f}s")

class HotReloadServer:
    """Main hot-reload server."""
    
    def __init__(self, project_name: str, watch_paths: List[str], build_tool: str = "cmake"):
        self.project_name = project_name
        self.watch_paths = watch_paths
        self.build_tool = build_tool
        self.cache = BuildCache()
        self.dependency_graph = DependencyGraph()
        self.build_queue = BuildQueue()
        self.builder = IncrementalBuilder(project_name, build_tool=build_tool)
        self.observer = None
        self.running = False
    
    def initial_build(self):
        """Perform initial build."""
        print("Performing initial build...")
        
        # Configure build if needed
        if not os.path.exists(self.builder.build_dir):
            os.makedirs(self.builder.build_dir)
            subprocess.run([
                "cmake", "-B", self.builder.build_dir,
                "-DCMAKE_BUILD_TYPE=Debug",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
            ])
        
        # Full build
        if self.builder.build():
            print("✓ Initial build complete")
            # Reload dependency graph
            self.dependency_graph.load_compile_commands()
        else:
            print("✗ Initial build failed")
            sys.exit(1)
    
    def build_worker(self):
        """Worker thread for processing build tasks."""
        while self.running:
            task = self.build_queue.get_task()
            
            if task:
                print(f"\\nBuilding: {task}")
                if self.builder.build(task):
                    self.cache.save_cache()
                    # Run tests if configured
                    self.run_tests()
            else:
                time.sleep(0.1)
    
    def run_tests(self):
        """Run tests after successful build."""
        # Check if tests are configured
        test_executable = os.path.join(self.builder.build_dir, "tests", f"{self.project_name}_test")
        
        if os.path.exists(test_executable):
            print("Running tests...")
            result = subprocess.run([test_executable], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✓ All tests passed")
            else:
                print("✗ Tests failed")
                print(result.stdout)
    
    def start(self):
        """Start the hot-reload server."""
        self.running = True
        
        # Perform initial build
        self.initial_build()
        
        # Start build worker thread
        build_thread = threading.Thread(target=self.build_worker, daemon=True)
        build_thread.start()
        
        # Setup file watcher
        event_handler = CppFileHandler(self.build_queue, self.cache, self.dependency_graph)
        self.observer = Observer()
        
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(event_handler, path, recursive=True)
                print(f"Watching: {path}")
        
        self.observer.start()
        
        print(f"\\n🔥 Hot-reload server started for {self.project_name}")
        print("Press Ctrl+C to stop\\n")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the hot-reload server."""
        print("\\nShutting down hot-reload server...")
        self.running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        self.builder.print_statistics()
        self.cache.save_cache()
        
        print("Hot-reload server stopped")

def main():
    parser = argparse.ArgumentParser(description='C++ Hot-Reload Development Server')
    parser.add_argument('project_name', help='Project name')
    parser.add_argument('--watch', '-w', nargs='+', default=['src', 'include', 'tests'],
                       help='Paths to watch for changes')
    parser.add_argument('--build-tool', '-b', choices=['cmake', 'make', 'ninja'],
                       default='cmake', help='Build tool to use')
    parser.add_argument('--build-dir', '-d', default='build',
                       help='Build directory')
    
    args = parser.parse_args()
    
    server = HotReloadServer(
        project_name=args.project_name,
        watch_paths=args.watch,
        build_tool=args.build_tool
    )
    
    server.start()

if __name__ == '__main__':
    main()`;
  }

  private static generateEntrSetup(): string {
    return `#!/bin/bash
# Setup script for entr file watcher

set -euo pipefail

echo "Setting up entr for hot-reload development..."

# Check if entr is installed
if command -v entr &> /dev/null; then
    echo "✓ entr is already installed"
    entr_version=$(entr 2>&1 | head -n1 || echo "Unknown version")
    echo "  Version: $entr_version"
else
    echo "Installing entr..."
    
    # Detect OS and install entr
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y entr
        elif command -v yum &> /dev/null; then
            # RHEL/CentOS/Fedora
            sudo yum install -y entr
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            sudo pacman -S --noconfirm entr
        else
            echo "Please install entr manually for your Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install entr
        else
            echo "Please install Homebrew first: https://brew.sh"
            exit 1
        fi
    elif [[ "$OSTYPE" == "freebsd"* ]]; then
        # FreeBSD
        sudo pkg install -y entr
    else
        echo "Unsupported OS: $OSTYPE"
        echo "Please install entr manually"
        exit 1
    fi
fi

# Create example entr usage script
cat > entr_example.sh << 'EOF'
#!/bin/bash
# Example entr usage for C++ development

# Watch C++ source files and rebuild on change
find src include -name "*.cpp" -o -name "*.h" | entr -c make

# Watch and run tests on change
find src tests -name "*.cpp" -o -name "*.h" | entr -c make test

# Watch with custom command
find . -name "*.cpp" -o -name "*.h" | entr -c bash -c 'clear && make && ./build/app'

# Watch with notification on success/failure
find src -name "*.cpp" | entr -c bash -c 'make && notify-send "Build Success" || notify-send "Build Failed"'
EOF

chmod +x entr_example.sh

echo ""
echo "✓ entr setup complete!"
echo ""
echo "Example usage:"
echo "  ./entr_example.sh"
echo ""
echo "For more information:"
echo "  man entr"
echo "  http://eradman.com/entrproject/"`;
  }

  private static generateWatchmanConfig(projectName: string): string {
    return `{
  "ignore_dirs": [
    "build",
    ".git",
    ".cache",
    "node_modules",
    "cmake-build-debug",
    "cmake-build-release",
    ".idea",
    ".vscode"
  ],
  "ignore_vcs": ["git"],
  "settle": 500,
  "root_files": ["CMakeLists.txt", ".watchmanconfig"],
  "prefer_watchman_since": true,
  "gc_age_seconds": 3600,
  "gc_interval_seconds": 600,
  "hint_num_files_per_dir": 50,
  "subscriptions": {
    "cpp-hot-reload": {
      "expression": [
        "anyof",
        ["suffix", "cpp"],
        ["suffix", "cc"],
        ["suffix", "cxx"],
        ["suffix", "c"],
        ["suffix", "h"],
        ["suffix", "hpp"],
        ["suffix", "hxx"],
        ["name", "CMakeLists.txt"],
        ["suffix", "cmake"]
      ],
      "fields": ["name", "size", "mtime_ms", "exists", "type"],
      "since": "c:0:0",
      "defer": ["hg.update"],
      "drop": ["hg.update"]
    }
  },
  "triggers": [
    {
      "name": "cpp-rebuild",
      "expression": [
        "anyof",
        ["suffix", "cpp"],
        ["suffix", "cc"],
        ["suffix", "h"],
        ["suffix", "hpp"]
      ],
      "command": ["cmake", "--build", "build", "--parallel"],
      "append_files": false,
      "stdin": ["name"],
      "stdout": ">build.log",
      "stderr": ">build-error.log",
      "max_files_stdin": 100
    }
  ]
}`;
  }

  private static generateInotifySetup(): string {
    return `#!/bin/bash
# Setup script for inotify-tools

set -euo pipefail

echo "Setting up inotify-tools for hot-reload development..."

# Check if inotify-tools is installed
if command -v inotifywait &> /dev/null; then
    echo "✓ inotify-tools is already installed"
    inotifywait --version | head -n1
else
    echo "Installing inotify-tools..."
    
    # Only works on Linux
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        echo "Error: inotify-tools is only available on Linux"
        echo "Consider using fswatch or entr on other platforms"
        exit 1
    fi
    
    # Detect Linux distribution and install
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y inotify-tools
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS/Fedora
        sudo yum install -y inotify-tools
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        sudo pacman -S --noconfirm inotify-tools
    elif command -v zypper &> /dev/null; then
        # openSUSE
        sudo zypper install -y inotify-tools
    else
        echo "Please install inotify-tools manually for your Linux distribution"
        exit 1
    fi
fi

# Check and increase inotify watch limit if needed
current_limit=$(cat /proc/sys/fs/inotify/max_user_watches)
recommended_limit=524288

if [ "$current_limit" -lt "$recommended_limit" ]; then
    echo "Current inotify watch limit: $current_limit"
    echo "Increasing to recommended limit: $recommended_limit"
    
    # Temporary increase
    sudo sysctl fs.inotify.max_user_watches=$recommended_limit
    
    # Permanent increase
    echo "fs.inotify.max_user_watches=$recommended_limit" | sudo tee -a /etc/sysctl.conf
    
    echo "✓ Increased inotify watch limit"
else
    echo "✓ inotify watch limit is sufficient: $current_limit"
fi

# Create example inotify usage script
cat > inotify_example.sh << 'EOF'
#!/bin/bash
# Example inotify usage for C++ development

# Watch single directory
inotifywait -m -r -e modify,create,delete,move src/ |
while read path action file; do
    echo "File $file in $path was $action"
    make
done

# Watch multiple directories with filtering
inotifywait -m -r -e modify,create,delete \
    --exclude '\\.(o|so|a|tmp)$' \
    --format '%w%f %e %T' \
    --timefmt '%Y-%m-%d %H:%M:%S' \
    src/ include/ tests/ |
while read file event timestamp; do
    echo "[$timestamp] $event: $file"
    if [[ "$file" =~ \\.(cpp|cc|h|hpp)$ ]]; then
        cmake --build build --parallel
    fi
done

# Watch with batch processing (wait for quiet period)
batch_timeout=2
last_change=$(date +%s)

inotifywait -m -r -e modify src/ include/ |
while read path action file; do
    current_time=$(date +%s)
    last_change=$current_time
    
    # Start a background job to build after quiet period
    (
        sleep $batch_timeout
        if [ $(date +%s) -ge $((last_change + batch_timeout)) ]; then
            echo "Building after batch timeout..."
            make
        fi
    ) &
done
EOF

chmod +x inotify_example.sh

echo ""
echo "✓ inotify-tools setup complete!"
echo ""
echo "Example usage:"
echo "  ./inotify_example.sh"
echo ""
echo "For more information:"
echo "  man inotifywait"
echo "  man inotifywatch"`;
  }

  private static generateFswatchSetup(): string {
    return `#!/bin/bash
# Setup script for fswatch

set -euo pipefail

echo "Setting up fswatch for hot-reload development..."

# Check if fswatch is installed
if command -v fswatch &> /dev/null; then
    echo "✓ fswatch is already installed"
    fswatch --version
else
    echo "Installing fswatch..."
    
    # Detect OS and install fswatch
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y fswatch
        elif command -v yum &> /dev/null; then
            # RHEL/CentOS/Fedora - build from source
            sudo yum install -y gcc-c++ make autoconf automake libtool
            git clone https://github.com/emcrisostomo/fswatch.git
            cd fswatch
            ./autogen.sh
            ./configure
            make
            sudo make install
            cd ..
            rm -rf fswatch
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            sudo pacman -S --noconfirm fswatch
        else
            echo "Please install fswatch manually for your Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install fswatch
        else
            echo "Please install Homebrew first: https://brew.sh"
            exit 1
        fi
    elif [[ "$OSTYPE" == "freebsd"* ]]; then
        # FreeBSD
        sudo pkg install -y fswatch
    else
        echo "Building fswatch from source..."
        git clone https://github.com/emcrisostomo/fswatch.git
        cd fswatch
        ./autogen.sh
        ./configure
        make
        sudo make install
        cd ..
        rm -rf fswatch
    fi
fi

# Create example fswatch usage script
cat > fswatch_example.sh << 'EOF'
#!/bin/bash
# Example fswatch usage for C++ development

# Basic file watching with rebuild
fswatch -o src include | xargs -n1 -I{} make

# Watch with file filters and custom action
fswatch -r -e ".*" -i "\\\\.cpp$" -i "\\\\.h$" -i "\\\\.hpp$" src include |
while read file; do
    echo "Changed: $file"
    cmake --build build --parallel
done

# Watch with multiple monitors (use best available)
fswatch -r -m poll_monitor -l 0.5 src include |
while read file; do
    make
done

# Watch with batch processing
fswatch -r -o --batch-marker=EOF src include |
while read line; do
    if [ "$line" = "EOF" ]; then
        echo "Batch complete, rebuilding..."
        make
    fi
done

# Watch with extended info
fswatch -x -r src include |
while read file event; do
    echo "File: $file"
    echo "Event: $event"
    
    case "$event" in
        *Created*|*Updated*|*Renamed*)
            cmake --build build --parallel
            ;;
        *Removed*)
            echo "File removed, full rebuild recommended"
            ;;
    esac
done

# Platform-specific optimized watching
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - use FSEvents
    fswatch -r -m fsevents_monitor src include | xargs -n1 -I{} make
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux - use inotify
    fswatch -r -m inotify_monitor src include | xargs -n1 -I{} make
else
    # Fallback to polling
    fswatch -r -m poll_monitor -l 1 src include | xargs -n1 -I{} make
fi
EOF

chmod +x fswatch_example.sh

# Create configuration file
cat > .fswatch.conf << 'EOF'
# fswatch configuration
--recursive
--extended
--exclude=".*\\.o$"
--exclude=".*\\.so$"
--exclude=".*\\.a$"
--exclude="^\\.git"
--exclude="^build/"
--exclude="^cmake-build-.*/"
--include=".*\\.cpp$"
--include=".*\\.cc$"
--include=".*\\.cxx$"
--include=".*\\.h$"
--include=".*\\.hpp$"
--include=".*\\.hxx$"
--include="CMakeLists\\.txt$"
--include=".*\\.cmake$"
EOF

echo ""
echo "✓ fswatch setup complete!"
echo ""
echo "Example usage:"
echo "  ./fswatch_example.sh"
echo ""
echo "Configuration file created: .fswatch.conf"
echo ""
echo "For more information:"
echo "  man fswatch"
echo "  https://github.com/emcrisostomo/fswatch"`;
  }

  private static generateWatchmanProjectConfig(): string {
    return `{
  "ignore_dirs": [
    ".git",
    "build",
    ".cache",
    "cmake-build-debug",
    "cmake-build-release"
  ]
}`;
  }

  private static generateHotReloadReadme(projectName: string): string {
    return `# Hot-Reload Development for ${projectName}

This directory contains configuration and tools for hot-reload development, enabling automatic rebuilding when source files change.

## Overview

Hot-reload development improves productivity by automatically rebuilding your C++ project when source files are modified. This implementation supports multiple file watching tools and build systems.

## Quick Start

\`\`\`bash
# Using the main hot-reload script
./scripts/hot-reload.sh

# Using Python-based watcher with advanced features
python3 scripts/watch-and-build.py ${projectName}

# Using Docker for consistent environment
docker-compose -f docker-compose.dev.yml up
\`\`\`

## Supported File Watchers

### 1. entr (Recommended for simplicity)
- **Pros**: Simple, efficient, cross-platform
- **Cons**: Requires restart when directories change
- **Setup**: \`./hot-reload/entr-setup.sh\`

### 2. Watchman (Recommended for large projects)
- **Pros**: Highly scalable, intelligent caching, Facebook's tool
- **Cons**: More complex setup, requires daemon
- **Setup**: Follow watchman installation guide

### 3. inotify (Linux only)
- **Pros**: Native Linux kernel support, very efficient
- **Cons**: Linux-only, watch limit constraints
- **Setup**: \`./hot-reload/inotify-setup.sh\`

### 4. fswatch (Cross-platform)
- **Pros**: Works on macOS, Linux, BSD, Windows
- **Cons**: Different backends per platform
- **Setup**: \`./hot-reload/fswatch-setup.sh\`

## Build Strategies

### 1. Rebuild Strategy
- Rebuilds entire project on any change
- Simple but slower for large projects
- Best for small projects or major changes

### 2. Incremental Strategy (Default)
- Only rebuilds changed targets
- Faster for most use cases
- Relies on build system dependency tracking

### 3. Module Strategy
- Rebuilds only the affected module
- Fastest for well-modularized projects
- Requires CMake target organization

## Advanced Features

### Build Caching

#### ccache Integration
\`\`\`bash
# Install ccache
sudo apt-get install ccache  # Debian/Ubuntu
brew install ccache          # macOS

# Enable in hot-reload
export CC="ccache gcc"
export CXX="ccache g++"
\`\`\`

#### distcc for Distributed Builds
\`\`\`bash
# Setup distcc
sudo apt-get install distcc

# Configure hosts
export DISTCC_HOSTS="localhost/4 192.168.1.100/8"
\`\`\`

### Intelligent Dependency Analysis
The Python-based watcher includes:
- Dependency graph analysis
- Affected file detection
- Build task deduplication
- Parallel build coordination

### Performance Monitoring
- Build time tracking
- Success/failure statistics
- Memory usage monitoring
- Cache hit rates

## IDE Integration

### Visual Studio Code
Configured tasks and launch configurations are provided:
- **Build Task**: Ctrl+Shift+B
- **Debug with Hot-Reload**: F5
- **Watch Mode**: Task "Start Hot-Reload"

### CLion
1. Add External Tool for hot-reload script
2. Configure File Watchers plugin
3. Use built-in CMake reload

### Vim/Neovim
\`\`\`vim
" Add to .vimrc
autocmd BufWritePost *.cpp,*.h silent! !touch .rebuild
nnoremap <leader>hr :!./scripts/hot-reload.sh<CR>
\`\`\`

## Configuration Options

### Environment Variables
\`\`\`bash
# Watcher tool selection
export HOT_RELOAD_WATCHER=entr  # entr|watchman|inotify|fswatch

# Build tool
export HOT_RELOAD_BUILD_TOOL=cmake  # cmake|make|ninja|bazel

# Reload strategy
export HOT_RELOAD_STRATEGY=incremental  # rebuild|incremental|module

# Enable features
export HOT_RELOAD_TESTS=true
export HOT_RELOAD_BENCHMARKS=false
export HOT_RELOAD_DEBUGGER=false
\`\`\`

### Custom Watch Paths
Edit \`hot-reload.sh\` to add custom paths:
\`\`\`bash
CUSTOM_PATHS=("config" "resources" "shaders")
\`\`\`

## Troubleshooting

### Common Issues

1. **"Too many open files" error**
   \`\`\`bash
   # Increase file descriptor limit
   ulimit -n 4096
   
   # For inotify, increase watch limit
   sudo sysctl fs.inotify.max_user_watches=524288
   \`\`\`

2. **Slow rebuild times**
   - Enable ccache
   - Use incremental or module strategy
   - Consider using Ninja instead of Make
   - Check for unnecessary includes

3. **Watcher not detecting changes**
   - Check ignored directories in config
   - Verify file permissions
   - Ensure watcher is monitoring correct paths

4. **Build failures in hot-reload**
   - Check build logs in build directory
   - Ensure all dependencies are installed
   - Verify CMake configuration

### Debug Mode
\`\`\`bash
# Enable debug output
export HOT_RELOAD_DEBUG=1
./scripts/hot-reload.sh
\`\`\`

## Performance Tips

1. **Use Precompiled Headers**
   \`\`\`cmake
   target_precompile_headers(${projectName} PRIVATE pch.h)
   \`\`\`

2. **Optimize Include Guards**
   Use \`#pragma once\` for faster preprocessing

3. **Module Organization**
   Split large files into smaller modules for faster incremental builds

4. **Build Parallelization**
   \`\`\`bash
   # Use all CPU cores
   cmake --build build -j$(nproc)
   \`\`\`

5. **Unity Builds**
   Enable CMake unity builds for faster full rebuilds

## Docker Development

### Using Docker Compose
\`\`\`bash
# Start development environment
docker-compose -f docker-compose.dev.yml up

# Rebuild container
docker-compose -f docker-compose.dev.yml build

# Enter container shell
docker-compose -f docker-compose.dev.yml exec dev bash
\`\`\`

### Benefits
- Consistent environment
- Isolated dependencies
- Easy onboarding
- CI/CD parity

## Best Practices

1. **Organize Code for Fast Builds**
   - Use forward declarations
   - Minimize header dependencies
   - Implement in source files, not headers

2. **Configure Ignore Patterns**
   - Exclude build directories
   - Ignore temporary files
   - Skip version control directories

3. **Use Appropriate Strategies**
   - Module strategy for large projects
   - Incremental for medium projects
   - Rebuild for small projects

4. **Monitor Performance**
   - Track build times
   - Identify slow modules
   - Optimize bottlenecks

## Resources

- [entr Documentation](http://eradman.com/entrproject/)
- [Watchman Documentation](https://facebook.github.io/watchman/)
- [inotify Manual](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [fswatch Documentation](https://github.com/emcrisostomo/fswatch)
- [ccache Documentation](https://ccache.dev/)
- [distcc Documentation](https://distcc.github.io/)`;
  }

  private static generateHotReloadCMake(): string {
    return `# Hot-Reload CMake Configuration
# Optimizations and utilities for fast incremental builds

# Hot-reload mode detection
option(ENABLE_HOT_RELOAD "Enable hot-reload optimizations" OFF)

if(ENABLE_HOT_RELOAD)
    message(STATUS "Hot-reload mode enabled")
    
    # Faster build settings for development
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    
    # Disable optimizations for faster compilation
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O0 -g)
    endif()
    
    # Enable incremental linking
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        add_link_options(/INCREMENTAL)
    endif()
endif()

# ccache integration
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND AND ENABLE_HOT_RELOAD)
    message(STATUS "ccache found, enabling compiler cache")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    
    # ccache configuration
    set(ENV{CCACHE_BASEDIR} \${CMAKE_SOURCE_DIR})
    set(ENV{CCACHE_SLOPPINESS} "pch_defines,time_macros")
endif()

# distcc integration
find_program(DISTCC_FOUND distcc)
if(DISTCC_FOUND AND ENABLE_HOT_RELOAD)
    message(STATUS "distcc found, enabling distributed compilation")
    if(NOT CCACHE_FOUND)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE distcc)
    else()
        # Use both ccache and distcc
        set(ENV{CCACHE_PREFIX} distcc)
    endif()
endif()

# Precompiled headers for faster builds
function(target_enable_pch TARGET)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.16" AND ENABLE_HOT_RELOAD)
        # Collect common headers
        set(PCH_HEADERS
            <algorithm>
            <array>
            <chrono>
            <cstddef>
            <cstdint>
            <cstdlib>
            <exception>
            <functional>
            <iostream>
            <iterator>
            <limits>
            <map>
            <memory>
            <numeric>
            <set>
            <sstream>
            <string>
            <string_view>
            <type_traits>
            <unordered_map>
            <unordered_set>
            <utility>
            <vector>
        )
        
        target_precompile_headers(\${TARGET} PRIVATE \${PCH_HEADERS})
    endif()
endfunction()

# Unity builds for faster full rebuilds
function(target_enable_unity_build TARGET)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.16" AND ENABLE_HOT_RELOAD)
        set_target_properties(\${TARGET} PROPERTIES UNITY_BUILD ON)
        set_target_properties(\${TARGET} PROPERTIES UNITY_BUILD_BATCH_SIZE 16)
    endif()
endfunction()

# Hot-reload friendly target configuration
function(configure_hot_reload_target TARGET)
    if(ENABLE_HOT_RELOAD)
        # Enable fast builds
        target_enable_pch(\${TARGET})
        
        # Disable certain warnings for faster compilation
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(\${TARGET} PRIVATE
                -Wno-unused-parameter
                -Wno-unused-variable
                -Wno-unused-function
            )
        endif()
        
        # Add hot-reload define
        target_compile_definitions(\${TARGET} PRIVATE HOT_RELOAD_ENABLED)
        
        # Create symlink for easy execution
        add_custom_command(TARGET \${TARGET} POST_BUILD
            COMMAND \${CMAKE_COMMAND} -E create_symlink
                    \$<TARGET_FILE:\${TARGET}>
                    \${CMAKE_BINARY_DIR}/\${TARGET}_hot
            COMMENT "Creating hot-reload symlink"
        )
    endif()
endfunction()

# Dependency change detection
function(add_hot_reload_deps TARGET)
    if(ENABLE_HOT_RELOAD)
        # Touch a timestamp file when target is built
        add_custom_command(TARGET \${TARGET} POST_BUILD
            COMMAND \${CMAKE_COMMAND} -E touch
                    \${CMAKE_BINARY_DIR}/.hot_reload_\${TARGET}
            COMMENT "Updating hot-reload timestamp"
        )
    endif()
endfunction()

# Test runner for hot-reload
function(add_hot_reload_test TARGET)
    if(ENABLE_HOT_RELOAD AND BUILD_TESTING)
        add_custom_target(hot_test_\${TARGET}
            COMMAND \$<TARGET_FILE:\${TARGET}>
            DEPENDS \${TARGET}
            WORKING_DIRECTORY \${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Running hot-reload test: \${TARGET}"
        )
    endif()
endfunction()

# Benchmark runner for hot-reload
function(add_hot_reload_benchmark TARGET)
    if(ENABLE_HOT_RELOAD)
        add_custom_target(hot_bench_\${TARGET}
            COMMAND \$<TARGET_FILE:\${TARGET}> --benchmark_format=json
            DEPENDS \${TARGET}
            WORKING_DIRECTORY \${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Running hot-reload benchmark: \${TARGET}"
        )
    endif()
endfunction()

# Module-based build organization
function(create_hot_reload_module MODULE_NAME)
    if(ENABLE_HOT_RELOAD)
        # Create a library for the module
        file(GLOB_RECURSE MODULE_SOURCES
            \${CMAKE_CURRENT_SOURCE_DIR}/\${MODULE_NAME}/*.cpp
            \${CMAKE_CURRENT_SOURCE_DIR}/\${MODULE_NAME}/*.cc
        )
        
        if(MODULE_SOURCES)
            add_library(\${MODULE_NAME}_module STATIC \${MODULE_SOURCES})
            configure_hot_reload_target(\${MODULE_NAME}_module)
            
            # Add module to main target
            target_link_libraries(\${PROJECT_NAME} PRIVATE \${MODULE_NAME}_module)
        endif()
    endif()
endfunction()

# Print hot-reload configuration
if(ENABLE_HOT_RELOAD)
    message(STATUS "")
    message(STATUS "Hot-Reload Configuration:")
    message(STATUS "  Build Type: \${CMAKE_BUILD_TYPE}")
    message(STATUS "  Compiler Cache: \${CCACHE_FOUND}")
    message(STATUS "  Distributed Build: \${DISTCC_FOUND}")
    message(STATUS "  Export Compile Commands: ON")
    message(STATUS "  Optimization Level: O0")
    message(STATUS "")
endif()`;
  }

  private static generateCcacheConfig(): string {
    return `# ccache configuration for hot-reload development

# Cache size (default: 5G)
max_size = 10G

# Compression (faster builds, more disk usage)
compression = true
compression_level = 1

# Cache statistics
stats = true

# Sloppiness settings for C++ development
sloppiness = file_macro,pch_defines,time_macros,include_file_ctime,include_file_mtime

# Direct mode (faster)
direct_mode = true

# Depend mode (better cache hits)
depend_mode = true

# File clone (save disk space on supported filesystems)
file_clone = true

# Hard link (save disk space)
hard_link = true

# Ignore temporary preprocessor files
temporary_dir = /tmp

# Hash directory levels
cache_dir_levels = 3

# Keep comments in preprocessor output
keep_comments_cpp = true

# PCH handling
pch_external_checksum = true

# Debugging (disable in production)
debug = false

# Log file (optional)
# log_file = /tmp/ccache.log

# Ignore certain paths
ignore_paths = /usr/include:/usr/local/include

# Compiler check
compiler_check = content

# Extension handling
cpp_extension = cpp,cc,cxx,CPP,CXX,C++`;
  }

  private static generateDistccConfig(): string {
    return `# distcc configuration for distributed compilation

# List of volunteer hosts
# Format: hostname/limit hostname:port/limit
# Examples:
# DISTCC_HOSTS="localhost/4 192.168.1.100/8 192.168.1.101/8"
# DISTCC_HOSTS="localhost/4 fast-machine/16 @slow-machine/2"
# DISTCC_HOSTS="--randomize localhost/4 host1/8,lzo host2/8,lzo"

# For hot-reload development (adjust to your network)
DISTCC_HOSTS="localhost/4"

# Fallback to local compilation
DISTCC_FALLBACK=1

# Verbose output (disable in production)
DISTCC_VERBOSE=0

# Log file
DISTCC_LOG="/tmp/distcc.log"

# Temporary directory
DISTCC_DIR="/tmp/.distcc"

# SSH command (if using SSH)
# DISTCC_SSH="ssh -c aes128-ctr"

# Compression
DISTCC_COMPRESS=1

# Color output
DISTCC_COLOR=1

# Save temporary files (for debugging)
# DISTCC_SAVE_TEMPS=1

# Backoff period
DISTCC_BACKOFF_PERIOD=60

# IO timeout
DISTCC_IO_TIMEOUT=300

# Skip preprocessor on client
# DISTCC_SKIP_LOCAL_PREPROCESSING=1

# Authentication (if needed)
# DISTCC_AUTH=password

# Maximum retries
DISTCC_MAX_RETRIES=3`;
  }

  private static generateClangdConfig(): string {
    return `# clangd configuration for hot-reload development

CompileFlags:
  # Compiler flags
  Add:
    - -std=c++17
    - -Wall
    - -Wextra
    - -Wpedantic
    - -Wno-unused-parameter  # Reduce noise during development
    - -Wno-unused-variable
    - -Wno-unused-function
    - -fcolor-diagnostics
    - -fansi-escape-codes
  
  # Remove flags that slow down parsing
  Remove:
    - -forward-unknown-to-host-compiler
    - --generate-code*
    - --expt-relaxed-constexpr
    - -fcoroutines-ts

  # Compiler path (adjust if needed)
  Compiler: clang++

Diagnostics:
  # Disable some checks during hot-reload for faster parsing
  ClangTidy:
    Add:
      - bugprone-*
      - performance-*
      - readability-identifier-naming
      - modernize-use-auto
      - modernize-use-nullptr
      - modernize-use-override
    Remove:
      - readability-magic-numbers
      - readability-braces-around-statements
      - modernize-use-trailing-return-type
      - google-readability-todo
      - cert-err58-cpp
    
    # Check options
    CheckOptions:
      readability-identifier-naming.NamespaceCase: lower_case
      readability-identifier-naming.ClassCase: CamelCase
      readability-identifier-naming.StructCase: CamelCase
      readability-identifier-naming.FunctionCase: camelCase
      readability-identifier-naming.VariableCase: camelCase
      readability-identifier-naming.ConstantCase: UPPER_CASE
      readability-identifier-naming.ParameterCase: camelCase
      readability-identifier-naming.MemberCase: camelCase
      readability-identifier-naming.PrivateMemberSuffix: _
  
  # Limit diagnostics during development
  UnusedIncludes: Strict
  MissingIncludes: Relaxed

Index:
  # Background indexing
  Background: Build
  
  # Standard library headers
  StandardLibrary: Yes

Completion:
  # Include all overloads
  AllScopes: Yes
  
  # Detailed completion
  DetailedLabel: Yes
  
  # Filter and sort
  FilterAndSort: Yes

InlayHints:
  # Enable inlay hints
  Enabled: Yes
  ParameterNames: Yes
  DeducedTypes: Yes

Hover:
  # Show documentation
  ShowAKA: Yes

# Performance settings for hot-reload
# Reduces memory usage and improves responsiveness
BackgroundIndex: Yes
BuildDynamicSymbolIndex: Yes
HeaderInsertion: IWYU`;
  }

  private static generateDevelopmentServer(projectName: string): string {
    return `#!/bin/bash
# Development Server with Hot-Reload for ${projectName}
# Integrated development environment with multiple services

set -euo pipefail

# Configuration
PROJECT_NAME="${projectName}"
BUILD_DIR="build"
PORT=\${DEV_SERVER_PORT:-8080}
API_PORT=\${API_SERVER_PORT:-3000}
METRICS_PORT=\${METRICS_PORT:-9090}

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
BLUE='\\033[0;34m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

# PID tracking
PIDS=()

echo -e "\\${BLUE}=== ${projectName} Development Server ===\\${NC}"

# Function to cleanup on exit
cleanup() {
    echo -e "\\n\\${YELLOW}Shutting down development server...\\${NC}"
    
    # Kill all child processes
    for pid in "\${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
        fi
    done
    
    # Stop any remaining services
    pkill -f "hot-reload.sh" || true
    pkill -f "${projectName}" || true
    
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "\\${YELLOW}Creating initial build...\\${NC}"
    cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DENABLE_HOT_RELOAD=ON
    cmake --build "$BUILD_DIR" --parallel
fi

# Start hot-reload watcher
echo -e "\\${GREEN}Starting hot-reload watcher...\\${NC}"
./scripts/hot-reload.sh &
PIDS+=($!)
sleep 2

# Start the main application
echo -e "\\${GREEN}Starting ${projectName} application...\\${NC}"
if [ -f "$BUILD_DIR/${projectName}" ]; then
    "$BUILD_DIR/${projectName}" --port "$PORT" &
    PIDS+=($!)
    echo -e "\\${GREEN}✓ Application running on http://localhost:$PORT\\${NC}"
else
    echo -e "\\${RED}✗ Application binary not found\\${NC}"
fi

# Start API mock server (if needed)
if command -v json-server &> /dev/null; then
    if [ -f "mock-api/db.json" ]; then
        echo -e "\\${GREEN}Starting mock API server...\\${NC}"
        json-server --watch mock-api/db.json --port "$API_PORT" &
        PIDS+=($!)
        echo -e "\\${GREEN}✓ Mock API running on http://localhost:$API_PORT\\${NC}"
    fi
fi

# Start metrics server
if [ -f "$BUILD_DIR/metrics_server" ]; then
    echo -e "\\${GREEN}Starting metrics server...\\${NC}"
    "$BUILD_DIR/metrics_server" --port "$METRICS_PORT" &
    PIDS+=($!)
    echo -e "\\${GREEN}✓ Metrics available on http://localhost:$METRICS_PORT/metrics\\${NC}"
fi

# Start documentation server
if command -v python3 &> /dev/null && [ -d "docs" ]; then
    echo -e "\\${GREEN}Starting documentation server...\\${NC}"
    cd docs && python3 -m http.server 8000 &
    PIDS+=($!)
    cd ..
    echo -e "\\${GREEN}✓ Documentation available on http://localhost:8000\\${NC}"
fi

# Development dashboard
echo -e "\\n\\${BLUE}=== Development Dashboard ===\\${NC}"
echo -e "Application:    http://localhost:$PORT"
echo -e "API:           http://localhost:$API_PORT"
echo -e "Metrics:       http://localhost:$METRICS_PORT/metrics"
echo -e "Documentation: http://localhost:8000"
echo -e "\\n\\${YELLOW}Press Ctrl+C to stop all services\\${NC}\\n"

# Monitor services
while true; do
    # Check if main application is still running
    if [ -f "$BUILD_DIR/${projectName}" ]; then
        if ! pgrep -f "${projectName}" > /dev/null; then
            echo -e "\\${YELLOW}Application crashed, restarting...\\${NC}"
            "$BUILD_DIR/${projectName}" --port "$PORT" &
            PIDS+=($!)
        fi
    fi
    
    sleep 5
done`;
  }

  private static generateDevDockerfile(projectName: string): string {
    return `# Development Dockerfile for ${projectName}
# Optimized for hot-reload development

FROM ubuntu:22.04

# Install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    cmake \\
    ninja-build \\
    ccache \\
    gdb \\
    valgrind \\
    clang \\
    clang-tools \\
    clang-format \\
    clang-tidy \\
    lldb \\
    git \\
    curl \\
    wget \\
    python3 \\
    python3-pip \\
    entr \\
    inotify-tools \\
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install watchdog pytest black flake8

# Install development tools
RUN apt-get update && apt-get install -y \\
    vim \\
    tmux \\
    htop \\
    tree \\
    jq \\
    ripgrep \\
    fd-find \\
    && rm -rf /var/lib/apt/lists/*

# Create development user
RUN useradd -m -s /bin/bash developer && \\
    usermod -aG sudo developer && \\
    echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up ccache
ENV PATH="/usr/lib/ccache:$PATH"
ENV CCACHE_DIR=/home/developer/.ccache
ENV CCACHE_MAXSIZE=5G

# Switch to developer user
USER developer
WORKDIR /home/developer/project

# Configure shell
RUN echo "alias ll='ls -alF'" >> ~/.bashrc && \\
    echo "alias la='ls -A'" >> ~/.bashrc && \\
    echo "alias l='ls -CF'" >> ~/.bashrc && \\
    echo "export PS1='\\[\\033[01;32m\\]\\u@dev\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '" >> ~/.bashrc

# Pre-create directories
RUN mkdir -p ~/.ccache ~/.cache

# Default command
CMD ["/bin/bash"]`;
  }

  private static generateDevDockerCompose(projectName: string): string {
    return `version: '3.8'

services:
  dev:
    build:
      context: .
      dockerfile: docker/Dockerfile.dev
    image: ${projectName}-dev:latest
    container_name: ${projectName}-dev
    
    volumes:
      # Mount source code
      - .:/home/developer/project:cached
      
      # Persistent ccache
      - ccache-data:/home/developer/.ccache
      
      # Persistent build directory
      - build-data:/home/developer/project/build
      
      # Share SSH keys for git
      - ~/.ssh:/home/developer/.ssh:ro
      
      # Share git config
      - ~/.gitconfig:/home/developer/.gitconfig:ro
    
    environment:
      - DISPLAY=\${DISPLAY}
      - TERM=xterm-256color
      - ENABLE_HOT_RELOAD=true
      - CMAKE_BUILD_TYPE=Debug
      - CCACHE_DIR=/home/developer/.ccache
      - CCACHE_MAXSIZE=10G
    
    # For GUI applications (optional)
    volumes:
      - /tmp/.X11-unix:/tmp/.X11-unix:rw
    
    network_mode: host
    
    # Keep container running
    stdin_open: true
    tty: true
    
    # Development ports
    ports:
      - "8080:8080"   # Application
      - "3000:3000"   # API
      - "9090:9090"   # Metrics
      - "8000:8000"   # Documentation
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
    
    # Health check
    healthcheck:
      test: ["CMD", "cmake", "--version"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    
    command: |
      bash -c "
        echo 'Starting development environment...'
        echo 'Run: ./scripts/hot-reload.sh to start hot-reload'
        echo 'Or use: ./scripts/development-server.sh for full stack'
        exec bash
      "

  # Optional services
  
  # Database for development
  db:
    image: postgres:15
    container_name: ${projectName}-db
    environment:
      - POSTGRES_USER=developer
      - POSTGRES_PASSWORD=devpass
      - POSTGRES_DB=${projectName}_dev
    volumes:
      - db-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    profiles:
      - with-db
  
  # Redis for caching
  redis:
    image: redis:7-alpine
    container_name: ${projectName}-redis
    ports:
      - "6379:6379"
    profiles:
      - with-redis
  
  # Documentation server
  docs:
    image: nginx:alpine
    container_name: ${projectName}-docs
    volumes:
      - ./docs:/usr/share/nginx/html:ro
    ports:
      - "8000:80"
    profiles:
      - with-docs

volumes:
  ccache-data:
  build-data:
  db-data:

networks:
  default:
    name: ${projectName}-dev-network`;
  }

  private static generateVSCodeTasks(): string {
    return `{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Start Hot-Reload",
      "type": "shell",
      "command": "./scripts/hot-reload.sh",
      "group": {
        "kind": "build",
        "isDefault": true
      },
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": true,
        "panel": "dedicated",
        "showReuseMessage": false,
        "clear": true
      },
      "problemMatcher": [
        "$gcc"
      ],
      "isBackground": true,
      "dependsOn": [
        "Create Build Directory"
      ]
    },
    {
      "label": "Create Build Directory",
      "type": "shell",
      "command": "cmake",
      "args": [
        "-B",
        "build",
        "-DCMAKE_BUILD_TYPE=Debug",
        "-DENABLE_HOT_RELOAD=ON",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
      ],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "silent",
        "focus": false,
        "panel": "shared"
      }
    },
    {
      "label": "Build (Debug)",
      "type": "shell",
      "command": "cmake",
      "args": [
        "--build",
        "build",
        "--parallel"
      ],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      },
      "problemMatcher": [
        "$gcc"
      ]
    },
    {
      "label": "Clean Build",
      "type": "shell",
      "command": "cmake",
      "args": [
        "--build",
        "build",
        "--target",
        "clean"
      ],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    },
    {
      "label": "Run Tests",
      "type": "shell",
      "command": "ctest",
      "args": [
        "--test-dir",
        "build",
        "--output-on-failure"
      ],
      "group": "test",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      },
      "problemMatcher": [
        "$gcc"
      ]
    },
    {
      "label": "Run Benchmarks",
      "type": "shell",
      "command": "./build/benchmarks/\\${workspaceFolderBasename}_benchmark",
      "group": "test",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    },
    {
      "label": "Start Development Server",
      "type": "shell",
      "command": "./scripts/development-server.sh",
      "group": "none",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": true,
        "panel": "dedicated",
        "showReuseMessage": false
      },
      "isBackground": true
    },
    {
      "label": "Docker: Build Dev Image",
      "type": "docker-build",
      "dockerBuild": {
        "context": "\\${workspaceFolder}",
        "dockerfile": "\\${workspaceFolder}/docker/Dockerfile.dev",
        "tag": "\\${workspaceFolderBasename}-dev:latest"
      },
      "group": "none"
    },
    {
      "label": "Docker: Start Dev Environment",
      "type": "shell",
      "command": "docker-compose",
      "args": [
        "-f",
        "docker-compose.dev.yml",
        "up",
        "-d"
      ],
      "group": "none",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    },
    {
      "label": "Format Code",
      "type": "shell",
      "command": "find",
      "args": [
        "src",
        "include",
        "tests",
        "-name",
        "*.cpp",
        "-o",
        "-name",
        "*.h",
        "-o",
        "-name",
        "*.hpp",
        "|",
        "xargs",
        "clang-format",
        "-i"
      ],
      "group": "none",
      "presentation": {
        "echo": true,
        "reveal": "silent",
        "focus": false,
        "panel": "shared"
      }
    }
  ]
}`;
  }

  private static generateVSCodeLaunch(projectName: string): string {
    return `{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug with Hot-Reload",
      "type": "cppdbg",
      "request": "launch",
      "program": "\\${workspaceFolder}/build/${projectName}",
      "args": [],
      "stopAtEntry": false,
      "cwd": "\\${workspaceFolder}",
      "environment": [
        {
          "name": "ENABLE_HOT_RELOAD",
          "value": "true"
        }
      ],
      "externalConsole": false,
      "MIMode": "gdb",
      "setupCommands": [
        {
          "description": "Enable pretty-printing for gdb",
          "text": "-enable-pretty-printing",
          "ignoreFailures": true
        },
        {
          "description": "Set disassembly flavor to Intel",
          "text": "-gdb-set disassembly-flavor intel",
          "ignoreFailures": true
        }
      ],
      "preLaunchTask": "Build (Debug)",
      "miDebuggerPath": "/usr/bin/gdb"
    },
    {
      "name": "Debug with LLDB",
      "type": "cppdbg",
      "request": "launch",
      "program": "\\${workspaceFolder}/build/${projectName}",
      "args": [],
      "stopAtEntry": false,
      "cwd": "\\${workspaceFolder}",
      "environment": [],
      "externalConsole": false,
      "MIMode": "lldb",
      "preLaunchTask": "Build (Debug)"
    },
    {
      "name": "Debug Tests",
      "type": "cppdbg",
      "request": "launch",
      "program": "\\${workspaceFolder}/build/tests/${projectName}_test",
      "args": [
        "--gtest_filter=*"
      ],
      "stopAtEntry": false,
      "cwd": "\\${workspaceFolder}/build/tests",
      "environment": [],
      "externalConsole": false,
      "MIMode": "gdb",
      "setupCommands": [
        {
          "description": "Enable pretty-printing for gdb",
          "text": "-enable-pretty-printing",
          "ignoreFailures": true
        }
      ],
      "preLaunchTask": "Build (Debug)"
    },
    {
      "name": "Debug Benchmarks",
      "type": "cppdbg",
      "request": "launch",
      "program": "\\${workspaceFolder}/build/benchmarks/${projectName}_benchmark",
      "args": [
        "--benchmark_filter=.*"
      ],
      "stopAtEntry": false,
      "cwd": "\\${workspaceFolder}/build/benchmarks",
      "environment": [],
      "externalConsole": false,
      "MIMode": "gdb",
      "preLaunchTask": "Build (Debug)"
    },
    {
      "name": "Attach to Process",
      "type": "cppdbg",
      "request": "attach",
      "program": "\\${workspaceFolder}/build/${projectName}",
      "processId": "\\${command:pickProcess}",
      "MIMode": "gdb",
      "setupCommands": [
        {
          "description": "Enable pretty-printing for gdb",
          "text": "-enable-pretty-printing",
          "ignoreFailures": true
        }
      ]
    },
    {
      "name": "Debug in Docker",
      "type": "cppdbg",
      "request": "launch",
      "program": "/home/developer/project/build/${projectName}",
      "args": [],
      "stopAtEntry": false,
      "cwd": "/home/developer/project",
      "environment": [],
      "externalConsole": false,
      "MIMode": "gdb",
      "miDebuggerPath": "/usr/bin/gdb",
      "miDebuggerServerAddress": "localhost:1234",
      "preLaunchTask": "Docker: Start Dev Environment",
      "pipeTransport": {
        "debuggerPath": "/usr/bin/gdb",
        "pipeProgram": "docker",
        "pipeArgs": [
          "exec",
          "-i",
          "${projectName}-dev"
        ],
        "pipeCwd": ""
      }
    }
  ],
  "compounds": [
    {
      "name": "Debug All Tests",
      "configurations": [
        "Debug Tests"
      ],
      "stopAll": true
    }
  ]
}`;
  }
}