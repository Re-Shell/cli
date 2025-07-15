/**
 * C++ Google Benchmark Integration Generator
 * Generates Google Benchmark configuration and templates for C++ projects
 */

export interface CppBenchmarkConfig {
  projectName: string;
  benchmarkVersion?: string;
  enableMemoryCounters?: boolean;
  enableTimeUnit?: 'ns' | 'us' | 'ms' | 's';
  enableMultithreading?: boolean;
  enableJsonOutput?: boolean;
  enableConsoleColors?: boolean;
}

export class CppBenchmarkGenerator {
  static generate(config: CppBenchmarkConfig): Record<string, string> {
    const {
      projectName,
      benchmarkVersion = "1.8.3",
      enableMemoryCounters = true,
      enableTimeUnit = 'us',
      enableMultithreading = true,
      enableJsonOutput = true,
      enableConsoleColors = true
    } = config;

    return {
      'benchmarks/CMakeLists.txt': this.generateBenchmarkCMake(projectName, benchmarkVersion),
      'benchmarks/main_benchmark.cpp': this.generateMainBenchmark(projectName),
      'benchmarks/api_benchmark.cpp': this.generateApiBenchmark(projectName),
      'benchmarks/performance_benchmark.cpp': this.generatePerformanceBenchmark(projectName),
      'scripts/run_benchmarks.sh': this.generateBenchmarkScript(enableJsonOutput, enableConsoleColors),
      'scripts/benchmark_analysis.py': this.generateBenchmarkAnalysis(),
      'benchmarks/README.md': this.generateBenchmarkReadme(projectName),
      '.github/workflows/benchmark.yml': this.generateBenchmarkCI(projectName),
      'cmake/benchmark.cmake': this.generateBenchmarkCMakeModule(),
      'benchmarks/utils/benchmark_utils.hpp': this.generateBenchmarkUtils(),
      'benchmarks/utils/benchmark_utils.cpp': this.generateBenchmarkUtilsImpl()
    };
  }

  private static generateBenchmarkCMake(projectName: string, version: string): string {
    return `# Google Benchmark Configuration for ${projectName}
cmake_minimum_required(VERSION 3.16)

# Find or download Google Benchmark
find_package(benchmark QUIET)
if(NOT benchmark_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        googlebenchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v${version}
    )
    
    # Configure benchmark options
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark testing")
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Disable gtest in benchmark")
    set(BENCHMARK_ENABLE_ASSEMBLY_TESTS OFF CACHE BOOL "Disable assembly tests")
    
    FetchContent_MakeAvailable(googlebenchmark)
endif()

# Create benchmark utilities library
add_library(benchmark_utils
    utils/benchmark_utils.cpp
    utils/benchmark_utils.hpp
)
target_link_libraries(benchmark_utils PUBLIC benchmark::benchmark)
target_include_directories(benchmark_utils PUBLIC utils)

# Main benchmark executable
add_executable(${projectName}_benchmark
    main_benchmark.cpp
    api_benchmark.cpp
    performance_benchmark.cpp
)

target_link_libraries(${projectName}_benchmark
    PRIVATE
    benchmark::benchmark
    benchmark_utils
    \${PROJECT_NAME}_lib  # Link to your main library
)

# Compiler optimizations for benchmarks
target_compile_options(${projectName}_benchmark PRIVATE
    \$<\$<CXX_COMPILER_ID:GNU>:-O3 -march=native -mtune=native>
    \$<\$<CXX_COMPILER_ID:Clang>:-O3 -march=native -mtune=native>
    \$<\$<CXX_COMPILER_ID:MSVC>:/O2>
)

# Benchmark registration and discovery
target_compile_definitions(${projectName}_benchmark PRIVATE
    BENCHMARK_ENABLE_MEMORY_COUNTERS=1
    BENCHMARK_ENABLE_THREADING=1
)

# Custom benchmark targets
add_custom_target(run_benchmarks
    COMMAND \${CMAKE_CURRENT_BINARY_DIR}/${projectName}_benchmark
    DEPENDS ${projectName}_benchmark
    COMMENT "Running performance benchmarks"
)

add_custom_target(benchmark_json
    COMMAND \${CMAKE_CURRENT_BINARY_DIR}/${projectName}_benchmark --benchmark_format=json --benchmark_out=benchmark_results.json
    DEPENDS ${projectName}_benchmark
    COMMENT "Running benchmarks with JSON output"
)

add_custom_target(benchmark_detailed
    COMMAND \${CMAKE_CURRENT_BINARY_DIR}/${projectName}_benchmark --benchmark_repetitions=10 --benchmark_display_aggregates_only=true
    DEPENDS ${projectName}_benchmark
    COMMENT "Running detailed benchmark analysis"
)`;
  }

  private static generateMainBenchmark(projectName: string): string {
    return `/**
 * Main Benchmark Suite for ${projectName}
 * Comprehensive performance testing and analysis
 */

#include <benchmark/benchmark.h>
#include "benchmark_utils.hpp"
#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <random>

// Example: String processing benchmark
static void BM_StringCreation(benchmark::State& state) {
    for (auto _ : state) {
        std::string empty_string;
        benchmark::DoNotOptimize(empty_string);
    }
}
BENCHMARK(BM_StringCreation);

// Example: String concatenation benchmark
static void BM_StringCopy(benchmark::State& state) {
    std::string x = "hello world";
    for (auto _ : state) {
        std::string copy(x);
        benchmark::DoNotOptimize(copy);
    }
}
BENCHMARK(BM_StringCopy);

// Memory allocation benchmark
static void BM_VectorCreation(benchmark::State& state) {
    for (auto _ : state) {
        std::vector<int> v;
        v.reserve(state.range(0));
        for (int i = 0; i < state.range(0); ++i) {
            v.push_back(i);
        }
        benchmark::DoNotOptimize(v.data());
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_VectorCreation)->Range(8, 8<<10);

// Memory access patterns
static void BM_SequentialAccess(benchmark::State& state) {
    std::vector<int> data(state.range(0));
    std::iota(data.begin(), data.end(), 0);
    
    for (auto _ : state) {
        long sum = 0;
        for (size_t i = 0; i < data.size(); ++i) {
            sum += data[i];
        }
        benchmark::DoNotOptimize(sum);
    }
    
    state.SetBytesProcessed(state.iterations() * state.range(0) * sizeof(int));
}
BENCHMARK(BM_SequentialAccess)->Range(1024, 1024*1024);

// Random access benchmark
static void BM_RandomAccess(benchmark::State& state) {
    std::vector<int> data(state.range(0));
    std::iota(data.begin(), data.end(), 0);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, data.size() - 1);
    
    for (auto _ : state) {
        long sum = 0;
        for (int i = 0; i < 1000; ++i) {
            sum += data[dis(gen)];
        }
        benchmark::DoNotOptimize(sum);
    }
}
BENCHMARK(BM_RandomAccess)->Range(1024, 1024*1024);

// Multithreaded benchmark example
static void BM_MultiThreadedWork(benchmark::State& state) {
    if (state.thread_index == 0) {
        // Setup shared data
    }
    
    for (auto _ : state) {
        // Work that each thread performs
        std::vector<int> local_data(1000);
        std::iota(local_data.begin(), local_data.end(), state.thread_index * 1000);
        
        long sum = 0;
        for (int val : local_data) {
            sum += val * val;
        }
        benchmark::DoNotOptimize(sum);
    }
}
BENCHMARK(BM_MultiThreadedWork)->Threads(1)->Threads(2)->Threads(4)->Threads(8);

BENCHMARK_MAIN();`;
  }

  private static generateApiBenchmark(projectName: string): string {
    return `/**
 * API Performance Benchmarks for ${projectName}
 * HTTP request/response processing benchmarks
 */

#include <benchmark/benchmark.h>
#include "benchmark_utils.hpp"
#include <string>
#include <vector>
#include <memory>

// Mock API endpoint processing
static void BM_JsonParsing(benchmark::State& state) {
    const std::string json_data = R"({
        "id": 12345,
        "name": "Test User",
        "email": "test@example.com",
        "metadata": {
            "preferences": ["setting1", "setting2", "setting3"],
            "scores": [85, 92, 78, 95, 87]
        }
    })";
    
    for (auto _ : state) {
        // Simulate JSON parsing
        BenchmarkUtils::ProcessJsonData(json_data);
        benchmark::ClobberMemory();
    }
    
    state.SetBytesProcessed(state.iterations() * json_data.size());
}
BENCHMARK(BM_JsonParsing);

// Database query simulation
static void BM_DatabaseQuery(benchmark::State& state) {
    auto connection = BenchmarkUtils::CreateMockConnection();
    
    for (auto _ : state) {
        auto result = BenchmarkUtils::ExecuteMockQuery(
            connection, 
            "SELECT * FROM users WHERE id = ?", 
            {std::to_string(state.range(0))}
        );
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_DatabaseQuery)->Range(1, 10000);

// HTTP request processing
static void BM_RequestProcessing(benchmark::State& state) {
    for (auto _ : state) {
        auto request = BenchmarkUtils::CreateMockRequest("GET", "/api/users/123");
        auto response = BenchmarkUtils::ProcessRequest(request);
        benchmark::DoNotOptimize(response);
    }
}
BENCHMARK(BM_RequestProcessing);

// Concurrent request handling
static void BM_ConcurrentRequests(benchmark::State& state) {
    if (state.thread_index == 0) {
        BenchmarkUtils::InitializeServer();
    }
    
    for (auto _ : state) {
        auto request = BenchmarkUtils::CreateMockRequest(
            "POST", 
            "/api/data",
            BenchmarkUtils::GenerateTestPayload(state.range(0))
        );
        auto response = BenchmarkUtils::ProcessRequestConcurrent(request);
        benchmark::DoNotOptimize(response);
    }
    
    if (state.thread_index == 0) {
        BenchmarkUtils::ShutdownServer();
    }
}
BENCHMARK(BM_ConcurrentRequests)
    ->Range(1024, 8<<10)
    ->Threads(1)->Threads(4)->Threads(8)->Threads(16);

// Authentication/Authorization benchmark
static void BM_Authentication(benchmark::State& state) {
    auto auth_service = BenchmarkUtils::CreateAuthService();
    
    for (auto _ : state) {
        std::string token = BenchmarkUtils::GenerateJWT();
        bool is_valid = BenchmarkUtils::ValidateToken(auth_service, token);
        benchmark::DoNotOptimize(is_valid);
    }
}
BENCHMARK(BM_Authentication);

// Data serialization benchmark
static void BM_DataSerialization(benchmark::State& state) {
    auto test_objects = BenchmarkUtils::GenerateTestObjects(state.range(0));
    
    for (auto _ : state) {
        std::string serialized = BenchmarkUtils::SerializeToJson(test_objects);
        benchmark::DoNotOptimize(serialized.data());
    }
    
    state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_DataSerialization)->Range(1, 1000);

// Data deserialization benchmark
static void BM_DataDeserialization(benchmark::State& state) {
    auto test_data = BenchmarkUtils::GenerateTestJsonArray(state.range(0));
    
    for (auto _ : state) {
        auto objects = BenchmarkUtils::DeserializeFromJson(test_data);
        benchmark::DoNotOptimize(objects.data());
    }
    
    state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_DataDeserialization)->Range(1, 1000);`;
  }

  private static generatePerformanceBenchmark(projectName: string): string {
    return `/**
 * Performance Critical Path Benchmarks for ${projectName}
 * Core algorithm and data structure benchmarks
 */

#include <benchmark/benchmark.h>
#include "benchmark_utils.hpp"
#include <algorithm>
#include <numeric>
#include <vector>
#include <unordered_map>
#include <map>
#include <set>
#include <string>
#include <memory>

// Sorting algorithms comparison
static void BM_StdSort(benchmark::State& state) {
    for (auto _ : state) {
        state.PauseTiming();
        auto data = BenchmarkUtils::GenerateRandomInts(state.range(0));
        state.ResumeTiming();
        
        std::sort(data.begin(), data.end());
        benchmark::DoNotOptimize(data.data());
    }
    state.SetComplexityN(state.range(0));
}
BENCHMARK(BM_StdSort)->Range(1<<10, 1<<20)->Complexity();

// Hash map vs tree map performance
static void BM_UnorderedMapInsert(benchmark::State& state) {
    std::unordered_map<int, std::string> map;
    auto keys = BenchmarkUtils::GenerateRandomInts(state.range(0));
    
    for (auto _ : state) {
        for (int key : keys) {
            map[key] = "value_" + std::to_string(key);
        }
        benchmark::ClobberMemory();
    }
    state.SetComplexityN(state.range(0));
}
BENCHMARK(BM_UnorderedMapInsert)->Range(1<<8, 1<<16)->Complexity();

static void BM_MapInsert(benchmark::State& state) {
    std::map<int, std::string> map;
    auto keys = BenchmarkUtils::GenerateRandomInts(state.range(0));
    
    for (auto _ : state) {
        for (int key : keys) {
            map[key] = "value_" + std::to_string(key);
        }
        benchmark::ClobberMemory();
    }
    state.SetComplexityN(state.range(0));
}
BENCHMARK(BM_MapInsert)->Range(1<<8, 1<<16)->Complexity();

// String processing benchmarks
static void BM_StringConcatenation(benchmark::State& state) {
    auto strings = BenchmarkUtils::GenerateRandomStrings(state.range(0), 20);
    
    for (auto _ : state) {
        std::string result;
        for (const auto& str : strings) {
            result += str;
        }
        benchmark::DoNotOptimize(result.data());
    }
    state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_StringConcatenation)->Range(1, 1000);

static void BM_StringJoin(benchmark::State& state) {
    auto strings = BenchmarkUtils::GenerateRandomStrings(state.range(0), 20);
    
    for (auto _ : state) {
        std::string result = BenchmarkUtils::JoinStrings(strings, ",");
        benchmark::DoNotOptimize(result.data());
    }
    state.SetItemsProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_StringJoin)->Range(1, 1000);

// Memory allocation patterns
static void BM_StackAllocation(benchmark::State& state) {
    for (auto _ : state) {
        int data[1000];
        std::iota(data, data + 1000, 0);
        benchmark::DoNotOptimize(data);
    }
}
BENCHMARK(BM_StackAllocation);

static void BM_HeapAllocation(benchmark::State& state) {
    for (auto _ : state) {
        auto data = std::make_unique<int[]>(1000);
        std::iota(data.get(), data.get() + 1000, 0);
        benchmark::DoNotOptimize(data.get());
    }
}
BENCHMARK(BM_HeapAllocation);

// Cache efficiency benchmarks
static void BM_CacheFriendlyAccess(benchmark::State& state) {
    std::vector<int> data(state.range(0));
    std::iota(data.begin(), data.end(), 0);
    
    for (auto _ : state) {
        long sum = 0;
        // Sequential access - cache friendly
        for (size_t i = 0; i < data.size(); ++i) {
            sum += data[i];
        }
        benchmark::DoNotOptimize(sum);
    }
    
    state.SetBytesProcessed(state.iterations() * state.range(0) * sizeof(int));
}
BENCHMARK(BM_CacheFriendlyAccess)->Range(1<<10, 1<<22);

static void BM_CacheUnfriendlyAccess(benchmark::State& state) {
    std::vector<int> data(state.range(0));
    std::iota(data.begin(), data.end(), 0);
    
    for (auto _ : state) {
        long sum = 0;
        // Stride access - cache unfriendly
        size_t stride = 64; // Assume 64-byte cache lines
        for (size_t i = 0; i < data.size(); i += stride) {
            sum += data[i];
        }
        benchmark::DoNotOptimize(sum);
    }
    
    state.SetBytesProcessed(state.iterations() * (state.range(0) / 64) * sizeof(int));
}
BENCHMARK(BM_CacheUnfriendlyAccess)->Range(1<<10, 1<<22);

// Algorithm complexity verification
static void BM_LinearSearch(benchmark::State& state) {
    auto data = BenchmarkUtils::GenerateRandomInts(state.range(0));
    int target = data[data.size() / 2];
    
    for (auto _ : state) {
        auto it = std::find(data.begin(), data.end(), target);
        benchmark::DoNotOptimize(it);
    }
    state.SetComplexityN(state.range(0));
}
BENCHMARK(BM_LinearSearch)->Range(1<<8, 1<<16)->Complexity();

static void BM_BinarySearch(benchmark::State& state) {
    auto data = BenchmarkUtils::GenerateRandomInts(state.range(0));
    std::sort(data.begin(), data.end());
    int target = data[data.size() / 2];
    
    for (auto _ : state) {
        bool found = std::binary_search(data.begin(), data.end(), target);
        benchmark::DoNotOptimize(found);
    }
    state.SetComplexityN(state.range(0));
}
BENCHMARK(BM_BinarySearch)->Range(1<<8, 1<<16)->Complexity();`;
  }

  private static generateBenchmarkScript(enableJsonOutput: boolean, enableConsoleColors: boolean): string {
    return `#!/bin/bash
# Google Benchmark Runner Script
# Comprehensive performance testing and analysis

set -euo pipefail

# Configuration
BENCHMARK_BINARY="./build/benchmarks/\\$(basename \\$(pwd))_benchmark"
RESULTS_DIR="benchmark_results"
TIMESTAMP="\\$(date +%Y%m%d_%H%M%S)"

# Create results directory
mkdir -p "\\${RESULTS_DIR}"

# Colors for output
if [[ "${enableConsoleColors}" == "true" ]]; then
    RED='\\033[0;31m'
    GREEN='\\033[0;32m'
    BLUE='\\033[0;34m'
    YELLOW='\\033[1;33m'
    NC='\\033[0m' # No Color
else
    RED=''
    GREEN=''
    BLUE=''
    YELLOW=''
    NC=''
fi

echo -e "\\${BLUE}=== Performance Benchmark Suite ===\\${NC}"

# Check if benchmark binary exists
if [[ ! -f "\\${BENCHMARK_BINARY}" ]]; then
    echo -e "\\${RED}Error: Benchmark binary not found at \\${BENCHMARK_BINARY}\\${NC}"
    echo "Please build the project first: cmake --build build --target \\$(basename \\$(pwd))_benchmark"
    exit 1
fi

# Function to run benchmark with specific options
run_benchmark() {
    local name="\\$1"
    local args="\\$2"
    local output_file="\\${RESULTS_DIR}/\\${name}_\\${TIMESTAMP}"
    
    echo -e "\\${YELLOW}Running \\${name} benchmark...\\${NC}"
    
    if [[ "${enableJsonOutput}" == "true" ]]; then
        \\${BENCHMARK_BINARY} \\${args} \\
            --benchmark_format=json \\
            --benchmark_out="\\${output_file}.json" \\
            --benchmark_counters_tabular=true \\
            | tee "\\${output_file}.txt"
    else
        \\${BENCHMARK_BINARY} \\${args} | tee "\\${output_file}.txt"
    fi
    
    echo -e "\\${GREEN}Results saved to \\${output_file}.*\\${NC}"
    echo
}

# Quick benchmark run
run_benchmark "quick" "--benchmark_filter=BM_.*"

# Detailed benchmark with repetitions
run_benchmark "detailed" "--benchmark_repetitions=5 --benchmark_display_aggregates_only=true"

# Memory intensive benchmarks
run_benchmark "memory" "--benchmark_filter=.*Memory.* --benchmark_memory_counters=true"

# Multithreaded benchmarks
run_benchmark "multithreaded" "--benchmark_filter=.*MultiThreaded.*"

# Performance regression detection
if [[ -f "\\${RESULTS_DIR}/baseline.json" ]]; then
    echo -e "\\${YELLOW}Running regression detection...\\${NC}"
    
    \\${BENCHMARK_BINARY} \\
        --benchmark_format=json \\
        --benchmark_out="\\${RESULTS_DIR}/current_\\${TIMESTAMP}.json" \\
        --benchmark_filter=BM_.*
    
    # Compare with baseline (requires compare.py tool)
    if command -v python3 &> /dev/null; then
        python3 scripts/benchmark_analysis.py \\
            "\\${RESULTS_DIR}/baseline.json" \\
            "\\${RESULTS_DIR}/current_\\${TIMESTAMP}.json" \\
            > "\\${RESULTS_DIR}/regression_report_\\${TIMESTAMP}.txt"
        
        echo -e "\\${GREEN}Regression report saved to \\${RESULTS_DIR}/regression_report_\\${TIMESTAMP}.txt\\${NC}"
    fi
fi

# Generate summary report
echo -e "\\${BLUE}=== Benchmark Summary ===\\${NC}"
echo "Timestamp: \\${TIMESTAMP}"
echo "Results directory: \\${RESULTS_DIR}"
echo "Binary: \\${BENCHMARK_BINARY}"

if [[ "${enableJsonOutput}" == "true" ]]; then
    echo "JSON results available for analysis"
    echo "Use: python3 scripts/benchmark_analysis.py <json_file>"
fi

echo -e "\\${GREEN}Benchmark suite completed successfully!\\${NC}"

# Optional: Upload results to performance tracking system
if [[ -n "\\${BENCHMARK_UPLOAD_URL:-}" ]]; then
    echo -e "\\${YELLOW}Uploading results to performance tracking system...\\${NC}"
    curl -X POST "\\${BENCHMARK_UPLOAD_URL}" \\
         -H "Content-Type: application/json" \\
         -d @"\\${RESULTS_DIR}/detailed_\\${TIMESTAMP}.json" || true
fi`;
  }

  private static generateBenchmarkAnalysis(): string {
    return `#!/usr/bin/env python3
"""
Google Benchmark Analysis Tool
Analyzes benchmark results and generates performance reports
"""

import json
import sys
import argparse
import statistics
from typing import Dict, List, Any, Optional
from datetime import datetime

class BenchmarkAnalyzer:
    def __init__(self):
        self.thresholds = {
            'regression': 1.10,  # 10% slowdown
            'improvement': 0.90,  # 10% speedup
            'significant_change': 0.05  # 5% change threshold
        }

    def load_benchmark_results(self, filename: str) -> Dict[str, Any]:
        """Load benchmark results from JSON file."""
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: File {filename} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            sys.exit(1)

    def extract_benchmark_data(self, results: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
        """Extract relevant benchmark data."""
        benchmarks = {}
        
        for benchmark in results.get('benchmarks', []):
            name = benchmark['name']
            benchmarks[name] = {
                'cpu_time': benchmark['cpu_time'],
                'real_time': benchmark['real_time'],
                'iterations': benchmark['iterations'],
                'bytes_per_second': benchmark.get('bytes_per_second', 0),
                'items_per_second': benchmark.get('items_per_second', 0)
            }
            
        return benchmarks

    def compare_benchmarks(self, baseline: Dict[str, Dict[str, float]], 
                          current: Dict[str, Dict[str, float]]) -> Dict[str, Dict[str, Any]]:
        """Compare current results with baseline."""
        comparison = {}
        
        for name in current:
            if name not in baseline:
                comparison[name] = {
                    'status': 'NEW',
                    'current': current[name],
                    'change': None
                }
                continue
                
            baseline_time = baseline[name]['cpu_time']
            current_time = current[name]['cpu_time']
            
            ratio = current_time / baseline_time
            change_pct = (ratio - 1.0) * 100
            
            status = 'STABLE'
            if ratio > self.thresholds['regression']:
                status = 'REGRESSION'
            elif ratio < self.thresholds['improvement']:
                status = 'IMPROVEMENT'
            elif abs(change_pct) > self.thresholds['significant_change'] * 100:
                status = 'CHANGED'
                
            comparison[name] = {
                'status': status,
                'baseline': baseline[name],
                'current': current[name],
                'ratio': ratio,
                'change_pct': change_pct
            }
            
        return comparison

    def generate_report(self, comparison: Dict[str, Dict[str, Any]]) -> str:
        """Generate a human-readable performance report."""
        report_lines = [
            "# Benchmark Performance Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            ""
        ]
        
        status_counts = {}
        for data in comparison.values():
            status = data['status']
            status_counts[status] = status_counts.get(status, 0) + 1
            
        for status, count in sorted(status_counts.items()):
            report_lines.append(f"- {status}: {count} benchmarks")
        
        report_lines.extend(["", "## Detailed Results", ""])
        
        # Sort by change percentage (worst regressions first)
        sorted_benchmarks = sorted(
            comparison.items(),
            key=lambda x: x[1].get('change_pct', 0),
            reverse=True
        )
        
        for name, data in sorted_benchmarks:
            status = data['status']
            
            if status == 'NEW':
                current_time = data['current']['cpu_time']
                report_lines.append(f"### {name} [NEW]")
                report_lines.append(f"- CPU Time: {current_time:.2f} ns")
                
            else:
                change_pct = data['change_pct']
                current_time = data['current']['cpu_time']
                baseline_time = data['baseline']['cpu_time']
                
                emoji = "🔴" if status == 'REGRESSION' else "🟢" if status == 'IMPROVEMENT' else "🟡"
                
                report_lines.append(f"### {name} [{status}] {emoji}")
                report_lines.append(f"- Change: {change_pct:+.2f}%")
                report_lines.append(f"- Current: {current_time:.2f} ns")
                report_lines.append(f"- Baseline: {baseline_time:.2f} ns")
                
            report_lines.append("")
            
        return "\\n".join(report_lines)

    def analyze_single_file(self, filename: str) -> str:
        """Analyze a single benchmark file."""
        results = self.load_benchmark_results(filename)
        benchmarks = self.extract_benchmark_data(results)
        
        report_lines = [
            f"# Benchmark Analysis: {filename}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Performance Summary",
            ""
        ]
        
        # Calculate statistics
        cpu_times = [b['cpu_time'] for b in benchmarks.values()]
        if cpu_times:
            report_lines.extend([
                f"- Total benchmarks: {len(benchmarks)}",
                f"- Average CPU time: {statistics.mean(cpu_times):.2f} ns",
                f"- Median CPU time: {statistics.median(cpu_times):.2f} ns",
                f"- Min CPU time: {min(cpu_times):.2f} ns",
                f"- Max CPU time: {max(cpu_times):.2f} ns",
                ""
            ])
        
        report_lines.extend(["## Benchmark Details", ""])
        
        for name, data in sorted(benchmarks.items()):
            report_lines.append(f"### {name}")
            report_lines.append(f"- CPU Time: {data['cpu_time']:.2f} ns")
            report_lines.append(f"- Real Time: {data['real_time']:.2f} ns")
            report_lines.append(f"- Iterations: {data['iterations']:,}")
            
            if data['bytes_per_second'] > 0:
                report_lines.append(f"- Throughput: {data['bytes_per_second']/1e6:.2f} MB/s")
            if data['items_per_second'] > 0:
                report_lines.append(f"- Items/sec: {data['items_per_second']:,.0f}")
                
            report_lines.append("")
            
        return "\\n".join(report_lines)

def main():
    parser = argparse.ArgumentParser(description='Analyze Google Benchmark results')
    parser.add_argument('baseline', help='Baseline benchmark results (JSON)')
    parser.add_argument('current', nargs='?', help='Current benchmark results (JSON)')
    parser.add_argument('--output', '-o', help='Output file for report')
    
    args = parser.parse_args()
    
    analyzer = BenchmarkAnalyzer()
    
    if args.current:
        # Compare two files
        baseline_results = analyzer.load_benchmark_results(args.baseline)
        current_results = analyzer.load_benchmark_results(args.current)
        
        baseline_data = analyzer.extract_benchmark_data(baseline_results)
        current_data = analyzer.extract_benchmark_data(current_results)
        
        comparison = analyzer.compare_benchmarks(baseline_data, current_data)
        report = analyzer.generate_report(comparison)
    else:
        # Analyze single file
        report = analyzer.analyze_single_file(args.baseline)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

if __name__ == '__main__':
    main()`;
  }

  private static generateBenchmarkReadme(projectName: string): string {
    return `# ${projectName} Performance Benchmarks

This directory contains comprehensive performance benchmarks using Google Benchmark framework.

## Overview

The benchmark suite includes:

- **Main Benchmarks** (\`main_benchmark.cpp\`): Core algorithm and data structure performance
- **API Benchmarks** (\`api_benchmark.cpp\`): HTTP request/response processing
- **Performance Benchmarks** (\`performance_benchmark.cpp\`): Critical path optimization

## Quick Start

### Building Benchmarks

\`\`\`bash
# Configure with benchmarks enabled
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build benchmark executable
cmake --build build --target ${projectName}_benchmark
\`\`\`

### Running Benchmarks

\`\`\`bash
# Quick benchmark run
./scripts/run_benchmarks.sh

# Manual execution
./build/benchmarks/${projectName}_benchmark

# With specific options
./build/benchmarks/${projectName}_benchmark --benchmark_filter=BM_String.*
\`\`\`

## Benchmark Categories

### Memory and Data Structures
- Vector creation and access patterns
- Hash map vs tree map performance
- Memory allocation strategies
- Cache efficiency analysis

### String Processing
- String creation and copying
- Concatenation vs joining
- Pattern matching and parsing

### API Performance
- JSON parsing and serialization
- Database query simulation
- HTTP request processing
- Authentication and authorization

### Concurrency
- Multithreaded workload distribution
- Concurrent request handling
- Lock contention analysis

### Algorithm Complexity
- Sorting algorithm comparisons
- Search algorithm verification
- Complexity analysis and validation

## Understanding Results

### Key Metrics

- **CPU Time**: Time spent on CPU (excludes I/O wait)
- **Real Time**: Wall clock time (includes everything)
- **Iterations**: Number of benchmark iterations
- **Bytes/sec**: Throughput for data processing
- **Items/sec**: Processing rate for discrete items

### Performance Analysis

\`\`\`bash
# Generate detailed analysis
python3 scripts/benchmark_analysis.py benchmark_results/detailed_TIMESTAMP.json

# Compare with baseline
python3 scripts/benchmark_analysis.py baseline.json current.json
\`\`\`

### Result Interpretation

- **Green (🟢)**: Performance improvement (>10% faster)
- **Yellow (🟡)**: Stable performance (±5% change)
- **Red (🔴)**: Performance regression (>10% slower)

## Benchmark Best Practices

### Writing Benchmarks

1. **Use DoNotOptimize()**: Prevent compiler optimization
2. **Use ClobberMemory()**: Prevent memory optimization
3. **Set proper ranges**: Test realistic data sizes
4. **Consider cache effects**: Test both hot and cold scenarios

### Example Benchmark

\`\`\`cpp
static void BM_YourFunction(benchmark::State& state) {
    // Setup (not measured)
    std::vector<int> data(state.range(0));
    
    for (auto _ : state) {
        // Code being measured
        auto result = your_function(data);
        benchmark::DoNotOptimize(result);
    }
    
    // Optional metrics
    state.SetBytesProcessed(state.iterations() * state.range(0) * sizeof(int));
    state.SetComplexityN(state.range(0));
}
BENCHMARK(BM_YourFunction)->Range(1<<10, 1<<20)->Complexity();
\`\`\`

## Continuous Integration

Benchmarks run automatically on:
- Pull requests (regression detection)
- Main branch commits (performance tracking)
- Nightly builds (comprehensive analysis)

## Performance Regression Detection

The CI system detects:
- **Major regressions**: >20% performance loss
- **Minor regressions**: 10-20% performance loss
- **Significant changes**: >5% performance change

## Configuration

### Environment Variables

- \`BENCHMARK_UPLOAD_URL\`: Upload results to tracking system
- \`BENCHMARK_BASELINE\`: Path to baseline results file
- \`BENCHMARK_REPETITIONS\`: Number of repetitions (default: 3)

### CMake Options

- \`BENCHMARK_ENABLE_TESTING\`: Enable Google Benchmark tests
- \`BENCHMARK_ENABLE_GTEST_TESTS\`: Enable Google Test integration
- \`BENCHMARK_ENABLE_ASSEMBLY_TESTS\`: Enable assembly tests

## Troubleshooting

### Common Issues

1. **Inconsistent results**: Ensure consistent CPU frequency, disable turbo boost
2. **Memory issues**: Check for memory leaks with valgrind
3. **Compiler optimizations**: Verify release mode compilation

### Performance Tips

1. **CPU isolation**: Use \`taskset\` for CPU pinning
2. **System load**: Run benchmarks on idle system
3. **Memory frequency**: Use consistent memory settings
4. **Compiler flags**: Use \`-O3 -march=native\` for maximum performance

## Resources

- [Google Benchmark Documentation](https://github.com/google/benchmark)
- [Performance Optimization Guide](https://github.com/google/benchmark/blob/main/docs/user_guide.md)
- [Benchmark Best Practices](https://github.com/google/benchmark/blob/main/docs/perf_counters.md)`;
  }

  private static generateBenchmarkCI(projectName: string): string {
    return `name: Performance Benchmarks

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run nightly benchmarks at 2 AM UTC
    - cron: '0 2 * * *'

env:
  BUILD_TYPE: Release

jobs:
  benchmark:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0  # Fetch full history for comparison
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y cmake ninja-build gcc-11 g++-11 python3-pip
        pip3 install matplotlib pandas scipy
    
    - name: Configure CMake
      run: |
        cmake -B build \\
          -DCMAKE_BUILD_TYPE=\\${{env.BUILD_TYPE}} \\
          -DCMAKE_CXX_COMPILER=g++-11 \\
          -DCMAKE_C_COMPILER=gcc-11 \\
          -GNinja
    
    - name: Build benchmarks
      run: cmake --build build --target ${projectName}_benchmark
    
    - name: Download baseline results
      if: github.event_name == 'pull_request'
      continue-on-error: true
      run: |
        # Download baseline from main branch artifact
        gh api repos/\\${{ github.repository }}/actions/artifacts \\
          --jq '.artifacts[] | select(.name=="benchmark-baseline") | .archive_download_url' \\
          | head -1 \\
          | xargs curl -L -H "Authorization: token \\${{ secrets.GITHUB_TOKEN }}" \\
          -o baseline.zip
        unzip -q baseline.zip || echo "No baseline found"
      env:
        GITHUB_TOKEN: \\${{ secrets.GITHUB_TOKEN }}
    
    - name: Run benchmarks
      run: |
        # Set CPU performance mode
        echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor || true
        
        # Run benchmarks
        mkdir -p benchmark_results
        
        ./build/benchmarks/${projectName}_benchmark \\
          --benchmark_format=json \\
          --benchmark_out=benchmark_results/current.json \\
          --benchmark_repetitions=3 \\
          --benchmark_display_aggregates_only=true \\
          --benchmark_counters_tabular=true
    
    - name: Analyze results
      if: github.event_name == 'pull_request'
      run: |
        if [ -f baseline.json ]; then
          python3 scripts/benchmark_analysis.py \\
            baseline.json \\
            benchmark_results/current.json \\
            --output benchmark_results/comparison.md
          
          # Add results to PR comment
          echo "## Benchmark Results" >> \\$GITHUB_STEP_SUMMARY
          cat benchmark_results/comparison.md >> \\$GITHUB_STEP_SUMMARY
        else
          echo "No baseline found, skipping comparison" >> \\$GITHUB_STEP_SUMMARY
          python3 scripts/benchmark_analysis.py \\
            benchmark_results/current.json \\
            --output benchmark_results/analysis.md
          cat benchmark_results/analysis.md >> \\$GITHUB_STEP_SUMMARY
        fi
    
    - name: Check for regressions
      if: github.event_name == 'pull_request'
      run: |
        if [ -f benchmark_results/comparison.md ]; then
          # Check for performance regressions
          if grep -q "REGRESSION.*🔴" benchmark_results/comparison.md; then
            echo "::warning::Performance regressions detected!"
            grep "REGRESSION.*🔴" benchmark_results/comparison.md || true
          fi
          
          # Fail on major regressions (>25%)
          if grep -q "Change: +[2-9][0-9]\\." benchmark_results/comparison.md; then
            echo "::error::Major performance regression detected (>20%)"
            exit 1
          fi
        fi
    
    - name: Upload benchmark results
      uses: actions/upload-artifact@v4
      with:
        name: benchmark-results-\\${{ github.sha }}
        path: benchmark_results/
        retention-days: 30
    
    - name: Save baseline for main branch
      if: github.ref == 'refs/heads/main'
      uses: actions/upload-artifact@v4
      with:
        name: benchmark-baseline
        path: benchmark_results/current.json
        retention-days: 90
    
    - name: Generate performance report
      if: github.event_name == 'schedule'
      run: |
        # Generate comprehensive nightly report
        python3 scripts/benchmark_analysis.py \\
          benchmark_results/current.json \\
          --output benchmark_results/nightly_report.md
        
        # Add historical comparison if available
        if [ -f benchmark_results/history.json ]; then
          python3 scripts/benchmark_analysis.py \\
            benchmark_results/history.json \\
            benchmark_results/current.json \\
            --output benchmark_results/historical_comparison.md
        fi
    
    - name: Notify on performance issues
      if: failure()
      uses: actions/github-script@v7
      with:
        script: |
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: '⚠️ **Performance benchmark failed!** Please check the benchmark results and address any regressions.'
          })

  benchmark-comparison:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    needs: benchmark
    
    steps:
    - name: Download current results
      uses: actions/download-artifact@v4
      with:
        name: benchmark-results-\\${{ github.sha }}
        path: current_results/
    
    - name: Download baseline results
      uses: actions/download-artifact@v4
      with:
        name: benchmark-baseline
        path: baseline_results/
      continue-on-error: true
    
    - name: Compare and comment
      if: success()
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          
          try {
            const comparison = fs.readFileSync('current_results/comparison.md', 'utf8');
            
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comparison
            });
          } catch (error) {
            console.log('No comparison results found');
          }`;
  }

  private static generateBenchmarkCMakeModule(): string {
    return `# Google Benchmark Integration Module
# Provides functions for easy benchmark integration

function(add_benchmark_executable TARGET_NAME)
    cmake_parse_arguments(
        BENCH
        ""
        "OUTPUT_NAME"
        "SOURCES;LIBRARIES;INCLUDES"
        \${ARGN}
    )
    
    if(NOT BENCH_OUTPUT_NAME)
        set(BENCH_OUTPUT_NAME "\${TARGET_NAME}")
    endif()
    
    # Create benchmark executable
    add_executable(\${TARGET_NAME} \${BENCH_SOURCES})
    
    # Set output name
    set_target_properties(\${TARGET_NAME} PROPERTIES
        OUTPUT_NAME "\${BENCH_OUTPUT_NAME}"
        RUNTIME_OUTPUT_DIRECTORY "\${CMAKE_BINARY_DIR}/benchmarks"
    )
    
    # Link libraries
    target_link_libraries(\${TARGET_NAME} PRIVATE benchmark::benchmark)
    if(BENCH_LIBRARIES)
        target_link_libraries(\${TARGET_NAME} PRIVATE \${BENCH_LIBRARIES})
    endif()
    
    # Include directories
    if(BENCH_INCLUDES)
        target_include_directories(\${TARGET_NAME} PRIVATE \${BENCH_INCLUDES})
    endif()
    
    # Optimization flags
    target_compile_options(\${TARGET_NAME} PRIVATE
        \$<\$<CXX_COMPILER_ID:GNU>:-O3 -march=native -mtune=native -DNDEBUG>
        \$<\$<CXX_COMPILER_ID:Clang>:-O3 -march=native -mtune=native -DNDEBUG>
        \$<\$<CXX_COMPILER_ID:MSVC>:/O2 /DNDEBUG>
    )
    
    # Benchmark-specific compile definitions
    target_compile_definitions(\${TARGET_NAME} PRIVATE
        BENCHMARK_ENABLE_MEMORY_COUNTERS=1
        BENCHMARK_ENABLE_THREADING=1
    )
    
    # Add to benchmark target group
    set_target_properties(\${TARGET_NAME} PROPERTIES FOLDER "Benchmarks")
endfunction()

function(add_benchmark_test BENCHMARK_TARGET)
    cmake_parse_arguments(
        TEST
        ""
        "NAME;FILTER;REPETITIONS"
        "ARGS"
        \${ARGN}
    )
    
    if(NOT TEST_NAME)
        set(TEST_NAME "benchmark_\${BENCHMARK_TARGET}")
    endif()
    
    if(NOT TEST_REPETITIONS)
        set(TEST_REPETITIONS 3)
    endif()
    
    set(BENCHMARK_ARGS "")
    if(TEST_FILTER)
        list(APPEND BENCHMARK_ARGS "--benchmark_filter=\${TEST_FILTER}")
    endif()
    
    if(TEST_REPETITIONS GREATER 1)
        list(APPEND BENCHMARK_ARGS "--benchmark_repetitions=\${TEST_REPETITIONS}")
        list(APPEND BENCHMARK_ARGS "--benchmark_display_aggregates_only=true")
    endif()
    
    if(TEST_ARGS)
        list(APPEND BENCHMARK_ARGS \${TEST_ARGS})
    endif()
    
    add_test(
        NAME \${TEST_NAME}
        COMMAND \${BENCHMARK_TARGET} \${BENCHMARK_ARGS}
        WORKING_DIRECTORY \${CMAKE_BINARY_DIR}
    )
    
    # Set timeout for benchmarks (default 5 minutes)
    set_tests_properties(\${TEST_NAME} PROPERTIES TIMEOUT 300)
endfunction()

# Helper function to discover and register all benchmarks
function(discover_benchmarks)
    if(TARGET benchmark::benchmark)
        file(GLOB_RECURSE BENCHMARK_SOURCES "\${CMAKE_CURRENT_SOURCE_DIR}/*benchmark*.cpp")
        
        foreach(BENCHMARK_SOURCE \${BENCHMARK_SOURCES})
            get_filename_component(BENCHMARK_NAME \${BENCHMARK_SOURCE} NAME_WE)
            
            # Skip if target already exists
            if(NOT TARGET \${BENCHMARK_NAME})
                add_benchmark_executable(\${BENCHMARK_NAME}
                    SOURCES \${BENCHMARK_SOURCE}
                    LIBRARIES \${PROJECT_NAME}_lib
                )
                
                add_benchmark_test(\${BENCHMARK_NAME})
            endif()
        endforeach()
    endif()
endfunction()

# Configuration helper
function(configure_benchmark_environment)
    # Create benchmark output directory
    file(MAKE_DIRECTORY "\${CMAKE_BINARY_DIR}/benchmarks")
    file(MAKE_DIRECTORY "\${CMAKE_BINARY_DIR}/benchmark_results")
    
    # Copy benchmark scripts
    if(EXISTS "\${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_benchmarks.sh")
        configure_file(
            "\${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_benchmarks.sh"
            "\${CMAKE_BINARY_DIR}/run_benchmarks.sh"
            COPYONLY
        )
        
        # Make executable on Unix systems
        if(UNIX)
            file(CHMOD "\${CMAKE_BINARY_DIR}/run_benchmarks.sh" 
                 PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                            GROUP_READ GROUP_EXECUTE
                            WORLD_READ WORLD_EXECUTE)
        endif()
    endif()
    
    # Copy analysis scripts
    if(EXISTS "\${CMAKE_CURRENT_SOURCE_DIR}/scripts/benchmark_analysis.py")
        configure_file(
            "\${CMAKE_CURRENT_SOURCE_DIR}/scripts/benchmark_analysis.py"
            "\${CMAKE_BINARY_DIR}/benchmark_analysis.py"
            COPYONLY
        )
    endif()
endfunction()

# Performance testing integration
function(add_performance_test TARGET_NAME BASELINE_FILE)
    cmake_parse_arguments(
        PERF
        ""
        "THRESHOLD;OUTPUT_FILE"
        "BENCHMARKS"
        \${ARGN}
    )
    
    if(NOT PERF_THRESHOLD)
        set(PERF_THRESHOLD 1.10)  # 10% regression threshold
    endif()
    
    if(NOT PERF_OUTPUT_FILE)
        set(PERF_OUTPUT_FILE "performance_test_results.json")
    endif()
    
    # Create performance test
    add_test(
        NAME \${TARGET_NAME}
        COMMAND python3 benchmark_analysis.py 
                \${BASELINE_FILE} 
                \${PERF_OUTPUT_FILE}
                --threshold \${PERF_THRESHOLD}
        WORKING_DIRECTORY \${CMAKE_BINARY_DIR}
    )
    
    # Set as performance test category
    set_tests_properties(\${TARGET_NAME} PROPERTIES 
        LABELS "Performance"
        TIMEOUT 600
    )
endfunction()`;
  }

  private static generateBenchmarkUtils(): string {
    return `/**
 * Benchmark Utilities Header
 * Common functions and helpers for benchmark implementations
 */

#pragma once

#include <benchmark/benchmark.h>
#include <vector>
#include <string>
#include <memory>
#include <random>
#include <chrono>

namespace BenchmarkUtils {

// Random data generation
std::vector<int> GenerateRandomInts(size_t count, int min_val = 0, int max_val = 100000);
std::vector<std::string> GenerateRandomStrings(size_t count, size_t avg_length = 20);
std::string GenerateRandomString(size_t length);

// String utilities
std::string JoinStrings(const std::vector<std::string>& strings, const std::string& delimiter);
void ProcessJsonData(const std::string& json);

// Mock API utilities
struct MockConnection {
    int id;
    bool is_connected;
    std::chrono::system_clock::time_point created_at;
};

struct MockRequest {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string, std::string> headers;
};

struct MockResponse {
    int status_code;
    std::string body;
    std::map<std::string, std::string> headers;
    std::chrono::microseconds processing_time;
};

std::shared_ptr<MockConnection> CreateMockConnection();
std::vector<std::string> ExecuteMockQuery(
    std::shared_ptr<MockConnection> conn,
    const std::string& query,
    const std::vector<std::string>& params
);

MockRequest CreateMockRequest(
    const std::string& method,
    const std::string& path,
    const std::string& body = ""
);

MockResponse ProcessRequest(const MockRequest& request);
MockResponse ProcessRequestConcurrent(const MockRequest& request);

// Server simulation
void InitializeServer();
void ShutdownServer();

// Authentication utilities
struct AuthService {
    std::string secret_key;
    std::chrono::seconds token_lifetime;
};

std::shared_ptr<AuthService> CreateAuthService();
std::string GenerateJWT();
bool ValidateToken(std::shared_ptr<AuthService> service, const std::string& token);

// Test data generation
struct TestObject {
    int id;
    std::string name;
    std::vector<double> values;
    std::map<std::string, std::string> metadata;
};

std::vector<TestObject> GenerateTestObjects(size_t count);
std::string SerializeToJson(const std::vector<TestObject>& objects);
std::vector<TestObject> DeserializeFromJson(const std::string& json);
std::string GenerateTestJsonArray(size_t count);
std::string GenerateTestPayload(size_t size_bytes);

// Memory utilities
template<typename T>
class AlignedVector {
public:
    explicit AlignedVector(size_t size, size_t alignment = 64)
        : size_(size), alignment_(alignment) {
        data_ = static_cast<T*>(std::aligned_alloc(alignment_, size_ * sizeof(T)));
        if (!data_) {
            throw std::bad_alloc();
        }
    }
    
    ~AlignedVector() {
        std::free(data_);
    }
    
    T* data() { return data_; }
    const T* data() const { return data_; }
    size_t size() const { return size_; }
    
    T& operator[](size_t index) { return data_[index]; }
    const T& operator[](size_t index) const { return data_[index]; }
    
private:
    T* data_;
    size_t size_;
    size_t alignment_;
};

// Cache simulation utilities
void FlushCaches();
void WarmupCaches(void* data, size_t size);

// CPU utilities
void PinToCore(int core_id);
void SetHighPriority();
void DisableTurboBoost();

// Timing utilities
class HighResolutionTimer {
public:
    void Start();
    void Stop();
    std::chrono::nanoseconds Elapsed() const;
    void Reset();
    
private:
    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point end_time_;
    bool is_running_ = false;
};

// Statistics utilities
struct BenchmarkStats {
    double mean;
    double median;
    double std_dev;
    double min_val;
    double max_val;
    size_t sample_count;
};

BenchmarkStats CalculateStats(const std::vector<double>& values);
void PrintStats(const BenchmarkStats& stats, const std::string& name);

// Hardware detection
struct SystemInfo {
    std::string cpu_model;
    size_t cpu_cores;
    size_t cpu_threads;
    size_t cache_l1_size;
    size_t cache_l2_size;
    size_t cache_l3_size;
    size_t memory_size;
    bool has_avx;
    bool has_avx2;
    bool has_sse4_2;
};

SystemInfo GetSystemInfo();
void PrintSystemInfo(const SystemInfo& info);

} // namespace BenchmarkUtils`;
  }

  private static generateBenchmarkUtilsImpl(): string {
    return `/**
 * Benchmark Utilities Implementation
 * Common functions and helpers for benchmark implementations
 */

#include "benchmark_utils.hpp"
#include <algorithm>
#include <numeric>
#include <random>
#include <sstream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <cstring>
#include <iostream>

#ifdef __linux__
#include <sched.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace BenchmarkUtils {

// Global random number generator
thread_local std::mt19937 g_rng(std::random_device{}());

std::vector<int> GenerateRandomInts(size_t count, int min_val, int max_val) {
    std::vector<int> result;
    result.reserve(count);
    
    std::uniform_int_distribution<int> dist(min_val, max_val);
    
    for (size_t i = 0; i < count; ++i) {
        result.push_back(dist(g_rng));
    }
    
    return result;
}

std::string GenerateRandomString(size_t length) {
    const std::string chars = 
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    
    std::string result;
    result.reserve(length);
    
    std::uniform_int_distribution<size_t> dist(0, chars.size() - 1);
    
    for (size_t i = 0; i < length; ++i) {
        result += chars[dist(g_rng)];
    }
    
    return result;
}

std::vector<std::string> GenerateRandomStrings(size_t count, size_t avg_length) {
    std::vector<std::string> result;
    result.reserve(count);
    
    std::normal_distribution<double> length_dist(avg_length, avg_length * 0.2);
    
    for (size_t i = 0; i < count; ++i) {
        size_t length = std::max(1, static_cast<int>(length_dist(g_rng)));
        result.push_back(GenerateRandomString(length));
    }
    
    return result;
}

std::string JoinStrings(const std::vector<std::string>& strings, const std::string& delimiter) {
    if (strings.empty()) return "";
    
    std::ostringstream oss;
    oss << strings[0];
    
    for (size_t i = 1; i < strings.size(); ++i) {
        oss << delimiter << strings[i];
    }
    
    return oss.str();
}

void ProcessJsonData(const std::string& json) {
    // Simulate JSON parsing workload
    size_t brace_count = 0;
    size_t bracket_count = 0;
    
    for (char c : json) {
        switch (c) {
            case '{': ++brace_count; break;
            case '}': --brace_count; break;
            case '[': ++bracket_count; break;
            case ']': --bracket_count; break;
        }
    }
    
    // Prevent optimization
    benchmark::DoNotOptimize(brace_count);
    benchmark::DoNotOptimize(bracket_count);
}

// Mock API Implementation
static std::atomic<int> g_connection_counter{0};
static std::mutex g_server_mutex;
static bool g_server_initialized = false;

std::shared_ptr<MockConnection> CreateMockConnection() {
    auto conn = std::make_shared<MockConnection>();
    conn->id = ++g_connection_counter;
    conn->is_connected = true;
    conn->created_at = std::chrono::system_clock::now();
    return conn;
}

std::vector<std::string> ExecuteMockQuery(
    std::shared_ptr<MockConnection> conn,
    const std::string& query,
    const std::vector<std::string>& params) {
    
    // Simulate database query processing time
    std::this_thread::sleep_for(std::chrono::microseconds(10 + params.size() * 2));
    
    std::vector<std::string> result;
    
    // Generate mock results based on query complexity
    size_t result_count = 1 + (query.length() % 10);
    for (size_t i = 0; i < result_count; ++i) {
        result.push_back("row_" + std::to_string(i) + "_conn_" + std::to_string(conn->id));
    }
    
    return result;
}

MockRequest CreateMockRequest(const std::string& method, const std::string& path, const std::string& body) {
    MockRequest request;
    request.method = method;
    request.path = path;
    request.body = body;
    
    // Add common headers
    request.headers["User-Agent"] = "BenchmarkClient/1.0";
    request.headers["Accept"] = "application/json";
    if (!body.empty()) {
        request.headers["Content-Type"] = "application/json";
        request.headers["Content-Length"] = std::to_string(body.length());
    }
    
    return request;
}

MockResponse ProcessRequest(const MockRequest& request) {
    auto start = std::chrono::high_resolution_clock::now();
    
    MockResponse response;
    response.status_code = 200;
    response.headers["Content-Type"] = "application/json";
    response.headers["Server"] = "BenchmarkServer/1.0";
    
    // Simulate processing based on request complexity
    size_t processing_complexity = request.path.length() + request.body.length();
    std::this_thread::sleep_for(std::chrono::microseconds(processing_complexity % 100));
    
    // Generate response body
    response.body = R"({"status":"success","id":)" + std::to_string(g_rng() % 10000) + R"(,"data":"processed"})";
    
    auto end = std::chrono::high_resolution_clock::now();
    response.processing_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    return response;
}

MockResponse ProcessRequestConcurrent(const MockRequest& request) {
    // Add small random delay to simulate real concurrency effects
    std::this_thread::sleep_for(std::chrono::microseconds(g_rng() % 50));
    return ProcessRequest(request);
}

void InitializeServer() {
    std::lock_guard<std::mutex> lock(g_server_mutex);
    g_server_initialized = true;
}

void ShutdownServer() {
    std::lock_guard<std::mutex> lock(g_server_mutex);
    g_server_initialized = false;
}

// Authentication Implementation
std::shared_ptr<AuthService> CreateAuthService() {
    auto service = std::make_shared<AuthService>();
    service->secret_key = "benchmark_secret_key_12345";
    service->token_lifetime = std::chrono::seconds(3600);
    return service;
}

std::string GenerateJWT() {
    // Simplified JWT simulation
    std::string header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    std::string payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkJlbmNobWFyayBVc2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ";
    std::string signature = GenerateRandomString(43);
    
    return header + "." + payload + "." + signature;
}

bool ValidateToken(std::shared_ptr<AuthService> service, const std::string& token) {
    // Simulate token validation complexity
    size_t complexity = token.length() + service->secret_key.length();
    
    // Simple validation simulation
    return token.length() > 100 && token.find('.') != std::string::npos;
}

// Test Object Implementation
std::vector<TestObject> GenerateTestObjects(size_t count) {
    std::vector<TestObject> objects;
    objects.reserve(count);
    
    std::uniform_real_distribution<double> value_dist(0.0, 1000.0);
    
    for (size_t i = 0; i < count; ++i) {
        TestObject obj;
        obj.id = static_cast<int>(i);
        obj.name = "object_" + std::to_string(i);
        
        // Generate random values
        size_t value_count = 3 + (i % 7);
        obj.values.reserve(value_count);
        for (size_t j = 0; j < value_count; ++j) {
            obj.values.push_back(value_dist(g_rng));
        }
        
        // Generate metadata
        size_t meta_count = 1 + (i % 3);
        for (size_t j = 0; j < meta_count; ++j) {
            obj.metadata["key_" + std::to_string(j)] = "value_" + std::to_string(i * 10 + j);
        }
        
        objects.push_back(std::move(obj));
    }
    
    return objects;
}

std::string SerializeToJson(const std::vector<TestObject>& objects) {
    std::ostringstream oss;
    oss << "[";
    
    for (size_t i = 0; i < objects.size(); ++i) {
        if (i > 0) oss << ",";
        
        const auto& obj = objects[i];
        oss << R"({"id":)" << obj.id << R"(,"name":")" << obj.name << R"(","values":[)";
        
        for (size_t j = 0; j < obj.values.size(); ++j) {
            if (j > 0) oss << ",";
            oss << obj.values[j];
        }
        
        oss << R"(],"metadata":{)";
        size_t meta_idx = 0;
        for (const auto& [key, value] : obj.metadata) {
            if (meta_idx > 0) oss << ",";
            oss << R"(")" << key << R"(":")" << value << R"(")";
            ++meta_idx;
        }
        oss << "}}";
    }
    
    oss << "]";
    return oss.str();
}

std::vector<TestObject> DeserializeFromJson(const std::string& json) {
    // Simplified deserialization simulation
    std::vector<TestObject> objects;
    
    // Count objects by counting opening braces
    size_t object_count = 0;
    for (char c : json) {
        if (c == '{') ++object_count;
    }
    
    // Generate mock objects
    for (size_t i = 0; i < object_count; ++i) {
        TestObject obj;
        obj.id = static_cast<int>(i);
        obj.name = "deserialized_" + std::to_string(i);
        obj.values = {1.0, 2.0, 3.0};
        obj.metadata["source"] = "json";
        objects.push_back(std::move(obj));
    }
    
    return objects;
}

std::string GenerateTestJsonArray(size_t count) {
    auto objects = GenerateTestObjects(count);
    return SerializeToJson(objects);
}

std::string GenerateTestPayload(size_t size_bytes) {
    std::string payload;
    payload.reserve(size_bytes);
    
    const std::string pattern = R"({"data":")" + GenerateRandomString(50) + R"("})";
    
    while (payload.length() < size_bytes) {
        payload += pattern;
    }
    
    payload.resize(size_bytes);
    return payload;
}

// Hardware utilities
void FlushCaches() {
#ifdef __linux__
    // Attempt to flush caches (requires root privileges)
    system("sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true");
#endif
}

void WarmupCaches(void* data, size_t size) {
    // Touch every cache line
    const size_t cache_line_size = 64;
    char* ptr = static_cast<char*>(data);
    
    for (size_t i = 0; i < size; i += cache_line_size) {
        benchmark::DoNotOptimize(ptr[i]);
    }
}

void PinToCore(int core_id) {
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    
    pthread_t current_thread = pthread_self();
    pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
#endif
}

void SetHighPriority() {
#ifdef __linux__
    setpriority(PRIO_PROCESS, 0, -20);
#endif
}

// Timer implementation
void HighResolutionTimer::Start() {
    start_time_ = std::chrono::high_resolution_clock::now();
    is_running_ = true;
}

void HighResolutionTimer::Stop() {
    end_time_ = std::chrono::high_resolution_clock::now();
    is_running_ = false;
}

std::chrono::nanoseconds HighResolutionTimer::Elapsed() const {
    auto end_point = is_running_ ? std::chrono::high_resolution_clock::now() : end_time_;
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end_point - start_time_);
}

void HighResolutionTimer::Reset() {
    start_time_ = std::chrono::high_resolution_clock::time_point{};
    end_time_ = std::chrono::high_resolution_clock::time_point{};
    is_running_ = false;
}

// Statistics implementation
BenchmarkStats CalculateStats(const std::vector<double>& values) {
    if (values.empty()) {
        return {0.0, 0.0, 0.0, 0.0, 0.0, 0};
    }
    
    BenchmarkStats stats;
    stats.sample_count = values.size();
    
    // Calculate mean
    stats.mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    
    // Calculate median
    std::vector<double> sorted_values = values;
    std::sort(sorted_values.begin(), sorted_values.end());
    size_t mid = sorted_values.size() / 2;
    if (sorted_values.size() % 2 == 0) {
        stats.median = (sorted_values[mid - 1] + sorted_values[mid]) / 2.0;
    } else {
        stats.median = sorted_values[mid];
    }
    
    // Calculate standard deviation
    double sum_sq_diff = 0.0;
    for (double value : values) {
        double diff = value - stats.mean;
        sum_sq_diff += diff * diff;
    }
    stats.std_dev = std::sqrt(sum_sq_diff / values.size());
    
    // Min and max
    stats.min_val = *std::min_element(values.begin(), values.end());
    stats.max_val = *std::max_element(values.begin(), values.end());
    
    return stats;
}

void PrintStats(const BenchmarkStats& stats, const std::string& name) {
    std::cout << "Statistics for " << name << ":\\n";
    std::cout << "  Samples: " << stats.sample_count << "\\n";
    std::cout << "  Mean: " << stats.mean << "\\n";
    std::cout << "  Median: " << stats.median << "\\n";
    std::cout << "  Std Dev: " << stats.std_dev << "\\n";
    std::cout << "  Min: " << stats.min_val << "\\n";
    std::cout << "  Max: " << stats.max_val << "\\n";
}

// System info (simplified implementation)
SystemInfo GetSystemInfo() {
    SystemInfo info;
    info.cpu_model = "Generic CPU";
    info.cpu_cores = std::thread::hardware_concurrency();
    info.cpu_threads = std::thread::hardware_concurrency();
    info.cache_l1_size = 32 * 1024;  // 32KB typical
    info.cache_l2_size = 256 * 1024; // 256KB typical
    info.cache_l3_size = 8 * 1024 * 1024; // 8MB typical
    info.memory_size = 8ULL * 1024 * 1024 * 1024; // 8GB default
    info.has_avx = false;
    info.has_avx2 = false;
    info.has_sse4_2 = false;
    
    return info;
}

void PrintSystemInfo(const SystemInfo& info) {
    std::cout << "System Information:\\n";
    std::cout << "  CPU: " << info.cpu_model << "\\n";
    std::cout << "  Cores: " << info.cpu_cores << "\\n";
    std::cout << "  Threads: " << info.cpu_threads << "\\n";
    std::cout << "  L1 Cache: " << (info.cache_l1_size / 1024) << " KB\\n";
    std::cout << "  L2 Cache: " << (info.cache_l2_size / 1024) << " KB\\n";
    std::cout << "  L3 Cache: " << (info.cache_l3_size / 1024 / 1024) << " MB\\n";
    std::cout << "  Memory: " << (info.memory_size / 1024 / 1024 / 1024) << " GB\\n";
}

} // namespace BenchmarkUtils`;
  }
}