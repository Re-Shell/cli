/**
 * C++ Valgrind Memory Analysis Generator
 * Generates Valgrind configuration and memory testing tools for C++ projects
 */

export interface CppValgrindConfig {
  projectName: string;
  enableMemcheck?: boolean;
  enableHelgrind?: boolean;
  enableCachegrind?: boolean;
  enableCallgrind?: boolean;
  enableMassif?: boolean;
  enableDRD?: boolean;
  suppressionFiles?: string[];
  customFlags?: string[];
}

export class CppValgrindGenerator {
  static generate(config: CppValgrindConfig): Record<string, string> {
    const {
      projectName,
      enableMemcheck = true,
      enableHelgrind = true,
      enableCachegrind = true,
      enableCallgrind = false,
      enableMassif = true,
      enableDRD = false,
      suppressionFiles = [],
      customFlags = []
    } = config;

    return {
      'valgrind/valgrind.cmake': this.generateValgrindCMake(projectName),
      'valgrind/memcheck.supp': this.generateMemcheckSuppressions(),
      'valgrind/helgrind.supp': this.generateHelgrindSuppressions(),
      'scripts/run_valgrind.sh': this.generateValgrindScript(projectName, {
        enableMemcheck,
        enableHelgrind,
        enableCachegrind,
        enableCallgrind,
        enableMassif,
        enableDRD,
        suppressionFiles,
        customFlags
      }),
      'scripts/valgrind_analysis.py': this.generateValgrindAnalysis(),
      'valgrind/README.md': this.generateValgrindReadme(projectName),
      '.github/workflows/valgrind.yml': this.generateValgrindCI(projectName),
      'valgrind/docker/Dockerfile.valgrind': this.generateValgrindDockerfile(),
      'valgrind/configs/memcheck.conf': this.generateMemcheckConfig(),
      'valgrind/configs/helgrind.conf': this.generateHelgrindConfig(),
      'valgrind/configs/cachegrind.conf': this.generateCachegrindConfig(),
      'valgrind/configs/massif.conf': this.generateMassifConfig(),
      'scripts/memory_report.py': this.generateMemoryReport()
    };
  }

  private static generateValgrindCMake(projectName: string): string {
    return `# Valgrind Integration for ${projectName}
# Memory analysis and profiling tools

find_program(VALGRIND_EXECUTABLE valgrind)

if(VALGRIND_EXECUTABLE)
    message(STATUS "Valgrind found: \${VALGRIND_EXECUTABLE}")
    
    # Valgrind configuration
    set(VALGRIND_COMMON_FLAGS
        --tool=memcheck
        --leak-check=full
        --show-leak-kinds=all
        --track-origins=yes
        --verbose
        --error-exitcode=1
        --gen-suppressions=all
        --suppressions=\${CMAKE_SOURCE_DIR}/valgrind/memcheck.supp
    )
    
    # Create valgrind targets for all executables
    function(add_valgrind_test TARGET_NAME)
        cmake_parse_arguments(
            VALGRIND
            "MEMCHECK;HELGRIND;CACHEGRIND;CALLGRIND;MASSIF;DRD"
            "WORKING_DIRECTORY;TIMEOUT"
            "ARGS;SUPPRESSIONS"
            \${ARGN}
        )
        
        if(NOT VALGRIND_WORKING_DIRECTORY)
            set(VALGRIND_WORKING_DIRECTORY \${CMAKE_CURRENT_BINARY_DIR})
        endif()
        
        if(NOT VALGRIND_TIMEOUT)
            set(VALGRIND_TIMEOUT 300)
        endif()
        
        # Memcheck (default)
        if(VALGRIND_MEMCHECK OR NOT (VALGRIND_HELGRIND OR VALGRIND_CACHEGRIND OR VALGRIND_CALLGRIND OR VALGRIND_MASSIF OR VALGRIND_DRD))
            set(MEMCHECK_FLAGS
                --tool=memcheck
                --leak-check=full
                --show-leak-kinds=all
                --track-origins=yes
                --verbose
                --error-exitcode=1
                --xml=yes
                --xml-file=\${CMAKE_BINARY_DIR}/valgrind_\${TARGET_NAME}_memcheck.xml
                --suppressions=\${CMAKE_SOURCE_DIR}/valgrind/memcheck.supp
            )
            
            foreach(SUPP_FILE \${VALGRIND_SUPPRESSIONS})
                list(APPEND MEMCHECK_FLAGS --suppressions=\${SUPP_FILE})
            endforeach()
            
            add_test(
                NAME valgrind_memcheck_\${TARGET_NAME}
                COMMAND \${VALGRIND_EXECUTABLE} \${MEMCHECK_FLAGS} \$<TARGET_FILE:\${TARGET_NAME}> \${VALGRIND_ARGS}
                WORKING_DIRECTORY \${VALGRIND_WORKING_DIRECTORY}
            )
            
            set_tests_properties(valgrind_memcheck_\${TARGET_NAME} PROPERTIES
                TIMEOUT \${VALGRIND_TIMEOUT}
                LABELS "Valgrind;Memcheck;Memory"
            )
        endif()
        
        # Helgrind (thread error detection)
        if(VALGRIND_HELGRIND)
            set(HELGRIND_FLAGS
                --tool=helgrind
                --verbose
                --error-exitcode=1
                --xml=yes
                --xml-file=\${CMAKE_BINARY_DIR}/valgrind_\${TARGET_NAME}_helgrind.xml
                --suppressions=\${CMAKE_SOURCE_DIR}/valgrind/helgrind.supp
            )
            
            add_test(
                NAME valgrind_helgrind_\${TARGET_NAME}
                COMMAND \${VALGRIND_EXECUTABLE} \${HELGRIND_FLAGS} \$<TARGET_FILE:\${TARGET_NAME}> \${VALGRIND_ARGS}
                WORKING_DIRECTORY \${VALGRIND_WORKING_DIRECTORY}
            )
            
            set_tests_properties(valgrind_helgrind_\${TARGET_NAME} PROPERTIES
                TIMEOUT \${VALGRIND_TIMEOUT}
                LABELS "Valgrind;Helgrind;Threading"
            )
        endif()
        
        # Cachegrind (cache profiling)
        if(VALGRIND_CACHEGRIND)
            set(CACHEGRIND_FLAGS
                --tool=cachegrind
                --verbose
                --cachegrind-out-file=\${CMAKE_BINARY_DIR}/cachegrind_\${TARGET_NAME}.out
            )
            
            add_test(
                NAME valgrind_cachegrind_\${TARGET_NAME}
                COMMAND \${VALGRIND_EXECUTABLE} \${CACHEGRIND_FLAGS} \$<TARGET_FILE:\${TARGET_NAME}> \${VALGRIND_ARGS}
                WORKING_DIRECTORY \${VALGRIND_WORKING_DIRECTORY}
            )
            
            set_tests_properties(valgrind_cachegrind_\${TARGET_NAME} PROPERTIES
                TIMEOUT \${VALGRIND_TIMEOUT}
                LABELS "Valgrind;Cachegrind;Performance"
            )
        endif()
        
        # Callgrind (call profiling)
        if(VALGRIND_CALLGRIND)
            set(CALLGRIND_FLAGS
                --tool=callgrind
                --verbose
                --callgrind-out-file=\${CMAKE_BINARY_DIR}/callgrind_\${TARGET_NAME}.out
                --dump-instr=yes
                --collect-jumps=yes
            )
            
            add_test(
                NAME valgrind_callgrind_\${TARGET_NAME}
                COMMAND \${VALGRIND_EXECUTABLE} \${CALLGRIND_FLAGS} \$<TARGET_FILE:\${TARGET_NAME}> \${VALGRIND_ARGS}
                WORKING_DIRECTORY \${VALGRIND_WORKING_DIRECTORY}
            )
            
            set_tests_properties(valgrind_callgrind_\${TARGET_NAME} PROPERTIES
                TIMEOUT \${VALGRIND_TIMEOUT}
                LABELS "Valgrind;Callgrind;Profiling"
            )
        endif()
        
        # Massif (heap profiling)
        if(VALGRIND_MASSIF)
            set(MASSIF_FLAGS
                --tool=massif
                --verbose
                --massif-out-file=\${CMAKE_BINARY_DIR}/massif_\${TARGET_NAME}.out
                --heap=yes
                --stacks=yes
                --time-unit=ms
            )
            
            add_test(
                NAME valgrind_massif_\${TARGET_NAME}
                COMMAND \${VALGRIND_EXECUTABLE} \${MASSIF_FLAGS} \$<TARGET_FILE:\${TARGET_NAME}> \${VALGRIND_ARGS}
                WORKING_DIRECTORY \${VALGRIND_WORKING_DIRECTORY}
            )
            
            set_tests_properties(valgrind_massif_\${TARGET_NAME} PROPERTIES
                TIMEOUT \${VALGRIND_TIMEOUT}
                LABELS "Valgrind;Massif;Heap"
            )
        endif()
        
        # DRD (data race detection)
        if(VALGRIND_DRD)
            set(DRD_FLAGS
                --tool=drd
                --verbose
                --error-exitcode=1
                --xml=yes
                --xml-file=\${CMAKE_BINARY_DIR}/valgrind_\${TARGET_NAME}_drd.xml
            )
            
            add_test(
                NAME valgrind_drd_\${TARGET_NAME}
                COMMAND \${VALGRIND_EXECUTABLE} \${DRD_FLAGS} \$<TARGET_FILE:\${TARGET_NAME}> \${VALGRIND_ARGS}
                WORKING_DIRECTORY \${VALGRIND_WORKING_DIRECTORY}
            )
            
            set_tests_properties(valgrind_drd_\${TARGET_NAME} PROPERTIES
                TIMEOUT \${VALGRIND_TIMEOUT}
                LABELS "Valgrind;DRD;Threading"
            )
        endif()
    endfunction()
    
    # Custom targets for comprehensive analysis
    add_custom_target(valgrind_all
        COMMENT "Running all Valgrind tools"
    )
    
    add_custom_target(valgrind_memcheck
        COMMENT "Running Valgrind Memcheck"
    )
    
    add_custom_target(valgrind_helgrind
        COMMENT "Running Valgrind Helgrind"
    )
    
    add_custom_target(valgrind_cachegrind
        COMMENT "Running Valgrind Cachegrind"
    )
    
    add_custom_target(valgrind_massif
        COMMENT "Running Valgrind Massif"
    )
    
    # Function to automatically add valgrind tests for all executables
    function(enable_valgrind_for_target TARGET_NAME)
        add_valgrind_test(\${TARGET_NAME} MEMCHECK HELGRIND CACHEGRIND MASSIF)
    endfunction()
    
else()
    message(WARNING "Valgrind not found. Memory analysis tools will not be available.")
    
    # Provide stub functions
    function(add_valgrind_test TARGET_NAME)
        # Do nothing
    endfunction()
    
    function(enable_valgrind_for_target TARGET_NAME)
        # Do nothing
    endfunction()
endif()

# Valgrind-specific compile flags
function(add_valgrind_flags TARGET_NAME)
    target_compile_options(\${TARGET_NAME} PRIVATE
        -g3                      # Maximum debug information
        -O0                      # No optimization for accurate results
        -fno-omit-frame-pointer  # Keep frame pointers for stack traces
        -fno-inline-functions    # Disable inlining for clearer traces
    )
    
    target_compile_definitions(\${TARGET_NAME} PRIVATE
        VALGRIND_BUILD=1
    )
endfunction()

# Integration with existing project
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND VALGRIND_EXECUTABLE)
    # Automatically enable valgrind for debug builds
    set(ENABLE_VALGRIND_BY_DEFAULT ON)
else()
    set(ENABLE_VALGRIND_BY_DEFAULT OFF)
endif()

option(ENABLE_VALGRIND "Enable Valgrind memory analysis" \${ENABLE_VALGRIND_BY_DEFAULT})`;
  }

  private static generateMemcheckSuppressions(): string {
    return `# Valgrind Memcheck Suppressions
# Common false positives and known issues

# Standard library suppressions
{
   std_string_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:_ZNSs4_Rep9_S_createEmm*
   fun:_ZNSs4_Rep8_M_cloneERK*
   fun:_ZNSs7reserveEm
}

{
   std_locale_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   obj:*libstdc++*
   fun:_ZNSt6locale5facet*
}

# Thread-local storage suppressions
{
   tls_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:calloc
   fun:_dl_allocate_tls
   fun:pthread_create@@GLIBC_*
}

# C++ global constructors/destructors
{
   global_constructor_leak
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:__static_initialization_and_destruction_*
}

{
   global_destructor_leak
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:__cxa_atexit
}

# OpenSSL suppressions
{
   openssl_init_leak
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:CRYPTO_malloc
   fun:*SSL_library_init*
}

# glibc suppressions
{
   glibc_dl_init
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_dl_new_object
   fun:_dl_map_object_from_fd
}

{
   glibc_getpwuid
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:nss_parse_service_list
   fun:__nss_database_lookup
}

# Boost suppressions
{
   boost_thread_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:_ZN5boost6thread*
}

# JSON library suppressions (nlohmann/json)
{
   json_allocator_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:_ZN8nlohmann*
}

# HTTP library suppressions (libcurl)
{
   curl_global_init
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:curl_global_init
}

# Database driver suppressions (PostgreSQL)
{
   postgresql_driver_init
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:PQconnectdb
}

# Custom application suppressions
{
   app_singleton_leak
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:*Singleton*
}

# Logging framework suppressions
{
   spdlog_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:*spdlog*
}

# Testing framework suppressions
{
   googletest_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:*testing*
}

# Benchmark framework suppressions
{
   benchmark_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:*benchmark*
}

# Docker/containerization suppressions
{
   container_runtime_leak
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_dl_init
   obj:*/ld-*.so
}

# Suppressions for specific architectures
{
   x86_64_syscall_param
   Memcheck:Param
   syscall(write)
   fun:write
   fun:_IO_file_write@@GLIBC_*
}

{
   arm64_specific_suppression
   Memcheck:Cond
   fun:__memcmp_sse4_1
   fun:*
}

# Networking library suppressions
{
   network_buffer_false_positive
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:*network*
   fun:*socket*
}

# Regex library suppressions
{
   regex_compilation_leak
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:_Znwm
   fun:*regex*
}

# Crypto library suppressions
{
   crypto_random_init
   Memcheck:Leak
   match-leak-kinds: reachable
   fun:malloc
   fun:*random*
   fun:*crypto*
}`;
  }

  private static generateHelgrindSuppressions(): string {
    return `# Valgrind Helgrind Suppressions
# Thread-related false positives

# Standard library thread suppressions
{
   std_thread_false_positive
   Helgrind:Race
   fun:_ZNSt6thread*
}

{
   std_mutex_false_positive
   Helgrind:Race
   fun:_ZNSt5mutex*
}

{
   std_condition_variable_false_positive
   Helgrind:Race
   fun:_ZNSt18condition_variable*
}

# C++ atomics suppressions
{
   atomic_operations_false_positive
   Helgrind:Race
   fun:*atomic*
}

# Thread-local storage
{
   tls_access_false_positive
   Helgrind:Race
   fun:*thread_local*
}

# glibc thread suppressions
{
   glibc_thread_init
   Helgrind:Race
   fun:pthread_create@@GLIBC_*
}

{
   glibc_mutex_init
   Helgrind:Race
   fun:pthread_mutex_init
}

# Boost thread suppressions
{
   boost_thread_library
   Helgrind:Race
   fun:_ZN5boost6thread*
}

{
   boost_mutex_library
   Helgrind:Race
   fun:_ZN5boost5mutex*
}

# OpenMP suppressions
{
   openmp_false_positive
   Helgrind:Race
   fun:*omp*
}

# Intel TBB suppressions
{
   tbb_false_positive
   Helgrind:Race
   fun:*tbb*
}

# Logging library thread safety
{
   spdlog_thread_safety
   Helgrind:Race
   fun:*spdlog*
}

# JSON library thread safety
{
   json_thread_safety
   Helgrind:Race
   fun:*nlohmann*
}

# HTTP client thread safety
{
   http_client_thread_safety
   Helgrind:Race
   fun:*curl*
}

# Database connection pool
{
   db_connection_pool_race
   Helgrind:Race
   fun:*connection*
   fun:*pool*
}

# Custom thread pool suppressions
{
   custom_thread_pool_race
   Helgrind:Race
   fun:*ThreadPool*
}

# Signal handling suppressions
{
   signal_handler_race
   Helgrind:Race
   fun:*signal*
}

# Memory allocator thread safety
{
   allocator_thread_safety
   Helgrind:Race
   fun:malloc
   fun:free
}

# Static initialization race
{
   static_init_race
   Helgrind:Race
   fun:__static_initialization_and_destruction_*
}

# Destructor race conditions
{
   destructor_race
   Helgrind:Race
   fun:__cxa_finalize
}

# Exception handling races
{
   exception_handling_race
   Helgrind:Race
   fun:__cxa_throw
}

# RTTI race conditions
{
   rtti_race
   Helgrind:Race
   fun:__dynamic_cast
}

# Stream operations race
{
   stream_operations_race
   Helgrind:Race
   fun:*iostream*
}

# Locale operations race
{
   locale_operations_race
   Helgrind:Race
   fun:*locale*
}

# Time operations race
{
   time_operations_race
   Helgrind:Race
   fun:*time*
}

# Random number generation race
{
   random_generation_race
   Helgrind:Race
   fun:*random*
}

# Filesystem operations race
{
   filesystem_operations_race
   Helgrind:Race
   fun:*filesystem*
}`;
  }

  private static generateValgrindScript(projectName: string, options: any): string {
    return `#!/bin/bash
# Comprehensive Valgrind Analysis Script for ${projectName}
# Memory analysis, thread safety, and performance profiling

set -euo pipefail

# Configuration
PROJECT_NAME="${projectName}"
BUILD_DIR="build"
EXECUTABLE_PATH="./\${BUILD_DIR}/\${PROJECT_NAME}"
RESULTS_DIR="valgrind_results"
TIMESTAMP="\\$(date +%Y%m%d_%H%M%S)"

# Valgrind tools configuration
ENABLE_MEMCHECK=${options.enableMemcheck}
ENABLE_HELGRIND=${options.enableHelgrind}
ENABLE_CACHEGRIND=${options.enableCachegrind}
ENABLE_CALLGRIND=${options.enableCallgrind}
ENABLE_MASSIF=${options.enableMassif}
ENABLE_DRD=${options.enableDRD}

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
BLUE='\\033[0;34m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

# Create results directory
mkdir -p "\\${RESULTS_DIR}"

echo -e "\\${BLUE}=== Valgrind Analysis Suite for \${PROJECT_NAME} ===\\${NC}"

# Check if executable exists
if [[ ! -f "\\${EXECUTABLE_PATH}" ]]; then
    echo -e "\\${RED}Error: Executable not found at \\${EXECUTABLE_PATH}\\${NC}"
    echo "Please build the project first with debug symbols:"
    echo "cmake -DCMAKE_BUILD_TYPE=Debug -B \\${BUILD_DIR}"
    echo "cmake --build \\${BUILD_DIR}"
    exit 1
fi

# Check if valgrind is available
if ! command -v valgrind &> /dev/null; then
    echo -e "\\${RED}Error: Valgrind not found. Please install valgrind.\\${NC}"
    exit 1
fi

# Common valgrind flags
COMMON_FLAGS=(
    --verbose
    --log-file="\\${RESULTS_DIR}/valgrind_\\${TIMESTAMP}.log"
    --time-stamp=yes
    --track-fds=yes
    --trace-children=yes
)

# Function to run valgrind tool
run_valgrind_tool() {
    local tool_name="\\$1"
    local tool_flags="\\$2"
    local output_file="\\$3"
    
    echo -e "\\${YELLOW}Running \\${tool_name}...\\${NC}"
    
    local start_time=\\$(date +%s)
    
    if valgrind \\${COMMON_FLAGS[@]} \\${tool_flags} \\${EXECUTABLE_PATH} > "\\${output_file}.stdout" 2> "\\${output_file}.stderr"; then
        local end_time=\\$(date +%s)
        local duration=\\$((end_time - start_time))
        echo -e "\\${GREEN}\\${tool_name} completed successfully in \\${duration}s\\${NC}"
        echo -e "Results saved to \\${output_file}.*"
        return 0
    else
        echo -e "\\${RED}\\${tool_name} detected issues. Check \\${output_file}.stderr\\${NC}"
        return 1
    fi
}

# Memcheck - Memory error detection
if [[ "\\${ENABLE_MEMCHECK}" == "true" ]]; then
    MEMCHECK_FLAGS=(
        --tool=memcheck
        --leak-check=full
        --show-leak-kinds=all
        --track-origins=yes
        --show-reachable=yes
        --error-exitcode=1
        --gen-suppressions=all
        --suppressions=valgrind/memcheck.supp
        --xml=yes
        --xml-file="\\${RESULTS_DIR}/memcheck_\\${TIMESTAMP}.xml"
    )
    
    run_valgrind_tool "Memcheck" "\\${MEMCHECK_FLAGS[*]}" "\\${RESULTS_DIR}/memcheck_\\${TIMESTAMP}"
    MEMCHECK_EXIT_CODE=\\$?
fi

# Helgrind - Thread error detection
if [[ "\\${ENABLE_HELGRIND}" == "true" ]]; then
    HELGRIND_FLAGS=(
        --tool=helgrind
        --history-level=full
        --conflict-cache-size=1000000
        --suppressions=valgrind/helgrind.supp
        --xml=yes
        --xml-file="\\${RESULTS_DIR}/helgrind_\\${TIMESTAMP}.xml"
    )
    
    run_valgrind_tool "Helgrind" "\\${HELGRIND_FLAGS[*]}" "\\${RESULTS_DIR}/helgrind_\\${TIMESTAMP}"
    HELGRIND_EXIT_CODE=\\$?
fi

# Cachegrind - Cache profiling
if [[ "\\${ENABLE_CACHEGRIND}" == "true" ]]; then
    CACHEGRIND_FLAGS=(
        --tool=cachegrind
        --cache-sim=yes
        --branch-sim=yes
        --cachegrind-out-file="\\${RESULTS_DIR}/cachegrind_\\${TIMESTAMP}.out"
    )
    
    run_valgrind_tool "Cachegrind" "\\${CACHEGRIND_FLAGS[*]}" "\\${RESULTS_DIR}/cachegrind_\\${TIMESTAMP}"
    
    # Generate cachegrind annotation
    if command -v cg_annotate &> /dev/null; then
        echo -e "\\${YELLOW}Generating Cachegrind annotation...\\${NC}"
        cg_annotate "\\${RESULTS_DIR}/cachegrind_\\${TIMESTAMP}.out" > "\\${RESULTS_DIR}/cachegrind_\\${TIMESTAMP}_annotation.txt"
    fi
fi

# Callgrind - Call profiling
if [[ "\\${ENABLE_CALLGRIND}" == "true" ]]; then
    CALLGRIND_FLAGS=(
        --tool=callgrind
        --dump-instr=yes
        --collect-jumps=yes
        --collect-systime=yes
        --callgrind-out-file="\\${RESULTS_DIR}/callgrind_\\${TIMESTAMP}.out"
    )
    
    run_valgrind_tool "Callgrind" "\\${CALLGRIND_FLAGS[*]}" "\\${RESULTS_DIR}/callgrind_\\${TIMESTAMP}"
    
    # Generate callgrind annotation
    if command -v callgrind_annotate &> /dev/null; then
        echo -e "\\${YELLOW}Generating Callgrind annotation...\\${NC}"
        callgrind_annotate "\\${RESULTS_DIR}/callgrind_\\${TIMESTAMP}.out" > "\\${RESULTS_DIR}/callgrind_\\${TIMESTAMP}_annotation.txt"
    fi
fi

# Massif - Heap profiling
if [[ "\\${ENABLE_MASSIF}" == "true" ]]; then
    MASSIF_FLAGS=(
        --tool=massif
        --heap=yes
        --stacks=yes
        --depth=30
        --threshold=0.1
        --peak-inaccuracy=0.1
        --time-unit=ms
        --massif-out-file="\\${RESULTS_DIR}/massif_\\${TIMESTAMP}.out"
    )
    
    run_valgrind_tool "Massif" "\\${MASSIF_FLAGS[*]}" "\\${RESULTS_DIR}/massif_\\${TIMESTAMP}"
    
    # Generate massif visualization
    if command -v ms_print &> /dev/null; then
        echo -e "\\${YELLOW}Generating Massif visualization...\\${NC}"
        ms_print "\\${RESULTS_DIR}/massif_\\${TIMESTAMP}.out" > "\\${RESULTS_DIR}/massif_\\${TIMESTAMP}_graph.txt"
    fi
fi

# DRD - Data race detection
if [[ "\\${ENABLE_DRD}" == "true" ]]; then
    DRD_FLAGS=(
        --tool=drd
        --check-stack-var=yes
        --exclusive-threshold=10
        --segment-merging=yes
        --shared-threshold=10
        --xml=yes
        --xml-file="\\${RESULTS_DIR}/drd_\\${TIMESTAMP}.xml"
    )
    
    run_valgrind_tool "DRD" "\\${DRD_FLAGS[*]}" "\\${RESULTS_DIR}/drd_\\${TIMESTAMP}"
    DRD_EXIT_CODE=\\$?
fi

# Generate comprehensive report
echo -e "\\${BLUE}=== Generating Analysis Report ===\\${NC}"

if command -v python3 &> /dev/null; then
    python3 scripts/valgrind_analysis.py \\
        --results-dir "\\${RESULTS_DIR}" \\
        --timestamp "\\${TIMESTAMP}" \\
        --project-name "\\${PROJECT_NAME}" \\
        --output "\\${RESULTS_DIR}/analysis_report_\\${TIMESTAMP}.html"
    
    echo -e "\\${GREEN}Comprehensive report generated: \\${RESULTS_DIR}/analysis_report_\\${TIMESTAMP}.html\\${NC}"
fi

# Summary
echo -e "\\${BLUE}=== Valgrind Analysis Summary ===\\${NC}"
echo "Project: \\${PROJECT_NAME}"
echo "Timestamp: \\${TIMESTAMP}"
echo "Results directory: \\${RESULTS_DIR}"
echo ""

# Exit status summary
OVERALL_EXIT_CODE=0

if [[ "\\${ENABLE_MEMCHECK}" == "true" ]]; then
    if [[ \\${MEMCHECK_EXIT_CODE:-0} -eq 0 ]]; then
        echo -e "\\${GREEN}✓ Memcheck: No memory errors detected\\${NC}"
    else
        echo -e "\\${RED}✗ Memcheck: Memory errors detected\\${NC}"
        OVERALL_EXIT_CODE=1
    fi
fi

if [[ "\\${ENABLE_HELGRIND}" == "true" ]]; then
    if [[ \\${HELGRIND_EXIT_CODE:-0} -eq 0 ]]; then
        echo -e "\\${GREEN}✓ Helgrind: No thread errors detected\\${NC}"
    else
        echo -e "\\${RED}✗ Helgrind: Thread errors detected\\${NC}"
        OVERALL_EXIT_CODE=1
    fi
fi

if [[ "\\${ENABLE_DRD}" == "true" ]]; then
    if [[ \\${DRD_EXIT_CODE:-0} -eq 0 ]]; then
        echo -e "\\${GREEN}✓ DRD: No data races detected\\${NC}"
    else
        echo -e "\\${RED}✗ DRD: Data races detected\\${NC}"
        OVERALL_EXIT_CODE=1
    fi
fi

echo ""
echo "For detailed analysis, check individual result files in \\${RESULTS_DIR}/"

if [[ \\${OVERALL_EXIT_CODE} -eq 0 ]]; then
    echo -e "\\${GREEN}All Valgrind tools passed successfully!\\${NC}"
else
    echo -e "\\${RED}Some Valgrind tools detected issues. Please review the results.\\${NC}"
fi

exit \\${OVERALL_EXIT_CODE}`;
  }

  private static generateValgrindAnalysis(): string {
    return `#!/usr/bin/env python3
"""
Valgrind Analysis Tool
Processes Valgrind output and generates comprehensive reports
"""

import os
import sys
import json
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional
import re

class ValgrindAnalyzer:
    def __init__(self, results_dir: str, timestamp: str, project_name: str):
        self.results_dir = results_dir
        self.timestamp = timestamp
        self.project_name = project_name
        self.analysis_results = {}

    def parse_memcheck_xml(self, xml_file: str) -> Dict[str, Any]:
        """Parse Memcheck XML output."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            errors = []
            for error in root.findall('.//error'):
                error_data = {
                    'kind': error.find('kind').text if error.find('kind') is not None else '',
                    'what': error.find('what').text if error.find('what') is not None else '',
                    'stack': []
                }
                
                # Parse stack trace
                stack = error.find('stack')
                if stack is not None:
                    for frame in stack.findall('frame'):
                        frame_data = {}
                        if frame.find('fn') is not None:
                            frame_data['function'] = frame.find('fn').text
                        if frame.find('file') is not None:
                            frame_data['file'] = frame.find('file').text
                        if frame.find('line') is not None:
                            frame_data['line'] = frame.find('line').text
                        error_data['stack'].append(frame_data)
                
                errors.append(error_data)
            
            return {
                'tool': 'memcheck',
                'errors': errors,
                'error_count': len(errors)
            }
            
        except Exception as e:
            print(f"Error parsing Memcheck XML: {e}")
            return {'tool': 'memcheck', 'errors': [], 'error_count': 0}

    def parse_helgrind_xml(self, xml_file: str) -> Dict[str, Any]:
        """Parse Helgrind XML output."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            errors = []
            for error in root.findall('.//error'):
                error_data = {
                    'kind': error.find('kind').text if error.find('kind') is not None else '',
                    'what': error.find('what').text if error.find('what') is not None else '',
                    'stack': []
                }
                
                # Parse stack trace
                stack = error.find('stack')
                if stack is not None:
                    for frame in stack.findall('frame'):
                        frame_data = {}
                        if frame.find('fn') is not None:
                            frame_data['function'] = frame.find('fn').text
                        if frame.find('file') is not None:
                            frame_data['file'] = frame.find('file').text
                        if frame.find('line') is not None:
                            frame_data['line'] = frame.find('line').text
                        error_data['stack'].append(frame_data)
                
                errors.append(error_data)
            
            return {
                'tool': 'helgrind',
                'errors': errors,
                'error_count': len(errors)
            }
            
        except Exception as e:
            print(f"Error parsing Helgrind XML: {e}")
            return {'tool': 'helgrind', 'errors': [], 'error_count': 0}

    def parse_cachegrind_output(self, output_file: str) -> Dict[str, Any]:
        """Parse Cachegrind output."""
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            
            # Extract summary statistics
            stats = {}
            for line in content.split('\\n'):
                if 'I   refs:' in line:
                    stats['instruction_refs'] = self.extract_number(line)
                elif 'I1  misses:' in line:
                    stats['l1_instruction_misses'] = self.extract_number(line)
                elif 'LLi misses:' in line:
                    stats['ll_instruction_misses'] = self.extract_number(line)
                elif 'D   refs:' in line:
                    stats['data_refs'] = self.extract_number(line)
                elif 'D1  misses:' in line:
                    stats['l1_data_misses'] = self.extract_number(line)
                elif 'LLd misses:' in line:
                    stats['ll_data_misses'] = self.extract_number(line)
            
            return {
                'tool': 'cachegrind',
                'stats': stats
            }
            
        except Exception as e:
            print(f"Error parsing Cachegrind output: {e}")
            return {'tool': 'cachegrind', 'stats': {}}

    def parse_massif_output(self, output_file: str) -> Dict[str, Any]:
        """Parse Massif output."""
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            
            # Extract memory usage statistics
            stats = {}
            peak_usage = 0
            snapshots = []
            
            for line in content.split('\\n'):
                if line.startswith('mem_heap_B='):
                    heap_usage = int(line.split('=')[1])
                    peak_usage = max(peak_usage, heap_usage)
                elif line.startswith('snapshot='):
                    snapshot_data = self.parse_massif_snapshot(line)
                    if snapshot_data:
                        snapshots.append(snapshot_data)
            
            stats['peak_heap_usage'] = peak_usage
            stats['snapshots'] = snapshots
            
            return {
                'tool': 'massif',
                'stats': stats
            }
            
        except Exception as e:
            print(f"Error parsing Massif output: {e}")
            return {'tool': 'massif', 'stats': {}}

    def extract_number(self, line: str) -> int:
        """Extract number from line with commas."""
        match = re.search(r'([0-9,]+)', line)
        if match:
            return int(match.group(1).replace(',', ''))
        return 0

    def parse_massif_snapshot(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse Massif snapshot line."""
        try:
            parts = line.split('=')
            if len(parts) >= 2:
                return {
                    'snapshot': int(parts[1].split('#')[0]),
                    'time': parts[2] if len(parts) > 2 else 0
                }
        except:
            pass
        return None

    def analyze_results(self):
        """Analyze all available Valgrind results."""
        
        # Check for Memcheck results
        memcheck_xml = os.path.join(self.results_dir, f'memcheck_{self.timestamp}.xml')
        if os.path.exists(memcheck_xml):
            self.analysis_results['memcheck'] = self.parse_memcheck_xml(memcheck_xml)
        
        # Check for Helgrind results
        helgrind_xml = os.path.join(self.results_dir, f'helgrind_{self.timestamp}.xml')
        if os.path.exists(helgrind_xml):
            self.analysis_results['helgrind'] = self.parse_helgrind_xml(helgrind_xml)
        
        # Check for Cachegrind results
        cachegrind_out = os.path.join(self.results_dir, f'cachegrind_{self.timestamp}.out')
        if os.path.exists(cachegrind_out):
            self.analysis_results['cachegrind'] = self.parse_cachegrind_output(cachegrind_out)
        
        # Check for Massif results
        massif_out = os.path.join(self.results_dir, f'massif_{self.timestamp}.out')
        if os.path.exists(massif_out):
            self.analysis_results['massif'] = self.parse_massif_output(massif_out)

    def generate_html_report(self, output_file: str):
        """Generate comprehensive HTML report."""
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Valgrind Analysis Report - {self.project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .error {{ background-color: #ffebee; border-left: 4px solid #f44336; }}
        .warning {{ background-color: #fff3e0; border-left: 4px solid #ff9800; }}
        .success {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; }}
        .info {{ background-color: #e3f2fd; border-left: 4px solid #2196f3; }}
        .stack-trace {{ background-color: #f5f5f5; padding: 10px; font-family: monospace; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .metric {{ font-size: 1.2em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Valgrind Analysis Report</h1>
        <p><strong>Project:</strong> {self.project_name}</p>
        <p><strong>Timestamp:</strong> {self.timestamp}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
"""
        
        # Executive Summary
        html_content += self.generate_executive_summary()
        
        # Detailed results for each tool
        for tool, results in self.analysis_results.items():
            html_content += self.generate_tool_section(tool, results)
        
        # Recommendations
        html_content += self.generate_recommendations()
        
        html_content += """
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)

    def generate_executive_summary(self) -> str:
        """Generate executive summary section."""
        total_errors = 0
        tools_run = []
        
        for tool, results in self.analysis_results.items():
            tools_run.append(tool)
            if 'error_count' in results:
                total_errors += results['error_count']
        
        status_class = 'success' if total_errors == 0 else 'error'
        
        return f"""
    <div class="section {status_class}">
        <h2>Executive Summary</h2>
        <p><span class="metric">Total Errors: {total_errors}</span></p>
        <p><strong>Tools Run:</strong> {', '.join(tools_run)}</p>
        <p><strong>Status:</strong> {'✓ Clean' if total_errors == 0 else '✗ Issues Found'}</p>
    </div>
"""

    def generate_tool_section(self, tool: str, results: Dict[str, Any]) -> str:
        """Generate section for specific tool results."""
        
        if tool == 'memcheck':
            return self.generate_memcheck_section(results)
        elif tool == 'helgrind':
            return self.generate_helgrind_section(results)
        elif tool == 'cachegrind':
            return self.generate_cachegrind_section(results)
        elif tool == 'massif':
            return self.generate_massif_section(results)
        else:
            return f'<div class="section info"><h3>{tool.title()}</h3><p>Results available</p></div>'

    def generate_memcheck_section(self, results: Dict[str, Any]) -> str:
        """Generate Memcheck results section."""
        error_count = results.get('error_count', 0)
        status_class = 'success' if error_count == 0 else 'error'
        
        content = f"""
    <div class="section {status_class}">
        <h2>Memcheck Results</h2>
        <p><span class="metric">Memory Errors: {error_count}</span></p>
"""
        
        if error_count > 0:
            content += "<h3>Error Details</h3>"
            for i, error in enumerate(results.get('errors', [])[:10]):  # Show first 10 errors
                content += f"""
        <div class="error">
            <h4>Error {i+1}: {error.get('kind', 'Unknown')}</h4>
            <p>{error.get('what', 'No description')}</p>
"""
                if error.get('stack'):
                    content += '<div class="stack-trace">'
                    for frame in error['stack'][:5]:  # Show first 5 frames
                        func = frame.get('function', 'Unknown')
                        file_line = f"{frame.get('file', 'Unknown')}:{frame.get('line', '?')}"
                        content += f"    {func} ({file_line})<br>"
                    content += '</div>'
                content += '</div>'
        
        content += '</div>'
        return content

    def generate_helgrind_section(self, results: Dict[str, Any]) -> str:
        """Generate Helgrind results section."""
        error_count = results.get('error_count', 0)
        status_class = 'success' if error_count == 0 else 'error'
        
        return f"""
    <div class="section {status_class}">
        <h2>Helgrind Results</h2>
        <p><span class="metric">Thread Errors: {error_count}</span></p>
        {'<p>No thread safety issues detected.</p>' if error_count == 0 else '<p>Thread safety issues detected. Check detailed logs.</p>'}
    </div>
"""

    def generate_cachegrind_section(self, results: Dict[str, Any]) -> str:
        """Generate Cachegrind results section."""
        stats = results.get('stats', {})
        
        content = """
    <div class="section info">
        <h2>Cachegrind Results</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
"""
        
        for metric, value in stats.items():
            formatted_value = f"{value:,}" if isinstance(value, int) else str(value)
            content += f"<tr><td>{metric.replace('_', ' ').title()}</td><td>{formatted_value}</td></tr>"
        
        content += """
        </table>
    </div>
"""
        return content

    def generate_massif_section(self, results: Dict[str, Any]) -> str:
        """Generate Massif results section."""
        stats = results.get('stats', {})
        peak_usage = stats.get('peak_heap_usage', 0)
        
        return f"""
    <div class="section info">
        <h2>Massif Results</h2>
        <p><span class="metric">Peak Heap Usage: {peak_usage:,} bytes</span></p>
        <p><span class="metric">Peak Heap Usage: {peak_usage / 1024 / 1024:.2f} MB</span></p>
        <p>Snapshots: {len(stats.get('snapshots', []))}</p>
    </div>
"""

    def generate_recommendations(self) -> str:
        """Generate recommendations section."""
        recommendations = []
        
        # Check for memory errors
        if 'memcheck' in self.analysis_results:
            error_count = self.analysis_results['memcheck'].get('error_count', 0)
            if error_count > 0:
                recommendations.append("Fix memory leaks and invalid memory accesses detected by Memcheck")
        
        # Check for thread errors
        if 'helgrind' in self.analysis_results:
            error_count = self.analysis_results['helgrind'].get('error_count', 0)
            if error_count > 0:
                recommendations.append("Address thread safety issues detected by Helgrind")
        
        # Performance recommendations
        if 'cachegrind' in self.analysis_results:
            recommendations.append("Review cache usage patterns for performance optimization")
        
        if 'massif' in self.analysis_results:
            recommendations.append("Monitor heap usage patterns for memory optimization")
        
        if not recommendations:
            recommendations.append("No issues detected. Continue with regular monitoring.")
        
        content = """
    <div class="section warning">
        <h2>Recommendations</h2>
        <ul>
"""
        for rec in recommendations:
            content += f"<li>{rec}</li>"
        
        content += """
        </ul>
    </div>
"""
        return content

def main():
    parser = argparse.ArgumentParser(description='Analyze Valgrind results')
    parser.add_argument('--results-dir', required=True, help='Directory containing Valgrind results')
    parser.add_argument('--timestamp', required=True, help='Timestamp for result files')
    parser.add_argument('--project-name', required=True, help='Project name')
    parser.add_argument('--output', required=True, help='Output HTML file')
    
    args = parser.parse_args()
    
    analyzer = ValgrindAnalyzer(args.results_dir, args.timestamp, args.project_name)
    analyzer.analyze_results()
    analyzer.generate_html_report(args.output)
    
    print(f"Analysis complete. Report saved to {args.output}")

if __name__ == '__main__':
    main()`;
  }

  private static generateValgrindReadme(projectName: string): string {
    return `# Valgrind Memory Analysis for ${projectName}

This directory contains Valgrind configuration and tools for comprehensive memory analysis and debugging.

## Overview

Valgrind is a powerful suite of tools for debugging and profiling programs:

- **Memcheck**: Memory error detection (leaks, invalid accesses, uninitialized memory)
- **Helgrind**: Thread error detection (race conditions, deadlocks)
- **Cachegrind**: Cache profiling and performance analysis
- **Callgrind**: Call profiling and performance analysis
- **Massif**: Heap profiling and memory usage analysis
- **DRD**: Alternative thread error detection

## Quick Start

### Building for Valgrind

\`\`\`bash
# Build with debug symbols and no optimization
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DENABLE_VALGRIND=ON
cmake --build build
\`\`\`

### Running Analysis

\`\`\`bash
# Run comprehensive analysis
./scripts/run_valgrind.sh

# Run specific tool
valgrind --tool=memcheck --leak-check=full ./build/${projectName}

# Run with CMake/CTest
ctest -R valgrind
\`\`\`

## Tools Overview

### Memcheck - Memory Error Detection

**Purpose**: Detect memory leaks, buffer overflows, use of uninitialized memory

**Common Issues Detected**:
- Memory leaks (heap, stack)
- Invalid memory accesses
- Use of uninitialized memory
- Double free errors
- Mismatched malloc/free and new/delete

**Usage**:
\`\`\`bash
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./build/${projectName}
\`\`\`

### Helgrind - Thread Error Detection

**Purpose**: Detect race conditions and threading issues

**Common Issues Detected**:
- Data races
- Lock ordering problems
- Misuse of POSIX pthreads API
- Inconsistent lock acquisition

**Usage**:
\`\`\`bash
valgrind --tool=helgrind ./build/${projectName}
\`\`\`

### Cachegrind - Cache Profiling

**Purpose**: Analyze cache usage and performance

**Metrics Provided**:
- L1/L2/L3 cache misses
- Branch misprediction rates
- Instruction execution counts

**Usage**:
\`\`\`bash
valgrind --tool=cachegrind ./build/${projectName}
# View results
cg_annotate cachegrind.out.{pid}
\`\`\`

### Massif - Heap Profiling

**Purpose**: Analyze heap memory usage over time

**Features**:
- Heap usage snapshots
- Memory allocation patterns
- Peak memory usage identification

**Usage**:
\`\`\`bash
valgrind --tool=massif ./build/${projectName}
# View results
ms_print massif.out.{pid}
\`\`\`

## Configuration Files

### Suppression Files

- \`memcheck.supp\`: Suppresses known false positives in Memcheck
- \`helgrind.supp\`: Suppresses known false positives in Helgrind

### Tool Configuration

- \`configs/memcheck.conf\`: Memcheck-specific settings
- \`configs/helgrind.conf\`: Helgrind-specific settings
- \`configs/cachegrind.conf\`: Cachegrind-specific settings
- \`configs/massif.conf\`: Massif-specific settings

## Integration with Build System

### CMake Integration

The project includes CMake functions for easy Valgrind integration:

\`\`\`cmake
# Add Valgrind tests for an executable
add_valgrind_test(my_executable MEMCHECK HELGRIND)

# Add Valgrind flags to a target
add_valgrind_flags(my_target)

# Enable Valgrind for all targets
enable_valgrind_for_target(my_target)
\`\`\`

### CTest Integration

Run Valgrind tests through CTest:

\`\`\`bash
# Run all Valgrind tests
ctest -R valgrind

# Run specific tool tests
ctest -R valgrind_memcheck
ctest -R valgrind_helgrind
\`\`\`

## Continuous Integration

### GitHub Actions

The project includes GitHub Actions workflow for automated Valgrind analysis:

- Runs on pull requests and main branch
- Detects memory leaks and thread errors
- Generates detailed reports
- Fails builds on critical issues

### Docker Support

Use the provided Docker image for consistent analysis:

\`\`\`bash
# Build Valgrind Docker image
docker build -f valgrind/docker/Dockerfile.valgrind -t ${projectName}-valgrind .

# Run analysis in container
docker run --rm -v \$(pwd):/workspace ${projectName}-valgrind
\`\`\`

## Analysis and Reporting

### Automated Analysis

The \`valgrind_analysis.py\` script provides:

- XML report parsing
- HTML report generation
- Error categorization and prioritization
- Performance metrics analysis

### Memory Report Generation

\`\`\`bash
# Generate comprehensive memory report
python3 scripts/memory_report.py --results-dir valgrind_results
\`\`\`

## Best Practices

### Writing Valgrind-Friendly Code

1. **Use RAII**: Ensure automatic cleanup of resources
2. **Initialize variables**: Avoid uninitialized memory access
3. **Proper synchronization**: Use mutexes and locks correctly
4. **Avoid raw pointers**: Use smart pointers when possible

### Debugging with Valgrind

1. **Build with debug symbols**: Use \`-g\` flag
2. **Disable optimization**: Use \`-O0\` for accurate results
3. **Use suppressions**: Filter out known false positives
4. **Start with Memcheck**: Address memory issues first

### Performance Considerations

- Valgrind slows down execution 10-50x
- Use suppressions to reduce noise
- Run on representative workloads
- Focus on critical code paths

## Troubleshooting

### Common Issues

1. **False positives**: Add suppressions for known issues
2. **Slow execution**: Use minimal test cases
3. **Missing debug info**: Ensure debug symbols are included
4. **System library issues**: Use system-specific suppressions

### Debugging Tips

\`\`\`bash
# Get more detailed output
valgrind --verbose --track-origins=yes

# Generate suppressions automatically
valgrind --gen-suppressions=all

# Increase verbosity for debugging
valgrind --verbose --trace-children=yes
\`\`\`

## Integration with IDEs

### Visual Studio Code

Add launch configuration for Valgrind debugging:

\`\`\`json
{
    "name": "Valgrind Debug",
    "type": "cppdbg",
    "request": "launch",
    "program": "valgrind",
    "args": ["--tool=memcheck", "--leak-check=full", "./build/${projectName}"],
    "stopAtEntry": false,
    "cwd": "\${workspaceFolder}",
    "environment": [],
    "externalConsole": false
}
\`\`\`

### CLion

Configure Valgrind as external tool:
1. Go to File → Settings → Tools → External Tools
2. Add new tool with Valgrind configuration
3. Use custom run configuration

## Resources

- [Valgrind Documentation](https://valgrind.org/docs/)
- [Memcheck Manual](https://valgrind.org/docs/manual/mc-manual.html)
- [Helgrind Manual](https://valgrind.org/docs/manual/hg-manual.html)
- [Performance Analysis Guide](https://valgrind.org/docs/manual/manual-core.html)`;
  }

  private static generateValgrindCI(projectName: string): string {
    return `name: Valgrind Memory Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run nightly analysis at 3 AM UTC
    - cron: '0 3 * * *'

env:
  BUILD_TYPE: Debug

jobs:
  valgrind-analysis:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y \\
          valgrind \\
          cmake \\
          ninja-build \\
          gcc-11 \\
          g++-11 \\
          python3-pip \\
          python3-lxml
        
        pip3 install matplotlib seaborn pandas
    
    - name: Configure CMake
      run: |
        cmake -B build \\
          -DCMAKE_BUILD_TYPE=\\${{env.BUILD_TYPE}} \\
          -DCMAKE_CXX_COMPILER=g++-11 \\
          -DCMAKE_C_COMPILER=gcc-11 \\
          -DENABLE_VALGRIND=ON \\
          -GNinja
    
    - name: Build
      run: cmake --build build --config \\${{env.BUILD_TYPE}}
    
    - name: Run Valgrind Memcheck
      run: |
        mkdir -p valgrind_results
        
        # Run Memcheck
        valgrind \\
          --tool=memcheck \\
          --leak-check=full \\
          --show-leak-kinds=all \\
          --track-origins=yes \\
          --verbose \\
          --xml=yes \\
          --xml-file=valgrind_results/memcheck.xml \\
          --error-exitcode=1 \\
          --suppressions=valgrind/memcheck.supp \\
          ./build/${projectName} \\
          2>&1 | tee valgrind_results/memcheck.log
      continue-on-error: true
      id: memcheck
    
    - name: Run Valgrind Helgrind
      run: |
        # Run Helgrind (thread error detection)
        valgrind \\
          --tool=helgrind \\
          --verbose \\
          --xml=yes \\
          --xml-file=valgrind_results/helgrind.xml \\
          --error-exitcode=1 \\
          --suppressions=valgrind/helgrind.supp \\
          ./build/${projectName} \\
          2>&1 | tee valgrind_results/helgrind.log
      continue-on-error: true
      id: helgrind
    
    - name: Run Valgrind Cachegrind
      run: |
        # Run Cachegrind (cache profiling)
        valgrind \\
          --tool=cachegrind \\
          --verbose \\
          --cachegrind-out-file=valgrind_results/cachegrind.out \\
          ./build/${projectName} \\
          2>&1 | tee valgrind_results/cachegrind.log
        
        # Generate annotation if available
        if command -v cg_annotate &> /dev/null; then
          cg_annotate valgrind_results/cachegrind.out > valgrind_results/cachegrind_annotation.txt
        fi
      continue-on-error: true
    
    - name: Run Valgrind Massif
      run: |
        # Run Massif (heap profiling)
        valgrind \\
          --tool=massif \\
          --verbose \\
          --massif-out-file=valgrind_results/massif.out \\
          --heap=yes \\
          --stacks=yes \\
          --time-unit=ms \\
          ./build/${projectName} \\
          2>&1 | tee valgrind_results/massif.log
        
        # Generate visualization if available
        if command -v ms_print &> /dev/null; then
          ms_print valgrind_results/massif.out > valgrind_results/massif_graph.txt
        fi
      continue-on-error: true
    
    - name: Generate Analysis Report
      run: |
        # Generate comprehensive analysis report
        python3 scripts/valgrind_analysis.py \\
          --results-dir valgrind_results \\
          --timestamp \\$(date +%Y%m%d_%H%M%S) \\
          --project-name "${projectName}" \\
          --output valgrind_results/analysis_report.html
        
        # Generate summary for GitHub
        python3 scripts/memory_report.py \\
          --results-dir valgrind_results \\
          --format markdown \\
          --output valgrind_results/summary.md
    
    - name: Upload Valgrind Results
      uses: actions/upload-artifact@v4
      with:
        name: valgrind-results-\\${{ github.sha }}
        path: valgrind_results/
        retention-days: 30
    
    - name: Comment PR with Results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          
          try {
            const summary = fs.readFileSync('valgrind_results/summary.md', 'utf8');
            
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: summary
            });
          } catch (error) {
            console.log('No summary file found');
          }
    
    - name: Check for Critical Issues
      run: |
        # Check for critical memory issues
        CRITICAL_ISSUES=0
        
        # Check Memcheck results
        if [ -f "valgrind_results/memcheck.xml" ]; then
          ERRORS=\\$(grep -c "<error>" valgrind_results/memcheck.xml || echo "0")
          if [ "\\$ERRORS" -gt 0 ]; then
            echo "::error::Memcheck detected \\$ERRORS memory errors"
            CRITICAL_ISSUES=1
          fi
        fi
        
        # Check Helgrind results
        if [ -f "valgrind_results/helgrind.xml" ]; then
          ERRORS=\\$(grep -c "<error>" valgrind_results/helgrind.xml || echo "0")
          if [ "\\$ERRORS" -gt 0 ]; then
            echo "::error::Helgrind detected \\$ERRORS thread errors"
            CRITICAL_ISSUES=1
          fi
        fi
        
        # Add results to step summary
        echo "## Valgrind Analysis Results" >> \\$GITHUB_STEP_SUMMARY
        echo "" >> \\$GITHUB_STEP_SUMMARY
        
        if [ "\\$CRITICAL_ISSUES" -eq 0 ]; then
          echo "✅ No critical memory or thread issues detected" >> \\$GITHUB_STEP_SUMMARY
        else
          echo "❌ Critical issues detected - please review the analysis report" >> \\$GITHUB_STEP_SUMMARY
        fi
        
        echo "" >> \\$GITHUB_STEP_SUMMARY
        echo "📊 **Analysis Files Generated:**" >> \\$GITHUB_STEP_SUMMARY
        echo "- Memcheck: \`valgrind_results/memcheck.xml\`" >> \\$GITHUB_STEP_SUMMARY
        echo "- Helgrind: \`valgrind_results/helgrind.xml\`" >> \\$GITHUB_STEP_SUMMARY
        echo "- Cachegrind: \`valgrind_results/cachegrind.out\`" >> \\$GITHUB_STEP_SUMMARY
        echo "- Massif: \`valgrind_results/massif.out\`" >> \\$GITHUB_STEP_SUMMARY
        echo "- Full Report: \`valgrind_results/analysis_report.html\`" >> \\$GITHUB_STEP_SUMMARY
        
        # Fail job if critical issues found
        if [ "\\$CRITICAL_ISSUES" -eq 1 ]; then
          exit 1
        fi
    
    - name: Store Historical Data
      if: github.ref == 'refs/heads/main'
      run: |
        # Store results for historical comparison
        mkdir -p historical_data
        
        # Extract key metrics
        echo "{\\"date\\": \\"\$(date -Iseconds)\\", \\"commit\\": \\"\\${{ github.sha }}\\"}" > historical_data/metrics.json
        
        # Store in artifact for later use
        echo "Historical data stored for commit \\${{ github.sha }}"
    
    - name: Performance Regression Check
      if: github.event_name == 'pull_request'
      run: |
        # Check for performance regressions in cache usage
        if [ -f "valgrind_results/cachegrind.out" ]; then
          # Simple regression check (can be enhanced)
          TOTAL_REFS=\\$(grep "I   refs:" valgrind_results/cachegrind.log | awk '{print \\$3}' | sed 's/,//g')
          
          if [ "\\$TOTAL_REFS" -gt 10000000 ]; then
            echo "::warning::High instruction count detected: \\$TOTAL_REFS"
          fi
        fi

  valgrind-docker:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Build Valgrind Docker Image
      run: |
        docker build -f valgrind/docker/Dockerfile.valgrind -t ${projectName}-valgrind .
    
    - name: Run Containerized Analysis
      run: |
        docker run --rm -v \$(pwd):/workspace ${projectName}-valgrind
    
    - name: Upload Docker Results
      uses: actions/upload-artifact@v4
      with:
        name: valgrind-docker-results-\\${{ github.sha }}
        path: valgrind_results/
        retention-days: 7`;
  }

  private static generateValgrindDockerfile(): string {
    return `# Valgrind Analysis Docker Image
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \\
    valgrind \\
    cmake \\
    ninja-build \\
    gcc-11 \\
    g++-11 \\
    python3 \\
    python3-pip \\
    python3-lxml \\
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install matplotlib seaborn pandas

# Set working directory
WORKDIR /workspace

# Copy analysis scripts
COPY scripts/ /workspace/scripts/
COPY valgrind/ /workspace/valgrind/

# Make scripts executable
RUN chmod +x /workspace/scripts/*.sh

# Set environment variables
ENV CC=gcc-11
ENV CXX=g++-11

# Default command
CMD ["./scripts/run_valgrind.sh"]`;
  }

  private static generateMemcheckConfig(): string {
    return `# Memcheck Configuration File
# Command line options for Valgrind Memcheck

# Memory leak detection
--leak-check=full
--show-leak-kinds=all
--leak-resolution=high

# Origin tracking
--track-origins=yes
--expensive-definedness-checks=yes

# Error reporting
--error-exitcode=1
--show-reachable=yes
--show-possibly-lost=yes

# Suppressions
--suppressions=valgrind/memcheck.supp
--gen-suppressions=all

# Output format
--xml=yes
--verbose
--time-stamp=yes
--track-fds=yes

# Memory allocation
--partial-loads-ok=yes
--undef-value-errors=yes

# Stack traces
--num-callers=20
--show-below-main=yes

# Performance
--malloc-fill=0xAA
--free-fill=0xBB`;
  }

  private static generateHelgrindConfig(): string {
    return `# Helgrind Configuration File
# Command line options for Valgrind Helgrind

# Thread error detection
--history-level=full
--conflict-cache-size=1000000

# Error reporting
--error-exitcode=1
--verbose
--time-stamp=yes

# Suppressions
--suppressions=valgrind/helgrind.supp
--gen-suppressions=all

# Output format
--xml=yes

# Stack traces
--num-callers=20

# Performance tuning
--free-is-write=no
--check-stack-refs=yes

# Lock analysis
--track-lockorders=yes
--show-lock-orders=yes`;
  }

  private static generateCachegrindConfig(): string {
    return `# Cachegrind Configuration File
# Command line options for Valgrind Cachegrind

# Cache simulation
--cache-sim=yes
--branch-sim=yes

# Cache configuration (can be auto-detected)
--I1=32768,8,64
--D1=32768,8,64
--LL=8388608,16,64

# Output options
--verbose
--cachegrind-out-file=cachegrind.out.%p

# Profiling options
--dump-instr=yes
--trace-jump=yes

# Performance
--collect-jumps=yes
--collect-bus=yes`;
  }

  private static generateMassifConfig(): string {
    return `# Massif Configuration File
# Command line options for Valgrind Massif

# Heap profiling
--heap=yes
--heap-admin=8
--stacks=yes
--depth=30

# Snapshot configuration
--threshold=1.0
--peak-inaccuracy=1.0
--time-unit=ms

# Output options
--massif-out-file=massif.out.%p
--verbose

# Profiling detail
--detailed-freq=10
--max-snapshots=100
--alloc-fn=malloc
--alloc-fn=calloc
--alloc-fn=realloc
--alloc-fn=memalign
--alloc-fn=new
--alloc-fn=new[]`;
  }

  private static generateMemoryReport(): string {
    return `#!/usr/bin/env python3
"""
Memory Analysis Report Generator
Generates comprehensive memory usage reports from Valgrind results
"""

import os
import sys
import json
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional
import re

class MemoryReportGenerator:
    def __init__(self, results_dir: str):
        self.results_dir = results_dir
        self.report_data = {}

    def parse_memcheck_xml(self, xml_file: str) -> Dict[str, Any]:
        """Parse Memcheck XML results for memory analysis."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            memory_stats = {
                'total_errors': 0,
                'error_types': {},
                'leak_summary': {},
                'critical_errors': []
            }
            
            for error in root.findall('.//error'):
                memory_stats['total_errors'] += 1
                
                error_kind = error.find('kind').text if error.find('kind') is not None else 'Unknown'
                memory_stats['error_types'][error_kind] = memory_stats['error_types'].get(error_kind, 0) + 1
                
                # Extract leak information
                if 'leak' in error_kind.lower():
                    bytes_leaked = 0
                    bytes_node = error.find('.//bytes')
                    if bytes_node is not None:
                        bytes_leaked = int(bytes_node.text)
                    
                    memory_stats['leak_summary'][error_kind] = {
                        'count': memory_stats['leak_summary'].get(error_kind, {}).get('count', 0) + 1,
                        'bytes': memory_stats['leak_summary'].get(error_kind, {}).get('bytes', 0) + bytes_leaked
                    }
                
                # Identify critical errors
                if error_kind in ['InvalidRead', 'InvalidWrite', 'InvalidFree', 'MismatchedFree']:
                    memory_stats['critical_errors'].append({
                        'kind': error_kind,
                        'what': error.find('what').text if error.find('what') is not None else 'Unknown'
                    })
            
            return memory_stats
            
        except Exception as e:
            print(f"Error parsing Memcheck XML: {e}")
            return {'total_errors': 0, 'error_types': {}, 'leak_summary': {}, 'critical_errors': []}

    def parse_massif_output(self, massif_file: str) -> Dict[str, Any]:
        """Parse Massif output for heap analysis."""
        try:
            with open(massif_file, 'r') as f:
                content = f.read()
            
            heap_stats = {
                'peak_heap_usage': 0,
                'total_heap_usage': 0,
                'snapshots': [],
                'allocation_timeline': []
            }
            
            current_snapshot = None
            
            for line in content.split('\\n'):
                line = line.strip()
                
                if line.startswith('mem_heap_B='):
                    heap_bytes = int(line.split('=')[1])
                    heap_stats['peak_heap_usage'] = max(heap_stats['peak_heap_usage'], heap_bytes)
                    
                    if current_snapshot:
                        current_snapshot['heap_usage'] = heap_bytes
                        heap_stats['allocation_timeline'].append(current_snapshot)
                
                elif line.startswith('snapshot='):
                    current_snapshot = {
                        'snapshot_id': len(heap_stats['snapshots']),
                        'heap_usage': 0
                    }
                    heap_stats['snapshots'].append(current_snapshot)
                
                elif line.startswith('time='):
                    if current_snapshot:
                        current_snapshot['time'] = line.split('=')[1]
            
            return heap_stats
            
        except Exception as e:
            print(f"Error parsing Massif output: {e}")
            return {'peak_heap_usage': 0, 'total_heap_usage': 0, 'snapshots': [], 'allocation_timeline': []}

    def generate_memory_summary(self) -> Dict[str, Any]:
        """Generate memory usage summary."""
        summary = {
            'analysis_date': datetime.now().isoformat(),
            'memory_health': 'UNKNOWN',
            'total_issues': 0,
            'critical_issues': 0,
            'recommendations': []
        }
        
        # Analyze Memcheck results
        memcheck_file = os.path.join(self.results_dir, 'memcheck.xml')
        if os.path.exists(memcheck_file):
            memcheck_data = self.parse_memcheck_xml(memcheck_file)
            summary['memcheck'] = memcheck_data
            summary['total_issues'] = memcheck_data['total_errors']
            summary['critical_issues'] = len(memcheck_data['critical_errors'])
        
        # Analyze Massif results
        massif_file = os.path.join(self.results_dir, 'massif.out')
        if os.path.exists(massif_file):
            massif_data = self.parse_massif_output(massif_file)
            summary['massif'] = massif_data
        
        # Determine memory health
        if summary['critical_issues'] > 0:
            summary['memory_health'] = 'CRITICAL'
            summary['recommendations'].append('Address critical memory errors immediately')
        elif summary['total_issues'] > 10:
            summary['memory_health'] = 'POOR'
            summary['recommendations'].append('Multiple memory issues detected - systematic review needed')
        elif summary['total_issues'] > 0:
            summary['memory_health'] = 'FAIR'
            summary['recommendations'].append('Minor memory issues detected - review and fix')
        else:
            summary['memory_health'] = 'GOOD'
            summary['recommendations'].append('No memory issues detected')
        
        return summary

    def generate_markdown_report(self) -> str:
        """Generate markdown report."""
        summary = self.generate_memory_summary()
        
        report = f"""# Memory Analysis Report
        
**Analysis Date:** {summary['analysis_date']}
**Memory Health:** {summary['memory_health']}

## Summary

- **Total Issues:** {summary['total_issues']}
- **Critical Issues:** {summary['critical_issues']}
- **Memory Health:** {summary['memory_health']}

"""
        
        # Add Memcheck results
        if 'memcheck' in summary:
            memcheck = summary['memcheck']
            report += f"""## Memory Error Analysis

### Error Summary
- **Total Errors:** {memcheck['total_errors']}
- **Critical Errors:** {len(memcheck['critical_errors'])}

### Error Types
"""
            for error_type, count in memcheck['error_types'].items():
                report += f"- **{error_type}:** {count}\\n"
            
            if memcheck['leak_summary']:
                report += "\\n### Memory Leaks\\n"
                for leak_type, info in memcheck['leak_summary'].items():
                    bytes_mb = info['bytes'] / (1024 * 1024)
                    report += f"- **{leak_type}:** {info['count']} leaks, {bytes_mb:.2f} MB\\n"
        
        # Add Massif results
        if 'massif' in summary:
            massif = summary['massif']
            peak_mb = massif['peak_heap_usage'] / (1024 * 1024)
            report += f"""
## Heap Usage Analysis

- **Peak Heap Usage:** {peak_mb:.2f} MB
- **Total Snapshots:** {len(massif['snapshots'])}
"""
        
        # Add recommendations
        report += "\\n## Recommendations\\n\\n"
        for rec in summary['recommendations']:
            report += f"- {rec}\\n"
        
        return report

    def generate_json_report(self) -> str:
        """Generate JSON report."""
        summary = self.generate_memory_summary()
        return json.dumps(summary, indent=2)

    def generate_html_report(self) -> str:
        """Generate HTML report."""
        summary = self.generate_memory_summary()
        
        health_color = {
            'GOOD': '#4CAF50',
            'FAIR': '#FF9800',
            'POOR': '#F44336',
            'CRITICAL': '#D32F2F'
        }.get(summary['memory_health'], '#9E9E9E')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Memory Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: {health_color}; color: white; padding: 20px; border-radius: 5px; }}
        .metric {{ font-size: 1.5em; font-weight: bold; margin: 10px 0; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .error {{ background-color: #ffebee; }}
        .warning {{ background-color: #fff3e0; }}
        .success {{ background-color: #e8f5e8; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Memory Analysis Report</h1>
        <div class="metric">Health Status: {summary['memory_health']}</div>
        <div>Analysis Date: {summary['analysis_date']}</div>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p><strong>Total Issues:</strong> {summary['total_issues']}</p>
        <p><strong>Critical Issues:</strong> {summary['critical_issues']}</p>
        <p><strong>Memory Health:</strong> {summary['memory_health']}</p>
    </div>
"""
        
        if 'memcheck' in summary:
            html += self.generate_memcheck_html_section(summary['memcheck'])
        
        if 'massif' in summary:
            html += self.generate_massif_html_section(summary['massif'])
        
        html += """
</body>
</html>
"""
        return html

    def generate_memcheck_html_section(self, memcheck: Dict[str, Any]) -> str:
        """Generate HTML section for Memcheck results."""
        section_class = 'error' if memcheck['critical_errors'] else 'warning' if memcheck['total_errors'] > 0 else 'success'
        
        html = f"""
    <div class="section {section_class}">
        <h2>Memory Error Analysis</h2>
        <p><strong>Total Errors:</strong> {memcheck['total_errors']}</p>
        <p><strong>Critical Errors:</strong> {len(memcheck['critical_errors'])}</p>
        
        <h3>Error Types</h3>
        <table>
            <tr><th>Error Type</th><th>Count</th></tr>
"""
        
        for error_type, count in memcheck['error_types'].items():
            html += f"<tr><td>{error_type}</td><td>{count}</td></tr>"
        
        html += "</table>"
        
        if memcheck['leak_summary']:
            html += """
        <h3>Memory Leaks</h3>
        <table>
            <tr><th>Leak Type</th><th>Count</th><th>Bytes</th></tr>
"""
            for leak_type, info in memcheck['leak_summary'].items():
                html += f"<tr><td>{leak_type}</td><td>{info['count']}</td><td>{info['bytes']:,}</td></tr>"
            html += "</table>"
        
        html += "</div>"
        return html

    def generate_massif_html_section(self, massif: Dict[str, Any]) -> str:
        """Generate HTML section for Massif results."""
        peak_mb = massif['peak_heap_usage'] / (1024 * 1024)
        
        return f"""
    <div class="section">
        <h2>Heap Usage Analysis</h2>
        <p><strong>Peak Heap Usage:</strong> {peak_mb:.2f} MB ({massif['peak_heap_usage']:,} bytes)</p>
        <p><strong>Total Snapshots:</strong> {len(massif['snapshots'])}</p>
    </div>
"""

def main():
    parser = argparse.ArgumentParser(description='Generate memory analysis report')
    parser.add_argument('--results-dir', required=True, help='Directory containing Valgrind results')
    parser.add_argument('--format', choices=['markdown', 'json', 'html'], default='markdown', help='Output format')
    parser.add_argument('--output', help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    generator = MemoryReportGenerator(args.results_dir)
    
    if args.format == 'markdown':
        report = generator.generate_markdown_report()
    elif args.format == 'json':
        report = generator.generate_json_report()
    elif args.format == 'html':
        report = generator.generate_html_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

if __name__ == '__main__':
    main()`;
  }
}