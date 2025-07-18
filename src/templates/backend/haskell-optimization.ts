import { BackendTemplate } from '../types';

export const haskellOptimizationTemplate: BackendTemplate = {
  id: 'haskell-optimization',
  name: 'haskell-optimization',
  displayName: 'Haskell GHC Optimization & Profiling',
  description: 'Advanced GHC optimization flags, profiling tools, and performance tuning for high-performance Haskell applications',
  framework: 'optimization',
  language: 'haskell',
  version: '9.6',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '⚡',
  type: 'performance',
  complexity: 'advanced',
  keywords: ['haskell', 'ghc', 'optimization', 'profiling', 'performance', 'tuning'],
  
  features: [
    'GHC optimization levels',
    'Profiling configuration',
    'Memory profiling',
    'Time profiling',
    'Core inspection',
    'STG inspection',
    'Heap profiling',
    'EventLog analysis',
    'ThreadScope integration',
    'Criterion benchmarking',
    'Space leak detection',
    'Strictness analysis',
    'Inlining control',
    'LLVM backend'
  ],
  
  structure: {
    'ghc-flags.yaml': `# GHC Optimization Flags Configuration

# Development flags (fast compilation, good debugging)
development:
  ghc-options:
    - -O0                    # No optimization
    - -g                     # Debug info
    - -fno-ignore-asserts    # Keep assertions
    - -fno-omit-yields       # Better stack traces
    - -fhide-source-paths    # Cleaner output
    
  # Warnings
    - -Wall                  # All warnings
    - -Wcompat               # Compatibility warnings
    - -Widentities           # Redundant constraints
    - -Wincomplete-record-updates
    - -Wincomplete-uni-patterns
    - -Wpartial-fields
    - -Wredundant-constraints
    - -Wmissing-export-lists
    - -Wmissing-deriving-strategies
    - -Wunused-packages
    - -Wunused-type-patterns

# Production flags (maximum optimization)
production:
  ghc-options:
    - -O2                    # Full optimization
    - -funbox-strict-fields  # Unbox strict fields
    - -fspecialise           # Specialize overloaded functions
    - -fspecialise-aggressively
    - -fcross-module-specialise
    - -flate-specialise      
    - -fstatic-argument-transformation
    - -fcse                  # Common subexpression elimination
    - -fstrictness           # Strictness analysis
    - -funbox-small-strict-fields
    - -fexpose-all-unfoldings # For cross-module inlining
    - -fsimpl-tick-factor=200 # More simplifier iterations
    
  # LLVM backend for better code generation
    - -fllvm
    - -optlo-O3

# Profiling flags
profiling:
  ghc-options:
    - -prof                  # Enable profiling
    - -fprof-auto            # Auto cost centers
    - -fprof-cafs            # Profile CAFs
    - -fno-prof-count-entries # Reduce overhead
    - -rtsopts               # Runtime options
    - -eventlog              # Event logging
    
  # Heap profiling options
  heap-profiling:
    - -hc    # Cost center
    - -hd    # Closure description
    - -hy    # Type description
    - -hr    # Retainer
    - -hb    # Biography

# Space leak detection
space-analysis:
  ghc-options:
    - -O2
    - -prof
    - -fprof-auto
    - -rtsopts
    - -fbreak-on-error
    - -fbreak-on-exception
    
  rts-options:
    - +RTS
    - -hc     # Heap profile by cost center
    - -i0.1   # Sample every 0.1 seconds
    - -xt     # Include threads
    - -RTS

# Parallel and concurrent optimization
parallel:
  ghc-options:
    - -O2
    - -threaded              # Threaded runtime
    - -rtsopts
    - -with-rtsopts=-N       # Use all cores
    - -feager-blackholing    # Better parallelism
    - -funbox-strict-fields
    
  # Event logging for ThreadScope
    - -eventlog
    - -fno-omit-yields       # Better thread profiling`,

    'app/Benchmark.hs': `{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}

module Main where

import Criterion.Main
import Criterion.Types
import Control.DeepSeq
import Control.Exception (evaluate)
import Control.Monad
import Data.List (foldl', sort)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import qualified Data.Vector.Unboxed as UV
import qualified Data.Map.Strict as Map
import qualified Data.HashMap.Strict as HashMap
import GHC.Generics (Generic)

-- Example data types for benchmarking
data Point = Point !Double !Double
    deriving (Show, Generic, NFData)

data Tree a = Leaf !a | Node !(Tree a) !a !(Tree a)
    deriving (Show, Generic, NFData)

-- Benchmark suite
main :: IO ()
main = defaultMainWith config
    [ bgroup "lists"
        [ bench "sum-foldl" $ nf (foldl (+) 0) [1..1000 :: Int]
        , bench "sum-foldl'" $ nf (foldl' (+) 0) [1..1000 :: Int]
        , bench "sum-foldr" $ nf (foldr (+) 0) [1..1000 :: Int]
        , bench "length" $ nf length [1..1000 :: Int]
        , bench "reverse" $ nf reverse [1..1000 :: Int]
        , bench "sort" $ nf sort (reverse [1..1000 :: Int])
        ]
    
    , bgroup "strings"
        [ bench "string-concat" $ nf (concat . replicate 100) "hello"
        , bench "text-concat" $ nf (T.concat . replicate 100) "hello"
        , bench "bytestring-concat" $ nf (BS.concat . replicate 100) "hello"
        , bench "text-encoding" $ nf (TE.encodeUtf8 . T.pack) longString
        , bench "text-decoding" $ nf (TE.decodeUtf8 . BS.pack) [1..255]
        ]
    
    , bgroup "data-structures"
        [ bench "list-index" $ nf (!! 500) [1..1000]
        , bench "vector-index" $ nf (V.! 500) (V.fromList [1..1000])
        , bench "unboxed-vector-index" $ nf (UV.! 500) (UV.fromList [1..1000])
        
        , bench "map-lookup" $ nf (Map.lookup 500) intMap
        , bench "hashmap-lookup" $ nf (HashMap.lookup 500) intHashMap
        
        , bench "map-insert" $ whnf (Map.insert 1001 "new") intMap
        , bench "hashmap-insert" $ whnf (HashMap.insert 1001 "new") intHashMap
        ]
    
    , bgroup "algorithms"
        [ bench "fibonacci-naive" $ nf fibNaive 30
        , bench "fibonacci-memo" $ nf fibMemo 30
        , bench "fibonacci-iter" $ nf fibIter 30
        
        , bench "quicksort" $ nf quickSort (reverse [1..100])
        , bench "mergesort" $ nf mergeSort (reverse [1..100])
        
        , bench "tree-sum" $ nf treeSum bigTree
        , bench "tree-depth" $ nf treeDepth bigTree
        ]
    
    , bgroup "strictness"
        [ bench "lazy-sum" $ nf sum [1..10000]
        , bench "strict-sum" $ nf strictSum [1..10000]
        , bench "bang-sum" $ nf bangSum [1..10000]
        
        , bench "lazy-point" $ nf computePoints 1000
        , bench "strict-point" $ nf computeStrictPoints 1000
        ]
    
    , bgroup "io"
        [ bench "write-file" $ nfIO $ BS.writeFile "/tmp/bench.txt" (BS.replicate 1000 65)
        , bench "read-file" $ nfIO $ BS.readFile "/tmp/bench.txt"
        , bench "write-lazy" $ nfIO $ BSL.writeFile "/tmp/bench.txt" (BSL.replicate 1000 65)
        ]
    ]
  where
    config = defaultConfig
        { timeLimit = 5.0
        , resamples = 1000
        , reportFile = Just "benchmark-report.html"
        , csvFile = Just "benchmark-results.csv"
        }
    
    longString = replicate 1000 'a'
    intMap = Map.fromList [(i, show i) | i <- [1..1000]]
    intHashMap = HashMap.fromList [(i, show i) | i <- [1..1000]]
    bigTree = buildTree 15

-- Benchmark implementations
fibNaive :: Int -> Int
fibNaive 0 = 0
fibNaive 1 = 1
fibNaive n = fibNaive (n-1) + fibNaive (n-2)

fibMemo :: Int -> Int
fibMemo = (map fib [0..] !!)
  where
    fib 0 = 0
    fib 1 = 1
    fib n = fibMemo (n-1) + fibMemo (n-2)

fibIter :: Int -> Int
fibIter n = go n 0 1
  where
    go 0 a _ = a
    go k a b = go (k-1) b (a+b)

quickSort :: Ord a => [a] -> [a]
quickSort [] = []
quickSort (x:xs) = quickSort lt ++ [x] ++ quickSort gt
  where
    lt = filter (< x) xs
    gt = filter (>= x) xs

mergeSort :: Ord a => [a] -> [a]
mergeSort [] = []
mergeSort [x] = [x]
mergeSort xs = merge (mergeSort left) (mergeSort right)
  where
    (left, right) = splitAt (length xs \`div\` 2) xs
    merge [] ys = ys
    merge xs [] = xs
    merge (x:xs) (y:ys)
        | x <= y = x : merge xs (y:ys)
        | otherwise = y : merge (x:xs) ys

buildTree :: Int -> Tree Int
buildTree 0 = Leaf 1
buildTree n = Node (buildTree (n-1)) n (buildTree (n-1))

treeSum :: Tree Int -> Int
treeSum (Leaf x) = x
treeSum (Node l x r) = treeSum l + x + treeSum r

treeDepth :: Tree a -> Int
treeDepth (Leaf _) = 1
treeDepth (Node l _ r) = 1 + max (treeDepth l) (treeDepth r)

strictSum :: [Int] -> Int
strictSum = foldl' (+) 0

bangSum :: [Int] -> Int
bangSum = go 0
  where
    go !acc [] = acc
    go !acc (x:xs) = go (acc + x) xs

computePoints :: Int -> Double
computePoints n = sum [x + y | Point x y <- points]
  where
    points = [Point (fromIntegral i) (fromIntegral j) | i <- [1..n], j <- [1..10]]

computeStrictPoints :: Int -> Double
computeStrictPoints n = sum [x + y | Point x y <- points]
  where
    points = [Point (fromIntegral i) (fromIntegral j) | i <- [1..n], j <- [1..10]]`,

    'src/Profile.hs': `{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fprof-auto #-}

module Profile where

import Control.Monad
import Data.List (foldl')
import System.Environment
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

-- Example program for profiling
main :: IO ()
main = do
    args <- getArgs
    let n = case args of
            [] -> 1000000
            (x:_) -> read x
    
    putStrLn $ "Running with n = " ++ show n
    
    -- Different computation styles to profile
    putStrLn "Lazy computation..."
    print $ lazyComputation n
    
    putStrLn "Strict computation..."
    print $ strictComputation n
    
    putStrLn "Space leak example..."
    print $ spaceLeakExample n
    
    putStrLn "Fixed space leak..."
    print $ fixedSpaceLeak n
    
    putStrLn "Map operations..."
    print $ mapOperations n

-- Lazy computation (may cause space leaks)
lazyComputation :: Int -> Int
lazyComputation n = sum $ map expensive [1..n]
  where
    expensive x = length $ show (x ^ 2)

-- Strict computation (better memory usage)
strictComputation :: Int -> Int
strictComputation n = foldl' (\\acc x -> acc + expensive x) 0 [1..n]
  where
    expensive x = length $ show (x ^ 2)

-- Classic space leak pattern
spaceLeakExample :: Int -> (Int, Int)
spaceLeakExample n = foldl accumulate (0, 0) [1..n]
  where
    accumulate (sumX, sumY) x = (sumX + x, sumY + x * x)

-- Fixed version with strict pattern
fixedSpaceLeak :: Int -> (Int, Int)
fixedSpaceLeak n = foldl' accumulate (0, 0) [1..n]
  where
    accumulate (!sumX, !sumY) x = (sumX + x, sumY + x * x)

-- Map operations for profiling
mapOperations :: Int -> Int
mapOperations n = Map.size finalMap
  where
    finalMap = foldl' insertIfEven Map.empty [1..n]
    insertIfEven m x
        | even x = Map.insert x (x * x) m
        | otherwise = m

-- To run profiling:
-- ghc -O2 -prof -fprof-auto -rtsopts Profile.hs
-- ./Profile +RTS -p -hc -RTS
-- hp2ps -e8in -c Profile.hp
-- open Profile.ps`,

    'src/SpaceLeak.hs': `{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StrictData #-}

module SpaceLeak where

import Control.Monad
import Control.Monad.State.Strict
import Data.List (foldl')
import qualified Data.Map.Strict as Map
import qualified Data.Map.Lazy as LazyMap
import System.Mem (performGC)

-- Common space leak patterns and their fixes

-- 1. Lazy accumulator in fold
-- BAD: Space leak
sumLazy :: [Int] -> Int
sumLazy = foldl (+) 0

-- GOOD: Strict accumulator
sumStrict :: [Int] -> Int
sumStrict = foldl' (+) 0

-- 2. Unevaluated thunks in data structures
-- BAD: Lazy fields accumulate thunks
data StatsLazy = StatsLazy
    { countLazy :: Int
    , sumLazy :: Int
    , sumSquaresLazy :: Int
    }

updateStatsLazy :: StatsLazy -> Int -> StatsLazy
updateStatsLazy stats x = StatsLazy
    { countLazy = countLazy stats + 1
    , sumLazy = sumLazy stats + x
    , sumSquaresLazy = sumSquaresLazy stats + x * x
    }

-- GOOD: Strict fields
data StatsStrict = StatsStrict
    { countStrict :: !Int
    , sumStrict :: !Int
    , sumSquaresStrict :: !Int
    }

updateStatsStrict :: StatsStrict -> Int -> StatsStrict
updateStatsStrict stats x = StatsStrict
    { countStrict = countStrict stats + 1
    , sumStrict = sumStrict stats + x
    , sumSquaresStrict = sumSquaresStrict stats + x * x
    }

-- 3. Lazy State monad
-- BAD: Lazy state accumulates thunks
lazyStateExample :: Int -> Int
lazyStateExample n = evalState (go n) 0
  where
    go 0 = get
    go k = do
        s <- get
        put (s + k)
        go (k - 1)

-- GOOD: Strict State monad
strictStateExample :: Int -> Int
strictStateExample n = evalState (go n) 0
  where
    go 0 = get
    go k = do
        s <- get
        put $! s + k  -- Force evaluation
        go (k - 1)

-- 4. Map updates
-- BAD: Lazy map operations
lazyMapLeak :: Int -> Map.Map Int Int
lazyMapLeak n = foldl insert LazyMap.empty [1..n]
  where
    insert m k = LazyMap.insertWith (+) (k \`mod\` 100) k m

-- GOOD: Strict map with forced values
strictMapFixed :: Int -> Map.Map Int Int
strictMapFixed n = foldl' insert Map.empty [1..n]
  where
    insert m k = Map.insertWith' (+) (k \`mod\` 100) k m

-- 5. List processing
-- BAD: Building large intermediate lists
badListProcessing :: [Int] -> Int
badListProcessing xs = sum $ map (*2) $ filter even xs

-- GOOD: Fusion and single pass
goodListProcessing :: [Int] -> Int
goodListProcessing = foldl' (\\acc x -> if even x then acc + x * 2 else acc) 0

-- 6. CAF (Constant Applicative Form) leak
-- BAD: Large CAF that's never freed
bigCAF :: [Int]
bigCAF = [1..10000000]

useBigCAF :: Int -> Int
useBigCAF n = bigCAF !! n

-- GOOD: Generate data on demand
generateData :: Int -> Int
generateData n = [1..10000000] !! n

-- Test functions to demonstrate space usage
testSpaceLeaks :: IO ()
testSpaceLeaks = do
    let n = 1000000
    
    putStrLn "Testing lazy sum (space leak)..."
    performGC
    print $ sumLazy [1..n]
    
    putStrLn "Testing strict sum (no leak)..."
    performGC
    print $ sumStrict [1..n]
    
    putStrLn "Testing lazy stats (space leak)..."
    performGC
    let lazyStats = foldl updateStatsLazy (StatsLazy 0 0 0) [1..n]
    print $ countLazy lazyStats
    
    putStrLn "Testing strict stats (no leak)..."
    performGC
    let strictStats = foldl' updateStatsStrict (StatsStrict 0 0 0) [1..n]
    print $ countStrict strictStats

-- Run with:
-- ghc -O2 -prof -fprof-auto -rtsopts SpaceLeak.hs
-- ./SpaceLeak +RTS -hc -p -RTS
-- hp2ps -e8in -c SpaceLeak.hp`,

    'Makefile': `# Makefile for optimization and profiling

.PHONY: all clean build profile benchmark heap-profile eventlog threadscope

# Compiler settings
GHC = ghc
GHCFLAGS = -O2 -threaded -rtsopts -eventlog

# Profiling flags
PROF_FLAGS = -prof -fprof-auto -fprof-cafs

# LLVM backend
LLVM_FLAGS = -fllvm -optlo-O3

# Build optimized binary
build:
	$(GHC) $(GHCFLAGS) -o app Main.hs

# Build with LLVM backend
build-llvm:
	$(GHC) $(GHCFLAGS) $(LLVM_FLAGS) -o app-llvm Main.hs

# Build for profiling
build-prof:
	$(GHC) $(GHCFLAGS) $(PROF_FLAGS) -o app-prof Main.hs

# Run time profiling
profile: build-prof
	./app-prof +RTS -p -RTS
	@echo "Profiling report generated: app-prof.prof"

# Heap profiling
heap-profile: build-prof
	@echo "Running heap profile by cost center..."
	./app-prof +RTS -hc -i0.1 -RTS
	hp2ps -e8in -c app-prof.hp
	@echo "Heap profile generated: app-prof.ps"

heap-profile-type: build-prof
	@echo "Running heap profile by type..."
	./app-prof +RTS -hy -i0.1 -RTS
	hp2ps -e8in -c app-prof.hp
	@echo "Heap profile generated: app-prof.ps"

heap-profile-retainer: build-prof
	@echo "Running retainer profile..."
	./app-prof +RTS -hr -i0.1 -RTS
	hp2ps -e8in -c app-prof.hp
	@echo "Heap profile generated: app-prof.ps"

# Biography profiling for space leaks
biography: build-prof
	./app-prof +RTS -hb -i0.1 -RTS
	hp2ps -e8in -c app-prof.hp
	@echo "Biography profile generated: app-prof.ps"

# EventLog for ThreadScope
eventlog: build
	./app +RTS -N -ls -RTS
	@echo "EventLog generated: app.eventlog"
	@echo "View with: threadscope app.eventlog"

# Run ThreadScope
threadscope: eventlog
	threadscope app.eventlog &

# Benchmark with Criterion
benchmark:
	$(GHC) $(GHCFLAGS) -o bench Benchmark.hs
	./bench --output benchmark-report.html
	@echo "Benchmark report generated: benchmark-report.html"

# Core inspection
core:
	$(GHC) -O2 -ddump-simpl -dsuppress-all -dsuppress-uniques -o app Main.hs > core.dump 2>&1
	@echo "Core output saved to: core.dump"

# STG inspection
stg:
	$(GHC) -O2 -ddump-stg -dsuppress-all -o app Main.hs > stg.dump 2>&1
	@echo "STG output saved to: stg.dump"

# Assembly inspection
asm:
	$(GHC) -O2 -S -o app.s Main.hs
	@echo "Assembly output saved to: app.s"

# LLVM inspection
llvm:
	$(GHC) -O2 -fllvm -ddump-llvm -o app Main.hs > llvm.dump 2>&1
	@echo "LLVM output saved to: llvm.dump"

# Space leak detection
space-leak: build-prof
	./app-prof +RTS -hc -hbdrag,void -i0.1 -RTS
	hp2ps -e8in -c app-prof.hp
	@echo "Space leak profile generated: app-prof.ps"

# Memory statistics
mem-stats: build
	./app +RTS -s -RTS 2>&1 | tee mem-stats.txt
	@echo "Memory statistics saved to: mem-stats.txt"

# Compile statistics
compile-stats:
	$(GHC) -O2 -v3 -o app Main.hs 2>&1 | tee compile-stats.txt
	@echo "Compilation statistics saved to: compile-stats.txt"

# Clean up
clean:
	rm -f app app-prof app-llvm bench
	rm -f *.hi *.o *.prof *.hp *.ps *.aux
	rm -f *.eventlog *.dump *.s
	rm -f benchmark-report.html benchmark-results.csv
	rm -f core.dump stg.dump llvm.dump
	rm -f mem-stats.txt compile-stats.txt`,

    'optimization-guide.md': `# GHC Optimization Guide

## Optimization Levels

### -O0 (No optimization)
- Fast compilation
- Good for development
- Preserves source structure

### -O1 (Standard optimization)
- Basic optimizations
- Reasonable compile time
- Good default

### -O2 (Full optimization)
- Aggressive optimizations
- Longer compile time
- Production builds

## Key Optimization Flags

### Strictness
\`\`\`bash
-funbox-strict-fields      # Unbox strict fields
-fstrictness              # Strictness analysis
-fstrictness-before=3     # Run strictness analysis earlier
\`\`\`

### Specialization
\`\`\`bash
-fspecialise              # Specialize overloaded functions
-fspecialise-aggressively # More aggressive specialization
-fcross-module-specialise # Cross-module specialization
\`\`\`

### Inlining
\`\`\`bash
-funfolding-use-threshold=100  # Inline threshold
-funfolding-keeness-factor=100 # Inlining eagerness
-fexpose-all-unfoldings       # Cross-module inlining
\`\`\`

### Other optimizations
\`\`\`bash
-fcse                     # Common subexpression elimination
-ffull-laziness          # Float out common subexpressions
-fignore-asserts         # Remove assertions
-fomit-interface-pragmas # Smaller interface files
\`\`\`

## Profiling

### Time profiling
\`\`\`bash
ghc -prof -fprof-auto -rtsopts Main.hs
./Main +RTS -p -RTS
\`\`\`

### Heap profiling
\`\`\`bash
# By cost center
./Main +RTS -hc -RTS

# By type
./Main +RTS -hy -RTS

# By retainer
./Main +RTS -hr -RTS

# By biography (for space leaks)
./Main +RTS -hb -RTS
\`\`\`

### Viewing profiles
\`\`\`bash
# Convert heap profile to PostScript
hp2ps -e8in -c Main.hp

# View time profile
cat Main.prof
\`\`\`

## Space Leak Detection

### Common patterns
1. Lazy accumulator in folds
2. Unevaluated thunks in data structures
3. CAFs (Constant Applicative Forms)
4. Lazy State monad

### Detection tools
- Heap profiling with -hb
- Retainer profiling with -hr
- Biography profiling

### Fixes
- Use strict data types
- Use seq and deepseq
- Use BangPatterns
- Use strict folds (foldl')

## Performance Tips

### Data structures
- Use Text instead of String
- Use ByteString for binary data
- Use Vector for arrays
- Use unboxed types when possible

### Algorithms
- Avoid repeated list traversals
- Use appropriate data structures
- Consider streaming libraries
- Use fusion where possible

### Parallelism
\`\`\`bash
-threaded              # Enable threaded runtime
-feager-blackholing    # Better parallelism
-rtsopts=-N           # Use all cores
\`\`\`

## LLVM Backend

### Enable LLVM
\`\`\`bash
ghc -fllvm -optlo-O3 Main.hs
\`\`\`

### Benefits
- Better low-level optimizations
- Improved numeric code
- Better vectorization

### Requirements
- LLVM toolchain installed
- Compatible LLVM version

## Core Inspection

### Dump simplified Core
\`\`\`bash
ghc -O2 -ddump-simpl -dsuppress-all Main.hs
\`\`\`

### What to look for
- Unnecessary allocations
- Missing specializations
- Unevaluated thunks
- Dictionary passing

## Benchmarking

### Using Criterion
\`\`\`haskell
import Criterion.Main

main = defaultMain
  [ bench "function1" $ nf function1 input
  , bench "function2" $ whnf function2 input
  ]
\`\`\`

### Best practices
- Use nf for full evaluation
- Use whnf for WHNF evaluation
- Run multiple times
- Control for noise

## Memory Management

### RTS options
\`\`\`bash
+RTS -A32m    # Larger allocation area
+RTS -H128m   # Suggested heap size
+RTS -M1g     # Maximum heap size
+RTS -c       # Parallel GC
\`\`\`

### GC statistics
\`\`\`bash
./Main +RTS -s -RTS
\`\`\`

## Debugging Performance

### EventLog
\`\`\`bash
ghc -eventlog Main.hs
./Main +RTS -l -RTS
threadscope Main.eventlog
\`\`\`

### Ticky-ticky profiling
\`\`\`bash
ghc -ticky Main.hs
./Main +RTS -r -RTS
\`\`\``,

    'package.yaml': `name: optimization-example
version: 0.1.0.0

dependencies:
- base >= 4.7 && < 5
- criterion
- deepseq
- vector
- containers
- unordered-containers
- text
- bytestring
- mtl

ghc-options:
  - -Wall
  - -Wcompat
  - -Widentities

executables:
  app:
    main: Main.hs
    source-dirs: app
    ghc-options:
      - -O2
      - -threaded
      - -rtsopts
      - -with-rtsopts=-N
      - -funbox-strict-fields
      - -fspecialise
      - -fspecialise-aggressively
      - -fcross-module-specialise
      - -fexpose-all-unfoldings

  app-prof:
    main: Main.hs
    source-dirs: app
    ghc-options:
      - -O2
      - -prof
      - -fprof-auto
      - -fprof-cafs
      - -threaded
      - -rtsopts

  app-llvm:
    main: Main.hs
    source-dirs: app
    ghc-options:
      - -O2
      - -fllvm
      - -optlo-O3
      - -threaded
      - -rtsopts

benchmarks:
  optimization-bench:
    main: Benchmark.hs
    source-dirs: app
    ghc-options:
      - -O2
      - -threaded
      - -rtsopts
      - -with-rtsopts=-N
    dependencies:
      - criterion

library:
  source-dirs: src
  ghc-options:
    - -O2
    - -funbox-strict-fields
    - -fspecialise`,

    'README.md': `# GHC Optimization & Profiling

Advanced optimization and profiling setup for high-performance Haskell applications.

## Features

- **GHC Optimization**: Comprehensive optimization flags
- **Profiling Tools**: Time, heap, and space leak profiling
- **LLVM Backend**: Better code generation
- **Core Inspection**: Analyze GHC Core output
- **Benchmarking**: Criterion integration
- **EventLog**: ThreadScope support
- **Space Leak Detection**: Biography profiling

## Quick Start

### Build optimized
\`\`\`bash
make build
\`\`\`

### Run profiling
\`\`\`bash
make profile
make heap-profile
\`\`\`

### Run benchmarks
\`\`\`bash
make benchmark
\`\`\`

## Optimization Levels

### Development
- Fast compilation
- Good debugging
- Assertions enabled

### Production
- Full optimization (-O2)
- Strict fields unboxed
- Cross-module inlining
- LLVM backend

### Profiling
- Cost center profiling
- Heap profiling
- EventLog generation

## Profiling Guide

### Time Profiling
\`\`\`bash
# Build with profiling
ghc -O2 -prof -fprof-auto Main.hs

# Run with profiling
./Main +RTS -p -RTS

# View report
cat Main.prof
\`\`\`

### Heap Profiling
\`\`\`bash
# Profile by cost center
./Main +RTS -hc -RTS

# Profile by type
./Main +RTS -hy -RTS

# Convert to PostScript
hp2ps -e8in -c Main.hp
\`\`\`

### Space Leak Detection
\`\`\`bash
# Biography profiling
./Main +RTS -hb -RTS

# Retainer profiling
./Main +RTS -hr -RTS
\`\`\`

## Performance Tips

### Strictness
- Use BangPatterns
- Use strict data types
- Use \`seq\` and \`deepseq\`
- Use strict folds

### Data Structures
- Text > String
- Vector > List (for indexing)
- ByteString for binary data
- Unboxed types when possible

### Optimization Flags
\`\`\`bash
-funbox-strict-fields
-fspecialise-aggressively
-fcross-module-specialise
-fexpose-all-unfoldings
\`\`\`

## LLVM Backend

### Enable LLVM
\`\`\`bash
ghc -fllvm -optlo-O3 Main.hs
\`\`\`

### Benefits
- Better numeric code
- Improved vectorization
- Advanced optimizations

## Core Inspection

### View Core
\`\`\`bash
make core
\`\`\`

### What to check
- Unnecessary allocations
- Missing specializations
- Dictionary passing
- Unboxing opportunities

## EventLog & ThreadScope

### Generate EventLog
\`\`\`bash
make eventlog
\`\`\`

### View with ThreadScope
\`\`\`bash
make threadscope
\`\`\`

## Memory Management

### RTS Options
\`\`\`bash
# Larger allocation area
+RTS -A32m

# Suggested heap size
+RTS -H128m

# Parallel GC
+RTS -c
\`\`\`

## Common Issues

### Space Leaks
- Lazy accumulators
- Unevaluated thunks
- Large CAFs

### Solutions
- Strict data types
- Force evaluation
- Use profiling tools

## Resources

- [GHC User Guide](https://downloads.haskell.org/ghc/latest/docs/html/users_guide/)
- [Real World Haskell - Profiling](http://book.realworldhaskell.org/read/profiling-and-optimization.html)
- [Haskell Performance](https://wiki.haskell.org/Performance)
- [ThreadScope](https://wiki.haskell.org/ThreadScope)`
  }
};