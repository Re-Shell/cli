import { BackendTemplate } from '../types';

export const haskellTestingTemplate: BackendTemplate = {
  id: 'haskell-testing',
  name: 'haskell-testing',
  displayName: 'Haskell Testing with HSpec & QuickCheck',
  description: 'Comprehensive testing setup for Haskell projects with property-based testing, BDD-style specs, and advanced testing patterns',
  framework: 'testing',
  language: 'haskell',
  version: '2.11',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🧪',
  type: 'testing',
  complexity: 'intermediate',
  keywords: ['haskell', 'testing', 'hspec', 'quickcheck', 'property-testing', 'bdd'],
  
  features: [
    'HSpec BDD-style testing',
    'QuickCheck property-based testing',
    'Test discovery',
    'Parallel test execution',
    'Code coverage reporting',
    'Golden testing',
    'Doctest integration',
    'Hedgehog property testing',
    'Tasty test framework',
    'Mock and stub support',
    'Test fixtures',
    'Performance testing',
    'Integration testing',
    'Mutation testing'
  ],
  
  structure: {
    'test/Spec.hs': `{-# OPTIONS_GHC -F -pgmF hspec-discover #-}
-- This file enables automatic test discovery
-- hspec-discover will find all modules ending with Spec
-- and generate the test runner automatically`,

    'test/Example/CoreSpec.hs': `{-# LANGUAGE OverloadedStrings #-}

module Example.CoreSpec (spec) where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Control.Exception (evaluate)

import Example.Core

-- | Main spec for Core module
spec :: Spec
spec = do
  describe "Basic HSpec examples" $ do
    context "when testing pure functions" $ do
      it "should add two numbers correctly" $ do
        add 2 3 \`shouldBe\` 5
        
      it "should handle negative numbers" $ do
        add (-5) 3 \`shouldBe\` (-2)
        
      it "should satisfy commutativity" $ do
        add 3 4 \`shouldBe\` add 4 3
    
    context "when testing with exceptions" $ do
      it "should throw an exception for division by zero" $ do
        evaluate (divide 5 0) \`shouldThrow\` anyException
        
      it "should not throw for valid division" $ do
        divide 10 2 \`shouldBe\` 5
    
    context "when using custom matchers" $ do
      it "should be approximately equal" $ do
        pi \`shouldSatisfy\` (\\x -> abs (x - 3.14159) < 0.001)
        
      it "should be within range" $ do
        randomInRange 1 10 \`shouldSatisfy\` (\\x -> x >= 1 && x <= 10)
  
  describe "QuickCheck property tests" $ do
    prop "addition is commutative" $ \\x y ->
      add x y == add y x
    
    prop "addition is associative" $ \\x y z ->
      add (add x y) z == add x (add y z)
    
    prop "zero is identity for addition" $ \\x ->
      add x 0 == x && add 0 x == x
    
    modifyMaxSuccess (const 1000) $ 
      prop "list reverse is involutive" $ \\xs ->
        reverse (reverse xs) == (xs :: [Int])
    
    prop "filter preserves order" $ \\p xs ->
      let filtered = filter p xs
      in all p filtered && isSubsequenceOf filtered xs
  
  describe "Stateful testing" $ do
    it "should maintain state correctly" $ do
      counter <- newCounter
      incrementCounter counter
      incrementCounter counter
      getCounter counter \`shouldReturn\` 2
    
    it "should handle concurrent updates" $ do
      counter <- newCounter
      replicateConcurrently_ 1000 (incrementCounter counter)
      count <- getCounter counter
      count \`shouldBe\` 1000`,

    'test/Example/PropertySpec.hs': `{-# LANGUAGE TemplateHaskell #-}

module Example.PropertySpec (spec) where

import Test.Hspec
import Test.QuickCheck
import Test.QuickCheck.Monadic
import Data.List (sort, nub)
import Control.Monad (when)

import Example.Types
import Example.Functions

-- | Custom generators
instance Arbitrary User where
  arbitrary = User
    <$> arbitrary
    <*> genEmail
    <*> choose (18, 100)
    <*> arbitrary
    
  shrink (User id email age active) =
    [ User id' email age active | id' <- shrink id ] ++
    [ User id email age' active | age' <- shrink age, age' >= 18 ]

genEmail :: Gen String
genEmail = do
  user <- listOf1 $ elements ['a'..'z']
  domain <- listOf1 $ elements ['a'..'z']
  return $ user ++ "@" ++ domain ++ ".com"

-- | Custom properties
prop_sortIdempotent :: [Int] -> Bool
prop_sortIdempotent xs = sort (sort xs) == sort xs

prop_reverseInvolution :: [Int] -> Bool
prop_reverseInvolution xs = reverse (reverse xs) == xs

prop_mapFusion :: Fun Int Int -> Fun Int Int -> [Int] -> Bool
prop_mapFusion f g xs = 
  map (apply f) (map (apply g) xs) == map (apply f . apply g) xs

-- | Conditional properties
prop_uniqueWhenNoDuplicates :: [Int] -> Property
prop_uniqueWhenNoDuplicates xs =
  nub xs == xs ==> length (unique xs) == length xs

prop_insertMaintainsSorted :: Int -> [Int] -> Property
prop_insertMaintainsSorted x xs =
  sorted xs ==> sorted (insertSorted x xs)
  where
    sorted ys = sort ys == ys

-- | Monadic properties
prop_fileWriteRead :: Property
prop_fileWriteRead = monadicIO $ do
  content <- pick arbitrary
  file <- run $ do
    let path = "/tmp/test.txt"
    writeFile path content
    readFile path
  assert (file == content)

-- | Stateful model testing
data Counter = Counter Int deriving (Eq, Show)

data CounterCommand
  = Increment
  | Decrement
  | Reset
  deriving (Show, Arbitrary)

runCommand :: CounterCommand -> Counter -> Counter
runCommand Increment (Counter n) = Counter (n + 1)
runCommand Decrement (Counter n) = Counter (n - 1)
runCommand Reset _ = Counter 0

prop_counterModel :: [CounterCommand] -> Bool
prop_counterModel cmds =
  let finalState = foldl (flip runCommand) (Counter 0) cmds
      increments = length $ filter (== Increment) cmds
      decrements = length $ filter (== Decrement) cmds
      resets = length $ filter (== Reset) cmds
  in if resets > 0
     then finalState == Counter (increments - decrements) 
          || any isResetLast (tails cmds)
     else finalState == Counter (increments - decrements)
  where
    isResetLast [] = False
    isResetLast (Reset:rest) = all (/= Reset) rest
    isResetLast (_:xs) = isResetLast xs

-- | Test specifications
spec :: Spec
spec = do
  describe "Basic QuickCheck properties" $ do
    it "sort is idempotent" $ property prop_sortIdempotent
    it "reverse is an involution" $ property prop_reverseInvolution
    it "map fusion law holds" $ property prop_mapFusion
  
  describe "Conditional properties" $ do
    it "unique preserves length when no duplicates" $ 
      property prop_uniqueWhenNoDuplicates
    it "insert maintains sorted order" $ 
      property prop_insertMaintainsSorted
  
  describe "Custom generators" $ do
    it "generates valid emails" $ property $ \\user ->
      '@' \`elem\` userEmail (user :: User)
    
    it "generates adults only" $ property $ \\user ->
      userAge (user :: User) >= 18
  
  describe "Monadic properties" $ do
    it "file operations are consistent" $ 
      property prop_fileWriteRead
  
  describe "Model-based testing" $ do
    it "counter model is consistent" $ 
      property prop_counterModel
  
  describe "Labeling and classification" $ do
    prop "classify list sizes" $ \\xs ->
      classify (null xs) "empty" $
      classify (length xs == 1) "singleton" $
      classify (length xs >= 2 && length xs <= 10) "small" $
      classify (length xs > 10) "large" $
      reverse (reverse xs) == (xs :: [Int])
    
    prop "collect statistics" $ \\x y ->
      collect (compare x y) $
      max x y >= min x y
  
  describe "Sized generators" $ do
    it "generates appropriately sized trees" $ 
      property $ sized $ \\n -> do
        tree <- genTree n
        return $ depth tree <= n
  
  describe "Shrinking" $ do
    it "shrinks to minimal counterexample" $ 
      property $ \\xs ->
        not (null xs) ==> head xs /= last xs
        -- This will fail, but shrinking will find minimal case`,

    'test/Example/HedgehogSpec.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Example.HedgehogSpec (spec) where

import Test.Hspec
import Test.Hspec.Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Hedgehog

import Example.Types
import Example.Functions

-- | Hedgehog generators (more sophisticated than QuickCheck)
genUser :: Gen User
genUser = do
  userId <- Gen.int (Range.linear 1 10000)
  userEmail <- genEmail
  userAge <- Gen.int (Range.linear 18 100)
  userActive <- Gen.bool
  pure $ User userId userEmail userAge userActive

genEmail :: Gen String
genEmail = do
  user <- Gen.string (Range.linear 1 20) Gen.alpha
  domain <- Gen.element ["gmail.com", "yahoo.com", "example.com"]
  pure $ user ++ "@" ++ domain

genTree :: Gen a -> Gen (Tree a)
genTree genA = Gen.recursive Gen.choice
  [ Leaf <$> genA ]  -- Base case
  [ Node <$> genA <*> genTree genA <*> genTree genA ]  -- Recursive case

-- | Hedgehog properties
prop_reverseInvolution :: Property
prop_reverseInvolution = property $ do
  xs <- forAll $ Gen.list (Range.linear 0 100) Gen.alpha
  reverse (reverse xs) === xs

prop_insertSorted :: Property
prop_insertSorted = property $ do
  xs <- forAll $ Gen.list (Range.linear 0 50) (Gen.int $ Range.linear 0 100)
  let sorted = sort xs
  x <- forAll $ Gen.int (Range.linear 0 100)
  assert $ isSorted (insertSorted x sorted)

prop_treeDepth :: Property
prop_treeDepth = property $ do
  tree <- forAll $ genTree (Gen.int $ Range.linear 0 100)
  let d = depth tree
      s = size tree
  assert $ d <= s
  classify "balanced" $ d <= log2 s + 1
  classify "linear" $ d == s

-- | State machine testing with Hedgehog
data ModelState = ModelState
  { modelValue :: Int
  , modelHistory :: [Command]
  } deriving (Eq, Show)

data Command
  = Add Int
  | Multiply Int
  | Reset
  deriving (Eq, Show)

genCommand :: Gen Command
genCommand = Gen.choice
  [ Add <$> Gen.int (Range.linear (-10) 10)
  , Multiply <$> Gen.int (Range.linear (-5) 5)
  , pure Reset
  ]

executeCommand :: Command -> ModelState -> ModelState
executeCommand (Add n) s = s 
  { modelValue = modelValue s + n
  , modelHistory = Add n : modelHistory s
  }
executeCommand (Multiply n) s = s
  { modelValue = modelValue s * n
  , modelHistory = Multiply n : modelHistory s
  }
executeCommand Reset s = s
  { modelValue = 0
  , modelHistory = Reset : modelHistory s
  }

prop_modelExecution :: Property
prop_modelExecution = property $ do
  commands <- forAll $ Gen.list (Range.linear 1 20) genCommand
  let finalState = foldl (flip executeCommand) (ModelState 0 []) commands
  
  -- Properties about the model
  when (Reset \`elem\` commands) $
    assert $ modelValue finalState == 0 || not (Reset \`elem\` take 1 (modelHistory finalState))
  
  diff (length (modelHistory finalState)) (===) (length commands)

-- | Integration with HSpec
spec :: Spec
spec = do
  describe "Hedgehog properties" $ do
    it "reverse is involution" $ hedgehog prop_reverseInvolution
    it "insertSorted maintains order" $ hedgehog prop_insertSorted
    it "tree depth is bounded by size" $ hedgehog prop_treeDepth
  
  describe "State machine testing" $ do
    it "model execution is consistent" $ hedgehog prop_modelExecution
  
  describe "Generator shrinking" $ do
    it "finds minimal counterexamples" $ hedgehog $ property $ do
      xs <- forAll $ Gen.list (Range.linear 2 10) (Gen.int $ Range.linear 0 100)
      assert $ length (nub xs) == length xs  -- Will fail and shrink to [0,0]`,

    'test/Example/TastySpec.hs': `{-# LANGUAGE OverloadedStrings #-}

module Example.TastySpec where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.Tasty.Golden
import Test.Tasty.Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Data.List
import System.Directory

import Example.Functions

-- | Tasty test tree combining multiple test frameworks
tests :: TestTree
tests = testGroup "Tasty Tests"
  [ unitTests
  , propertyTests
  , goldenTests
  , hedgehogTests
  ]

-- | HUnit tests
unitTests :: TestTree
unitTests = testGroup "Unit tests"
  [ testCase "List comparison" $ do
      [1,2,3] \`compare\` [1,2] @?= GT
      
  , testCase "Exception handling" $ do
      result <- tryDivide 10 0
      result @?= Left "Division by zero"
      
  , testGroup "Nested tests"
    [ testCase "String operations" $ do
        reverse "hello" @?= "olleh"
        
    , testCase "Math operations" $ do
        2 + 2 @?= 4
    ]
  ]

-- | QuickCheck properties
propertyTests :: TestTree
propertyTests = testGroup "QuickCheck properties"
  [ testProperty "reverse involution" $ \\xs ->
      reverse (reverse xs) == (xs :: [Int])
      
  , testProperty "sort idempotent" $ \\xs ->
      sort (sort xs) == sort (xs :: [Int])
      
  , localOption (QuickCheckTests 1000) $
    testProperty "with custom test count" $ \\x y ->
      x + y == y + x
  ]

-- | Golden tests for regression testing
goldenTests :: TestTree
goldenTests = testGroup "Golden tests"
  [ goldenVsFile "simple output" 
      "test/golden/expected.txt"
      "test/golden/actual.txt" $ do
      writeFile "test/golden/actual.txt" "Hello, World!\\n"
      
  , goldenVsString "JSON output"
      "test/golden/user.json"
      (pure "{\\"name\\": \\"test\\", \\"age\\": 30}")
      
  , goldenVsFileDiff "custom diff"
      (\\ref new -> ["diff", "-u", ref, new])
      "test/golden/expected.txt"
      "test/golden/actual.txt" $ do
      writeFile "test/golden/actual.txt" "Hello, World!\\n"
  ]

-- | Hedgehog tests
hedgehogTests :: TestTree
hedgehogTests = testGroup "Hedgehog tests"
  [ testProperty "list reverse" $ property $ do
      xs <- forAll $ Gen.list (Range.linear 0 100) Gen.alpha
      reverse (reverse xs) === xs
  ]

-- | Main test runner with options
main :: IO ()
main = defaultMainWithIngredients ingredients tests
  where
    ingredients = defaultIngredients ++
      [ listingTests
      , includingOptions
        [ Option (Proxy :: Proxy QuickCheckTests)
        , Option (Proxy :: Proxy QuickCheckReplay)
        , Option (Proxy :: Proxy QuickCheckMaxSize)
        ]
      ]`,

    'test/Example/DoctestSpec.hs': `module Example.DoctestSpec where

-- | Doctest integration
-- Run with: cabal test doctest
-- or: stack test :doctest

import Test.DocTest

main :: IO ()
main = doctest
  [ "-isrc"
  , "-XOverloadedStrings"
  , "-XRecordWildCards"
  , "src/Example/Core.hs"
  , "src/Example/Types.hs"
  , "src/Example/Functions.hs"
  ]

-- Example of doctests in source files:
-- |
-- >>> add 2 3
-- 5
--
-- >>> add (-1) 1
-- 0
--
-- prop> \\x y -> add x y == add y x`,

    'test/Example/MockSpec.hs': `{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE RankNTypes #-}

module Example.MockSpec (spec) where

import Test.Hspec
import Test.Hspec.Expectations.Contrib.HUnit
import Control.Monad.State
import Control.Monad.Writer
import Data.IORef

import Example.Services

-- | Mock implementations
data MockDatabase = MockDatabase
  { mockUsers :: IORef [User]
  , mockLogs :: IORef [String]
  }

createMockDatabase :: IO MockDatabase
createMockDatabase = MockDatabase
  <$> newIORef []
  <*> newIORef []

instance Database MockDatabase where
  saveUser db user = do
    modifyIORef (mockUsers db) (user:)
    modifyIORef (mockLogs db) ("Saved user: " ++ show (userId user) :)
    
  getUser db uid = do
    users <- readIORef (mockUsers db)
    modifyIORef (mockLogs db) ("Fetched user: " ++ show uid :)
    return $ find (\\u -> userId u == uid) users
    
  deleteUser db uid = do
    modifyIORef (mockUsers db) (filter (\\u -> userId u /= uid))
    modifyIORef (mockLogs db) ("Deleted user: " ++ show uid :)

-- | Stub implementations
stubEmailService :: EmailService
stubEmailService = EmailService
  { sendEmail = \\to subject body -> return $ Right ("Email sent to " ++ to)
  , validateEmail = \\email -> '@' \`elem\` email
  }

-- | Spy implementations
data SpyLogger = SpyLogger (IORef [String])

createSpyLogger :: IO SpyLogger
createSpyLogger = SpyLogger <$> newIORef []

instance Logger SpyLogger where
  logInfo (SpyLogger ref) msg = modifyIORef ref (("INFO: " ++ msg) :)
  logError (SpyLogger ref) msg = modifyIORef ref (("ERROR: " ++ msg) :)
  
getSpyLogs :: SpyLogger -> IO [String]
getSpyLogs (SpyLogger ref) = reverse <$> readIORef ref

-- | Test specifications
spec :: Spec
spec = do
  describe "Mock testing" $ do
    it "should save and retrieve users with mock database" $ do
      db <- createMockDatabase
      let user = User 1 "test@example.com" 25 True
      
      saveUser db user
      retrieved <- getUser db 1
      
      retrieved \`shouldBe\` Just user
      
      -- Verify interactions
      logs <- readIORef (mockLogs db)
      logs \`shouldContain\` ["Saved user: 1", "Fetched user: 1"]
    
    it "should handle user deletion" $ do
      db <- createMockDatabase
      let user1 = User 1 "user1@example.com" 25 True
          user2 = User 2 "user2@example.com" 30 True
      
      saveUser db user1
      saveUser db user2
      deleteUser db 1
      
      remaining <- readIORef (mockUsers db)
      map userId remaining \`shouldBe\` [2]
  
  describe "Stub testing" $ do
    it "should use stub email service" $ do
      let emailResult = runEmailService stubEmailService $ do
            result <- sendEmail "test@example.com" "Subject" "Body"
            return result
      
      emailResult \`shouldBe\` Right "Email sent to test@example.com"
    
    it "should validate emails with stub" $ do
      validateEmail stubEmailService "test@example.com" \`shouldBe\` True
      validateEmail stubEmailService "invalid" \`shouldBe\` False
  
  describe "Spy testing" $ do
    it "should capture log calls with spy" $ do
      spyLogger <- createSpyLogger
      
      runWithLogger spyLogger $ do
        logInfo "Starting process"
        logError "Something went wrong"
        logInfo "Process completed"
      
      logs <- getSpyLogs spyLogger
      logs \`shouldBe\`
        [ "INFO: Starting process"
        , "ERROR: Something went wrong"
        , "INFO: Process completed"
        ]
  
  describe "Test doubles with type classes" $ do
    it "should work with polymorphic functions" $ do
      -- Using mock database
      db <- createMockDatabase
      result <- runUserService db $ do
        createUser "test@example.com" 25
        findUserByEmail "test@example.com"
      
      case result of
        Just user -> userEmail user \`shouldBe\` "test@example.com"
        Nothing -> expectationFailure "User not found"`,

    'test/Example/IntegrationSpec.hs': `{-# LANGUAGE OverloadedStrings #-}

module Example.IntegrationSpec (spec) where

import Test.Hspec
import Database.PostgreSQL.Simple
import Network.HTTP.Simple
import Control.Exception
import System.Process
import System.Environment

import Example.Server
import Example.Database

-- | Integration test helpers
withTestDatabase :: (Connection -> IO a) -> IO a
withTestDatabase action = bracket
  (connect testDbInfo)
  close
  (\\conn -> do
    setupTestSchema conn
    action conn
    teardownTestSchema conn)

testDbInfo :: ConnectInfo
testDbInfo = defaultConnectInfo
  { connectHost = "localhost"
  , connectDatabase = "test_db"
  , connectUser = "test_user"
  , connectPassword = "test_pass"
  }

withTestServer :: (String -> IO a) -> IO a
withTestServer action = bracket
  startServer
  stopServer
  (\\port -> action ("http://localhost:" ++ port))
  where
    startServer = do
      -- Start server on random port
      port <- findFreePort
      pid <- spawnProcess "stack" ["run", "--", "--port", show port]
      threadDelay 1000000  -- Wait for server to start
      return (port, pid)
    
    stopServer (_, pid) = terminateProcess pid

-- | Integration tests
spec :: Spec
spec = do
  describe "Database integration" $ do
    it "should perform CRUD operations" $ \withTestDatabase $ \conn -> do
      -- Create
      userId <- insertUser conn "test@example.com" "Test User"
      userId \`shouldSatisfy\` (> 0)
      
      -- Read
      user <- getUser conn userId
      userEmail <$> user \`shouldBe\` Just "test@example.com"
      
      -- Update
      updateUser conn userId "newemail@example.com"
      updated <- getUser conn userId
      userEmail <$> updated \`shouldBe\` Just "newemail@example.com"
      
      -- Delete
      deleteUser conn userId
      deleted <- getUser conn userId
      deleted \`shouldBe\` Nothing
    
    it "should handle transactions correctly" $ \withTestDatabase $ \conn -> do
      result <- try $ withTransaction conn $ do
        insertUser conn "user1@example.com" "User 1"
        insertUser conn "user2@example.com" "User 2"
        fail "Simulated error"
      
      case result of
        Left (e :: SomeException) -> return ()
        Right _ -> expectationFailure "Transaction should have failed"
      
      -- Verify rollback
      users <- getAllUsers conn
      users \`shouldBe\` []
  
  describe "HTTP API integration" $ do
    around withTestServer $ do
      it "should handle GET requests" $ \baseUrl -> do
        response <- httpLBS =<< parseRequest (baseUrl ++ "/api/health")
        getResponseStatusCode response \`shouldBe\` 200
        getResponseBody response \`shouldBe\` "{\\"status\\":\\"ok\\"}"
      
      it "should handle POST requests" $ \baseUrl -> do
        let request = setRequestMethod "POST"
                    $ setRequestPath "/api/users"
                    $ setRequestBodyJSON (object ["email" .= "test@example.com"])
                    =<< parseRequest baseUrl
        
        response <- httpLBS request
        getResponseStatusCode response \`shouldBe\` 201
        
        let body = decode (getResponseBody response) :: Maybe Value
        body ^? _Just . key "id" \`shouldSatisfy\` isJust
      
      it "should handle authentication" $ \baseUrl -> do
        -- Login
        let loginRequest = setRequestMethod "POST"
                        $ setRequestPath "/api/login"
                        $ setRequestBodyJSON (object 
                            [ "username" .= "admin"
                            , "password" .= "secret"
                            ])
                        =<< parseRequest baseUrl
        
        loginResponse <- httpLBS loginRequest
        let token = getResponseBody loginResponse ^? key "token" . _String
        
        -- Use token
        let authRequest = setRequestHeader "Authorization" ["Bearer " <> toStrict token]
                        $ setRequestPath "/api/protected"
                        =<< parseRequest baseUrl
        
        authResponse <- httpLBS authRequest
        getResponseStatusCode authResponse \`shouldBe\` 200
  
  describe "End-to-end testing" $ do
    it "should complete full user workflow" $ do
      -- This would test the complete flow from UI to database
      -- Often using tools like Selenium for browser automation
      pending "Implement with Selenium"`,

    'test/Example/PerformanceSpec.hs': `{-# LANGUAGE BangPatterns #-}

module Example.PerformanceSpec (spec) where

import Test.Hspec
import Criterion.Measurement
import Control.DeepSeq
import Control.Monad
import Data.Time.Clock
import System.Timeout

import Example.Algorithms

-- | Performance testing helpers
timeAction :: NFData a => IO a -> IO Double
timeAction action = do
  start <- getCPUTime
  !result <- action
  deepseq result $ return ()
  end <- getCPUTime
  return $ fromIntegral (end - start) / (10^12)

-- | Performance specifications
spec :: Spec
spec = do
  describe "Performance tests" $ do
    it "should complete sorting within time limit" $ do
      let input = reverse [1..10000]
      time <- timeAction $ return $! quickSort input
      time \`shouldSatisfy\` (< 0.1)  -- Less than 100ms
    
    it "should handle large inputs efficiently" $ do
      let largeList = [1..100000]
      result <- timeout 5000000 $ return $! sum largeList  -- 5 second timeout
      result \`shouldSatisfy\` isJust
    
    it "should have linear time complexity for map" $ do
      -- Test that doubling input size roughly doubles time
      time1 <- timeAction $ return $! map (*2) [1..10000]
      time2 <- timeAction $ return $! map (*2) [1..20000]
      
      let ratio = time2 / time1
      ratio \`shouldSatisfy\` (\\r -> r > 1.8 && r < 2.5)
    
    it "should not have memory leaks" $ do
      -- This is a simple check; use tools like hp2ps for detailed analysis
      let bigComputation = foldl' (+) 0 [1..1000000]
      result <- timeAction $ return $! bigComputation
      result \`shouldSatisfy\` (< 0.5)
  
  describe "Comparative performance" $ do
    it "should use efficient algorithm" $ do
      let n = 1000
          input = [1..n]
      
      -- Naive O(n²) algorithm
      naiveTime <- timeAction $ return $! naiveDuplicates input
      
      -- Efficient O(n log n) algorithm  
      efficientTime <- timeAction $ return $! efficientDuplicates input
      
      efficientTime \`shouldSatisfy\` (< naiveTime * 0.5)
  
  describe "Space complexity" $ do
    it "should use constant space for foldl'" $ do
      -- This won't actually measure space, but ensures it completes
      -- Use profiling tools for actual space measurement
      let result = foldl' (+) 0 [1..10000000]
      result \`shouldBe\` 50000005000000
    
    it "should handle lazy evaluation properly" $ do
      -- Test that we can work with infinite lists
      let infiniteList = [1..]
          result = take 10 infiniteList
      length result \`shouldBe\` 10`,

    'test-suite/hspec.cabal': `name:                test-suite
version:             0.1.0.0
build-type:          Simple
cabal-version:       >=1.10

test-suite spec
  type:                exitcode-stdio-1.0
  main-is:             Spec.hs
  other-modules:       Example.CoreSpec
                       Example.PropertySpec
                       Example.HedgehogSpec
                       Example.MockSpec
                       Example.IntegrationSpec
                       Example.PerformanceSpec
  build-depends:       base
                     , hspec >= 2.10
                     , hspec-discover >= 2.10
                     , QuickCheck >= 2.14
                     , hedgehog >= 1.2
                     , tasty >= 1.4
                     , tasty-hunit
                     , tasty-quickcheck
                     , tasty-hedgehog
                     , tasty-golden
                     , hspec-expectations-lifted
                     , hspec-contrib
                     , criterion
                     , deepseq
                     , time
                     , async
                     , stm
                     , postgresql-simple
                     , http-conduit
                     , aeson
  hs-source-dirs:      test
  default-language:    Haskell2010
  ghc-options:         -threaded -rtsopts -with-rtsopts=-N
  build-tool-depends:  hspec-discover:hspec-discover`,

    'README.md': `# Haskell Testing Suite

Comprehensive testing setup for Haskell projects using HSpec, QuickCheck, Hedgehog, and more.

## Testing Frameworks

### HSpec (BDD-style testing)
- Behavior-driven development style
- Automatic test discovery
- Integration with QuickCheck
- Parallel test execution
- Test focusing and pending tests

### QuickCheck (Property-based testing)
- Generate random test data
- Shrinking for minimal counterexamples
- Custom generators and shrinkers
- Stateful testing
- Performance testing

### Hedgehog (Modern property testing)
- Integrated shrinking
- Better error messages
- Monadic generators
- State machine testing
- Coverage tracking

### Tasty (Test framework)
- Combines multiple test frameworks
- Ingredient system for extensibility
- Pattern-based test filtering
- Parallel execution
- Resource management

## Running Tests

### Basic test execution
\`\`\`bash
# Run all tests
cabal test
# or
stack test

# Run specific test suite
cabal test spec
stack test :spec

# Run with options
stack test --test-arguments="--match \\"Core\\""
\`\`\`

### Test discovery
\`\`\`bash
# HSpec discover finds all *Spec.hs files
hspec-discover

# Run only specific specs
cabal test --test-options="-m \\"should add\\""
\`\`\`

### Coverage
\`\`\`bash
# Generate coverage report
stack test --coverage
# or
cabal test --enable-coverage

# View coverage
stack hpc report
hpc report dist/hpc
\`\`\`

### Property test configuration
\`\`\`bash
# More QuickCheck tests
stack test --test-arguments="--quickcheck-tests=1000"

# Set seed for reproducibility
stack test --test-arguments="--seed=42"

# Maximum test size
stack test --test-arguments="--quickcheck-max-size=200"
\`\`\`

## Test Patterns

### HSpec patterns
\`\`\`haskell
-- Focus on specific test
fit "only this test runs" $ ...

-- Skip test
xit "this test is skipped" $ ...

-- Pending test
it "not yet implemented" $ 
  pending

-- Custom expectations
shouldSatisfy, shouldContain, shouldStartWith, shouldEndWith
\`\`\`

### QuickCheck patterns
\`\`\`haskell
-- Conditional properties
prop_example x = 
  x > 0 ==> someProperty x

-- Collecting statistics
prop_classified xs =
  classify (null xs) "empty" $
  classify (length xs > 10) "large" $
  property

-- Custom generators
genEven :: Gen Int
genEven = (* 2) <$> arbitrary
\`\`\`

### Golden tests
\`\`\`haskell
-- Regression testing
goldenVsFile "test name"
  "expected/output.txt"
  "actual/output.txt"
  computation
\`\`\`

## Test Organization

### Directory structure
\`\`\`
test/
├── Spec.hs                 # Main entry point
├── Example/
│   ├── CoreSpec.hs        # Unit tests
│   ├── PropertySpec.hs    # Property tests
│   ├── IntegrationSpec.hs # Integration tests
│   └── fixtures/          # Test data
└── golden/                # Golden test files
\`\`\`

### Naming conventions
- `*Spec.hs` - HSpec test modules
- `*Test.hs` - Other test modules
- `prop_*` - Property test names
- `spec_*` - Specification test names

## Advanced Testing

### Mocking and stubbing
- Type class based mocking
- IORef for stateful mocks
- Reader monad for dependency injection

### Performance testing
- Criterion integration
- Time and space complexity
- Memory leak detection

### Integration testing
- Database testing with transactions
- HTTP API testing
- End-to-end testing

## Best Practices

1. **Write tests first** - TDD/BDD approach
2. **Property > Example** - Prefer properties when possible
3. **Fast tests** - Keep unit tests fast
4. **Isolated tests** - No shared state
5. **Descriptive names** - Clear test descriptions
6. **Test edge cases** - Empty, null, boundaries
7. **Shrink properly** - Good counterexamples
8. **CI integration** - Run tests automatically

## Tools and Commands

### Useful commands
\`\`\`bash
# Watch mode
ghcid --command="stack ghci --test" --test="main"

# Run specific test
stack test --ta="-m \\"pattern\\""

# Generate HPC report
stack hpc report --all

# Profile tests
stack test --profile
\`\`\`

### IDE Integration
- HLS supports test code lenses
- VS Code Haskell extension
- IntelliJ Haskell plugin

## Resources

- [HSpec documentation](https://hspec.github.io/)
- [QuickCheck manual](http://www.cse.chalmers.se/~rjmh/QuickCheck/manual.html)
- [Hedgehog tutorial](https://hedgehog.qa/)
- [Tasty documentation](https://github.com/UnkindPartition/tasty)`
  }
};