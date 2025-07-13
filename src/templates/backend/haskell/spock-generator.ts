/**
 * Spock Framework Template Generator
 * A lightweight Haskell web framework for rapid development
 */

import { HaskellBackendGenerator } from './haskell-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class SpockGenerator extends HaskellBackendGenerator {
  constructor() {
    super('Spock');
  }

  protected getFrameworkDependencies(): string[] {
    return [
      'Spock: ^0.14',
      'Spock-core: ^0.14',
      'reroute: ^0.6',
      'hvect: ^0.4',
      'wai: ^3.2',
      'warp: ^3.3',
      'http-types: ^0.12',
      'aeson: ^2.1',
      'text: ^2.0',
      'bytestring: ^0.11',
      'mtl: ^2.3',
      'transformers: ^0.6',
      'stm: ^2.5',
      'containers: ^0.6',
      'unordered-containers: ^0.2',
      'hashable: ^1.4',
      'time: ^1.12',
      'uuid: ^1.3',
      'random: ^1.2',
      'hasql: ^1.6',
      'hasql-pool: ^0.9',
      'hasql-migration: ^0.3',
      'hasql-transaction: ^1.0',
      'contravariant: ^1.5',
      'profunctors: ^5.6',
      'vector: ^0.13',
      'jose: ^0.10',
      'cryptonite: ^0.30',
      'memory: ^0.18',
      'base64-bytestring: ^1.2',
      'wai-cors: ^0.2',
      'wai-extra: ^3.1',
      'case-insensitive: ^1.2',
      'cookie: ^0.4',
      'vault: ^0.3',
      'lifted-base: ^0.2',
      'monad-control: ^1.0',
      'resourcet: ^1.3',
      'unliftio: ^0.2',
      'async: ^2.2',
      'retry: ^0.9',
      'network: ^3.1',
      'http-client: ^0.7',
      'http-client-tls: ^0.3'
    ];
  }

  protected getExtraDeps(): string[] {
    return [];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application
    await this.generateMainApp(projectPath, options);

    // Generate app structure
    await this.generateAppStructure(projectPath);

    // Generate routes
    await this.generateRoutes(projectPath);

    // Generate handlers
    await this.generateHandlers(projectPath);

    // Generate middleware
    await this.generateMiddleware(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate database
    await this.generateDatabase(projectPath);

    // Generate services
    await this.generateServices(projectPath);

    // Generate config
    await this.generateConfig(projectPath, options);

    // Generate utilities
    await this.generateUtilities(projectPath);

    // Generate types
    await this.generateTypes(projectPath);
  }

  private async generateMainApp(projectPath: string, options: any): Promise<void> {
    const mainContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}

module Main where

import Control.Monad (void)
import System.Environment (lookupEnv)
import Network.Wai.Handler.Warp (run)
import Web.Spock
import Web.Spock.Config

import App
import Config
import Database
import Routes
import Middleware

main :: IO ()
main = do
  -- Load configuration
  config <- loadConfig
  
  -- Initialize database
  dbPool <- initDatabase config
  
  -- Run migrations
  runMigrations dbPool
  
  -- Create session configuration
  sessionCfg <- defaultSessionCfg "${options.name}_session" (configSessionTimeout config)
  
  -- Create Spock configuration
  spockCfg <- defaultSpockCfg sessionCfg (PCPool dbPool) (AppState config)
  
  -- Get port from environment or config
  port <- maybe (configPort config) read <$> lookupEnv "PORT"
  
  putStrLn $ "Starting Spock server on port " ++ show port
  
  -- Run application
  runSpock port $ spock spockCfg app

app :: SpockM Connection Session AppState ()
app = do
  -- Apply middleware
  middleware corsMiddleware
  middleware loggingMiddleware
  middleware errorHandlerMiddleware
  
  -- Define routes
  routes
`;

    await fs.writeFile(
      path.join(projectPath, 'app', 'Main.hs'),
      mainContent
    );
  }

  private async generateAppStructure(projectPath: string): Promise<void> {
    const appContent = `{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module App where

import Control.Monad.Reader
import Data.Text (Text)
import Data.Time.Clock
import Data.UUID
import Hasql.Pool (Pool)
import Hasql.Connection (Connection)
import Web.Spock
import qualified Data.Vault.Lazy as Vault

import Config

-- Application State
data AppState = AppState
  { appConfig :: Config
  }

-- Session type
data Session = Session
  { sessionUserId :: Maybe UUID
  , sessionCreated :: UTCTime
  , sessionData :: [(Text, Text)]
  } deriving (Show, Eq)

-- Create empty session
emptySession :: IO Session
emptySession = do
  now <- getCurrentTime
  return Session
    { sessionUserId = Nothing
    , sessionCreated = now
    , sessionData = []
    }

-- Application monad type alias
type Api = SpockM Connection Session AppState
type ApiAction a = SpockAction Connection Session AppState a

-- Context keys for request-scoped data
userIdKey :: Vault.Key UUID
userIdKey = unsafePerformIO Vault.newKey
{-# NOINLINE userIdKey #-}

requestIdKey :: Vault.Key Text
requestIdKey = unsafePerformIO Vault.newKey
{-# NOINLINE requestIdKey #-}

-- Get current user ID from context
getCurrentUserId :: ApiAction (Maybe UUID)
getCurrentUserId = do
  vault <- getContext
  return $ Vault.lookup userIdKey vault

-- Require authenticated user
requireAuth :: ApiAction a -> ApiAction a
requireAuth action = do
  maybeUserId <- getCurrentUserId
  case maybeUserId of
    Nothing -> do
      setStatus status401
      json $ object
        [ "error" .= ("Unauthorized" :: Text)
        , "message" .= ("Authentication required" :: Text)
        ]
    Just _ -> action

-- Get app config
getConfig :: ApiAction Config
getConfig = appConfig <$> getState

-- Error type
data ApiError = ApiError
  { errorCode :: Int
  , errorMessage :: Text
  , errorDetails :: Maybe Value
  } deriving (Show)

instance ToJSON ApiError where
  toJSON err = object $
    [ "error" .= object
        [ "code" .= errorCode err
        , "message" .= errorMessage err
        ]
    ] ++ maybe [] (\\d -> ["details" .= d]) (errorDetails err)

-- Error helpers
throwError :: Int -> Text -> ApiAction a
throwError code msg = do
  setStatus $ mkStatus code (encodeUtf8 msg)
  json $ ApiError code msg Nothing

badRequest :: Text -> ApiAction a
badRequest = throwError 400

unauthorized :: Text -> ApiAction a
unauthorized = throwError 401

forbidden :: Text -> ApiAction a
forbidden = throwError 403

notFound :: Text -> ApiAction a
notFound = throwError 404

internalError :: Text -> ApiAction a
internalError = throwError 500
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'App.hs'),
      appContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    const routesContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module Routes where

import Web.Spock
import Web.Spock.Action

import App
import Handlers.Auth
import Handlers.User
import Handlers.Health
import Handlers.Admin

routes :: Api ()
routes = do
  -- Health check routes
  get root $ redirect "/health"
  get "health" healthCheckHandler
  get ("api" <//> "v1" <//> "health") healthCheckHandler
  
  -- Public API routes
  subcomponent "api/v1" $ do
    -- Authentication routes
    post "auth/register" registerHandler
    post "auth/login" loginHandler
    post "auth/refresh" refreshTokenHandler
    post "auth/logout" $ requireAuth logoutHandler
    get "auth/me" $ requireAuth getMeHandler
    
    -- User routes (protected)
    get "users" $ requireAuth listUsersHandler
    get ("users" <//> var) $ requireAuth getUserHandler
    put ("users" <//> var) $ requireAuth updateUserHandler
    delete ("users" <//> var) $ requireAuth deleteUserHandler
    
    -- Admin routes
    subcomponent "admin" $ requireAuth $ do
      post "users" createUserHandler
      get "stats" getStatsHandler
      
  -- Static file serving (optional)
  -- wildcard $ \\path -> do
  --   file <- liftIO $ serveStatic ("static/" ++ T.unpack path)
  --   case file of
  --     Nothing -> notFound "File not found"
  --     Just content -> bytes content
  
  -- Catch-all 404 handler
  hookAny GET $ \\_ -> notFound "Endpoint not found"
  hookAny POST $ \\_ -> notFound "Endpoint not found"
  hookAny PUT $ \\_ -> notFound "Endpoint not found"
  hookAny DELETE $ \\_ -> notFound "Endpoint not found"
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Routes.hs'),
      routesContent
    );
  }

  private async generateHandlers(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Handlers'), { recursive: true });

    // Health handler
    const healthContent = `{-# LANGUAGE OverloadedStrings #-}

module Handlers.Health where

import Control.Exception (try, SomeException)
import Data.Time.Clock
import Web.Spock

import App
import Database

healthCheckHandler :: ApiAction ()
healthCheckHandler = do
  currentTime <- liftIO getCurrentTime
  
  -- Check database connection
  pool <- getContext >>= \\ctx -> return $ pcPool ctx
  dbStatus <- liftIO $ checkDatabaseHealth pool
  
  -- Get version from config
  config <- getConfig
  
  json $ object
    [ "status" .= ("healthy" :: Text)
    , "timestamp" .= currentTime
    , "version" .= configVersion config
    , "environment" .= show (configEnv config)
    , "services" .= object
        [ "database" .= object
            [ "status" .= if dbStatus then "up" else "down" :: Text
            , "type" .= ("postgresql" :: Text)
            ]
        ]
    ]

checkDatabaseHealth :: Pool Connection -> IO Bool
checkDatabaseHealth pool = do
  result <- try $ use pool $ statement () checkHealthQuery
  case result of
    Left (_ :: SomeException) -> return False
    Right (Right True) -> return True
    _ -> return False
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Handlers', 'Health.hs'),
      healthContent
    );

    // Auth handler
    const authContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Handlers.Auth where

import Control.Monad (when, unless)
import Crypto.KDF.BCrypt (validatePassword, hashPassword)
import Data.Time.Clock
import Data.UUID.V4 (nextRandom)
import Web.Spock
import qualified Data.Text.Encoding as T

import App
import Types.Auth
import Types.User
import Database.User
import Services.JWT
import Utils.Validation

registerHandler :: ApiAction ()
registerHandler = do
  RegisterRequest{..} <- jsonBody'
  
  -- Validate input
  unless (isValidEmail registerEmail) $
    badRequest "Invalid email format"
  
  unless (isValidPassword registerPassword) $
    badRequest "Password must be at least 8 characters with mixed case and numbers"
  
  -- Check if user exists
  pool <- getContext >>= \\ctx -> return $ pcPool ctx
  existingUser <- liftIO $ getUserByEmail pool registerEmail
  
  case existingUser of
    Right (Just _) -> badRequest "Email already registered"
    Left err -> internalError $ "Database error: " <> pack (show err)
    Right Nothing -> do
      -- Hash password
      hashedPw <- liftIO $ hashPassword 12 (T.encodeUtf8 registerPassword)
      
      -- Create user
      userId <- liftIO nextRandom
      now <- liftIO getCurrentTime
      
      let newUser = User
            { userId = userId
            , userEmail = registerEmail
            , userPasswordHash = hashedPw
            , userName = registerName
            , userRole = "user"
            , userEmailVerified = False
            , userCreatedAt = now
            , userUpdatedAt = now
            }
      
      -- Save user
      result <- liftIO $ createUser pool newUser
      
      case result of
        Left err -> internalError $ "Failed to create user: " <> pack (show err)
        Right _ -> do
          -- Generate tokens
          config <- getConfig
          accessToken <- liftIO $ generateAccessToken config userId
          refreshToken <- liftIO $ generateRefreshToken config userId
          
          -- Update session
          modifySession $ \\s -> s { sessionUserId = Just userId }
          
          -- Return response
          json $ object
            [ "user" .= toPublicUser newUser
            , "tokens" .= object
                [ "access" .= accessToken
                , "refresh" .= refreshToken
                ]
            ]

loginHandler :: ApiAction ()
loginHandler = do
  LoginRequest{..} <- jsonBody'
  
  -- Find user
  pool <- getContext >>= \\ctx -> return $ pcPool ctx
  userResult <- liftIO $ getUserByEmail pool loginEmail
  
  case userResult of
    Left err -> internalError $ "Database error: " <> pack (show err)
    Right Nothing -> unauthorized "Invalid credentials"
    Right (Just user) -> do
      -- Verify password
      let valid = validatePassword (T.encodeUtf8 loginPassword) (userPasswordHash user)
      
      unless valid $
        unauthorized "Invalid credentials"
      
      -- Generate tokens
      config <- getConfig
      accessToken <- liftIO $ generateAccessToken config (userId user)
      refreshToken <- liftIO $ generateRefreshToken config (userId user)
      
      -- Update session
      modifySession $ \\s -> s { sessionUserId = Just (userId user) }
      
      -- Return response
      json $ object
        [ "user" .= toPublicUser user
        , "tokens" .= object
            [ "access" .= accessToken
            , "refresh" .= refreshToken
            ]
        ]

refreshTokenHandler :: ApiAction ()
refreshTokenHandler = do
  RefreshRequest{..} <- jsonBody'
  
  config <- getConfig
  
  case verifyRefreshToken config refreshToken of
    Left err -> unauthorized $ "Invalid refresh token: " <> err
    Right claims -> do
      -- Generate new access token
      newAccessToken <- liftIO $ generateAccessToken config (jwtUserId claims)
      
      json $ object
        [ "tokens" .= object
            [ "access" .= newAccessToken
            , "refresh" .= refreshToken  -- Keep same refresh token
            ]
        ]

logoutHandler :: ApiAction ()
logoutHandler = do
  -- Clear session
  modifySession $ \\s -> s { sessionUserId = Nothing }
  
  -- In production, you might want to blacklist the token
  json $ object ["message" .= ("Logged out successfully" :: Text)]

getMeHandler :: ApiAction ()
getMeHandler = do
  maybeUserId <- getSession >>= \\s -> return (sessionUserId s)
  
  case maybeUserId of
    Nothing -> unauthorized "Not logged in"
    Just uid -> do
      pool <- getContext >>= \\ctx -> return $ pcPool ctx
      userResult <- liftIO $ getUserById pool uid
      
      case userResult of
        Left err -> internalError $ "Database error: " <> pack (show err)
        Right Nothing -> notFound "User not found"
        Right (Just user) -> json $ object ["user" .= toPublicUser user]
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Handlers', 'Auth.hs'),
      authContent
    );

    // User handler
    const userContent = `{-# LANGUAGE OverloadedStrings #-}

module Handlers.User where

import Control.Monad (when, unless)
import Data.Maybe (fromMaybe)
import Data.UUID (UUID, fromText)
import Web.Spock
import Web.Spock.Action

import App
import Types.User
import Database.User
import Utils.Pagination

listUsersHandler :: ApiAction ()
listUsersHandler = do
  -- Get pagination params
  page <- fromMaybe 1 <$> param "page"
  limit <- fromMaybe 10 <$> param "limit"
  search <- param "search"
  
  let offset = (page - 1) * limit
  
  pool <- getContext >>= \\ctx -> return $ pcPool ctx
  
  -- Get users and count
  usersResult <- liftIO $ getUsers pool limit offset search
  countResult <- liftIO $ getUserCount pool search
  
  case (usersResult, countResult) of
    (Right users, Right total) -> do
      let publicUsers = map toPublicUser users
      paginatedResponse publicUsers page limit total
    _ -> internalError "Failed to fetch users"

getUserHandler :: UUID -> ApiAction ()
getUserHandler uid = do
  pool <- getContext >>= \\ctx -> return $ pcPool ctx
  userResult <- liftIO $ getUserById pool uid
  
  case userResult of
    Left err -> internalError $ "Database error: " <> pack (show err)
    Right Nothing -> notFound "User not found"
    Right (Just user) -> json $ object ["user" .= toPublicUser user]

updateUserHandler :: UUID -> ApiAction ()
updateUserHandler uid = do
  -- Check permission
  currentUser <- requireCurrentUser
  
  unless (userId currentUser == uid || userRole currentUser == "admin") $
    forbidden "You can only update your own profile"
  
  UpdateUserRequest{..} <- jsonBody'
  
  -- Validate updates
  case updateEmail of
    Just email -> unless (isValidEmail email) $
      badRequest "Invalid email format"
    Nothing -> return ()
  
  pool <- getContext >>= \\ctx -> return $ pcPool ctx
  
  -- Check if email is taken
  case updateEmail of
    Just newEmail -> do
      existingResult <- liftIO $ getUserByEmail pool newEmail
      case existingResult of
        Right (Just existing) -> when (userId existing /= uid) $
          badRequest "Email already taken"
        _ -> return ()
    Nothing -> return ()
  
  -- Update user
  now <- liftIO getCurrentTime
  updateResult <- liftIO $ updateUser pool uid UpdateUserData
    { updateUserName = updateName
    , updateUserEmail = updateEmail
    , updateUserUpdatedAt = now
    }
  
  case updateResult of
    Left err -> internalError $ "Update failed: " <> pack (show err)
    Right Nothing -> notFound "User not found"
    Right (Just user) -> json $ object ["user" .= toPublicUser user]

deleteUserHandler :: UUID -> ApiAction ()
deleteUserHandler uid = do
  -- Only admins can delete users
  currentUser <- requireCurrentUser
  
  unless (userRole currentUser == "admin") $
    forbidden "Admin access required"
  
  -- Prevent self-deletion
  when (userId currentUser == uid) $
    badRequest "Cannot delete your own account"
  
  pool <- getContext >>= \\ctx -> return $ pcPool ctx
  deleteResult <- liftIO $ deleteUser pool uid
  
  case deleteResult of
    Left err -> internalError $ "Delete failed: " <> pack (show err)
    Right False -> notFound "User not found"
    Right True -> json $ object ["message" .= ("User deleted successfully" :: Text)]

-- Helper to get current user
requireCurrentUser :: ApiAction User
requireCurrentUser = do
  maybeUserId <- getSession >>= \\s -> return (sessionUserId s)
  
  case maybeUserId of
    Nothing -> unauthorized "Authentication required"
    Just uid -> do
      pool <- getContext >>= \\ctx -> return $ pcPool ctx
      userResult <- liftIO $ getUserById pool uid
      
      case userResult of
        Right (Just user) -> return user
        _ -> unauthorized "User not found"
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Handlers', 'User.hs'),
      userContent
    );

    // Admin handler
    const adminContent = `{-# LANGUAGE OverloadedStrings #-}

module Handlers.Admin where

import Web.Spock

import App
import Types.User
import Database.Stats

createUserHandler :: ApiAction ()
createUserHandler = do
  -- Verify admin
  currentUser <- requireCurrentUser
  unless (userRole currentUser == "admin") $
    forbidden "Admin access required"
  
  -- Implementation similar to register but with admin controls
  json $ object ["message" .= ("Admin user creation not implemented" :: Text)]

getStatsHandler :: ApiAction ()
getStatsHandler = do
  -- Verify admin
  currentUser <- requireCurrentUser
  unless (userRole currentUser == "admin") $
    forbidden "Admin access required"
  
  pool <- getContext >>= \\ctx -> return $ pcPool ctx
  
  -- Get various stats
  userCountResult <- liftIO $ getTotalUserCount pool
  activeUsersResult <- liftIO $ getActiveUserCount pool
  
  case (userCountResult, activeUsersResult) of
    (Right userCount, Right activeUsers) ->
      json $ object
        [ "stats" .= object
            [ "totalUsers" .= userCount
            , "activeUsers" .= activeUsers
            , "newUsersToday" .= (0 :: Int)  -- TODO: Implement
            , "totalSessions" .= (0 :: Int)  -- TODO: Implement
            ]
        ]
    _ -> internalError "Failed to fetch statistics"
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Handlers', 'Admin.hs'),
      adminContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    const middlewareContent = `{-# LANGUAGE OverloadedStrings #-}

module Middleware where

import Control.Monad.IO.Class (liftIO)
import Data.Text.Lazy (toStrict)
import Data.UUID.V4 (nextRandom)
import Network.HTTP.Types
import Network.Wai
import Network.Wai.Middleware.Cors
import Network.Wai.Middleware.RequestLogger
import Web.Spock
import qualified Data.ByteString.Char8 as BS
import qualified Data.CaseInsensitive as CI
import qualified Data.Text as T
import qualified Data.Vault.Lazy as Vault

import App
import Services.JWT

-- CORS middleware
corsMiddleware :: Middleware
corsMiddleware = cors $ const $ Just CorsResourcePolicy
  { corsOrigins = Nothing  -- Allow all origins
  , corsMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  , corsRequestHeaders = ["Authorization", "Content-Type"]
  , corsExposedHeaders = Nothing
  , corsMaxAge = Just 86400
  , corsVaryOrigin = False
  , corsRequireOrigin = False
  , corsIgnoreFailures = False
  }

-- Logging middleware
loggingMiddleware :: Middleware
loggingMiddleware = logStdoutDev

-- Error handler middleware
errorHandlerMiddleware :: Middleware
errorHandlerMiddleware app req respond = do
  app req respond \`catch\` handleException
  where
    handleException :: SomeException -> IO ResponseReceived
    handleException e = respond $ responseLBS
      status500
      [("Content-Type", "application/json")]
      $ encode $ object
          [ "error" .= object
              [ "code" .= (500 :: Int)
              , "message" .= ("Internal server error" :: Text)
              , "details" .= show e
              ]
          ]

-- JWT authentication middleware (for specific routes)
jwtMiddleware :: Text -> Middleware
jwtMiddleware secret app req respond = do
  let headers = requestHeaders req
      authHeader = lookup "Authorization" headers
  
  case authHeader >>= extractBearer of
    Nothing -> app req respond
    Just token -> 
      case verifyAccessToken secret token of
        Left _ -> respond $ responseLBS
          status401
          [("Content-Type", "application/json")]
          $ encode $ object
              [ "error" .= object
                  [ "code" .= (401 :: Int)
                  , "message" .= ("Invalid or expired token" :: Text)
                  ]
              ]
        Right claims -> do
          -- Add user ID to vault
          let vault' = Vault.insert userIdKey (jwtUserId claims) (vault req)
              req' = req { vault = vault' }
          app req' respond
  where
    extractBearer :: ByteString -> Maybe Text
    extractBearer auth =
      case BS.words auth of
        ["Bearer", token] -> Just $ T.pack $ BS.unpack token
        _ -> Nothing

-- Request ID middleware
requestIdMiddleware :: Middleware
requestIdMiddleware app req respond = do
  requestId <- liftIO $ toText <$> nextRandom
  let vault' = Vault.insert requestIdKey requestId (vault req)
      req' = req { vault = vault' }
  app req' respond

-- Rate limiting middleware (simple in-memory implementation)
-- In production, use Redis or similar
rateLimitMiddleware :: Int -> Middleware
rateLimitMiddleware _limit app req respond = do
  -- TODO: Implement proper rate limiting
  app req respond
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Middleware.hs'),
      middlewareContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Types'), { recursive: true });

    // User types
    const userTypesContent = `{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Types.User where

import Data.Aeson
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Time.Clock
import Data.UUID
import GHC.Generics

-- User model
data User = User
  { userId :: UUID
  , userEmail :: Text
  , userPasswordHash :: ByteString
  , userName :: Text
  , userRole :: Text
  , userEmailVerified :: Bool
  , userCreatedAt :: UTCTime
  , userUpdatedAt :: UTCTime
  } deriving (Show, Eq, Generic)

-- Public user (without sensitive data)
data PublicUser = PublicUser
  { publicUserId :: UUID
  , publicUserEmail :: Text
  , publicUserName :: Text
  , publicUserRole :: Text
  , publicUserEmailVerified :: Bool
  , publicUserCreatedAt :: UTCTime
  } deriving (Show, Eq, Generic)

instance ToJSON PublicUser where
  toJSON u = object
    [ "id" .= publicUserId u
    , "email" .= publicUserEmail u
    , "name" .= publicUserName u
    , "role" .= publicUserRole u
    , "emailVerified" .= publicUserEmailVerified u
    , "createdAt" .= publicUserCreatedAt u
    ]

-- Convert User to PublicUser
toPublicUser :: User -> PublicUser
toPublicUser u = PublicUser
  { publicUserId = userId u
  , publicUserEmail = userEmail u
  , publicUserName = userName u
  , publicUserRole = userRole u
  , publicUserEmailVerified = userEmailVerified u
  , publicUserCreatedAt = userCreatedAt u
  }

-- Update user request
data UpdateUserRequest = UpdateUserRequest
  { updateName :: Maybe Text
  , updateEmail :: Maybe Text
  } deriving (Show, Generic)

instance FromJSON UpdateUserRequest where
  parseJSON = withObject "UpdateUserRequest" $ \\v -> UpdateUserRequest
    <$> v .:? "name"
    <*> v .:? "email"

-- Update user data (for database)
data UpdateUserData = UpdateUserData
  { updateUserName :: Maybe Text
  , updateUserEmail :: Maybe Text
  , updateUserUpdatedAt :: UTCTime
  } deriving (Show)
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Types', 'User.hs'),
      userTypesContent
    );

    // Auth types
    const authTypesContent = `{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Types.Auth where

import Data.Aeson
import Data.Text (Text)
import Data.UUID
import GHC.Generics

-- Register request
data RegisterRequest = RegisterRequest
  { registerEmail :: Text
  , registerPassword :: Text
  , registerName :: Text
  } deriving (Show, Generic)

instance FromJSON RegisterRequest where
  parseJSON = withObject "RegisterRequest" $ \\v -> RegisterRequest
    <$> v .: "email"
    <*> v .: "password"
    <*> v .: "name"

-- Login request
data LoginRequest = LoginRequest
  { loginEmail :: Text
  , loginPassword :: Text
  } deriving (Show, Generic)

instance FromJSON LoginRequest where
  parseJSON = withObject "LoginRequest" $ \\v -> LoginRequest
    <$> v .: "email"
    <*> v .: "password"

-- Refresh token request
data RefreshRequest = RefreshRequest
  { refreshToken :: Text
  } deriving (Show, Generic)

instance FromJSON RefreshRequest where
  parseJSON = withObject "RefreshRequest" $ \\v -> RefreshRequest
    <$> v .: "refreshToken"

-- JWT Claims
data JWTClaims = JWTClaims
  { jwtUserId :: UUID
  , jwtEmail :: Text
  , jwtRole :: Text
  , jwtExp :: Integer
  } deriving (Show, Eq)
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Types', 'Auth.hs'),
      authTypesContent
    );
  }

  private async generateDatabase(projectPath: string): Promise<void> {
    const databaseContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Database where

import Control.Exception (bracket)
import Data.Text (Text)
import Hasql.Connection (Connection, Settings, settings)
import Hasql.Pool (Pool, acquire, release, use)
import Hasql.Session (Session, statement)
import Hasql.Statement (Statement)
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import qualified Hasql.Migration as M

import Config

-- Initialize database connection pool
initDatabase :: Config -> IO (Pool Connection)
initDatabase config = do
  let dbSettings = settings
        (encodeUtf8 $ configDbHost config)
        (fromIntegral $ configDbPort config)
        (encodeUtf8 $ configDbUser config)
        (encodeUtf8 $ configDbPassword config)
        (encodeUtf8 $ configDbName config)
  
  acquire (configDbPoolSize config) 30 dbSettings

-- Run migrations
runMigrations :: Pool Connection -> IO ()
runMigrations pool = do
  putStrLn "Running database migrations..."
  
  let migrations = M.MigrationInitialization : map M.MigrationScript
        [ createUsersTable
        , createSessionsTable
        , createIndexes
        ]
  
  result <- use pool $ M.runMigration M.defaultOptions migrations
  
  case result of
    Left err -> error $ "Migration failed: " ++ show err
    Right _ -> putStrLn "Migrations completed successfully"

-- Migration scripts
createUsersTable :: ByteString
createUsersTable = [q|
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash BYTEA NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
|]

createSessionsTable :: ByteString
createSessionsTable = [q|
  CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
|]

createIndexes :: ByteString
createIndexes = [q|
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
|]

-- Health check query
checkHealthQuery :: Statement () Bool
checkHealthQuery = Statement
  "SELECT true"
  E.noParams
  (D.singleRow D.bool)
  True
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Database.hs'),
      databaseContent
    );

    // User database module
    await fs.mkdir(path.join(projectPath, 'src', 'Database'), { recursive: true });
    const userDbContent = `{-# LANGUAGE OverloadedStrings #-}

module Database.User where

import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Time.Clock
import Data.UUID
import Hasql.Pool (Pool, use)
import Hasql.Session (Session, statement)
import Hasql.Statement (Statement)
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import Hasql.Connection (Connection)

import Types.User

-- Get user by ID
getUserById :: Pool Connection -> UUID -> IO (Either String (Maybe User))
getUserById pool uid = do
  result <- use pool $ statement uid getUserByIdQuery
  return $ case result of
    Left err -> Left $ show err
    Right user -> Right user

getUserByIdQuery :: Statement UUID (Maybe User)
getUserByIdQuery = Statement
  "SELECT id, email, password_hash, name, role, email_verified, created_at, updated_at FROM users WHERE id = $1"
  (E.param (E.nonNullable E.uuid))
  (D.rowMaybe userDecoder)
  True

-- Get user by email
getUserByEmail :: Pool Connection -> Text -> IO (Either String (Maybe User))
getUserByEmail pool email = do
  result <- use pool $ statement email getUserByEmailQuery
  return $ case result of
    Left err -> Left $ show err
    Right user -> Right user

getUserByEmailQuery :: Statement Text (Maybe User)
getUserByEmailQuery = Statement
  "SELECT id, email, password_hash, name, role, email_verified, created_at, updated_at FROM users WHERE email = $1"
  (E.param (E.nonNullable E.text))
  (D.rowMaybe userDecoder)
  True

-- Create user
createUser :: Pool Connection -> User -> IO (Either String ())
createUser pool user = do
  result <- use pool $ statement user createUserQuery
  return $ case result of
    Left err -> Left $ show err
    Right _ -> Right ()

createUserQuery :: Statement User ()
createUserQuery = Statement
  "INSERT INTO users (id, email, password_hash, name, role, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
  userEncoder
  D.noResult
  True

-- Get users with pagination
getUsers :: Pool Connection -> Int -> Int -> Maybe Text -> IO (Either String [User])
getUsers pool limit offset search = do
  result <- use pool $ statement (limit, offset, search) getUsersQuery
  return $ case result of
    Left err -> Left $ show err
    Right users -> Right users

getUsersQuery :: Statement (Int, Int, Maybe Text) [User]
getUsersQuery = Statement
  "SELECT id, email, password_hash, name, role, email_verified, created_at, updated_at FROM users \\
   WHERE ($3 IS NULL OR name ILIKE '%' || $3 || '%' OR email ILIKE '%' || $3 || '%') \\
   ORDER BY created_at DESC LIMIT $1 OFFSET $2"
  ((,,) <$> E.param (E.nonNullable E.int4)
        <*> E.param (E.nonNullable E.int4)
        <*> E.param (E.nullable E.text))
  (D.rowList userDecoder)
  True

-- Get user count
getUserCount :: Pool Connection -> Maybe Text -> IO (Either String Int)
getUserCount pool search = do
  result <- use pool $ statement search getUserCountQuery
  return $ case result of
    Left err -> Left $ show err
    Right count -> Right $ fromIntegral count

getUserCountQuery :: Statement (Maybe Text) Int64
getUserCountQuery = Statement
  "SELECT COUNT(*) FROM users WHERE ($1 IS NULL OR name ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%')"
  (E.param (E.nullable E.text))
  (D.singleRow (D.column (D.nonNullable D.int8)))
  True

-- Update user
updateUser :: Pool Connection -> UUID -> UpdateUserData -> IO (Either String (Maybe User))
updateUser pool uid updates = do
  result <- use pool $ do
    statement (uid, updates) updateUserQuery
    statement uid getUserByIdQuery
  return $ case result of
    Left err -> Left $ show err
    Right user -> Right user

updateUserQuery :: Statement (UUID, UpdateUserData) ()
updateUserQuery = Statement
  "UPDATE users SET \\
   name = COALESCE($2, name), \\
   email = COALESCE($3, email), \\
   updated_at = $4 \\
   WHERE id = $1"
  ((,) <$> E.param (E.nonNullable E.uuid)
       <*> updateEncoder)
  D.noResult
  True
  where
    updateEncoder = UpdateUserData
      <$> E.param (E.nullable E.text)
      <*> E.param (E.nullable E.text)
      <*> E.param (E.nonNullable E.timestamptz)

-- Delete user
deleteUser :: Pool Connection -> UUID -> IO (Either String Bool)
deleteUser pool uid = do
  result <- use pool $ statement uid deleteUserQuery
  return $ case result of
    Left err -> Left $ show err
    Right count -> Right (count > 0)

deleteUserQuery :: Statement UUID Int64
deleteUserQuery = Statement
  "DELETE FROM users WHERE id = $1"
  (E.param (E.nonNullable E.uuid))
  D.rowsAffected
  True

-- Decoders and encoders
userDecoder :: D.Row User
userDecoder = User
  <$> D.column (D.nonNullable D.uuid)
  <*> D.column (D.nonNullable D.text)
  <*> D.column (D.nonNullable D.bytea)
  <*> D.column (D.nonNullable D.text)
  <*> D.column (D.nonNullable D.text)
  <*> D.column (D.nonNullable D.bool)
  <*> D.column (D.nonNullable D.timestamptz)
  <*> D.column (D.nonNullable D.timestamptz)

userEncoder :: E.Params User
userEncoder = contramap userId (E.param (E.nonNullable E.uuid))
  <> contramap userEmail (E.param (E.nonNullable E.text))
  <> contramap userPasswordHash (E.param (E.nonNullable E.bytea))
  <> contramap userName (E.param (E.nonNullable E.text))
  <> contramap userRole (E.param (E.nonNullable E.text))
  <> contramap userEmailVerified (E.param (E.nonNullable E.bool))
  <> contramap userCreatedAt (E.param (E.nonNullable E.timestamptz))
  <> contramap userUpdatedAt (E.param (E.nonNullable E.timestamptz))
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Database', 'User.hs'),
      userDbContent
    );

    // Stats database module
    const statsDbContent = `{-# LANGUAGE OverloadedStrings #-}

module Database.Stats where

import Hasql.Pool (Pool, use)
import Hasql.Session (statement)
import Hasql.Statement (Statement)
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import Hasql.Connection (Connection)

-- Get total user count
getTotalUserCount :: Pool Connection -> IO (Either String Int)
getTotalUserCount pool = do
  result <- use pool $ statement () getTotalUserCountQuery
  return $ case result of
    Left err -> Left $ show err
    Right count -> Right $ fromIntegral count

getTotalUserCountQuery :: Statement () Int64
getTotalUserCountQuery = Statement
  "SELECT COUNT(*) FROM users"
  E.noParams
  (D.singleRow (D.column (D.nonNullable D.int8)))
  True

-- Get active user count (logged in within last 30 days)
getActiveUserCount :: Pool Connection -> IO (Either String Int)
getActiveUserCount pool = do
  result <- use pool $ statement () getActiveUserCountQuery
  return $ case result of
    Left err -> Left $ show err
    Right count -> Right $ fromIntegral count

getActiveUserCountQuery :: Statement () Int64
getActiveUserCountQuery = Statement
  "SELECT COUNT(DISTINCT user_id) FROM sessions WHERE expires_at > CURRENT_TIMESTAMP"
  E.noParams
  (D.singleRow (D.column (D.nonNullable D.int8)))
  True
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Database', 'Stats.hs'),
      statsDbContent
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Services'), { recursive: true });

    // JWT service
    const jwtServiceContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Services.JWT where

import Control.Monad (when)
import Crypto.JWT
import Data.Aeson
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.Time.Clock
import Data.Time.Clock.POSIX
import Data.UUID
import qualified Data.Map.Strict as Map

import Config
import Types.Auth

-- Generate access token
generateAccessToken :: Config -> UUID -> IO Text
generateAccessToken config userId = do
  now <- getCurrentTime
  let expTime = addUTCTime (15 * 60) now -- 15 minutes
  createToken config userId "access" expTime

-- Generate refresh token
generateRefreshToken :: Config -> UUID -> IO Text
generateRefreshToken config userId = do
  now <- getCurrentTime
  let expTime = addUTCTime (7 * 24 * 60 * 60) now -- 7 days
  createToken config userId "refresh" expTime

-- Create JWT token
createToken :: Config -> UUID -> Text -> UTCTime -> IO Text
createToken config userId tokenType expTime = do
  now <- getCurrentTime
  
  let claims = emptyClaimsSet
        & claimIss ?~ fromString (configJwtIssuer config)
        & claimSub ?~ fromString (toText userId)
        & claimAud ?~ Audience [fromString "spock-api"]
        & claimExp ?~ NumericDate (utcTimeToPOSIXSeconds expTime)
        & claimIat ?~ NumericDate (utcTimeToPOSIXSeconds now)
        & addClaim "type" (toJSON tokenType)
        & addClaim "userId" (toJSON $ toText userId)
  
  let key = fromOctets $ encodeUtf8 $ configJwtSecret config
  
  result <- runJOSE $ do
    alg <- bestJWSAlg key
    signClaims key (newJWSHeader ((), alg)) claims
  
  case result of
    Left err -> error $ "JWT generation failed: " ++ show err
    Right jwt -> return $ decodeUtf8 $ encodeCompact jwt

-- Verify access token
verifyAccessToken :: Text -> Text -> Either Text JWTClaims
verifyAccessToken secret token = verifyToken secret token "access"

-- Verify refresh token
verifyRefreshToken :: Text -> Text -> Either Text JWTClaims
verifyRefreshToken secret token = verifyToken secret token "refresh"

-- Generic token verification
verifyToken :: Text -> Text -> Text -> Either Text JWTClaims
verifyToken secret token expectedType = do
  let key = fromOctets $ encodeUtf8 secret
  
  result <- runJOSE $ do
    jwt <- decodeCompact $ encodeUtf8 token
    verifyClaims (defaultJWTValidationSettings (== "spock-api")) key jwt
  
  case result of
    Left err -> Left $ "JWT verification failed: " <> pack (show err)
    Right claimsSet -> do
      -- Check token type
      case Map.lookup "type" (unregisteredClaims claimsSet) of
        Just (String t) | t == expectedType -> return ()
        _ -> Left "Invalid token type"
      
      -- Extract user ID
      userId <- case Map.lookup "userId" (unregisteredClaims claimsSet) of
        Just (String uid) -> case fromText uid of
          Nothing -> Left "Invalid user ID in token"
          Just u -> Right u
        _ -> Left "User ID missing from token"
      
      -- Get expiration
      expTime <- case claimExp claimsSet of
        Nothing -> Left "Token missing expiration"
        Just (NumericDate exp) -> Right $ floor exp
      
      Right $ JWTClaims userId "" "" expTime

-- Helper to add custom claims
addClaim :: Text -> Value -> ClaimsSet -> ClaimsSet
addClaim key value claims = claims
  { unregisteredClaims = Map.insert key value (unregisteredClaims claims)
  }
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Services', 'JWT.hs'),
      jwtServiceContent
    );
  }

  private async generateConfig(projectPath: string, options: any): Promise<void> {
    const configContent = `{-# LANGUAGE OverloadedStrings #-}

module Config where

import Data.Text (Text)
import System.Environment (getEnv, lookupEnv)

data Environment = Development | Production
  deriving (Show, Eq)

data Config = Config
  { configEnv :: Environment
  , configPort :: Int
  , configVersion :: Text
  , configSessionTimeout :: Int  -- seconds
  , configDbHost :: Text
  , configDbPort :: Int
  , configDbUser :: Text
  , configDbPassword :: Text
  , configDbName :: Text
  , configDbPoolSize :: Int
  , configJwtSecret :: Text
  , configJwtIssuer :: Text
  , configCorsOrigin :: Text
  } deriving (Show)

loadConfig :: IO Config
loadConfig = do
  env <- maybe Development parseEnv <$> lookupEnv "ENV"
  port <- maybe 3000 read <$> lookupEnv "PORT"
  
  dbHost <- maybe "localhost" pack <$> lookupEnv "DB_HOST"
  dbPort <- maybe 5432 read <$> lookupEnv "DB_PORT"
  dbUser <- maybe "postgres" pack <$> lookupEnv "DB_USER"
  dbPassword <- maybe "postgres" pack <$> lookupEnv "DB_PASSWORD"
  dbName <- maybe "${options.name}" pack <$> lookupEnv "DB_NAME"
  dbPoolSize <- maybe 10 read <$> lookupEnv "DB_POOL_SIZE"
  
  jwtSecret <- maybe "your-256-bit-secret-change-in-production" pack <$> lookupEnv "JWT_SECRET"
  jwtIssuer <- maybe "${options.name}-api" pack <$> lookupEnv "JWT_ISSUER"
  
  corsOrigin <- maybe "*" pack <$> lookupEnv "CORS_ORIGIN"
  
  return Config
    { configEnv = env
    , configPort = port
    , configVersion = "1.0.0"
    , configSessionTimeout = 3600  -- 1 hour
    , configDbHost = dbHost
    , configDbPort = dbPort
    , configDbUser = dbUser
    , configDbPassword = dbPassword
    , configDbName = dbName
    , configDbPoolSize = dbPoolSize
    , configJwtSecret = jwtSecret
    , configJwtIssuer = jwtIssuer
    , configCorsOrigin = corsOrigin
    }
  where
    parseEnv "production" = Production
    parseEnv "prod" = Production
    parseEnv _ = Development
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Config.hs'),
      configContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Utils'), { recursive: true });

    // Validation utilities
    const validationContent = `{-# LANGUAGE OverloadedStrings #-}

module Utils.Validation where

import Data.Char (isAlphaNum, isDigit, isLower, isUpper)
import Data.Text (Text)
import qualified Data.Text as T
import Text.Regex.TDFA ((=~))

-- Email validation
isValidEmail :: Text -> Bool
isValidEmail email = 
  T.unpack email =~ ("^[a-zA-Z0-9+._-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$" :: String)

-- Password validation (min 8 chars, mixed case, number)
isValidPassword :: Text -> Bool
isValidPassword password =
  T.length password >= 8 &&
  any isUpper (T.unpack password) &&
  any isLower (T.unpack password) &&
  any isDigit (T.unpack password)

-- Username validation
isValidUsername :: Text -> Bool
isValidUsername username =
  T.length username >= 3 &&
  T.length username <= 30 &&
  T.all (\\c -> isAlphaNum c || c == '_' || c == '-') username

-- UUID validation
isValidUUID :: Text -> Bool
isValidUUID uuid =
  T.unpack uuid =~ ("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" :: String)

-- Phone number validation (basic)
isValidPhone :: Text -> Bool
isValidPhone phone =
  T.length phone >= 10 &&
  T.all (\\c -> isDigit c || c \`elem\` "+-() ") phone

-- URL validation
isValidURL :: Text -> Bool
isValidURL url =
  T.unpack url =~ ("^https?://[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}" :: String)

-- Sanitize text input
sanitizeText :: Text -> Text
sanitizeText = T.strip . T.filter (\\c -> c /= '<' && c /= '>' && c /= '&' && c /= '\"')

-- Validate required field
requireField :: Text -> Text -> Either Text Text
requireField fieldName value
  | T.null (T.strip value) = Left $ fieldName <> " is required"
  | otherwise = Right value

-- Validate field length
validateLength :: Text -> Int -> Int -> Text -> Either Text Text
validateLength fieldName minLen maxLen value
  | len < minLen = Left $ fieldName <> " must be at least " <> T.pack (show minLen) <> " characters"
  | len > maxLen = Left $ fieldName <> " must be at most " <> T.pack (show maxLen) <> " characters"
  | otherwise = Right value
  where
    len = T.length value
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Utils', 'Validation.hs'),
      validationContent
    );

    // Pagination utilities
    const paginationContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module Utils.Pagination where

import Data.Aeson
import GHC.Generics
import Web.Spock

import App

-- Pagination response
data PaginatedResponse a = PaginatedResponse
  { items :: [a]
  , pagination :: PaginationInfo
  } deriving (Show, Generic)

data PaginationInfo = PaginationInfo
  { currentPage :: Int
  , pageSize :: Int
  , totalItems :: Int
  , totalPages :: Int
  , hasNext :: Bool
  , hasPrev :: Bool
  } deriving (Show, Generic)

instance ToJSON a => ToJSON (PaginatedResponse a)
instance ToJSON PaginationInfo

-- Create paginated response
paginatedResponse :: ToJSON a => [a] -> Int -> Int -> Int -> ApiAction ()
paginatedResponse items page limit total = do
  let totalPages = ceiling (fromIntegral total / fromIntegral limit :: Double)
      hasNext = page < totalPages
      hasPrev = page > 1
      
      paginationInfo = PaginationInfo
        { currentPage = page
        , pageSize = limit
        , totalItems = total
        , totalPages = totalPages
        , hasNext = hasNext
        , hasPrev = hasPrev
        }
      
      response = PaginatedResponse
        { items = items
        , pagination = paginationInfo
        }
  
  json response

-- Parse pagination parameters
data PaginationParams = PaginationParams
  { pageParam :: Int
  , limitParam :: Int
  , offsetParam :: Int
  } deriving (Show)

parsePaginationParams :: ApiAction PaginationParams
parsePaginationParams = do
  page <- max 1 . fromMaybe 1 <$> param "page"
  limit <- min 100 . max 1 . fromMaybe 10 <$> param "limit"
  let offset = (page - 1) * limit
  
  return PaginationParams
    { pageParam = page
    , limitParam = limit
    , offsetParam = offset
    }

-- Validate pagination parameters
validatePagination :: Int -> Int -> (Int, Int)
validatePagination page limit =
  let validPage = max 1 page
      validLimit = min 100 $ max 1 limit
      offset = (validPage - 1) * validLimit
  in (validLimit, offset)
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Utils', 'Pagination.hs'),
      paginationContent
    );
  }

  private async generateTypes(projectPath: string): Promise<void> {
    // Types are already generated in generateModels
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is implemented in Handlers.Health
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocsContent = `# ${this.config.framework} API Documentation

## Overview

This is a RESTful API built with Spock framework in Haskell.

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

## Base URL

\`\`\`
http://localhost:3000/api/v1
\`\`\`

## Endpoints

### Health Check

\`\`\`http
GET /health
GET /api/v1/health
\`\`\`

Returns the health status of the API.

**Response:**
\`\`\`json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "1.0.0",
  "environment": "development",
  "services": {
    "database": {
      "status": "up",
      "type": "postgresql"
    }
  }
}
\`\`\`

### Authentication

#### Register
\`\`\`http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123",
  "name": "John Doe"
}
\`\`\`

**Response:**
\`\`\`json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "user",
    "emailVerified": false,
    "createdAt": "2024-01-01T00:00:00Z"
  },
  "tokens": {
    "access": "eyJ...",
    "refresh": "eyJ..."
  }
}
\`\`\`

#### Login
\`\`\`http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123"
}
\`\`\`

#### Refresh Token
\`\`\`http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "<refresh-token>"
}
\`\`\`

#### Get Current User
\`\`\`http
GET /api/v1/auth/me
Authorization: Bearer <access-token>
\`\`\`

#### Logout
\`\`\`http
POST /api/v1/auth/logout
Authorization: Bearer <access-token>
\`\`\`

### Users

#### List Users
\`\`\`http
GET /api/v1/users?page=1&limit=10&search=john
Authorization: Bearer <access-token>
\`\`\`

**Response:**
\`\`\`json
{
  "items": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "name": "John Doe",
      "role": "user",
      "emailVerified": true,
      "createdAt": "2024-01-01T00:00:00Z"
    }
  ],
  "pagination": {
    "currentPage": 1,
    "pageSize": 10,
    "totalItems": 50,
    "totalPages": 5,
    "hasNext": true,
    "hasPrev": false
  }
}
\`\`\`

#### Get User
\`\`\`http
GET /api/v1/users/:id
Authorization: Bearer <access-token>
\`\`\`

#### Update User
\`\`\`http
PUT /api/v1/users/:id
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "name": "Jane Doe",
  "email": "jane@example.com"
}
\`\`\`

#### Delete User (Admin Only)
\`\`\`http
DELETE /api/v1/users/:id
Authorization: Bearer <access-token>
\`\`\`

### Admin

#### Create User (Admin Only)
\`\`\`http
POST /api/v1/admin/users
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "email": "newuser@example.com",
  "password": "TempPass123",
  "name": "New User",
  "role": "user"
}
\`\`\`

#### Get Statistics (Admin Only)
\`\`\`http
GET /api/v1/admin/stats
Authorization: Bearer <access-token>
\`\`\`

**Response:**
\`\`\`json
{
  "stats": {
    "totalUsers": 150,
    "activeUsers": 89,
    "newUsersToday": 5,
    "totalSessions": 234
  }
}
\`\`\`

## Error Responses

All error responses follow this format:

\`\`\`json
{
  "error": {
    "code": 400,
    "message": "Error description"
  },
  "details": {} // Optional additional information
}
\`\`\`

### Common HTTP Status Codes

- \`200\` - Success
- \`201\` - Created
- \`204\` - No Content
- \`400\` - Bad Request
- \`401\` - Unauthorized
- \`403\` - Forbidden
- \`404\` - Not Found
- \`409\` - Conflict
- \`500\` - Internal Server Error

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Anonymous users**: 60 requests per hour
- **Authenticated users**: 600 requests per hour
- **Rate limit headers**:
  - \`X-RateLimit-Limit\`: Maximum requests allowed
  - \`X-RateLimit-Remaining\`: Requests remaining
  - \`X-RateLimit-Reset\`: Time when limit resets (Unix timestamp)

## Pagination

Paginated endpoints accept these query parameters:

- \`page\`: Page number (default: 1)
- \`limit\`: Items per page (default: 10, max: 100)
- \`search\`: Search term (optional)

Paginated responses include a \`pagination\` object with metadata.

## Data Validation

### Email
- Must be a valid email format
- Maximum 255 characters

### Password
- Minimum 8 characters
- Must contain uppercase, lowercase, and numbers

### Username
- Minimum 3 characters
- Maximum 30 characters
- Alphanumeric characters, underscores, and hyphens only
`;

    await fs.writeFile(
      path.join(projectPath, 'docs', 'API.md'),
      apiDocsContent
    );
  }
}