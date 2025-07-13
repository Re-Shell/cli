/**
 * Scotty Framework Template Generator
 * A Haskell web framework inspired by Ruby's Sinatra
 */

import { HaskellBackendGenerator } from './haskell-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class ScottyGenerator extends HaskellBackendGenerator {
  constructor() {
    super('Scotty');
  }

  protected getFrameworkDependencies(): string[] {
    return [
      'scotty: ^0.12',
      'wai: ^3.2',
      'wai-extra: ^3.1',
      'wai-cors: ^0.2',
      'warp: ^3.3',
      'http-types: ^0.12',
      'aeson: ^2.1',
      'text: ^2.0',
      'bytestring: ^0.11',
      'transformers: ^0.6',
      'mtl: ^2.3',
      'postgresql-simple: ^0.6',
      'resource-pool: ^0.4',
      'configurator: ^0.3',
      'jwt: ^0.11',
      'bcrypt: ^0.0.11',
      'time: ^1.12',
      'uuid: ^1.3',
      'random: ^1.2',
      'containers: ^0.6',
      'unordered-containers: ^0.2',
      'case-insensitive: ^1.2',
      'network: ^3.1',
      'async: ^2.2',
      'stm: ^2.5',
      'exceptions: ^0.10',
      'lifted-base: ^0.2',
      'monad-control: ^1.0',
      'safe: ^0.3',
      'parsec: ^3.1'
    ];
  }

  protected getExtraDeps(): string[] {
    return [];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application
    await this.generateMainApp(projectPath, options);

    // Generate app module
    await this.generateApp(projectPath);

    // Generate routes
    await this.generateRoutes(projectPath);

    // Generate controllers
    await this.generateControllers(projectPath);

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
  }

  private async generateMainApp(projectPath: string, options: any): Promise<void> {
    const mainContent = `{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Concurrent (forkIO)
import Control.Monad (void)
import Data.Text.Lazy (Text)
import Network.Wai.Handler.Warp (run)
import Network.Wai.Middleware.Cors
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Web.Scotty

import App
import Config
import Database
import Middleware.Auth
import Middleware.Error
import Routes

main :: IO ()
main = do
  -- Load configuration
  config <- loadConfig "config/app.conf"
  
  -- Initialize database
  pool <- initDB config
  
  -- Run migrations
  runMigrations pool
  
  -- Create app state
  appState <- createAppState config pool
  
  -- Start background workers
  void $ forkIO $ startWorkers appState
  
  let port = configPort config
      env = configEnv config
  
  putStrLn $ "Starting Scotty server on port " ++ show port ++ " in " ++ show env ++ " mode"
  
  -- Create Scotty app
  scottyApp <- scottyAppT (runAppM appState) $ do
    -- Middleware
    when (env == Development) $ do
      middleware logStdoutDev
    
    middleware simpleCors
    middleware errorHandler
    middleware $ authMiddleware (configJwtSecret config)
    
    -- Routes
    routes
  
  -- Run the app
  run port scottyApp

startWorkers :: AppState -> IO ()
startWorkers appState = do
  -- Start background job processor
  -- Start metrics collector
  -- Start cache warmer
  return ()
`;

    await fs.writeFile(
      path.join(projectPath, 'app', 'Main.hs'),
      mainContent
    );
  }

  private async generateApp(projectPath: string): Promise<void> {
    const appContent = `{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module App where

import Control.Monad.Reader
import Control.Monad.Except
import Data.Pool
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status
import Web.Scotty.Trans

import Config

-- Application State
data AppState = AppState
  { appConfig :: Config
  , appConnPool :: Pool Connection
  , appLogger :: Logger
  }

-- Application Monad
newtype AppM a = AppM
  { unAppM :: ReaderT AppState (ExceptT AppError IO) a
  } deriving ( Functor
             , Applicative
             , Monad
             , MonadIO
             , MonadReader AppState
             , MonadError AppError
             )

-- Application Error
data AppError = AppError
  { errorStatus :: Status
  , errorMessage :: Text
  , errorDetails :: Maybe Value
  } deriving (Show)

-- Run AppM in IO
runAppM :: AppState -> AppM a -> IO (Either AppError a)
runAppM state app = runExceptT $ runReaderT (unAppM app) state

-- Create app state
createAppState :: Config -> Pool Connection -> IO AppState
createAppState config pool = do
  logger <- createLogger (configLogLevel config)
  return AppState
    { appConfig = config
    , appConnPool = pool
    , appLogger = logger
    }

-- Get database connection from pool
withDB :: (Connection -> IO a) -> AppM a
withDB action = do
  pool <- asks appConnPool
  liftIO $ withResource pool action

-- Logging
data LogLevel = Debug | Info | Warning | Error
  deriving (Show, Eq, Ord)

data Logger = Logger
  { logLevel :: LogLevel
  , logAction :: LogLevel -> Text -> IO ()
  }

createLogger :: LogLevel -> IO Logger
createLogger level = return Logger
  { logLevel = level
  , logAction = \\lvl msg -> 
      when (lvl >= level) $ 
        putStrLn $ "[" ++ show lvl ++ "] " ++ show msg
  }

logDebug, logInfo, logWarning, logError :: Text -> AppM ()
logDebug msg = do
  logger <- asks appLogger
  liftIO $ logAction logger Debug msg

logInfo msg = do
  logger <- asks appLogger
  liftIO $ logAction logger Info msg

logWarning msg = do
  logger <- asks appLogger
  liftIO $ logAction logger Warning msg

logError msg = do
  logger <- asks appLogger
  liftIO $ logAction logger Error msg

-- Error helpers
notFoundError :: Text -> AppError
notFoundError msg = AppError status404 msg Nothing

badRequestError :: Text -> AppError
badRequestError msg = AppError status400 msg Nothing

unauthorizedError :: Text -> AppError
unauthorizedError msg = AppError status401 msg Nothing

forbiddenError :: Text -> AppError
forbiddenError msg = AppError status403 msg Nothing

internalError :: Text -> AppError
internalError msg = AppError status500 msg Nothing
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'App.hs'),
      appContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    const routesContent = `{-# LANGUAGE OverloadedStrings #-}

module Routes where

import Web.Scotty.Trans

import App
import Controllers.Auth
import Controllers.User
import Controllers.Health
import Middleware.Auth (requireAuth)

routes :: ScottyT Text AppM ()
routes = do
  -- Health check
  get "/health" healthCheck
  get "/api/v1/health" healthCheck
  
  -- Authentication routes
  post "/api/v1/auth/register" register
  post "/api/v1/auth/login" login
  post "/api/v1/auth/refresh" refreshToken
  
  -- Protected routes
  get "/api/v1/auth/me" $ requireAuth getMe
  post "/api/v1/auth/logout" $ requireAuth logout
  
  -- User routes
  get "/api/v1/users" $ requireAuth listUsers
  get "/api/v1/users/:id" $ requireAuth getUser
  put "/api/v1/users/:id" $ requireAuth updateUser
  delete "/api/v1/users/:id" $ requireAuth deleteUser
  
  -- Admin routes
  post "/api/v1/admin/users" $ requireAuth $ requireAdmin createUser
  
  -- Static files
  get "/" $ do
    setHeader "Content-Type" "text/html"
    html "<h1>Scotty API Server</h1><p>Visit <a href='/api/v1/health'>/api/v1/health</a> for health check.</p>"
  
  -- 404 handler
  notFound $ do
    status status404
    json $ object
      [ "error" .= ("Not Found" :: Text)
      , "message" .= ("The requested resource was not found" :: Text)
      ]
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Routes.hs'),
      routesContent
    );
  }

  private async generateControllers(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Controllers'), { recursive: true });

    // Health controller
    const healthContent = `{-# LANGUAGE OverloadedStrings #-}

module Controllers.Health where

import Data.Time.Clock (getCurrentTime)
import Web.Scotty.Trans

import App
import Database

healthCheck :: ActionT Text AppM ()
healthCheck = do
  currentTime <- liftIO getCurrentTime
  
  -- Check database connection
  dbStatus <- lift $ checkDatabaseConnection
  
  let health = object
        [ "status" .= ("healthy" :: Text)
        , "timestamp" .= currentTime
        , "version" .= ("1.0.0" :: Text)
        , "services" .= object
            [ "database" .= if dbStatus then "up" else "down" :: Text
            ]
        ]
  
  json health

checkDatabaseConnection :: AppM Bool
checkDatabaseConnection = do
  result <- try $ withDB $ \\conn -> do
    [Only count] <- query_ conn "SELECT 1" :: IO [Only Int]
    return $ count == 1
  
  case result of
    Left (e :: SomeException) -> do
      logError $ "Database health check failed: " <> pack (show e)
      return False
    Right success -> return success
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Controllers', 'Health.hs'),
      healthContent
    );

    // Auth controller
    const authContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Controllers.Auth where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt
import Data.Time.Clock
import Data.UUID.V4 (nextRandom)
import Web.Scotty.Trans

import App
import Models.User
import Services.JWT
import Services.User

-- Register new user
register :: ActionT Text AppM ()
register = do
  RegisterRequest{..} <- jsonData
  
  -- Validate input
  when (T.length registerEmail < 3) $
    raise $ badRequestError "Email too short"
  
  when (T.length registerPassword < 8) $
    raise $ badRequestError "Password must be at least 8 characters"
  
  -- Check if user exists
  existingUser <- lift $ getUserByEmail registerEmail
  case existingUser of
    Just _ -> raise $ badRequestError "Email already registered"
    Nothing -> return ()
  
  -- Hash password
  hashedPassword <- liftIO $ hashPasswordUsingPolicy slowerBcryptHashingPolicy (encodeUtf8 registerPassword)
  case hashedPassword of
    Nothing -> raise $ internalError "Failed to hash password"
    Just hash -> do
      -- Create user
      userId <- liftIO nextRandom
      now <- liftIO getCurrentTime
      
      let newUser = User
            { userId = userId
            , userEmail = registerEmail
            , userPasswordHash = decodeUtf8 hash
            , userName = registerName
            , userCreatedAt = now
            , userUpdatedAt = now
            }
      
      -- Save user
      lift $ createUser newUser
      
      -- Generate tokens
      config <- lift $ asks appConfig
      accessToken <- liftIO $ generateAccessToken config userId
      refreshToken <- liftIO $ generateRefreshToken config userId
      
      -- Return response
      json $ object
        [ "user" .= newUser
        , "accessToken" .= accessToken
        , "refreshToken" .= refreshToken
        ]

-- Login user
login :: ActionT Text AppM ()
login = do
  LoginRequest{..} <- jsonData
  
  -- Find user
  maybeUser <- lift $ getUserByEmail loginEmail
  user <- case maybeUser of
    Nothing -> raise $ unauthorizedError "Invalid credentials"
    Just u -> return u
  
  -- Verify password
  let valid = validatePassword (encodeUtf8 $ userPasswordHash user) (encodeUtf8 loginPassword)
  unless valid $
    raise $ unauthorizedError "Invalid credentials"
  
  -- Generate tokens
  config <- lift $ asks appConfig
  accessToken <- liftIO $ generateAccessToken config (userId user)
  refreshToken <- liftIO $ generateRefreshToken config (userId user)
  
  -- Return response
  json $ object
    [ "user" .= user
    , "accessToken" .= accessToken
    , "refreshToken" .= refreshToken
    ]

-- Get current user
getMe :: ActionT Text AppM ()
getMe = do
  userId <- getUserId
  
  maybeUser <- lift $ getUserById userId
  user <- case maybeUser of
    Nothing -> raise $ notFoundError "User not found"
    Just u -> return u
  
  json $ object ["user" .= user]

-- Logout user
logout :: ActionT Text AppM ()
logout = do
  -- In a real app, you might want to invalidate the refresh token
  json $ object ["message" .= ("Logged out successfully" :: Text)]

-- Refresh access token
refreshToken :: ActionT Text AppM ()
refreshToken = do
  RefreshRequest{..} <- jsonData
  
  config <- lift $ asks appConfig
  claims <- case verifyRefreshToken config refreshRequestToken of
    Left err -> raise $ unauthorizedError $ "Invalid refresh token: " <> err
    Right c -> return c
  
  -- Generate new access token
  newAccessToken <- liftIO $ generateAccessToken config (jwtUserId claims)
  
  json $ object
    [ "accessToken" .= newAccessToken
    ]

-- Request types
data RegisterRequest = RegisterRequest
  { registerEmail :: Text
  , registerPassword :: Text
  , registerName :: Text
  } deriving (Show)

instance FromJSON RegisterRequest where
  parseJSON = withObject "RegisterRequest" $ \\v -> RegisterRequest
    <$> v .: "email"
    <*> v .: "password"
    <*> v .: "name"

data LoginRequest = LoginRequest
  { loginEmail :: Text
  , loginPassword :: Text
  } deriving (Show)

instance FromJSON LoginRequest where
  parseJSON = withObject "LoginRequest" $ \\v -> LoginRequest
    <$> v .: "email"
    <*> v .: "password"

data RefreshRequest = RefreshRequest
  { refreshRequestToken :: Text
  } deriving (Show)

instance FromJSON RefreshRequest where
  parseJSON = withObject "RefreshRequest" $ \\v -> RefreshRequest
    <$> v .: "refreshToken"
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Controllers', 'Auth.hs'),
      authContent
    );

    // User controller
    const userContent = `{-# LANGUAGE OverloadedStrings #-}

module Controllers.User where

import Control.Monad (when)
import Data.UUID (fromText)
import Web.Scotty.Trans

import App
import Models.User
import Services.User

-- List all users
listUsers :: ActionT Text AppM ()
listUsers = do
  page <- param "page" \`rescue\` const (return 1)
  limit <- param "limit" \`rescue\` const (return 10)
  
  let offset = (page - 1) * limit
  
  users <- lift $ getUsers limit offset
  total <- lift $ getUserCount
  
  json $ object
    [ "users" .= users
    , "pagination" .= object
        [ "page" .= page
        , "limit" .= limit
        , "total" .= total
        , "pages" .= ceiling (fromIntegral total / fromIntegral limit :: Double)
        ]
    ]

-- Get user by ID
getUser :: ActionT Text AppM ()
getUser = do
  userIdParam <- param "id"
  
  userId <- case fromText userIdParam of
    Nothing -> raise $ badRequestError "Invalid user ID format"
    Just uid -> return uid
  
  maybeUser <- lift $ getUserById userId
  user <- case maybeUser of
    Nothing -> raise $ notFoundError "User not found"
    Just u -> return u
  
  json $ object ["user" .= user]

-- Update user
updateUser :: ActionT Text AppM ()
updateUser = do
  currentUserId <- getUserId
  userIdParam <- param "id"
  
  targetUserId <- case fromText userIdParam of
    Nothing -> raise $ badRequestError "Invalid user ID format"
    Just uid -> return uid
  
  -- Check permission (users can only update themselves unless admin)
  when (currentUserId /= targetUserId) $ do
    isAdmin <- checkIsAdmin
    unless isAdmin $
      raise $ forbiddenError "You can only update your own profile"
  
  -- Get update data
  UpdateUserRequest{..} <- jsonData
  
  -- Update user
  updated <- lift $ updateUserDetails targetUserId updateName updateEmail
  
  case updated of
    Nothing -> raise $ notFoundError "User not found"
    Just user -> json $ object ["user" .= user]

-- Delete user
deleteUser :: ActionT Text AppM ()
deleteUser = do
  currentUserId <- getUserId
  userIdParam <- param "id"
  
  targetUserId <- case fromText userIdParam of
    Nothing -> raise $ badRequestError "Invalid user ID format"
    Just uid -> return uid
  
  -- Only admins can delete users
  requireAdmin $ do
    -- Don't allow self-deletion
    when (currentUserId == targetUserId) $
      raise $ badRequestError "Cannot delete your own account"
    
    deleted <- lift $ deleteUserById targetUserId
    
    if deleted
      then json $ object ["message" .= ("User deleted successfully" :: Text)]
      else raise $ notFoundError "User not found"

-- Create user (admin only)
createUser :: ActionT Text AppM ()
createUser = do
  CreateUserRequest{..} <- jsonData
  
  -- Implementation similar to register but allows admin to set roles
  json $ object ["message" .= ("User created" :: Text)]

-- Helper functions
getUserId :: ActionT Text AppM UUID
getUserId = do
  maybeUserId <- header "X-User-ID"
  case maybeUserId of
    Nothing -> raise $ internalError "User ID not found in request"
    Just uid -> case fromText (toStrict uid) of
      Nothing -> raise $ internalError "Invalid user ID format"
      Just userId -> return userId

checkIsAdmin :: ActionT Text AppM Bool
checkIsAdmin = do
  -- In a real app, check user roles from database
  return False

requireAdmin :: ActionT Text AppM () -> ActionT Text AppM ()
requireAdmin action = do
  isAdmin <- checkIsAdmin
  if isAdmin
    then action
    else raise $ forbiddenError "Admin access required"

-- Request types
data UpdateUserRequest = UpdateUserRequest
  { updateName :: Maybe Text
  , updateEmail :: Maybe Text
  } deriving (Show)

instance FromJSON UpdateUserRequest where
  parseJSON = withObject "UpdateUserRequest" $ \\v -> UpdateUserRequest
    <$> v .:? "name"
    <*> v .:? "email"

data CreateUserRequest = CreateUserRequest
  { createEmail :: Text
  , createPassword :: Text
  , createName :: Text
  , createRole :: Maybe Text
  } deriving (Show)

instance FromJSON CreateUserRequest where
  parseJSON = withObject "CreateUserRequest" $ \\v -> CreateUserRequest
    <$> v .: "email"
    <*> v .: "password"
    <*> v .: "name"
    <*> v .:? "role"
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Controllers', 'User.hs'),
      userContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Middleware'), { recursive: true });

    // Auth middleware
    const authMiddlewareContent = `{-# LANGUAGE OverloadedStrings #-}

module Middleware.Auth where

import Data.Text.Lazy (toStrict)
import Network.HTTP.Types.Status
import Network.Wai
import Web.Scotty.Trans

import App
import Services.JWT

-- JWT authentication middleware
authMiddleware :: Text -> Middleware
authMiddleware jwtSecret app req respond = do
  let headers = requestHeaders req
      authHeader = lookup "Authorization" headers
  
  case authHeader of
    Nothing -> app req respond
    Just auth -> do
      let token = extractToken auth
      case token >>= verifyAccessToken jwtSecret of
        Left _ -> app req respond
        Right claims -> do
          -- Add user ID to headers for downstream use
          let newHeaders = ("X-User-ID", encodeUtf8 $ toStrict $ jwtUserId claims) : headers
              newReq = req { requestHeaders = newHeaders }
          app newReq respond

-- Extract token from Authorization header
extractToken :: ByteString -> Maybe Text
extractToken auth = 
  case B.stripPrefix "Bearer " auth of
    Nothing -> Nothing
    Just token -> Just $ decodeUtf8 token

-- Require authentication for a route
requireAuth :: ActionT Text AppM () -> ActionT Text AppM ()
requireAuth action = do
  maybeUserId <- header "X-User-ID"
  case maybeUserId of
    Nothing -> do
      status status401
      json $ object 
        [ "error" .= ("Unauthorized" :: Text)
        , "message" .= ("Authentication required" :: Text)
        ]
    Just _ -> action
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Middleware', 'Auth.hs'),
      authMiddlewareContent
    );

    // Error middleware
    const errorMiddlewareContent = `{-# LANGUAGE OverloadedStrings #-}

module Middleware.Error where

import Control.Exception
import Network.HTTP.Types.Status
import Network.Wai
import Web.Scotty.Trans

import App

-- Error handling middleware
errorHandler :: Middleware
errorHandler app req respond = do
  app req respond \`catch\` handleException
  where
    handleException :: SomeException -> IO ResponseReceived
    handleException e = respond $ responseLBS
      status500
      [("Content-Type", "application/json")]
      $ encode $ object
          [ "error" .= ("Internal Server Error" :: Text)
          , "message" .= ("An unexpected error occurred" :: Text)
          , "details" .= show e
          ]

-- Scotty error handler
scottyErrorHandler :: Text -> ActionT Text AppM ()
scottyErrorHandler err = do
  status status500
  json $ object
    [ "error" .= ("Internal Server Error" :: Text)
    , "message" .= err
    ]
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Middleware', 'Error.hs'),
      errorMiddlewareContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Models'), { recursive: true });

    // User model
    const userModelContent = `{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Models.User where

import Data.Aeson
import Data.Time.Clock
import Data.UUID
import GHC.Generics

data User = User
  { userId :: UUID
  , userEmail :: Text
  , userPasswordHash :: Text
  , userName :: Text
  , userCreatedAt :: UTCTime
  , userUpdatedAt :: UTCTime
  } deriving (Show, Eq, Generic)

-- Don't include password hash in JSON
instance ToJSON User where
  toJSON user = object
    [ "id" .= userId user
    , "email" .= userEmail user
    , "name" .= userName user
    , "createdAt" .= userCreatedAt user
    , "updatedAt" .= userUpdatedAt user
    ]

instance FromJSON User where
  parseJSON = withObject "User" $ \\v -> User
    <$> v .: "id"
    <*> v .: "email"
    <*> v .: "passwordHash"
    <*> v .: "name"
    <*> v .: "createdAt"
    <*> v .: "updatedAt"

-- User role
data UserRole = UserRole
  { roleId :: UUID
  , roleName :: Text
  , rolePermissions :: [Text]
  } deriving (Show, Eq, Generic)

instance ToJSON UserRole
instance FromJSON UserRole

-- User session
data UserSession = UserSession
  { sessionId :: UUID
  , sessionUserId :: UUID
  , sessionToken :: Text
  , sessionExpiresAt :: UTCTime
  , sessionCreatedAt :: UTCTime
  } deriving (Show, Eq, Generic)

instance ToJSON UserSession
instance FromJSON UserSession
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Models', 'User.hs'),
      userModelContent
    );
  }

  private async generateDatabase(projectPath: string): Promise<void> {
    const databaseContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Database where

import Control.Exception (bracket)
import Data.Pool
import Data.Text (pack)
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.SqlQQ

import Config

-- Initialize database connection pool
initDB :: Config -> IO (Pool Connection)
initDB config = createPool
  (connect $ postgresConnInfo config)
  close
  1 -- stripes
  60 -- keep alive (seconds)
  10 -- max connections

-- Create PostgreSQL connection info
postgresConnInfo :: Config -> ConnectInfo
postgresConnInfo config = ConnectInfo
  { connectHost = configDbHost config
  , connectPort = fromIntegral $ configDbPort config
  , connectUser = configDbUser config
  , connectPassword = configDbPassword config
  , connectDatabase = configDbName config
  }

-- Run database migrations
runMigrations :: Pool Connection -> IO ()
runMigrations pool = withResource pool $ \\conn -> do
  putStrLn "Running database migrations..."
  
  -- Create migrations table
  execute_ conn [sql|
    CREATE TABLE IF NOT EXISTS migrations (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL UNIQUE,
      applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  |]
  
  -- Create users table
  execute_ conn [sql|
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  |]
  
  -- Create sessions table
  execute_ conn [sql|
    CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token VARCHAR(500) NOT NULL UNIQUE,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  |]
  
  -- Create roles table
  execute_ conn [sql|
    CREATE TABLE IF NOT EXISTS roles (
      id UUID PRIMARY KEY,
      name VARCHAR(100) NOT NULL UNIQUE,
      permissions TEXT[] NOT NULL DEFAULT '{}',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  |]
  
  -- Create user_roles table
  execute_ conn [sql|
    CREATE TABLE IF NOT EXISTS user_roles (
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
      assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, role_id)
    )
  |]
  
  -- Create indexes
  execute_ conn "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)"
  execute_ conn "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)"
  execute_ conn "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)"
  
  putStrLn "Migrations completed successfully"

-- Transaction helper
withTransaction :: Pool Connection -> (Connection -> IO a) -> IO a
withTransaction pool action = withResource pool $ \\conn ->
  withTransaction conn (action conn)
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Database.hs'),
      databaseContent
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Services'), { recursive: true });

    // JWT service
    const jwtServiceContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Services.JWT where

import Control.Monad (when)
import Data.Aeson
import Data.Text (Text)
import Data.Time.Clock
import Data.Time.Clock.POSIX
import Data.UUID
import Web.JWT

import Config

data JWTClaims = JWTClaims
  { jwtUserId :: UUID
  , jwtEmail :: Text
  , jwtExp :: UTCTime
  } deriving (Show, Eq)

-- Generate access token (short-lived)
generateAccessToken :: Config -> UUID -> IO Text
generateAccessToken config userId = do
  now <- getCurrentTime
  let expTime = addUTCTime (15 * 60) now -- 15 minutes
      claims = JWTClaims userId "" expTime
  return $ createToken config claims "access"

-- Generate refresh token (long-lived)
generateRefreshToken :: Config -> UUID -> IO Text
generateRefreshToken config userId = do
  now <- getCurrentTime
  let expTime = addUTCTime (7 * 24 * 60 * 60) now -- 7 days
      claims = JWTClaims userId "" expTime
  return $ createToken config claims "refresh"

-- Create JWT token
createToken :: Config -> JWTClaims -> Text -> Text
createToken config JWTClaims{..} tokenType =
  let cs = mempty
        { iss = stringOrURI $ configJwtIssuer config
        , sub = stringOrURI $ toText jwtUserId
        , aud = Left <$> stringOrURI "api"
        , Web.JWT.exp = numericDate $ utcTimeToPOSIXSeconds jwtExp
        , iat = numericDate $ utcTimeToPOSIXSeconds $ addUTCTime (-60) jwtExp
        , unregisteredClaims = ClaimsMap $ fromList
            [ ("type", String tokenType)
            , ("userId", String $ toText jwtUserId)
            ]
        }
      key = hmacSecret $ configJwtSecret config
  in encodeSigned key mempty cs

-- Verify access token
verifyAccessToken :: Text -> Text -> Either Text JWTClaims
verifyAccessToken secret token = verifyToken secret token "access"

-- Verify refresh token
verifyRefreshToken :: Text -> Text -> Either Text JWTClaims
verifyRefreshToken secret token = verifyToken secret token "refresh"

-- Generic token verification
verifyToken :: Text -> Text -> Text -> Either Text JWTClaims
verifyToken secret token expectedType = do
  let key = hmacSecret secret
  
  unverified <- case decode token of
    Nothing -> Left "Invalid token format"
    Just t -> Right t
  
  verified <- case verify key unverified of
    Nothing -> Left "Token signature verification failed"
    Just t -> Right t
  
  let cs = claims verified
      ClaimsMap customClaims = unregisteredClaims cs
  
  -- Check token type
  case lookup "type" customClaims of
    Just (String t) | t == expectedType -> return ()
    _ -> Left "Invalid token type"
  
  -- Check expiration
  now <- getCurrentTime
  case Web.JWT.exp cs of
    Nothing -> Left "Token missing expiration"
    Just expTime -> do
      let expUTC = posixSecondsToUTCTime $ secondsToNominalDiffTime $ fromInteger $ fromNumericDate expTime
      when (now > expUTC) $ Left "Token expired"
  
  -- Extract user ID
  userId <- case lookup "userId" customClaims of
    Just (String uid) -> case fromText uid of
      Nothing -> Left "Invalid user ID in token"
      Just u -> Right u
    _ -> Left "User ID missing from token"
  
  -- Get expiration time
  expTime <- case Web.JWT.exp cs of
    Nothing -> Left "Expiration time missing"
    Just e -> Right $ posixSecondsToUTCTime $ secondsToNominalDiffTime $ fromInteger $ fromNumericDate e
  
  Right $ JWTClaims userId "" expTime
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Services', 'JWT.hs'),
      jwtServiceContent
    );

    // User service
    const userServiceContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Services.User where

import Control.Monad (forM)
import Data.UUID
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.SqlQQ

import App
import Models.User

-- Get user by ID
getUserById :: UUID -> AppM (Maybe User)
getUserById uid = withDB $ \\conn -> do
  rows <- query conn [sql|
    SELECT id, email, password_hash, name, created_at, updated_at
    FROM users
    WHERE id = ?
  |] (Only uid)
  
  case rows of
    [] -> return Nothing
    [(id, email, hash, name, created, updated)] ->
      return $ Just User
        { userId = id
        , userEmail = email
        , userPasswordHash = hash
        , userName = name
        , userCreatedAt = created
        , userUpdatedAt = updated
        }
    _ -> error "Multiple users with same ID"

-- Get user by email
getUserByEmail :: Text -> AppM (Maybe User)
getUserByEmail email = withDB $ \\conn -> do
  rows <- query conn [sql|
    SELECT id, email, password_hash, name, created_at, updated_at
    FROM users
    WHERE email = ?
  |] (Only email)
  
  case rows of
    [] -> return Nothing
    [(id, em, hash, name, created, updated)] ->
      return $ Just User
        { userId = id
        , userEmail = em
        , userPasswordHash = hash
        , userName = name
        , userCreatedAt = created
        , userUpdatedAt = updated
        }
    _ -> error "Multiple users with same email"

-- Create new user
createUser :: User -> AppM ()
createUser user = withDB $ \\conn -> do
  execute conn [sql|
    INSERT INTO users (id, email, password_hash, name, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  |] ( userId user
     , userEmail user
     , userPasswordHash user
     , userName user
     , userCreatedAt user
     , userUpdatedAt user
     )
  return ()

-- Get users with pagination
getUsers :: Int -> Int -> AppM [User]
getUsers limit offset = withDB $ \\conn -> do
  rows <- query conn [sql|
    SELECT id, email, password_hash, name, created_at, updated_at
    FROM users
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  |] (limit, offset)
  
  forM rows $ \\(id, email, hash, name, created, updated) ->
    return User
      { userId = id
      , userEmail = email
      , userPasswordHash = hash
      , userName = name
      , userCreatedAt = created
      , userUpdatedAt = updated
      }

-- Get total user count
getUserCount :: AppM Int
getUserCount = withDB $ \\conn -> do
  [Only count] <- query_ conn "SELECT COUNT(*) FROM users"
  return count

-- Update user details
updateUserDetails :: UUID -> Maybe Text -> Maybe Text -> AppM (Maybe User)
updateUserDetails uid maybeName maybeEmail = withDB $ \\conn -> do
  -- Build dynamic update query
  let updates = catMaybes
        [ ("name = ?" ,) . Only <$> maybeName
        , ("email = ?" ,) . Only <$> maybeEmail
        ]
  
  if null updates
    then getUserById uid
    else do
      -- Execute update
      execute conn (Query $ "UPDATE users SET " <> intercalate ", " (map fst updates) <> ", updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        (map snd updates ++ [Only uid])
      
      getUserById uid

-- Delete user
deleteUserById :: UUID -> AppM Bool
deleteUserById uid = withDB $ \\conn -> do
  count <- execute conn "DELETE FROM users WHERE id = ?" (Only uid)
  return $ count > 0
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Services', 'User.hs'),
      userServiceContent
    );
  }

  private async generateConfig(projectPath: string, options: any): Promise<void> {
    const configContent = `{-# LANGUAGE OverloadedStrings #-}

module Config where

import Data.Configurator
import Data.Text (Text)
import qualified Data.Text as T

data Environment = Development | Staging | Production
  deriving (Show, Eq)

data Config = Config
  { configEnv :: Environment
  , configPort :: Int
  , configHost :: Text
  , configDbHost :: String
  , configDbPort :: Int
  , configDbUser :: String
  , configDbPassword :: String
  , configDbName :: String
  , configJwtSecret :: Text
  , configJwtIssuer :: Text
  , configLogLevel :: LogLevel
  , configCorsOrigin :: Text
  } deriving (Show)

loadConfig :: FilePath -> IO Config
loadConfig path = do
  cfg <- load [Required path]
  
  env <- lookupDefault "development" cfg "environment" :: IO String
  let environment = case env of
        "production" -> Production
        "staging" -> Staging
        _ -> Development
  
  Config
    <$> pure environment
    <*> lookupDefault 3000 cfg "server.port"
    <*> lookupDefault "0.0.0.0" cfg "server.host"
    <*> lookupDefault "localhost" cfg "database.host"
    <*> lookupDefault 5432 cfg "database.port"
    <*> lookupDefault "postgres" cfg "database.user"
    <*> lookupDefault "postgres" cfg "database.password"
    <*> lookupDefault "${options.name}" cfg "database.name"
    <*> lookupDefault "your-256-bit-secret" cfg "jwt.secret"
    <*> lookupDefault "${options.name}-api" cfg "jwt.issuer"
    <*> (parseLogLevel <$> lookupDefault "info" cfg "log.level")
    <*> lookupDefault "*" cfg "cors.origin"

parseLogLevel :: String -> LogLevel
parseLogLevel "debug" = Debug
parseLogLevel "info" = Info
parseLogLevel "warning" = Warning
parseLogLevel "error" = Error
parseLogLevel _ = Info
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Config.hs'),
      configContent
    );

    // Create config file
    await fs.mkdir(path.join(projectPath, 'config'), { recursive: true });
    const appConfContent = `# Scotty Application Configuration

environment = "development"

[server]
port = 3000
host = "0.0.0.0"

[database]
host = "localhost"
port = 5432
user = "postgres"
password = "postgres"
name = "${options.name}"

[jwt]
secret = "your-256-bit-secret-change-in-production"
issuer = "${options.name}-api"

[log]
level = "info"

[cors]
origin = "*"
`;

    await fs.writeFile(
      path.join(projectPath, 'config', 'app.conf'),
      appConfContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Utils'), { recursive: true });

    // Validation utilities
    const validationContent = `{-# LANGUAGE OverloadedStrings #-}

module Utils.Validation where

import Data.Text (Text)
import qualified Data.Text as T
import Text.Regex.TDFA

-- Email validation
isValidEmail :: Text -> Bool
isValidEmail email = 
  T.unpack email =~ ("^[a-zA-Z0-9+._-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$" :: String)

-- Password validation
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
  T.all isAlphaNum username

-- UUID validation
isValidUUID :: Text -> Bool
isValidUUID uuid =
  T.unpack uuid =~ ("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" :: String)

-- Sanitize input
sanitizeInput :: Text -> Text
sanitizeInput = T.strip . T.filter (\\c -> c /= '<' && c /= '>' && c /= '&')
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Utils', 'Validation.hs'),
      validationContent
    );

    // Response utilities
    const responseContent = `{-# LANGUAGE OverloadedStrings #-}

module Utils.Response where

import Data.Aeson
import Network.HTTP.Types.Status
import Web.Scotty.Trans

import App

-- Success response helpers
success :: ToJSON a => a -> ActionT Text AppM ()
success = json

successWithMessage :: Text -> ActionT Text AppM ()
successWithMessage msg = json $ object ["message" .= msg]

created :: ToJSON a => a -> ActionT Text AppM ()
created resource = do
  status status201
  json resource

noContent :: ActionT Text AppM ()
noContent = status status204

-- Error response helpers
errorResponse :: Status -> Text -> Maybe Value -> ActionT Text AppM ()
errorResponse s msg details = do
  status s
  json $ object $ 
    [ "error" .= True
    , "message" .= msg
    ] ++ maybe [] (\\d -> ["details" .= d]) details

badRequest :: Text -> ActionT Text AppM ()
badRequest = errorResponse status400

unauthorized :: Text -> ActionT Text AppM ()
unauthorized = errorResponse status401

forbidden :: Text -> ActionT Text AppM ()
forbidden = errorResponse status403

notFound :: Text -> ActionT Text AppM ()
notFound = errorResponse status404

conflict :: Text -> ActionT Text AppM ()
conflict = errorResponse status409

internalServerError :: Text -> ActionT Text AppM ()
internalServerError = errorResponse status500

-- Pagination helpers
data PaginatedResponse a = PaginatedResponse
  { items :: [a]
  , page :: Int
  , pageSize :: Int
  , totalItems :: Int
  , totalPages :: Int
  } deriving (Show)

instance ToJSON a => ToJSON (PaginatedResponse a) where
  toJSON pr = object
    [ "items" .= items pr
    , "pagination" .= object
        [ "page" .= page pr
        , "pageSize" .= pageSize pr
        , "totalItems" .= totalItems pr
        , "totalPages" .= totalPages pr
        , "hasNext" .= (page pr < totalPages pr)
        , "hasPrev" .= (page pr > 1)
        ]
    ]

paginatedResponse :: ToJSON a => [a] -> Int -> Int -> Int -> ActionT Text AppM ()
paginatedResponse items currentPage size total = 
  json $ PaginatedResponse items currentPage size total $
    ceiling (fromIntegral total / fromIntegral size :: Double)
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Utils', 'Response.hs'),
      responseContent
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is implemented in Controllers.Health
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocsContent = `# ${this.config.framework} API Documentation

## Overview

This is a RESTful API built with Scotty framework in Haskell.

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
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
  "services": {
    "database": "up"
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
GET /api/v1/users?page=1&limit=10
Authorization: Bearer <access-token>
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

## Error Responses

All error responses follow this format:

\`\`\`json
{
  "error": true,
  "message": "Error description",
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

## Pagination

Paginated endpoints return data in this format:

\`\`\`json
{
  "items": [...],
  "pagination": {
    "page": 1,
    "pageSize": 10,
    "totalItems": 100,
    "totalPages": 10,
    "hasNext": true,
    "hasPrev": false
  }
}
\`\`\`
`;

    await fs.writeFile(
      path.join(projectPath, 'docs', 'API.md'),
      apiDocsContent
    );
  }
}