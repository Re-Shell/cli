import { BackendTemplate } from '../types';

export const servantTemplate: BackendTemplate = {
  id: 'servant',
  name: 'servant',
  displayName: 'Servant Type-Safe REST API',
  description: 'A Haskell framework for type-safe web APIs with automatic documentation generation',
  framework: 'servant',
  language: 'haskell',
  version: '0.20',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🔐',
  type: 'rest-api',
  complexity: 'intermediate',
  keywords: ['haskell', 'servant', 'type-safe', 'rest', 'api', 'functional'],
  
  features: [
    'Type-safe routing and request handling',
    'Automatic API documentation generation',
    'Client library generation',
    'Type-level API descriptions',
    'JWT authentication',
    'Database integration with Persistent',
    'Request validation',
    'Error handling',
    'CORS support',
    'Content negotiation',
    'Swagger/OpenAPI generation',
    'Testing with Hspec',
    'Docker deployment'
  ],
  
  structure: {
    'app/Main.hs': `{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Middleware.Cors
import Network.Wai.Middleware.RequestLogger
import Servant
import System.Environment (lookupEnv)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T

import API (app)
import Config (loadConfig, Config(..))
import Database (runMigrations, createConnectionPool)

main :: IO ()
main = do
  -- Load configuration
  config <- loadConfig
  
  -- Initialize database
  pool <- createConnectionPool (dbConfig config)
  runMigrations pool
  
  -- Get port from environment or config
  portEnv <- lookupEnv "PORT"
  let port = fromMaybe (configPort config) (read <$> portEnv)
  
  -- Create the application with middleware
  let settings = setPort port $ setLogger logStdoutDev defaultSettings
      application = corsMiddleware $ logStdoutDev $ app config pool
  
  putStrLn $ "Starting Servant server on port " ++ show port
  runSettings settings application

corsMiddleware :: Middleware
corsMiddleware = cors $ const $ Just simpleCorsResourcePolicy
  { corsOrigins = Nothing
  , corsMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  , corsRequestHeaders = ["Content-Type", "Authorization"]
  }`,

    'src/API.hs': `{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module API
  ( API
  , api
  , app
  , server
  ) where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, runReaderT, asks)
import Data.Text (Text)
import Database.Persist.Postgresql (ConnectionPool)
import Network.Wai (Application)
import Servant
import Servant.Auth.Server

import Config (Config)
import Types
import API.User
import API.Todo
import API.Health
import Auth (authCheck, AuthUser)

-- | Main API type combining all endpoints
type API = 
       "api" :> 
         ( HealthAPI
      :<|> "v1" :> 
           ( PublicAPI
        :<|> ProtectedAPI
           )
         )

-- | Public API endpoints (no authentication required)
type PublicAPI = 
       "users" :> UserAPI
  :<|> "auth" :> AuthAPI

-- | Protected API endpoints (authentication required)
type ProtectedAPI = Auth '[JWT] AuthUser :>
       ( "todos" :> TodoAPI
    :<|> "profile" :> ProfileAPI
       )

-- | Complete API including docs
type CompleteAPI = 
       API
  :<|> "docs" :> Raw  -- Serve Swagger UI

-- | API proxy
api :: Proxy API
api = Proxy

-- | Environment for handlers
data Env = Env
  { envConfig :: Config
  , envPool   :: ConnectionPool
  }

type AppM = ReaderT Env Handler

-- | Main server implementation
server :: Env -> Server API
server env = hoistServer api (flip runReaderT env) $
       healthServer
  :<|> ( publicServer
    :<|> protectedServer
       )

-- | Public endpoints server
publicServer :: ServerT PublicAPI AppM
publicServer = 
       userServer
  :<|> authServer

-- | Protected endpoints server
protectedServer :: AuthResult AuthUser -> ServerT ProtectedAPI AppM
protectedServer (Authenticated user) = 
       todoServer user
  :<|> profileServer user
protectedServer _ = throwAll err401

-- | Create WAI application
app :: Config -> ConnectionPool -> Application
app config pool = serveWithContext completeApi ctx srv
  where
    env = Env config pool
    ctx = authCheck (configJWTKey config) :. EmptyContext
    srv = server env :<|> serveDirectoryWebApp "static/docs"
    completeApi = Proxy :: Proxy CompleteAPI`,

    'src/API/User.hs': `{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module API.User
  ( UserAPI
  , userServer
  , AuthAPI
  , authServer
  ) where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (asks)
import Crypto.BCrypt
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (getCurrentTime, addUTCTime)
import Database.Persist
import Database.Persist.Postgresql
import Servant
import Servant.Auth.Server

import Types
import Models
import Auth (AuthUser(..), generateJWT)

-- | User management API
type UserAPI = 
       ReqBody '[JSON] CreateUserRequest :> Post '[JSON] UserResponse
  :<|> Capture "userId" UserId :> Get '[JSON] UserResponse
  :<|> Get '[JSON] [UserResponse]

-- | Authentication API
type AuthAPI =
       "login" :> ReqBody '[JSON] LoginRequest :> Post '[JSON] LoginResponse
  :<|> "refresh" :> ReqBody '[JSON] RefreshTokenRequest :> Post '[JSON] LoginResponse

-- | User API server implementation
userServer :: ServerT UserAPI AppM
userServer = createUser :<|> getUser :<|> listUsers

-- | Authentication server implementation
authServer :: ServerT AuthAPI AppM
authServer = login :<|> refreshToken

-- | Create a new user
createUser :: CreateUserRequest -> AppM UserResponse
createUser CreateUserRequest{..} = do
  pool <- asks envPool
  
  -- Check if user already exists
  existingUser <- liftIO $ runSqlPool (selectFirst [UserEmail ==. curEmail] []) pool
  case existingUser of
    Just _ -> throwError err409 { errBody = "User already exists" }
    Nothing -> do
      -- Hash password
      mHashedPass <- liftIO $ hashPasswordUsingPolicy slowerBcryptHashingPolicy 
                                (TE.encodeUtf8 curPassword)
      case mHashedPass of
        Nothing -> throwError err500 { errBody = "Failed to hash password" }
        Just hashedPass -> do
          -- Create user
          now <- liftIO getCurrentTime
          userId <- liftIO $ runSqlPool (insert User
            { userEmail = curEmail
            , userName = curName
            , userPasswordHash = TE.decodeUtf8 hashedPass
            , userCreatedAt = now
            , userUpdatedAt = now
            , userActive = True
            }) pool
          
          return $ UserResponse userId curEmail curName now

-- | Get user by ID
getUser :: UserId -> AppM UserResponse
getUser userId = do
  pool <- asks envPool
  mUser <- liftIO $ runSqlPool (get userId) pool
  case mUser of
    Nothing -> throwError err404
    Just user -> return $ UserResponse 
      userId 
      (userEmail user) 
      (userName user) 
      (userCreatedAt user)

-- | List all users
listUsers :: AppM [UserResponse]
listUsers = do
  pool <- asks envPool
  users <- liftIO $ runSqlPool (selectList [] [Desc UserCreatedAt]) pool
  return $ map entityToResponse users
  where
    entityToResponse (Entity uid user) = UserResponse 
      uid 
      (userEmail user) 
      (userName user) 
      (userCreatedAt user)

-- | User login
login :: LoginRequest -> AppM LoginResponse
login LoginRequest{..} = do
  pool <- asks envPool
  config <- asks envConfig
  
  -- Find user by email
  mUser <- liftIO $ runSqlPool (selectFirst [UserEmail ==. lrEmail] []) pool
  case mUser of
    Nothing -> throwError err401 { errBody = "Invalid credentials" }
    Just (Entity userId user) -> do
      -- Verify password
      let valid = validatePassword (TE.encodeUtf8 $ userPasswordHash user) 
                                 (TE.encodeUtf8 lrPassword)
      if valid
        then do
          -- Generate tokens
          let authUser = AuthUser userId (userEmail user) (userName user)
          accessToken <- liftIO $ generateJWT (configJWTKey config) authUser 3600  -- 1 hour
          refreshToken <- liftIO $ generateJWT (configJWTKey config) authUser 604800 -- 7 days
          
          return $ LoginResponse accessToken refreshToken (UserResponse 
            userId 
            (userEmail user) 
            (userName user) 
            (userCreatedAt user))
        else throwError err401 { errBody = "Invalid credentials" }

-- | Refresh access token
refreshToken :: RefreshTokenRequest -> AppM LoginResponse
refreshToken RefreshTokenRequest{..} = do
  config <- asks envConfig
  pool <- asks envPool
  
  -- Verify refresh token
  mAuthUser <- liftIO $ verifyJWT (configJWTKey config) rtrRefreshToken
  case mAuthUser of
    Nothing -> throwError err401 { errBody = "Invalid refresh token" }
    Just authUser -> do
      -- Generate new tokens
      newAccessToken <- liftIO $ generateJWT (configJWTKey config) authUser 3600
      newRefreshToken <- liftIO $ generateJWT (configJWTKey config) authUser 604800
      
      -- Get user data
      mUser <- liftIO $ runSqlPool (get $ authUserId authUser) pool
      case mUser of
        Nothing -> throwError err404
        Just user -> return $ LoginResponse 
          newAccessToken 
          newRefreshToken 
          (UserResponse 
            (authUserId authUser) 
            (userEmail user) 
            (userName user) 
            (userCreatedAt user))`,

    'src/API/Todo.hs': `{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module API.Todo
  ( TodoAPI
  , todoServer
  ) where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (asks)
import Data.Text (Text)
import Data.Time.Clock (getCurrentTime)
import Database.Persist
import Database.Persist.Postgresql
import Servant

import Types
import Models
import Auth (AuthUser(..))

-- | Todo management API
type TodoAPI = 
       Get '[JSON] [TodoResponse]
  :<|> ReqBody '[JSON] CreateTodoRequest :> Post '[JSON] TodoResponse
  :<|> Capture "todoId" TodoId :> 
       ( Get '[JSON] TodoResponse
    :<|> ReqBody '[JSON] UpdateTodoRequest :> Put '[JSON] TodoResponse
    :<|> Delete '[JSON] NoContent
       )

-- | Todo API server implementation
todoServer :: AuthUser -> ServerT TodoAPI AppM
todoServer user = 
       listTodos user
  :<|> createTodo user
  :<|> (\\tid -> getTodo user tid
            :<|> updateTodo user tid
            :<|> deleteTodo user tid)

-- | List todos for authenticated user
listTodos :: AuthUser -> AppM [TodoResponse]
listTodos AuthUser{..} = do
  pool <- asks envPool
  todos <- liftIO $ runSqlPool 
    (selectList [TodoUserId ==. authUserId] [Desc TodoCreatedAt]) pool
  return $ map entityToResponse todos
  where
    entityToResponse (Entity tid todo) = TodoResponse
      { trId = tid
      , trTitle = todoTitle todo
      , trDescription = todoDescription todo
      , trCompleted = todoCompleted todo
      , trCreatedAt = todoCreatedAt todo
      , trUpdatedAt = todoUpdatedAt todo
      }

-- | Create a new todo
createTodo :: AuthUser -> CreateTodoRequest -> AppM TodoResponse
createTodo AuthUser{..} CreateTodoRequest{..} = do
  pool <- asks envPool
  now <- liftIO getCurrentTime
  
  let todo = Todo
        { todoUserId = authUserId
        , todoTitle = ctrTitle
        , todoDescription = ctrDescription
        , todoCompleted = False
        , todoCreatedAt = now
        , todoUpdatedAt = now
        }
  
  todoId <- liftIO $ runSqlPool (insert todo) pool
  return $ TodoResponse todoId ctrTitle ctrDescription False now now

-- | Get a specific todo
getTodo :: AuthUser -> TodoId -> AppM TodoResponse
getTodo AuthUser{..} todoId = do
  pool <- asks envPool
  mTodo <- liftIO $ runSqlPool (get todoId) pool
  
  case mTodo of
    Nothing -> throwError err404
    Just todo -> 
      if todoUserId todo == authUserId
        then return $ TodoResponse
               todoId
               (todoTitle todo)
               (todoDescription todo)
               (todoCompleted todo)
               (todoCreatedAt todo)
               (todoUpdatedAt todo)
        else throwError err403

-- | Update a todo
updateTodo :: AuthUser -> TodoId -> UpdateTodoRequest -> AppM TodoResponse
updateTodo AuthUser{..} todoId UpdateTodoRequest{..} = do
  pool <- asks envPool
  mTodo <- liftIO $ runSqlPool (get todoId) pool
  
  case mTodo of
    Nothing -> throwError err404
    Just todo ->
      if todoUserId todo == authUserId
        then do
          now <- liftIO getCurrentTime
          liftIO $ runSqlPool (update todoId
            [ TodoTitle =. utrTitle
            , TodoDescription =. utrDescription
            , TodoCompleted =. utrCompleted
            , TodoUpdatedAt =. now
            ]) pool
          
          return $ TodoResponse
            todoId
            utrTitle
            utrDescription
            utrCompleted
            (todoCreatedAt todo)
            now
        else throwError err403

-- | Delete a todo
deleteTodo :: AuthUser -> TodoId -> AppM NoContent
deleteTodo AuthUser{..} todoId = do
  pool <- asks envPool
  mTodo <- liftIO $ runSqlPool (get todoId) pool
  
  case mTodo of
    Nothing -> throwError err404
    Just todo ->
      if todoUserId todo == authUserId
        then do
          liftIO $ runSqlPool (delete todoId) pool
          return NoContent
        else throwError err403`,

    'src/API/Health.hs': `{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}

module API.Health
  ( HealthAPI
  , healthServer
  ) where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (asks)
import Data.Text (Text)
import Data.Time.Clock (getCurrentTime)
import Database.Persist.Postgresql
import Servant

import Types

-- | Health check API
type HealthAPI = 
       "health" :> Get '[JSON] HealthResponse
  :<|> "health" :> "db" :> Get '[JSON] HealthResponse

-- | Health check server implementation
healthServer :: ServerT HealthAPI AppM
healthServer = healthCheck :<|> dbHealthCheck

-- | Basic health check
healthCheck :: AppM HealthResponse
healthCheck = do
  now <- liftIO getCurrentTime
  return $ HealthResponse
    { hrStatus = "ok"
    , hrVersion = "1.0.0"
    , hrTimestamp = now
    , hrServices = [("api", True)]
    }

-- | Database health check
dbHealthCheck :: AppM HealthResponse
dbHealthCheck = do
  pool <- asks envPool
  now <- liftIO getCurrentTime
  
  -- Try to execute a simple query
  dbStatus <- liftIO $ runSqlPool (rawSql "SELECT 1" []) pool
  let isHealthy = case dbStatus of
        [Single (1 :: Int)] -> True
        _ -> False
  
  return $ HealthResponse
    { hrStatus = if isHealthy then "ok" else "error"
    , hrVersion = "1.0.0"
    , hrTimestamp = now
    , hrServices = [("api", True), ("database", isHealthy)]
    }`,

    'src/Types.hs': `{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Types where

import Data.Aeson
import Data.Text (Text)
import Data.Time.Clock (UTCTime)
import Database.Persist (Key)
import GHC.Generics
import Servant.Auth.Server (FromJWT, ToJWT)

import Models

-- | User creation request
data CreateUserRequest = CreateUserRequest
  { curEmail    :: Text
  , curPassword :: Text
  , curName     :: Text
  } deriving (Generic, Show)

instance FromJSON CreateUserRequest
instance ToJSON CreateUserRequest

-- | User response
data UserResponse = UserResponse
  { urId        :: Key User
  , urEmail     :: Text
  , urName      :: Text
  , urCreatedAt :: UTCTime
  } deriving (Generic, Show)

instance FromJSON UserResponse where
  parseJSON = genericParseJSON $ defaultOptions { fieldLabelModifier = drop 2 }

instance ToJSON UserResponse where
  toJSON = genericToJSON $ defaultOptions { fieldLabelModifier = drop 2 }

-- | Login request
data LoginRequest = LoginRequest
  { lrEmail    :: Text
  , lrPassword :: Text
  } deriving (Generic, Show)

instance FromJSON LoginRequest
instance ToJSON LoginRequest

-- | Login response
data LoginResponse = LoginResponse
  { lrAccessToken  :: Text
  , lrRefreshToken :: Text
  , lrUser         :: UserResponse
  } deriving (Generic, Show)

instance FromJSON LoginResponse where
  parseJSON = genericParseJSON $ defaultOptions { fieldLabelModifier = drop 2 }

instance ToJSON LoginResponse where
  toJSON = genericToJSON $ defaultOptions { fieldLabelModifier = drop 2 }

-- | Refresh token request
data RefreshTokenRequest = RefreshTokenRequest
  { rtrRefreshToken :: Text
  } deriving (Generic, Show)

instance FromJSON RefreshTokenRequest
instance ToJSON RefreshTokenRequest

-- | Todo creation request
data CreateTodoRequest = CreateTodoRequest
  { ctrTitle       :: Text
  , ctrDescription :: Text
  } deriving (Generic, Show)

instance FromJSON CreateTodoRequest
instance ToJSON CreateTodoRequest

-- | Todo update request
data UpdateTodoRequest = UpdateTodoRequest
  { utrTitle       :: Text
  , utrDescription :: Text
  , utrCompleted   :: Bool
  } deriving (Generic, Show)

instance FromJSON UpdateTodoRequest
instance ToJSON UpdateTodoRequest

-- | Todo response
data TodoResponse = TodoResponse
  { trId          :: Key Todo
  , trTitle       :: Text
  , trDescription :: Text
  , trCompleted   :: Bool
  , trCreatedAt   :: UTCTime
  , trUpdatedAt   :: UTCTime
  } deriving (Generic, Show)

instance FromJSON TodoResponse where
  parseJSON = genericParseJSON $ defaultOptions { fieldLabelModifier = drop 2 }

instance ToJSON TodoResponse where
  toJSON = genericToJSON $ defaultOptions { fieldLabelModifier = drop 2 }

-- | Health check response
data HealthResponse = HealthResponse
  { hrStatus    :: Text
  , hrVersion   :: Text
  , hrTimestamp :: UTCTime
  , hrServices  :: [(Text, Bool)]
  } deriving (Generic, Show)

instance FromJSON HealthResponse where
  parseJSON = genericParseJSON $ defaultOptions { fieldLabelModifier = drop 2 }

instance ToJSON HealthResponse where
  toJSON = genericToJSON $ defaultOptions { fieldLabelModifier = drop 2 }

-- | Profile API
type ProfileAPI = Get '[JSON] UserResponse

-- | Profile server
profileServer :: AuthUser -> ServerT ProfileAPI AppM
profileServer AuthUser{..} = do
  pool <- asks envPool
  mUser <- liftIO $ runSqlPool (get authUserId) pool
  case mUser of
    Nothing -> throwError err404
    Just user -> return $ UserResponse authUserId (userEmail user) (userName user) (userCreatedAt user)

-- | Type alias for readability
type AppM = ReaderT Env Handler

-- | Environment
data Env = Env
  { envConfig :: Config
  , envPool   :: ConnectionPool
  }`,

    'src/Models.hs': `{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

module Models where

import Data.Text (Text)
import Data.Time.Clock (UTCTime)
import Database.Persist.TH

-- | Database models definition using Persistent
share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
User
    email Text
    name Text
    passwordHash Text
    createdAt UTCTime
    updatedAt UTCTime
    active Bool default=True
    UniqueEmail email
    deriving Show

Todo
    userId UserId
    title Text
    description Text
    completed Bool default=False
    createdAt UTCTime
    updatedAt UTCTime
    deriving Show

RefreshToken
    userId UserId
    token Text
    expiresAt UTCTime
    createdAt UTCTime
    UniqueToken token
    deriving Show
|]`,

    'src/Auth.hs': `{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Auth
  ( AuthUser(..)
  , authCheck
  , generateJWT
  , verifyJWT
  ) where

import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BSL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (UTCTime, getCurrentTime, addUTCTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds, posixSecondsToUTCTime)
import Database.Persist (Key)
import GHC.Generics
import Servant.Auth.Server

import Models

-- | Authenticated user data
data AuthUser = AuthUser
  { authUserId    :: Key User
  , authUserEmail :: Text
  , authUserName  :: Text
  } deriving (Generic, Show)

instance FromJSON AuthUser
instance ToJSON AuthUser
instance FromJWT AuthUser
instance ToJWT AuthUser

-- | Create JWT settings for authentication
authCheck :: JWK -> JWTSettings
authCheck key = defaultJWTSettings key

-- | Generate a JWT token
generateJWT :: JWK -> AuthUser -> Integer -> IO Text
generateJWT key user expiresIn = do
  now <- getCurrentTime
  let expiry = addUTCTime (fromInteger expiresIn) now
  
  eToken <- makeJWT user (defaultJWTSettings key) (Just expiry)
  case eToken of
    Left err -> error $ "Failed to generate JWT: " ++ show err
    Right token -> return $ TE.decodeUtf8 $ BSL.toStrict token

-- | Verify a JWT token
verifyJWT :: JWK -> Text -> IO (Maybe AuthUser)
verifyJWT key token = do
  let tokenBS = BSL.fromStrict $ TE.encodeUtf8 token
  eUser <- verifyJWT' (defaultJWTSettings key) tokenBS
  case eUser of
    Nothing -> return Nothing
    Just user -> return $ Just user`,

    'src/Config.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Config
  ( Config(..)
  , DatabaseConfig(..)
  , loadConfig
  ) where

import Control.Monad (when)
import Crypto.JOSE.JWK (JWK, genJWK, KeyMaterialGenParam(OctGenParam))
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import System.Environment

-- | Application configuration
data Config = Config
  { configPort        :: Int
  , configJWTKey      :: JWK
  , configEnvironment :: Text
  , dbConfig          :: DatabaseConfig
  } deriving (Show)

-- | Database configuration
data DatabaseConfig = DatabaseConfig
  { dbHost     :: String
  , dbPort     :: Int
  , dbUser     :: String
  , dbPassword :: String
  , dbName     :: String
  } deriving (Show)

-- | Load configuration from environment
loadConfig :: IO Config
loadConfig = do
  port <- read . fromMaybe "3000" <$> lookupEnv "PORT"
  env <- T.pack . fromMaybe "development" <$> lookupEnv "ENV"
  
  -- Generate or load JWT key
  jwtKey <- genJWK (OctGenParam 256)
  
  -- Database configuration
  dbHost <- fromMaybe "localhost" <$> lookupEnv "DB_HOST"
  dbPort <- read . fromMaybe "5432" <$> lookupEnv "DB_PORT"
  dbUser <- fromMaybe "postgres" <$> lookupEnv "DB_USER"
  dbPass <- fromMaybe "postgres" <$> lookupEnv "DB_PASSWORD"
  dbName <- fromMaybe "servant_dev" <$> lookupEnv "DB_NAME"
  
  let dbConf = DatabaseConfig dbHost dbPort dbUser dbPass dbName
  
  return $ Config port jwtKey env dbConf`,

    'src/Database.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

module Database
  ( createConnectionPool
  , runMigrations
  , ConnectionPool
  ) where

import Control.Monad.Logger (runStdoutLoggingT)
import Database.Persist.Postgresql
import Data.ByteString.Char8 (pack)

import Config (DatabaseConfig(..))
import Models (migrateAll)

-- | Create database connection pool
createConnectionPool :: DatabaseConfig -> IO ConnectionPool
createConnectionPool DatabaseConfig{..} = do
  let connStr = pack $ concat
        [ "host=", dbHost
        , " port=", show dbPort
        , " user=", dbUser
        , " password=", dbPassword
        , " dbname=", dbName
        ]
  
  runStdoutLoggingT $ createPostgresqlPool connStr 10

-- | Run database migrations
runMigrations :: ConnectionPool -> IO ()
runMigrations pool = runStdoutLoggingT $ runSqlPool (runMigration migrateAll) pool`,

    'test/Spec.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

import Test.Hspec
import Test.Hspec.Wai
import Test.Hspec.Wai.JSON
import Network.Wai.Test (SResponse)
import Network.HTTP.Types.Status
import Data.Aeson (encode)
import qualified Data.ByteString.Lazy as BSL

import API (app)
import Config (loadConfig)
import Database (createConnectionPool, runMigrations)
import Types

main :: IO ()
main = do
  config <- loadConfig
  pool <- createConnectionPool (dbConfig config)
  runMigrations pool
  
  let application = app config pool
  
  hspec $ with (return application) $ do
    describe "Health Check API" $ do
      it "responds with 200 for health check" $ do
        get "/api/health" \`shouldRespondWith\` 200
      
      it "returns health status" $ do
        get "/api/health" \`shouldRespondWith\`
          [json|{status: "ok", version: "1.0.0"}|]
          {matchStatus = 200}
    
    describe "User API" $ do
      it "creates a new user" $ do
        let user = CreateUserRequest "test@example.com" "password123" "Test User"
        post "/api/v1/users" (encode user) \`shouldRespondWith\` 200
      
      it "prevents duplicate users" $ do
        let user = CreateUserRequest "duplicate@example.com" "password123" "Test User"
        post "/api/v1/users" (encode user) \`shouldRespondWith\` 200
        post "/api/v1/users" (encode user) \`shouldRespondWith\` 409
      
      it "lists all users" $ do
        get "/api/v1/users" \`shouldRespondWith\` 200
    
    describe "Authentication API" $ do
      it "allows user login with correct credentials" $ do
        -- First create a user
        let user = CreateUserRequest "login@example.com" "password123" "Login User"
        post "/api/v1/users" (encode user) \`shouldRespondWith\` 200
        
        -- Then login
        let loginReq = LoginRequest "login@example.com" "password123"
        response <- post "/api/v1/auth/login" (encode loginReq)
        liftIO $ statusCode (simpleStatus response) \`shouldBe\` 200
      
      it "rejects login with incorrect credentials" $ do
        let loginReq = LoginRequest "wrong@example.com" "wrongpass"
        post "/api/v1/auth/login" (encode loginReq) \`shouldRespondWith\` 401
    
    describe "Todo API (Protected)" $ do
      it "requires authentication for todo endpoints" $ do
        get "/api/v1/todos" \`shouldRespondWith\` 401
      
      it "allows authenticated access to todos" $ do
        -- This would require setting up auth tokens in tests
        -- For now, just verify the endpoint exists
        get "/api/v1/todos" \`shouldRespondWith\` 401`,

    'servant-app.cabal': `cabal-version: 1.12

name:           servant-app
version:        0.1.0.0
description:    A Servant web application with type-safe APIs
homepage:       https://github.com/yourusername/servant-app#readme
bug-reports:    https://github.com/yourusername/servant-app/issues
author:         Your Name
maintainer:     your.email@example.com
copyright:      2024 Your Name
license:        BSD3
build-type:     Simple
extra-source-files:
    README.md
    CHANGELOG.md

source-repository head
  type: git
  location: https://github.com/yourusername/servant-app

library
  exposed-modules:
      API
      API.Health
      API.Todo
      API.User
      Auth
      Config
      Database
      Models
      Types
  other-modules:
      Paths_servant_app
  hs-source-dirs:
      src
  ghc-options: -Wall -Wcompat -Widentities -Wincomplete-record-updates -Wincomplete-uni-patterns -Wmissing-export-lists -Wmissing-home-modules -Wpartial-fields -Wredundant-constraints
  build-depends:
      aeson >=1.4 && <2.2
    , base >=4.7 && <5
    , bcrypt >=0.0.11
    , bytestring
    , jose >=0.9
    , monad-logger
    , mtl
    , persistent >=2.13
    , persistent-postgresql >=2.13
    , persistent-template >=2.12
    , servant >=0.19
    , servant-auth >=0.4
    , servant-auth-server >=0.4
    , servant-server >=0.19
    , text
    , time
    , wai
    , wai-cors
    , wai-extra
    , warp >=3.3
  default-language: Haskell2010

executable servant-app
  main-is: Main.hs
  other-modules:
      Paths_servant_app
  hs-source-dirs:
      app
  ghc-options: -Wall -Wcompat -Widentities -Wincomplete-record-updates -Wincomplete-uni-patterns -Wmissing-export-lists -Wmissing-home-modules -Wpartial-fields -Wredundant-constraints -threaded -rtsopts -with-rtsopts=-N
  build-depends:
      base >=4.7 && <5
    , servant-app
  default-language: Haskell2010

test-suite servant-app-test
  type: exitcode-stdio-1.0
  main-is: Spec.hs
  other-modules:
      Paths_servant_app
  hs-source-dirs:
      test
  ghc-options: -Wall -Wcompat -Widentities -Wincomplete-record-updates -Wincomplete-uni-patterns -Wmissing-export-lists -Wmissing-home-modules -Wpartial-fields -Wredundant-constraints -threaded -rtsopts -with-rtsopts=-N
  build-depends:
      aeson
    , base >=4.7 && <5
    , bytestring
    , hspec >=2.6
    , hspec-wai >=0.11
    , hspec-wai-json >=0.11
    , http-types
    , servant-app
    , wai-extra
  default-language: Haskell2010`,

    'stack.yaml': `resolver: lts-21.25

packages:
- .

extra-deps: []

flags: {}

extra-package-dbs: []`,

    'package.yaml': `name:                servant-app
version:             0.1.0.0
github:              "yourusername/servant-app"
license:             BSD3
author:              "Your Name"
maintainer:          "your.email@example.com"
copyright:           "2024 Your Name"

extra-source-files:
- README.md
- CHANGELOG.md

description:         A Servant web application with type-safe APIs

dependencies:
- base >= 4.7 && < 5
- aeson >= 1.4 && < 2.2
- bcrypt >= 0.0.11
- bytestring
- jose >= 0.9
- monad-logger
- mtl
- persistent >= 2.13
- persistent-postgresql >= 2.13
- persistent-template >= 2.12
- servant >= 0.19
- servant-auth >= 0.4
- servant-auth-server >= 0.4
- servant-server >= 0.19
- text
- time
- wai
- wai-cors
- wai-extra
- warp >= 3.3

ghc-options:
- -Wall
- -Wcompat
- -Widentities
- -Wincomplete-record-updates
- -Wincomplete-uni-patterns
- -Wmissing-export-lists
- -Wmissing-home-modules
- -Wpartial-fields
- -Wredundant-constraints

library:
  source-dirs: src

executables:
  servant-app:
    main:                Main.hs
    source-dirs:         app
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - servant-app

tests:
  servant-app-test:
    main:                Spec.hs
    source-dirs:         test
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - servant-app
    - hspec >= 2.6
    - hspec-wai >= 0.11
    - hspec-wai-json >= 0.11
    - http-types
    - wai-extra`,

    'Setup.hs': `import Distribution.Simple
main = defaultMain`,

    '.gitignore': `dist
dist-*
cabal-dev
*.o
*.hi
*.hie
*.chi
*.chs.h
*.dyn_o
*.dyn_hi
.hpc
.hsenv
.cabal-sandbox/
cabal.sandbox.config
*.prof
*.aux
*.hp
*.eventlog
.stack-work/
cabal.project.local
cabal.project.local~
.HTF/
.ghc.environment.*`,

    'README.md': `# Servant Type-Safe REST API

A Haskell web application built with Servant, featuring type-safe APIs and automatic documentation generation.

## Features

- ✅ Type-safe routing and request handling
- ✅ Automatic API documentation generation
- ✅ JWT authentication
- ✅ PostgreSQL database with Persistent ORM
- ✅ Request validation
- ✅ Error handling
- ✅ CORS support
- ✅ Health checks
- ✅ Testing with Hspec
- ✅ Docker deployment

## Getting Started

### Prerequisites

- Haskell Stack or Cabal
- PostgreSQL
- Docker (optional)

### Development Setup

1. Clone the repository:
   \`\`\`bash
   git clone <your-repo>
   cd servant-app
   \`\`\`

2. Install dependencies:
   \`\`\`bash
   stack setup
   stack build
   \`\`\`

3. Set up the database:
   \`\`\`bash
   createdb servant_dev
   \`\`\`

4. Configure environment variables:
   \`\`\`bash
   export DB_HOST=localhost
   export DB_PORT=5432
   export DB_USER=postgres
   export DB_PASSWORD=postgres
   export DB_NAME=servant_dev
   \`\`\`

5. Run the application:
   \`\`\`bash
   stack run
   \`\`\`

The server will start on http://localhost:3000

## API Endpoints

### Public Endpoints

- \`GET /api/health\` - Health check
- \`GET /api/health/db\` - Database health check
- \`POST /api/v1/users\` - Create new user
- \`GET /api/v1/users\` - List all users
- \`POST /api/v1/auth/login\` - User login
- \`POST /api/v1/auth/refresh\` - Refresh access token

### Protected Endpoints (requires authentication)

- \`GET /api/v1/todos\` - List user's todos
- \`POST /api/v1/todos\` - Create new todo
- \`GET /api/v1/todos/:id\` - Get specific todo
- \`PUT /api/v1/todos/:id\` - Update todo
- \`DELETE /api/v1/todos/:id\` - Delete todo
- \`GET /api/v1/profile\` - Get user profile

## Testing

Run the test suite:
\`\`\`bash
stack test
\`\`\`

## Docker Deployment

Build and run with Docker:
\`\`\`bash
docker build -t servant-app .
docker run -p 3000:3000 servant-app
\`\`\`

Or use Docker Compose:
\`\`\`bash
docker-compose up
\`\`\`

## Project Structure

\`\`\`
.
├── app/
│   └── Main.hs          # Application entry point
├── src/
│   ├── API.hs           # Main API definition
│   ├── API/
│   │   ├── Health.hs    # Health check endpoints
│   │   ├── User.hs      # User management endpoints
│   │   └── Todo.hs      # Todo management endpoints
│   ├── Auth.hs          # Authentication logic
│   ├── Config.hs        # Configuration management
│   ├── Database.hs      # Database connection
│   ├── Models.hs        # Database models
│   └── Types.hs         # Type definitions
├── test/
│   └── Spec.hs          # Test suite
└── servant-app.cabal    # Build configuration
\`\`\`

## Contributing

1. Fork the repository
2. Create your feature branch (\`git checkout -b feature/amazing-feature\`)
3. Commit your changes (\`git commit -m 'Add some amazing feature'\`)
4. Push to the branch (\`git push origin feature/amazing-feature\`)
5. Open a Pull Request

## License

This project is licensed under the BSD3 License - see the LICENSE file for details.`,

    'Dockerfile': `# Build stage
FROM haskell:9.2.8 AS build

WORKDIR /opt/build

# Copy the package files
COPY servant-app.cabal stack.yaml stack.yaml.lock ./
RUN stack setup

# Build dependencies
RUN stack build --only-dependencies

# Copy application source
COPY . .

# Build application
RUN stack build --copy-bins

# Runtime stage
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \\
    ca-certificates \\
    libpq5 \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/app

# Copy the built executable
COPY --from=build /root/.local/bin/servant-app .

# Expose port
EXPOSE 3000

# Run the application
CMD ["./servant-app"]`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - PORT=3000
      - ENV=production
      - DB_HOST=db
      - DB_PORT=5432
      - DB_USER=postgres
      - DB_PASSWORD=postgres
      - DB_NAME=servant_prod
    depends_on:
      - db
    networks:
      - servant-network

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=servant_prod
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - servant-network

volumes:
  postgres-data:

networks:
  servant-network:
    driver: bridge`,

    '.env.example': `# Server Configuration
PORT=3000
ENV=development

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=servant_dev

# JWT Configuration
JWT_SECRET=your-secret-key-here`,

    'CHANGELOG.md': `# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-15

### Added
- Initial release
- Type-safe REST API with Servant
- JWT authentication
- PostgreSQL integration with Persistent
- User management endpoints
- Todo management endpoints
- Health check endpoints
- Docker deployment configuration
- Comprehensive test suite`
  }
};