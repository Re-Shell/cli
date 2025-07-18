import { BackendTemplate } from '../types';

export const scottyTemplate: BackendTemplate = {
  id: 'scotty',
  name: 'scotty',
  displayName: 'Scotty Lightweight Web Framework',
  description: 'A Haskell web framework inspired by Ruby\'s Sinatra, designed for simplicity and rapid development',
  framework: 'scotty',
  language: 'haskell',
  version: '0.20',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🌟',
  type: 'rest-api',
  complexity: 'beginner',
  keywords: ['haskell', 'scotty', 'web', 'lightweight', 'simple', 'sinatra-like'],
  
  features: [
    'Minimalist and lightweight design',
    'Simple routing DSL',
    'JSON support built-in',
    'Middleware support',
    'Static file serving',
    'Request parameter handling',
    'Response helpers',
    'Cookie support',
    'Session management',
    'Error handling',
    'WebSocket support',
    'PostgreSQL integration',
    'JWT authentication',
    'CORS middleware'
  ],
  
  structure: {
    'app/Main.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module Main where

import Web.Scotty
import Network.Wai.Middleware.Cors
import Network.Wai.Middleware.RequestLogger
import Network.Wai.Middleware.Static
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified Data.Text.Lazy as TL
import Control.Monad.IO.Class (liftIO)
import System.Environment (lookupEnv)
import Data.Maybe (fromMaybe)

import Routes
import Database
import Auth
import Config

main :: IO ()
main = do
  -- Load configuration
  config <- loadConfig
  
  -- Initialize database
  pool <- createConnectionPool (dbConfig config)
  runMigrations pool
  
  -- Get port from environment
  port <- fromMaybe 3000 . fmap read <$> lookupEnv "PORT"
  
  -- Start Scotty server
  scotty port $ do
    -- Middleware
    middleware logStdoutDev
    middleware simpleCors
    middleware $ staticPolicy (noDots >-> addBase "public")
    
    -- Register routes
    routes config pool`,

    'src/Routes.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module Routes (routes) where

import Web.Scotty
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified Data.Text.Lazy as TL
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple (Connection)
import Data.Pool (Pool)

import Auth
import Handlers.User
import Handlers.Todo
import Handlers.Health
import Middleware
import Config

-- Request/Response types
data LoginRequest = LoginRequest
  { username :: TL.Text
  , password :: TL.Text
  } deriving (Generic, Show)

instance FromJSON LoginRequest
instance ToJSON LoginRequest

data ApiResponse a = ApiResponse
  { success :: Bool
  , message :: TL.Text
  , data :: Maybe a
  } deriving (Generic, Show)

instance ToJSON a => ToJSON (ApiResponse a)

-- Route definitions
routes :: Config -> Pool Connection -> ScottyM ()
routes config pool = do
  -- Health check
  get "/health" $ healthHandler pool
  
  -- Authentication routes
  post "/api/auth/register" $ registerHandler pool
  post "/api/auth/login" $ loginHandler config pool
  post "/api/auth/logout" $ authMiddleware config logoutHandler
  get "/api/auth/me" $ authMiddleware config $ currentUserHandler pool
  
  -- User routes (protected)
  get "/api/users" $ authMiddleware config $ getUsersHandler pool
  get "/api/users/:id" $ authMiddleware config $ getUserHandler pool
  put "/api/users/:id" $ authMiddleware config $ updateUserHandler pool
  delete "/api/users/:id" $ authMiddleware config $ deleteUserHandler pool
  
  -- Todo routes (protected)
  get "/api/todos" $ authMiddleware config $ getTodosHandler pool
  post "/api/todos" $ authMiddleware config $ createTodoHandler pool
  get "/api/todos/:id" $ authMiddleware config $ getTodoHandler pool
  put "/api/todos/:id" $ authMiddleware config $ updateTodoHandler pool
  delete "/api/todos/:id" $ authMiddleware config $ deleteTodoHandler pool
  
  -- Static files and 404
  notFound $ do
    status notFound404
    json $ ApiResponse False "Resource not found" (Nothing :: Maybe ())`,

    'src/Handlers/User.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module Handlers.User where

import Web.Scotty
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified Data.Text.Lazy as TL
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple
import Data.Pool (Pool, withResource)
import Data.Time (getCurrentTime)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID
import Crypto.BCrypt

import Models.User
import Database

-- Request types
data CreateUserRequest = CreateUserRequest
  { username :: TL.Text
  , email :: TL.Text
  , password :: TL.Text
  } deriving (Generic, Show)

instance FromJSON CreateUserRequest
instance ToJSON CreateUserRequest

data UpdateUserRequest = UpdateUserRequest
  { email :: Maybe TL.Text
  , bio :: Maybe TL.Text
  } deriving (Generic, Show)

instance FromJSON UpdateUserRequest
instance ToJSON UpdateUserRequest

-- Handlers
registerHandler :: Pool Connection -> ActionM ()
registerHandler pool = do
  req <- jsonData :: ActionM CreateUserRequest
  
  -- Hash password
  let pass = TL.toStrict $ password req
  maybeHash <- liftIO $ hashPasswordUsingPolicy slowerBcryptHashingPolicy pass
  
  case maybeHash of
    Nothing -> do
      status internalServerError500
      json $ object ["error" .= ("Failed to hash password" :: String)]
    
    Just hash -> do
      -- Create user
      userId <- liftIO $ UUID.nextRandom
      now <- liftIO getCurrentTime
      
      let user = User
            { userId = userId
            , userUsername = username req
            , userEmail = email req
            , userPasswordHash = TL.pack $ show hash
            , userBio = Nothing
            , userCreatedAt = now
            , userUpdatedAt = now
            }
      
      result <- liftIO $ withResource pool $ \conn ->
        insertUser conn user
      
      case result of
        Left err -> do
          status badRequest400
          json $ object ["error" .= err]
        Right u -> do
          status created201
          json $ u { userPasswordHash = "" }  -- Don't send password hash

getUsersHandler :: Pool Connection -> ActionM ()
getUsersHandler pool = do
  users <- liftIO $ withResource pool getUsers
  json $ map (\u -> u { userPasswordHash = "" }) users

getUserHandler :: Pool Connection -> ActionM ()
getUserHandler pool = do
  uid <- param "id"
  maybeUser <- liftIO $ withResource pool $ \conn -> getUserById conn uid
  
  case maybeUser of
    Nothing -> do
      status notFound404
      json $ object ["error" .= ("User not found" :: String)]
    Just user -> json $ user { userPasswordHash = "" }

updateUserHandler :: Pool Connection -> ActionM ()
updateUserHandler pool = do
  uid <- param "id"
  req <- jsonData :: ActionM UpdateUserRequest
  authUser <- getAuthUser
  
  -- Check if user can update this profile
  if userId authUser /= uid
    then do
      status forbidden403
      json $ object ["error" .= ("Forbidden" :: String)]
    else do
      result <- liftIO $ withResource pool $ \conn ->
        updateUser conn uid (email req) (bio req)
      
      case result of
        Nothing -> do
          status notFound404
          json $ object ["error" .= ("User not found" :: String)]
        Just user -> json $ user { userPasswordHash = "" }

deleteUserHandler :: Pool Connection -> ActionM ()
deleteUserHandler pool = do
  uid <- param "id"
  authUser <- getAuthUser
  
  -- Check if user can delete this profile
  if userId authUser /= uid
    then do
      status forbidden403
      json $ object ["error" .= ("Forbidden" :: String)]
    else do
      success <- liftIO $ withResource pool $ \conn -> deleteUser conn uid
      
      if success
        then json $ object ["message" .= ("User deleted" :: String)]
        else do
          status notFound404
          json $ object ["error" .= ("User not found" :: String)]`,

    'src/Handlers/Todo.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module Handlers.Todo where

import Web.Scotty
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified Data.Text.Lazy as TL
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple
import Data.Pool (Pool, withResource)
import Data.Time (getCurrentTime)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID

import Models.Todo
import Models.User
import Database
import Auth

-- Request types
data CreateTodoRequest = CreateTodoRequest
  { title :: TL.Text
  , description :: Maybe TL.Text
  } deriving (Generic, Show)

instance FromJSON CreateTodoRequest
instance ToJSON CreateTodoRequest

data UpdateTodoRequest = UpdateTodoRequest
  { title :: Maybe TL.Text
  , description :: Maybe TL.Text
  , completed :: Maybe Bool
  } deriving (Generic, Show)

instance FromJSON UpdateTodoRequest
instance ToJSON UpdateTodoRequest

-- Handlers
getTodosHandler :: Pool Connection -> ActionM ()
getTodosHandler pool = do
  authUser <- getAuthUser
  todos <- liftIO $ withResource pool $ \conn ->
    getTodosByUserId conn (userId authUser)
  json todos

createTodoHandler :: Pool Connection -> ActionM ()
createTodoHandler pool = do
  authUser <- getAuthUser
  req <- jsonData :: ActionM CreateTodoRequest
  
  todoId <- liftIO UUID.nextRandom
  now <- liftIO getCurrentTime
  
  let todo = Todo
        { todoId = todoId
        , todoUserId = userId authUser
        , todoTitle = title req
        , todoDescription = description req
        , todoCompleted = False
        , todoCreatedAt = now
        , todoUpdatedAt = now
        }
  
  result <- liftIO $ withResource pool $ \conn ->
    insertTodo conn todo
  
  case result of
    Left err -> do
      status badRequest400
      json $ object ["error" .= err]
    Right t -> do
      status created201
      json t

getTodoHandler :: Pool Connection -> ActionM ()
getTodoHandler pool = do
  authUser <- getAuthUser
  tid <- param "id"
  
  maybeTodo <- liftIO $ withResource pool $ \conn ->
    getTodoById conn tid
  
  case maybeTodo of
    Nothing -> do
      status notFound404
      json $ object ["error" .= ("Todo not found" :: String)]
    Just todo ->
      if todoUserId todo /= userId authUser
        then do
          status forbidden403
          json $ object ["error" .= ("Forbidden" :: String)]
        else json todo

updateTodoHandler :: Pool Connection -> ActionM ()
updateTodoHandler pool = do
  authUser <- getAuthUser
  tid <- param "id"
  req <- jsonData :: ActionM UpdateTodoRequest
  
  -- Check ownership
  maybeTodo <- liftIO $ withResource pool $ \conn ->
    getTodoById conn tid
  
  case maybeTodo of
    Nothing -> do
      status notFound404
      json $ object ["error" .= ("Todo not found" :: String)]
    Just todo ->
      if todoUserId todo /= userId authUser
        then do
          status forbidden403
          json $ object ["error" .= ("Forbidden" :: String)]
        else do
          result <- liftIO $ withResource pool $ \conn ->
            updateTodo conn tid (title req) (description req) (completed req)
          
          case result of
            Nothing -> do
              status notFound404
              json $ object ["error" .= ("Todo not found" :: String)]
            Just updatedTodo -> json updatedTodo

deleteTodoHandler :: Pool Connection -> ActionM ()
deleteTodoHandler pool = do
  authUser <- getAuthUser
  tid <- param "id"
  
  -- Check ownership
  maybeTodo <- liftIO $ withResource pool $ \conn ->
    getTodoById conn tid
  
  case maybeTodo of
    Nothing -> do
      status notFound404
      json $ object ["error" .= ("Todo not found" :: String)]
    Just todo ->
      if todoUserId todo /= userId authUser
        then do
          status forbidden403
          json $ object ["error" .= ("Forbidden" :: String)]
        else do
          success <- liftIO $ withResource pool $ \conn ->
            deleteTodo conn tid
          
          if success
            then json $ object ["message" .= ("Todo deleted" :: String)]
            else do
              status notFound404
              json $ object ["error" .= ("Todo not found" :: String)]`,

    'src/Auth.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module Auth where

import Web.Scotty
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified Data.Text.Lazy as TL
import qualified Data.Text as T
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple (Connection)
import Data.Pool (Pool, withResource)
import Data.Time (getCurrentTime, addUTCTime)
import qualified Data.UUID as UUID
import Crypto.BCrypt
import Web.JWT
import Data.Maybe (isJust)

import Models.User
import Database
import Config

-- JWT claims
data AuthUser = AuthUser
  { userId :: UUID.UUID
  , username :: TL.Text
  , email :: TL.Text
  } deriving (Generic, Show)

instance ToJSON AuthUser
instance FromJSON AuthUser

-- Create JWT token
createToken :: Config -> AuthUser -> IO TL.Text
createToken config user = do
  now <- getCurrentTime
  let expiry = addUTCTime (24 * 60 * 60) now  -- 24 hours
  
  let cs = mempty
        { iss = stringOrURI "re-shell-scotty"
        , sub = stringOrURI $ T.pack $ show $ userId user
        , exp = numericDate expiry
        , unregisteredClaims = Map.fromList
            [ ("username", String $ TL.toStrict $ username user)
            , ("email", String $ TL.toStrict $ email user)
            ]
        }
  
  return $ TL.fromStrict $ encodeSigned
    (hmacSecret $ T.pack $ jwtSecret config)
    mempty
    cs

-- Verify JWT token
verifyToken :: Config -> TL.Text -> Maybe AuthUser
verifyToken config token = do
  let secret = hmacSecret $ T.pack $ jwtSecret config
  jwt <- decodeAndVerifySignature secret $ TL.toStrict token
  
  -- Extract claims
  let claims = unregisteredClaims $ claims jwt
  uid <- sub $ claims jwt >>= stringOrURIToText >>= UUID.fromString . T.unpack
  uname <- Map.lookup "username" claims >>= \case
    String s -> Just $ TL.fromStrict s
    _ -> Nothing
  mail <- Map.lookup "email" claims >>= \case
    String s -> Just $ TL.fromStrict s
    _ -> Nothing
  
  return AuthUser
    { userId = uid
    , username = uname
    , email = mail
    }

-- Login handler
loginHandler :: Config -> Pool Connection -> ActionM ()
loginHandler config pool = do
  LoginRequest uname pass <- jsonData
  
  -- Find user by username
  maybeUser <- liftIO $ withResource pool $ \conn ->
    getUserByUsername conn uname
  
  case maybeUser of
    Nothing -> do
      status unauthorized401
      json $ object ["error" .= ("Invalid credentials" :: String)]
    
    Just user -> do
      -- Verify password
      let valid = validatePassword
            (TL.toStrict $ userPasswordHash user)
            (TL.toStrict pass)
      
      if valid
        then do
          -- Create token
          let authUser = AuthUser
                { userId = userId user
                , username = userUsername user
                , email = userEmail user
                }
          token <- liftIO $ createToken config authUser
          
          json $ object
            [ "token" .= token
            , "user" .= authUser
            ]
        else do
          status unauthorized401
          json $ object ["error" .= ("Invalid credentials" :: String)]

-- Logout handler (mainly for client-side token removal)
logoutHandler :: ActionM ()
logoutHandler = json $ object ["message" .= ("Logged out successfully" :: String)]

-- Get current user
currentUserHandler :: Pool Connection -> ActionM ()
currentUserHandler pool = do
  authUser <- getAuthUser
  json authUser

-- Extract auth user from request context
getAuthUser :: ActionM AuthUser
getAuthUser = do
  maybeUser <- reqHeader "X-Auth-User"
  case maybeUser of
    Nothing -> do
      status unauthorized401
      json $ object ["error" .= ("Unauthorized" :: String)]
      finish
    Just userData -> return $ read $ TL.unpack userData`,

    'src/Middleware.hs': `{-# LANGUAGE OverloadedStrings #-}

module Middleware where

import Web.Scotty
import qualified Data.Text.Lazy as TL
import Control.Monad (when)
import Network.HTTP.Types.Status

import Auth
import Config

-- Authentication middleware
authMiddleware :: Config -> ActionM () -> ActionM ()
authMiddleware config action = do
  -- Get authorization header
  maybeAuth <- header "Authorization"
  
  case maybeAuth of
    Nothing -> do
      status unauthorized401
      json $ object ["error" .= ("No authorization header" :: String)]
    
    Just authHeader -> do
      -- Extract token (Bearer <token>)
      let token = TL.drop 7 authHeader  -- Remove "Bearer "
      
      case verifyToken config token of
        Nothing -> do
          status unauthorized401
          json $ object ["error" .= ("Invalid token" :: String)]
        
        Just user -> do
          -- Add user to request context
          setHeader "X-Auth-User" $ TL.pack $ show user
          action

-- CORS middleware configuration
simpleCors :: Middleware
simpleCors app req respond = do
  let headers =
        [ ("Access-Control-Allow-Origin", "*")
        , ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        , ("Access-Control-Allow-Headers", "Content-Type, Authorization")
        ]
  
  if requestMethod req == "OPTIONS"
    then respond $ responseLBS status200 headers ""
    else app req $ \response -> do
      let (status, headers', body) = responseToRaw response
      respond $ responseFromRaw status (headers' ++ headers) body`,

    'src/Database.hs': `{-# LANGUAGE OverloadedStrings #-}

module Database where

import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.Migration
import Data.Pool
import Control.Exception (bracket)
import qualified Data.ByteString.Char8 as BS
import Data.Maybe (listToMaybe)
import qualified Data.UUID as UUID
import qualified Data.Text.Lazy as TL

import Models.User
import Models.Todo
import Config

-- Database connection
createConnectionPool :: DatabaseConfig -> IO (Pool Connection)
createConnectionPool config = createPool
  (connectPostgreSQL $ BS.pack $ databaseUrl config)
  close
  1  -- stripes
  60 -- keep alive (seconds)
  10 -- max connections

-- Run migrations
runMigrations :: Pool Connection -> IO ()
runMigrations pool = withResource pool $ \conn -> do
  result <- withTransaction conn $ runMigrations conn commands
  case result of
    MigrationError err -> error $ "Migration failed: " ++ err
    _ -> putStrLn "Migrations completed successfully"
  where
    commands =
      [ MigrationInitialization
      , MigrationDirectory "migrations"
      ]

-- User queries
insertUser :: Connection -> User -> IO (Either String User)
insertUser conn user = do
  result <- query conn
    "INSERT INTO users (id, username, email, password_hash, bio, created_at, updated_at) \
    \VALUES (?, ?, ?, ?, ?, ?, ?) \
    \ON CONFLICT (username) DO NOTHING \
    \RETURNING id, username, email, password_hash, bio, created_at, updated_at"
    ( userId user
    , userUsername user
    , userEmail user
    , userPasswordHash user
    , userBio user
    , userCreatedAt user
    , userUpdatedAt user
    )
  
  case result of
    [] -> return $ Left "Username already exists"
    [u] -> return $ Right u
    _ -> return $ Left "Unexpected error"

getUsers :: Connection -> IO [User]
getUsers conn = query_ conn
  "SELECT id, username, email, password_hash, bio, created_at, updated_at \
  \FROM users ORDER BY created_at DESC"

getUserById :: Connection -> UUID.UUID -> IO (Maybe User)
getUserById conn uid = listToMaybe <$> query conn
  "SELECT id, username, email, password_hash, bio, created_at, updated_at \
  \FROM users WHERE id = ?"
  (Only uid)

getUserByUsername :: Connection -> TL.Text -> IO (Maybe User)
getUserByUsername conn uname = listToMaybe <$> query conn
  "SELECT id, username, email, password_hash, bio, created_at, updated_at \
  \FROM users WHERE username = ?"
  (Only uname)

updateUser :: Connection -> UUID.UUID -> Maybe TL.Text -> Maybe TL.Text -> IO (Maybe User)
updateUser conn uid email bio = listToMaybe <$> query conn
  "UPDATE users SET email = COALESCE(?, email), bio = COALESCE(?, bio), \
  \updated_at = CURRENT_TIMESTAMP \
  \WHERE id = ? \
  \RETURNING id, username, email, password_hash, bio, created_at, updated_at"
  (email, bio, uid)

deleteUser :: Connection -> UUID.UUID -> IO Bool
deleteUser conn uid = do
  n <- execute conn "DELETE FROM users WHERE id = ?" (Only uid)
  return $ n > 0

-- Todo queries
insertTodo :: Connection -> Todo -> IO (Either String Todo)
insertTodo conn todo = do
  result <- query conn
    "INSERT INTO todos (id, user_id, title, description, completed, created_at, updated_at) \
    \VALUES (?, ?, ?, ?, ?, ?, ?) \
    \RETURNING id, user_id, title, description, completed, created_at, updated_at"
    ( todoId todo
    , todoUserId todo
    , todoTitle todo
    , todoDescription todo
    , todoCompleted todo
    , todoCreatedAt todo
    , todoUpdatedAt todo
    )
  
  case result of
    [t] -> return $ Right t
    _ -> return $ Left "Failed to create todo"

getTodosByUserId :: Connection -> UUID.UUID -> IO [Todo]
getTodosByUserId conn uid = query conn
  "SELECT id, user_id, title, description, completed, created_at, updated_at \
  \FROM todos WHERE user_id = ? ORDER BY created_at DESC"
  (Only uid)

getTodoById :: Connection -> UUID.UUID -> IO (Maybe Todo)
getTodoById conn tid = listToMaybe <$> query conn
  "SELECT id, user_id, title, description, completed, created_at, updated_at \
  \FROM todos WHERE id = ?"
  (Only tid)

updateTodo :: Connection -> UUID.UUID -> Maybe TL.Text -> Maybe TL.Text -> Maybe Bool -> IO (Maybe Todo)
updateTodo conn tid title desc completed = listToMaybe <$> query conn
  "UPDATE todos SET \
  \title = COALESCE(?, title), \
  \description = COALESCE(?, description), \
  \completed = COALESCE(?, completed), \
  \updated_at = CURRENT_TIMESTAMP \
  \WHERE id = ? \
  \RETURNING id, user_id, title, description, completed, created_at, updated_at"
  (title, desc, completed, tid)

deleteTodo :: Connection -> UUID.UUID -> IO Bool
deleteTodo conn tid = do
  n <- execute conn "DELETE FROM todos WHERE id = ?" (Only tid)
  return $ n > 0`,

    'src/Models/User.hs': `{-# LANGUAGE DeriveGeneric #-}

module Models.User where

import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified Data.Text.Lazy as TL
import qualified Data.UUID as UUID
import Data.Time (UTCTime)
import Database.PostgreSQL.Simple.FromRow

data User = User
  { userId :: UUID.UUID
  , userUsername :: TL.Text
  , userEmail :: TL.Text
  , userPasswordHash :: TL.Text
  , userBio :: Maybe TL.Text
  , userCreatedAt :: UTCTime
  , userUpdatedAt :: UTCTime
  } deriving (Generic, Show)

instance FromJSON User
instance ToJSON User
instance FromRow User where
  fromRow = User <$> field <*> field <*> field <*> field 
                 <*> field <*> field <*> field`,

    'src/Models/Todo.hs': `{-# LANGUAGE DeriveGeneric #-}

module Models.Todo where

import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified Data.Text.Lazy as TL
import qualified Data.UUID as UUID
import Data.Time (UTCTime)
import Database.PostgreSQL.Simple.FromRow

data Todo = Todo
  { todoId :: UUID.UUID
  , todoUserId :: UUID.UUID
  , todoTitle :: TL.Text
  , todoDescription :: Maybe TL.Text
  , todoCompleted :: Bool
  , todoCreatedAt :: UTCTime
  , todoUpdatedAt :: UTCTime
  } deriving (Generic, Show)

instance FromJSON Todo
instance ToJSON Todo
instance FromRow Todo where
  fromRow = Todo <$> field <*> field <*> field <*> field 
                 <*> field <*> field <*> field`,

    'src/Config.hs': `{-# LANGUAGE DeriveGeneric #-}

module Config where

import Data.Aeson (FromJSON, decode)
import GHC.Generics (Generic)
import qualified Data.ByteString.Lazy as BSL
import System.Environment (lookupEnv)
import Data.Maybe (fromMaybe)

data Config = Config
  { port :: Int
  , databaseUrl :: String
  , jwtSecret :: String
  , logLevel :: String
  } deriving (Generic, Show)

instance FromJSON Config

data DatabaseConfig = DatabaseConfig
  { dbHost :: String
  , dbPort :: Int
  , dbName :: String
  , dbUser :: String
  , dbPassword :: String
  } deriving (Generic, Show)

instance FromJSON DatabaseConfig

-- Load configuration from file or environment
loadConfig :: IO Config
loadConfig = do
  -- Try to load from config file
  maybeConfig <- decode <$> BSL.readFile "config/app.json" 
    `catch` \(_ :: IOError) -> return Nothing
  
  case maybeConfig of
    Just cfg -> return cfg
    Nothing -> do
      -- Fall back to environment variables
      port <- fromMaybe "3000" <$> lookupEnv "PORT"
      dbUrl <- fromMaybe "postgresql://localhost/scotty_dev" <$> lookupEnv "DATABASE_URL"
      secret <- fromMaybe "development-secret-key" <$> lookupEnv "JWT_SECRET"
      level <- fromMaybe "info" <$> lookupEnv "LOG_LEVEL"
      
      return Config
        { port = read port
        , databaseUrl = dbUrl
        , jwtSecret = secret
        , logLevel = level
        }

-- Database config helper
dbConfig :: Config -> DatabaseConfig
dbConfig cfg = DatabaseConfig
  { dbHost = "localhost"
  , dbPort = 5432
  , dbName = "scotty_dev"
  , dbUser = "scotty"
  , dbPassword = "scotty"
  }`,

    'scotty-app.cabal': `cabal-version:      2.4
name:               scotty-app
version:            0.1.0.0
synopsis:           A lightweight web application built with Scotty
description:        REST API with authentication, database integration, and more
license:            MIT
license-file:       LICENSE
author:             Re-Shell Team
maintainer:         team@re-shell.com
category:           Web
build-type:         Simple
extra-source-files: README.md

common warnings
    ghc-options: -Wall

library
    import:           warnings
    exposed-modules:  Routes
                    , Auth
                    , Database
                    , Config
                    , Middleware
                    , Models.User
                    , Models.Todo
                    , Handlers.User
                    , Handlers.Todo
                    , Handlers.Health
    build-depends:    base ^>=4.17.0.0
                    , scotty >= 0.20
                    , wai
                    , wai-extra
                    , wai-cors
                    , warp
                    , aeson
                    , text
                    , bytestring
                    , postgresql-simple
                    , postgresql-simple-migration
                    , resource-pool
                    , bcrypt
                    , jwt
                    , uuid
                    , time
                    , mtl
                    , containers
                    , http-types
    hs-source-dirs:   src
    default-language: Haskell2010

executable scotty-app
    import:           warnings
    main-is:          Main.hs
    build-depends:    base ^>=4.17.0.0
                    , scotty-app
                    , scotty
                    , wai
                    , wai-extra
                    , wai-cors
                    , aeson
                    , text
    hs-source-dirs:   app
    default-language: Haskell2010

test-suite scotty-app-test
    import:           warnings
    default-language: Haskell2010
    type:             exitcode-stdio-1.0
    hs-source-dirs:   test
    main-is:          Spec.hs
    other-modules:    AuthSpec
                    , DatabaseSpec
                    , HandlersSpec
    build-depends:    base ^>=4.17.0.0
                    , scotty-app
                    , hspec
                    , hspec-wai
                    , QuickCheck
                    , scotty
                    , wai
                    , aeson
                    , text`,

    'stack.yaml': `resolver: lts-21.0

packages:
- .

extra-deps:
- scotty-0.20.1
- wai-cors-0.2.7
- jwt-0.11.0
- bcrypt-0.0.11

flags: {}

extra-package-dbs: []`,

    'package.yaml': `name:                scotty-app
version:             0.1.0.0
github:              "reshell/scotty-app"
license:             MIT
author:              "Re-Shell Team"
maintainer:          "team@re-shell.com"
copyright:           "2024 Re-Shell Team"

extra-source-files:
- README.md

synopsis:            A lightweight web application built with Scotty
category:            Web

description:         Please see the README on GitHub

dependencies:
- base >= 4.7 && < 5
- scotty >= 0.20
- wai
- wai-extra
- wai-cors
- warp
- aeson
- text
- bytestring
- postgresql-simple
- postgresql-simple-migration
- resource-pool
- bcrypt
- jwt
- uuid
- time
- mtl
- containers
- http-types

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
  scotty-app:
    main:                Main.hs
    source-dirs:         app
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - scotty-app

tests:
  scotty-app-test:
    main:                Spec.hs
    source-dirs:         test
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - scotty-app
    - hspec
    - hspec-wai
    - QuickCheck`,

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
.ghc.environment.*
*.cabal`,

    'README.md': `# Scotty Web Application

A lightweight web application built with the Scotty web framework for Haskell.

## Features

- Simple and intuitive routing DSL
- JWT authentication
- PostgreSQL database integration
- RESTful API design
- Middleware support (CORS, logging, static files)
- User management
- Todo CRUD operations
- JSON request/response handling
- Session management
- Error handling

## Prerequisites

- GHC 9.2.x or higher
- Stack or Cabal
- PostgreSQL
- Git

## Quick Start

1. **Clone the repository**
   \`\`\`bash
   git clone <repository-url>
   cd scotty-app
   \`\`\`

2. **Install dependencies**
   \`\`\`bash
   # Using Stack
   stack setup
   stack build

   # Using Cabal
   cabal update
   cabal build
   \`\`\`

3. **Set up the database**
   \`\`\`bash
   createdb scotty_dev
   psql scotty_dev < migrations/001_initial_schema.sql
   \`\`\`

4. **Configure environment**
   \`\`\`bash
   export DATABASE_URL="postgresql://localhost/scotty_dev"
   export JWT_SECRET="your-secret-key"
   export PORT=3000
   \`\`\`

5. **Run the application**
   \`\`\`bash
   # Using Stack
   stack exec scotty-app

   # Using Cabal
   cabal run scotty-app
   \`\`\`

## Project Structure

\`\`\`
.
├── app/
│   └── Main.hs              # Application entry point
├── src/
│   ├── Routes.hs            # Route definitions
│   ├── Auth.hs              # Authentication logic
│   ├── Database.hs          # Database operations
│   ├── Config.hs            # Configuration management
│   ├── Middleware.hs        # Custom middleware
│   ├── Models/
│   │   ├── User.hs          # User model
│   │   └── Todo.hs          # Todo model
│   └── Handlers/
│       ├── User.hs          # User handlers
│       ├── Todo.hs          # Todo handlers
│       └── Health.hs        # Health check handler
├── test/
│   └── Spec.hs              # Test suite
├── migrations/              # Database migrations
├── public/                  # Static files
├── config/                  # Configuration files
├── scotty-app.cabal         # Cabal configuration
├── stack.yaml               # Stack configuration
└── package.yaml             # Package configuration
\`\`\`

## API Endpoints

### Authentication
- \`POST /api/auth/register\` - Register a new user
- \`POST /api/auth/login\` - Login user
- \`POST /api/auth/logout\` - Logout user
- \`GET /api/auth/me\` - Get current user

### Users (Protected)
- \`GET /api/users\` - List all users
- \`GET /api/users/:id\` - Get user by ID
- \`PUT /api/users/:id\` - Update user
- \`DELETE /api/users/:id\` - Delete user

### Todos (Protected)
- \`GET /api/todos\` - List user's todos
- \`POST /api/todos\` - Create a new todo
- \`GET /api/todos/:id\` - Get todo by ID
- \`PUT /api/todos/:id\` - Update todo
- \`DELETE /api/todos/:id\` - Delete todo

### Health
- \`GET /health\` - Health check endpoint

## Development

### Running Tests
\`\`\`bash
# Using Stack
stack test

# Using Cabal
cabal test
\`\`\`

### Building for Production
\`\`\`bash
# Using Stack
stack build --pedantic

# Using Cabal
cabal build -O2
\`\`\`

### Database Migrations
\`\`\`bash
# Run migrations
psql $DATABASE_URL < migrations/001_initial_schema.sql
\`\`\`

## Configuration

Configuration can be provided through:
1. Environment variables
2. \`config/app.json\` file

### Environment Variables
- \`PORT\` - Server port (default: 3000)
- \`DATABASE_URL\` - PostgreSQL connection string
- \`JWT_SECRET\` - Secret key for JWT tokens
- \`LOG_LEVEL\` - Logging level (default: info)

## Docker Support

\`\`\`dockerfile
FROM haskell:9.2

WORKDIR /app

# Copy project files
COPY . .

# Build the application
RUN stack setup
RUN stack build --copy-bins

# Run the application
CMD ["stack", "exec", "scotty-app"]
\`\`\`

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - see LICENSE file for details`,

    'migrations/001_initial_schema.sql': `-- Initial database schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    bio TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Todos table
CREATE TABLE IF NOT EXISTS todos (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_todos_user_id ON todos(user_id);
CREATE INDEX idx_todos_created_at ON todos(created_at DESC);

-- Updated at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_todos_updated_at BEFORE UPDATE ON todos
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://scotty:scotty@db:5432/scotty_dev
      - JWT_SECRET=development-secret-key
      - PORT=3000
    depends_on:
      - db
    volumes:
      - .:/app
      - stack-cache:/root/.stack
    command: stack exec scotty-app

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=scotty
      - POSTGRES_PASSWORD=scotty
      - POSTGRES_DB=scotty_dev
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"

volumes:
  postgres-data:
  stack-cache:`,

    'Dockerfile': `FROM haskell:9.2 AS builder

WORKDIR /build

# Copy package files
COPY package.yaml stack.yaml ./
COPY *.cabal ./

# Install dependencies
RUN stack setup
RUN stack build --dependencies-only

# Copy source code
COPY . .

# Build application
RUN stack build --copy-bins --local-bin-path /app

# Runtime image
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/scotty-app /app/
COPY public /app/public
COPY config /app/config

EXPOSE 3000

CMD ["/app/scotty-app"]`,

    '.env.example': `# Server configuration
PORT=3000
LOG_LEVEL=info

# Database configuration
DATABASE_URL=postgresql://scotty:scotty@localhost:5432/scotty_dev

# Authentication
JWT_SECRET=your-secret-key-here

# Development
NODE_ENV=development`
  }
};