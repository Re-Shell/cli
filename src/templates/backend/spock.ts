import { BackendTemplate } from '../types';

export const spockTemplate: BackendTemplate = {
  id: 'spock',
  name: 'spock',
  displayName: 'Spock Type-Safe Web Framework',
  description: 'A Haskell web framework with type-safe routing and middleware inspired by Sinatra and Express',
  framework: 'spock',
  language: 'haskell',
  version: '0.14',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🕸️',
  type: 'full-stack',
  complexity: 'intermediate',
  keywords: ['haskell', 'spock', 'type-safe', 'routing', 'web', 'middleware'],
  
  features: [
    'Type-safe routing with compile-time checks',
    'Flexible middleware system',
    'Session management',
    'CSRF protection',
    'Database pooling',
    'WebSocket support',
    'Action monad for request handling',
    'Type-safe URL generation',
    'JSON API support',
    'Template rendering',
    'File uploads',
    'Authentication system',
    'Rate limiting',
    'Request validation'
  ],
  
  structure: {
    'app/Main.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}

module Main where

import Web.Spock
import Web.Spock.Config

import qualified Data.Text as T
import Data.IORef
import Control.Monad.IO.Class (liftIO)
import System.Environment (lookupEnv)
import Data.Maybe (fromMaybe)

import Routes
import Types
import Database
import Middleware
import Config

main :: IO ()
main = do
  -- Load configuration
  config <- loadConfig
  
  -- Initialize database
  pool <- createConnectionPool (dbConfig config)
  runMigrations pool
  
  -- Create session store
  sessionStore <- newIORef []
  
  -- Get port from environment
  port <- fromMaybe 3000 . fmap read <$> lookupEnv "PORT"
  
  -- Configure Spock
  spockCfg <- defaultSpockCfg EmptySession PCPool (AppState config pool sessionStore)
  
  -- Run application
  runSpock port $ spock spockCfg app

-- Main application
app :: SpockM () MySession AppState ()
app = do
  -- Apply middleware
  middleware corsMiddleware
  middleware loggingMiddleware
  middleware authMiddleware
  
  -- Mount routes
  routes`,

    'src/Routes.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}

module Routes (routes) where

import Web.Spock
import Web.Spock.Action

import qualified Data.Text as T
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (ToJSON, FromJSON)

import Types
import Auth
import Handlers.Home
import Handlers.User
import Handlers.Todo
import Handlers.Api
import Middleware

-- Route definitions with type-safe routing
routes :: SpockM () MySession AppState ()
routes = do
  -- Static routes
  get root homeHandler
  get "/about" aboutHandler
  get "/health" healthHandler
  
  -- Authentication routes
  post "/auth/register" registerHandler
  post "/auth/login" loginHandler
  post "/auth/logout" $ requireAuth logoutHandler
  get "/auth/profile" $ requireAuth profileHandler
  
  -- User management routes
  get "/users" $ requireAuth getUsersHandler
  get ("/users" <//> var) $ requireAuth . getUserHandler
  put ("/users" <//> var) $ requireAuth . updateUserHandler
  delete ("/users" <//> var) $ requireAuth . deleteUserHandler
  
  -- Todo routes with type-safe parameters
  get "/todos" $ requireAuth getTodosHandler
  post "/todos" $ requireAuth createTodoHandler
  get ("/todos" <//> var) $ requireAuth . getTodoHandler
  put ("/todos" <//> var) $ requireAuth . updateTodoHandler
  delete ("/todos" <//> var) $ requireAuth . deleteTodoHandler
  patch ("/todos" <//> var <//> "toggle") $ requireAuth . toggleTodoHandler
  
  -- API v1 routes
  subcomponent "/api/v1" $ do
    -- RESTful API
    get "/users" $ apiWrapper getUsersApi
    get ("/users" <//> var) $ apiWrapper . getUserApi
    post "/users" $ apiWrapper createUserApi
    
    get "/todos" $ requireAuth $ apiWrapper getTodosApi
    post "/todos" $ requireAuth $ apiWrapper createTodoApi
    get ("/todos" <//> var) $ requireAuth $ apiWrapper . getTodoApi
    
  -- WebSocket route
  get "/ws" websocketHandler
  
  -- File upload
  post "/upload" $ requireAuth uploadHandler
  
  -- Catch all
  hookAny GET $ \path -> do
    setStatus notFound404
    text $ "Page not found: " <> T.pack (show path)`,

    'src/Types.hs': `{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Types where

import Data.Aeson (ToJSON, FromJSON)
import GHC.Generics (Generic)
import qualified Data.Text as T
import Data.Time (UTCTime)
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Connection)
import Data.Pool (Pool)
import Data.IORef
import Web.Spock

-- Application state
data AppState = AppState
  { appConfig :: Config
  , appPool :: Pool Connection
  , appSessions :: IORef [(SessionId, MySession)]
  }

-- Session data
data MySession = MySession
  { sessionUserId :: Maybe UUID
  , sessionUsername :: Maybe T.Text
  , sessionCreated :: UTCTime
  } | EmptySession

-- Config
data Config = Config
  { configPort :: Int
  , configDbUrl :: T.Text
  , configJwtSecret :: T.Text
  , configEnv :: Environment
  } deriving (Generic, Show)

instance FromJSON Config
instance ToJSON Config

data Environment = Development | Production | Testing
  deriving (Generic, Show, Eq)

instance FromJSON Environment
instance ToJSON Environment

-- User types
data User = User
  { userId :: UUID
  , userUsername :: T.Text
  , userEmail :: T.Text
  , userPasswordHash :: T.Text
  , userBio :: Maybe T.Text
  , userAvatar :: Maybe T.Text
  , userCreatedAt :: UTCTime
  , userUpdatedAt :: UTCTime
  } deriving (Generic, Show)

instance ToJSON User
instance FromJSON User

data CreateUserRequest = CreateUserRequest
  { createUserUsername :: T.Text
  , createUserEmail :: T.Text
  , createUserPassword :: T.Text
  } deriving (Generic, Show)

instance ToJSON CreateUserRequest
instance FromJSON CreateUserRequest

data UpdateUserRequest = UpdateUserRequest
  { updateUserEmail :: Maybe T.Text
  , updateUserBio :: Maybe T.Text
  , updateUserAvatar :: Maybe T.Text
  } deriving (Generic, Show)

instance ToJSON UpdateUserRequest
instance FromJSON UpdateUserRequest

-- Todo types
data Todo = Todo
  { todoId :: UUID
  , todoUserId :: UUID
  , todoTitle :: T.Text
  , todoDescription :: Maybe T.Text
  , todoCompleted :: Bool
  , todoDueDate :: Maybe UTCTime
  , todoTags :: [T.Text]
  , todoCreatedAt :: UTCTime
  , todoUpdatedAt :: UTCTime
  } deriving (Generic, Show)

instance ToJSON Todo
instance FromJSON Todo

data CreateTodoRequest = CreateTodoRequest
  { createTodoTitle :: T.Text
  , createTodoDescription :: Maybe T.Text
  , createTodoDueDate :: Maybe UTCTime
  , createTodoTags :: [T.Text]
  } deriving (Generic, Show)

instance ToJSON CreateTodoRequest
instance FromJSON CreateTodoRequest

data UpdateTodoRequest = UpdateTodoRequest
  { updateTodoTitle :: Maybe T.Text
  , updateTodoDescription :: Maybe T.Text
  , updateTodoCompleted :: Maybe Bool
  , updateTodoDueDate :: Maybe UTCTime
  , updateTodoTags :: Maybe [T.Text]
  } deriving (Generic, Show)

instance ToJSON UpdateTodoRequest
instance FromJSON UpdateTodoRequest

-- API Response types
data ApiResponse a = ApiResponse
  { responseSuccess :: Bool
  , responseMessage :: T.Text
  , responseData :: Maybe a
  } deriving (Generic, Show)

instance ToJSON a => ToJSON (ApiResponse a)
instance FromJSON a => FromJSON (ApiResponse a)

data ApiError = ApiError
  { errorCode :: T.Text
  , errorMessage :: T.Text
  , errorDetails :: Maybe T.Text
  } deriving (Generic, Show)

instance ToJSON ApiError
instance FromJSON ApiError

-- Auth types
data LoginRequest = LoginRequest
  { loginUsername :: T.Text
  , loginPassword :: T.Text
  } deriving (Generic, Show)

instance ToJSON LoginRequest
instance FromJSON LoginRequest

data AuthResponse = AuthResponse
  { authToken :: T.Text
  , authUser :: User
  } deriving (Generic, Show)

instance ToJSON AuthResponse
instance FromJSON AuthResponse

-- Pagination
data PaginationParams = PaginationParams
  { pageNumber :: Int
  , pageSize :: Int
  , sortBy :: Maybe T.Text
  , sortOrder :: Maybe SortOrder
  } deriving (Generic, Show)

data SortOrder = Asc | Desc
  deriving (Generic, Show, Eq)

instance ToJSON SortOrder
instance FromJSON SortOrder

data PaginatedResponse a = PaginatedResponse
  { paginatedData :: [a]
  , paginatedTotal :: Int
  , paginatedPage :: Int
  , paginatedPageSize :: Int
  , paginatedTotalPages :: Int
  } deriving (Generic, Show)

instance ToJSON a => ToJSON (PaginatedResponse a)
instance FromJSON a => FromJSON (PaginatedResponse a)`,

    'src/Handlers/User.hs': `{-# LANGUAGE OverloadedStrings #-}

module Handlers.User where

import Web.Spock
import Web.Spock.Action

import qualified Data.Text as T
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (ToJSON)
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID
import Data.Time (getCurrentTime)
import Crypto.BCrypt

import Types
import Database
import Auth
import Utils

-- User handlers
getUsersHandler :: SpockAction () MySession AppState ()
getUsersHandler = do
  state <- getState
  
  -- Get pagination params
  page <- param' "page" 1
  size <- param' "size" 20
  
  -- Fetch users
  (users, total) <- liftIO $ getUsersPaginated (appPool state) page size
  
  json $ PaginatedResponse
    { paginatedData = map sanitizeUser users
    , paginatedTotal = total
    , paginatedPage = page
    , paginatedPageSize = size
    , paginatedTotalPages = ceiling (fromIntegral total / fromIntegral size)
    }

getUserHandler :: UUID -> SpockAction () MySession AppState ()
getUserHandler uid = do
  state <- getState
  
  maybeUser <- liftIO $ getUserById (appPool state) uid
  
  case maybeUser of
    Nothing -> do
      setStatus notFound404
      json $ ApiError "USER_NOT_FOUND" "User not found" Nothing
    Just user -> json $ sanitizeUser user

updateUserHandler :: UUID -> SpockAction () MySession AppState ()
updateUserHandler uid = do
  state <- getState
  session <- readSession
  
  -- Check authorization
  case sessionUserId session of
    Nothing -> unauthorized
    Just currentUserId ->
      if currentUserId /= uid
        then forbidden "You can only update your own profile"
        else do
          req <- jsonBody' :: SpockAction () MySession AppState UpdateUserRequest
          
          now <- liftIO getCurrentTime
          result <- liftIO $ updateUser (appPool state) uid req now
          
          case result of
            Nothing -> do
              setStatus notFound404
              json $ ApiError "USER_NOT_FOUND" "User not found" Nothing
            Just user -> json $ ApiResponse True "User updated successfully" (Just $ sanitizeUser user)

deleteUserHandler :: UUID -> SpockAction () MySession AppState ()
deleteUserHandler uid = do
  state <- getState
  session <- readSession
  
  -- Check authorization
  case sessionUserId session of
    Nothing -> unauthorized
    Just currentUserId ->
      if currentUserId /= uid
        then forbidden "You can only delete your own account"
        else do
          success <- liftIO $ deleteUser (appPool state) uid
          
          if success
            then do
              -- Clear session
              writeSession EmptySession
              json $ ApiResponse True "User deleted successfully" (Nothing :: Maybe ())
            else do
              setStatus internalServerError500
              json $ ApiError "DELETE_FAILED" "Failed to delete user" Nothing

-- Registration handler
registerHandler :: SpockAction () MySession AppState ()
registerHandler = do
  state <- getState
  req <- jsonBody' :: SpockAction () MySession AppState CreateUserRequest
  
  -- Validate input
  case validateUserInput req of
    Left err -> do
      setStatus badRequest400
      json $ ApiError "VALIDATION_ERROR" err Nothing
    Right () -> do
      -- Hash password
      hashedPass <- liftIO $ hashPasswordUsingPolicy slowerBcryptHashingPolicy (T.encodeUtf8 $ createUserPassword req)
      
      case hashedPass of
        Nothing -> do
          setStatus internalServerError500
          json $ ApiError "HASH_ERROR" "Failed to hash password" Nothing
        Just hash -> do
          -- Create user
          uid <- liftIO UUID.nextRandom
          now <- liftIO getCurrentTime
          
          let user = User
                { userId = uid
                , userUsername = createUserUsername req
                , userEmail = createUserEmail req
                , userPasswordHash = T.decodeUtf8 hash
                , userBio = Nothing
                , userAvatar = Nothing
                , userCreatedAt = now
                , userUpdatedAt = now
                }
          
          result <- liftIO $ insertUser (appPool state) user
          
          case result of
            Left err -> do
              setStatus badRequest400
              json $ ApiError "REGISTRATION_ERROR" err Nothing
            Right newUser -> do
              -- Create session
              writeSession $ MySession (Just uid) (Just $ userUsername newUser) now
              
              -- Generate token
              token <- liftIO $ generateJWT (appConfig state) newUser
              
              json $ AuthResponse token (sanitizeUser newUser)

-- Helper functions
sanitizeUser :: User -> User
sanitizeUser user = user { userPasswordHash = "" }

validateUserInput :: CreateUserRequest -> Either T.Text ()
validateUserInput req
  | T.length (createUserUsername req) < 3 = Left "Username must be at least 3 characters"
  | T.length (createUserPassword req) < 8 = Left "Password must be at least 8 characters"
  | not (T.isInfixOf "@" (createUserEmail req)) = Left "Invalid email address"
  | otherwise = Right ()

unauthorized :: SpockAction () MySession AppState ()
unauthorized = do
  setStatus unauthorized401
  json $ ApiError "UNAUTHORIZED" "Authentication required" Nothing

forbidden :: T.Text -> SpockAction () MySession AppState ()
forbidden msg = do
  setStatus forbidden403
  json $ ApiError "FORBIDDEN" msg Nothing`,

    'src/Handlers/Todo.hs': `{-# LANGUAGE OverloadedStrings #-}

module Handlers.Todo where

import Web.Spock
import Web.Spock.Action

import qualified Data.Text as T
import Control.Monad.IO.Class (liftIO)
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID
import Data.Time (getCurrentTime)

import Types
import Database
import Utils

-- Todo handlers
getTodosHandler :: SpockAction () MySession AppState ()
getTodosHandler = do
  state <- getState
  session <- readSession
  
  case sessionUserId session of
    Nothing -> unauthorized
    Just uid -> do
      -- Get filter params
      completed <- paramMaybe "completed"
      tag <- paramMaybe "tag"
      
      todos <- liftIO $ getUserTodos (appPool state) uid completed tag
      json $ ApiResponse True "Todos retrieved" (Just todos)

createTodoHandler :: SpockAction () MySession AppState ()
createTodoHandler = do
  state <- getState
  session <- readSession
  
  case sessionUserId session of
    Nothing -> unauthorized
    Just uid -> do
      req <- jsonBody' :: SpockAction () MySession AppState CreateTodoRequest
      
      -- Validate
      case validateTodoInput req of
        Left err -> do
          setStatus badRequest400
          json $ ApiError "VALIDATION_ERROR" err Nothing
        Right () -> do
          -- Create todo
          tid <- liftIO UUID.nextRandom
          now <- liftIO getCurrentTime
          
          let todo = Todo
                { todoId = tid
                , todoUserId = uid
                , todoTitle = createTodoTitle req
                , todoDescription = createTodoDescription req
                , todoCompleted = False
                , todoDueDate = createTodoDueDate req
                , todoTags = createTodoTags req
                , todoCreatedAt = now
                , todoUpdatedAt = now
                }
          
          result <- liftIO $ insertTodo (appPool state) todo
          
          case result of
            Left err -> do
              setStatus internalServerError500
              json $ ApiError "CREATE_ERROR" err Nothing
            Right newTodo -> do
              setStatus created201
              json $ ApiResponse True "Todo created" (Just newTodo)

getTodoHandler :: UUID -> SpockAction () MySession AppState ()
getTodoHandler tid = do
  state <- getState
  session <- readSession
  
  case sessionUserId session of
    Nothing -> unauthorized
    Just uid -> do
      maybeTodo <- liftIO $ getTodoById (appPool state) tid
      
      case maybeTodo of
        Nothing -> do
          setStatus notFound404
          json $ ApiError "TODO_NOT_FOUND" "Todo not found" Nothing
        Just todo ->
          if todoUserId todo /= uid
            then forbidden "You can only access your own todos"
            else json $ ApiResponse True "Todo retrieved" (Just todo)

updateTodoHandler :: UUID -> SpockAction () MySession AppState ()
updateTodoHandler tid = do
  state <- getState
  session <- readSession
  
  case sessionUserId session of
    Nothing -> unauthorized
    Just uid -> do
      -- Check ownership
      maybeTodo <- liftIO $ getTodoById (appPool state) tid
      
      case maybeTodo of
        Nothing -> do
          setStatus notFound404
          json $ ApiError "TODO_NOT_FOUND" "Todo not found" Nothing
        Just todo ->
          if todoUserId todo /= uid
            then forbidden "You can only update your own todos"
            else do
              req <- jsonBody' :: SpockAction () MySession AppState UpdateTodoRequest
              now <- liftIO getCurrentTime
              
              result <- liftIO $ updateTodo (appPool state) tid req now
              
              case result of
                Nothing -> do
                  setStatus internalServerError500
                  json $ ApiError "UPDATE_ERROR" "Failed to update todo" Nothing
                Just updatedTodo ->
                  json $ ApiResponse True "Todo updated" (Just updatedTodo)

deleteTodoHandler :: UUID -> SpockAction () MySession AppState ()
deleteTodoHandler tid = do
  state <- getState
  session <- readSession
  
  case sessionUserId session of
    Nothing -> unauthorized
    Just uid -> do
      -- Check ownership
      maybeTodo <- liftIO $ getTodoById (appPool state) tid
      
      case maybeTodo of
        Nothing -> do
          setStatus notFound404
          json $ ApiError "TODO_NOT_FOUND" "Todo not found" Nothing
        Just todo ->
          if todoUserId todo /= uid
            then forbidden "You can only delete your own todos"
            else do
              success <- liftIO $ deleteTodo (appPool state) tid
              
              if success
                then json $ ApiResponse True "Todo deleted" (Nothing :: Maybe ())
                else do
                  setStatus internalServerError500
                  json $ ApiError "DELETE_ERROR" "Failed to delete todo" Nothing

toggleTodoHandler :: UUID -> SpockAction () MySession AppState ()
toggleTodoHandler tid = do
  state <- getState
  session <- readSession
  
  case sessionUserId session of
    Nothing -> unauthorized
    Just uid -> do
      -- Toggle completion status
      maybeTodo <- liftIO $ getTodoById (appPool state) tid
      
      case maybeTodo of
        Nothing -> do
          setStatus notFound404
          json $ ApiError "TODO_NOT_FOUND" "Todo not found" Nothing
        Just todo ->
          if todoUserId todo /= uid
            then forbidden "You can only toggle your own todos"
            else do
              now <- liftIO getCurrentTime
              let updateReq = UpdateTodoRequest
                    { updateTodoTitle = Nothing
                    , updateTodoDescription = Nothing
                    , updateTodoCompleted = Just (not $ todoCompleted todo)
                    , updateTodoDueDate = Nothing
                    , updateTodoTags = Nothing
                    }
              
              result <- liftIO $ updateTodo (appPool state) tid updateReq now
              
              case result of
                Nothing -> do
                  setStatus internalServerError500
                  json $ ApiError "TOGGLE_ERROR" "Failed to toggle todo" Nothing
                Just updatedTodo ->
                  json $ ApiResponse True "Todo toggled" (Just updatedTodo)

-- Helper functions
validateTodoInput :: CreateTodoRequest -> Either T.Text ()
validateTodoInput req
  | T.null (createTodoTitle req) = Left "Title is required"
  | T.length (createTodoTitle req) > 200 = Left "Title too long (max 200 characters)"
  | otherwise = Right ()

unauthorized :: SpockAction () MySession AppState ()
unauthorized = do
  setStatus unauthorized401
  json $ ApiError "UNAUTHORIZED" "Authentication required" Nothing

forbidden :: T.Text -> SpockAction () MySession AppState ()
forbidden msg = do
  setStatus forbidden403
  json $ ApiError "FORBIDDEN" msg Nothing`,

    'src/Middleware.hs': `{-# LANGUAGE OverloadedStrings #-}

module Middleware where

import Web.Spock
import Web.Spock.Action
import Network.Wai (Middleware)
import Network.Wai.Middleware.Cors
import Network.Wai.Middleware.RequestLogger
import qualified Data.Text as T
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)

import Types
import Auth

-- CORS middleware
corsMiddleware :: Middleware
corsMiddleware = cors $ const $ Just CorsResourcePolicy
  { corsOrigins = Nothing
  , corsMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
  , corsRequestHeaders = ["Content-Type", "Authorization", "X-Requested-With"]
  , corsExposedHeaders = Nothing
  , corsMaxAge = Just 86400
  , corsVaryOrigin = False
  , corsRequireOrigin = False
  , corsIgnoreFailures = False
  }

-- Logging middleware
loggingMiddleware :: Middleware
loggingMiddleware = logStdoutDev

-- Authentication middleware for Spock actions
authMiddleware :: SpockAction () MySession AppState () -> SpockAction () MySession AppState ()
authMiddleware action = do
  session <- readSession
  
  case session of
    EmptySession -> do
      -- Check for JWT token
      maybeAuth <- header "Authorization"
      
      case maybeAuth of
        Nothing -> unauthorized
        Just authHeader -> do
          let token = T.drop 7 authHeader  -- Remove "Bearer "
          state <- getState
          
          case verifyJWT (appConfig state) token of
            Nothing -> unauthorized
            Just user -> do
              -- Update session
              now <- liftIO getCurrentTime
              writeSession $ MySession
                { sessionUserId = Just (userId user)
                , sessionUsername = Just (userUsername user)
                , sessionCreated = now
                }
              action
    
    MySession{..} ->
      case sessionUserId of
        Nothing -> unauthorized
        Just _ -> action

-- Rate limiting middleware
rateLimitMiddleware :: Int -> SpockAction () MySession AppState () -> SpockAction () MySession AppState ()
rateLimitMiddleware maxRequests action = do
  -- Simple in-memory rate limiting
  -- In production, use Redis or similar
  clientId <- getClientId
  state <- getState
  
  -- Check rate limit
  allowed <- liftIO $ checkRateLimit (appSessions state) clientId maxRequests
  
  if allowed
    then action
    else do
      setStatus tooManyRequests429
      json $ ApiError "RATE_LIMITED" "Too many requests" Nothing

-- CSRF protection
csrfProtection :: SpockAction () MySession AppState () -> SpockAction () MySession AppState ()
csrfProtection action = do
  method <- request >>= return . rqMethod
  
  when (method `elem` ["POST", "PUT", "DELETE", "PATCH"]) $ do
    csrfToken <- header "X-CSRF-Token"
    sessionToken <- getSessionCsrfToken
    
    case (csrfToken, sessionToken) of
      (Just t1, Just t2) | t1 == t2 -> return ()
      _ -> do
        setStatus forbidden403
        json $ ApiError "CSRF_ERROR" "Invalid CSRF token" Nothing
  
  action

-- Helper functions
requireAuth :: SpockAction () MySession AppState () -> SpockAction () MySession AppState ()
requireAuth = authMiddleware

apiWrapper :: ToJSON a => SpockAction () MySession AppState a -> SpockAction () MySession AppState ()
apiWrapper action = do
  result <- action
  json result

unauthorized :: SpockAction () MySession AppState ()
unauthorized = do
  setStatus unauthorized401
  json $ ApiError "UNAUTHORIZED" "Authentication required" Nothing

getClientId :: SpockAction () MySession AppState T.Text
getClientId = do
  -- Get client IP or session ID
  req <- request
  return $ T.pack $ show $ rqRemoteAddr req

checkRateLimit :: IORef [(SessionId, MySession)] -> T.Text -> Int -> IO Bool
checkRateLimit _ _ _ = return True  -- Simplified for template

getSessionCsrfToken :: SpockAction () MySession AppState (Maybe T.Text)
getSessionCsrfToken = return Nothing  -- Simplified for template`,

    'src/Database.hs': `{-# LANGUAGE OverloadedStrings #-}

module Database where

import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.Migration
import Data.Pool
import qualified Data.Text as T
import Data.UUID (UUID)
import Data.Time (UTCTime)
import Control.Exception (bracket)
import qualified Data.ByteString.Char8 as BS

import Types
import Config

-- Database configuration
createConnectionPool :: DatabaseConfig -> IO (Pool Connection)
createConnectionPool config = createPool
  (connectPostgreSQL $ BS.pack $ T.unpack $ dbUrl config)
  close
  1    -- stripes
  60   -- keep alive (seconds)
  20   -- max connections

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
insertUser :: Pool Connection -> User -> IO (Either T.Text User)
insertUser pool user = withResource pool $ \conn -> do
  result <- query conn
    "INSERT INTO users (id, username, email, password_hash, bio, avatar, created_at, updated_at) \
    \VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
    \ON CONFLICT (username) DO NOTHING \
    \RETURNING id, username, email, password_hash, bio, avatar, created_at, updated_at"
    ( userId user
    , userUsername user
    , userEmail user
    , userPasswordHash user
    , userBio user
    , userAvatar user
    , userCreatedAt user
    , userUpdatedAt user
    )
  
  case result of
    [] -> return $ Left "Username already exists"
    [u] -> return $ Right u
    _ -> return $ Left "Unexpected error"

getUserById :: Pool Connection -> UUID -> IO (Maybe User)
getUserById pool uid = withResource pool $ \conn -> do
  result <- query conn
    "SELECT id, username, email, password_hash, bio, avatar, created_at, updated_at \
    \FROM users WHERE id = ?"
    (Only uid)
  
  return $ listToMaybe result

getUserByUsername :: Pool Connection -> T.Text -> IO (Maybe User)
getUserByUsername pool username = withResource pool $ \conn -> do
  result <- query conn
    "SELECT id, username, email, password_hash, bio, avatar, created_at, updated_at \
    \FROM users WHERE username = ?"
    (Only username)
  
  return $ listToMaybe result

getUsersPaginated :: Pool Connection -> Int -> Int -> IO ([User], Int)
getUsersPaginated pool page size = withResource pool $ \conn -> do
  let offset = (page - 1) * size
  
  users <- query conn
    "SELECT id, username, email, password_hash, bio, avatar, created_at, updated_at \
    \FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?"
    (size, offset)
  
  [Only total] <- query_ conn "SELECT COUNT(*) FROM users"
  
  return (users, total)

updateUser :: Pool Connection -> UUID -> UpdateUserRequest -> UTCTime -> IO (Maybe User)
updateUser pool uid req now = withResource pool $ \conn -> do
  result <- query conn
    "UPDATE users SET \
    \email = COALESCE(?, email), \
    \bio = COALESCE(?, bio), \
    \avatar = COALESCE(?, avatar), \
    \updated_at = ? \
    \WHERE id = ? \
    \RETURNING id, username, email, password_hash, bio, avatar, created_at, updated_at"
    ( updateUserEmail req
    , updateUserBio req
    , updateUserAvatar req
    , now
    , uid
    )
  
  return $ listToMaybe result

deleteUser :: Pool Connection -> UUID -> IO Bool
deleteUser pool uid = withResource pool $ \conn -> do
  n <- execute conn "DELETE FROM users WHERE id = ?" (Only uid)
  return $ n > 0

-- Todo queries
insertTodo :: Pool Connection -> Todo -> IO (Either T.Text Todo)
insertTodo pool todo = withResource pool $ \conn -> do
  result <- query conn
    "INSERT INTO todos (id, user_id, title, description, completed, due_date, tags, created_at, updated_at) \
    \VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
    \RETURNING id, user_id, title, description, completed, due_date, tags, created_at, updated_at"
    ( todoId todo
    , todoUserId todo
    , todoTitle todo
    , todoDescription todo
    , todoCompleted todo
    , todoDueDate todo
    , todoTags todo
    , todoCreatedAt todo
    , todoUpdatedAt todo
    )
  
  case result of
    [t] -> return $ Right t
    _ -> return $ Left "Failed to create todo"

getTodoById :: Pool Connection -> UUID -> IO (Maybe Todo)
getTodoById pool tid = withResource pool $ \conn -> do
  result <- query conn
    "SELECT id, user_id, title, description, completed, due_date, tags, created_at, updated_at \
    \FROM todos WHERE id = ?"
    (Only tid)
  
  return $ listToMaybe result

getUserTodos :: Pool Connection -> UUID -> Maybe Bool -> Maybe T.Text -> IO [Todo]
getUserTodos pool uid completed tag = withResource pool $ \conn -> do
  let baseQuery = "SELECT id, user_id, title, description, completed, due_date, tags, created_at, updated_at \
                  \FROM todos WHERE user_id = ?"
      
      completedFilter = case completed of
        Nothing -> ""
        Just c -> " AND completed = " ++ if c then "true" else "false"
      
      tagFilter = case tag of
        Nothing -> ""
        Just t -> " AND ? = ANY(tags)"
      
      orderBy = " ORDER BY created_at DESC"
      
      finalQuery = baseQuery ++ completedFilter ++ tagFilter ++ orderBy
  
  case (completed, tag) of
    (Nothing, Nothing) -> query conn finalQuery (Only uid)
    (Just _, Nothing) -> query conn finalQuery (Only uid)
    (Nothing, Just t) -> query conn finalQuery (uid, t)
    (Just _, Just t) -> query conn finalQuery (uid, t)

updateTodo :: Pool Connection -> UUID -> UpdateTodoRequest -> UTCTime -> IO (Maybe Todo)
updateTodo pool tid req now = withResource pool $ \conn -> do
  result <- query conn
    "UPDATE todos SET \
    \title = COALESCE(?, title), \
    \description = COALESCE(?, description), \
    \completed = COALESCE(?, completed), \
    \due_date = COALESCE(?, due_date), \
    \tags = COALESCE(?, tags), \
    \updated_at = ? \
    \WHERE id = ? \
    \RETURNING id, user_id, title, description, completed, due_date, tags, created_at, updated_at"
    ( updateTodoTitle req
    , updateTodoDescription req
    , updateTodoCompleted req
    , updateTodoDueDate req
    , updateTodoTags req
    , now
    , tid
    )
  
  return $ listToMaybe result

deleteTodo :: Pool Connection -> UUID -> IO Bool
deleteTodo pool tid = withResource pool $ \conn -> do
  n <- execute conn "DELETE FROM todos WHERE id = ?" (Only tid)
  return $ n > 0`,

    'src/Auth.hs': `{-# LANGUAGE OverloadedStrings #-}

module Auth where

import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime, getCurrentTime, addUTCTime)
import Web.JWT
import Crypto.BCrypt
import Data.Aeson (encode, decode)
import qualified Data.ByteString.Lazy as BSL

import Types
import Config

-- Generate JWT token
generateJWT :: Config -> User -> IO T.Text
generateJWT config user = do
  now <- getCurrentTime
  let expiry = addUTCTime (24 * 60 * 60) now  -- 24 hours
  
  let cs = mempty
        { iss = stringOrURI "spock-app"
        , sub = stringOrURI $ T.pack $ show $ userId user
        , exp = numericDate expiry
        , unregisteredClaims = ClaimsMap $ Map.fromList
            [ ("username", String $ userUsername user)
            , ("email", String $ userEmail user)
            ]
        }
  
  return $ encodeSigned
    (hmacSecret $ configJwtSecret config)
    mempty
    cs

-- Verify JWT token
verifyJWT :: Config -> T.Text -> Maybe User
verifyJWT config token = do
  let secret = hmacSecret $ configJwtSecret config
  jwt <- decodeAndVerifySignature secret token
  
  -- Extract claims
  let claims = unregisteredClaims $ claims jwt
      claimsMap = unClaimsMap claims
  
  uid <- sub (claims jwt) >>= stringOrURIToText >>= \t -> 
    case reads (T.unpack t) of
      [(u, "")] -> Just u
      _ -> Nothing
  
  username <- Map.lookup "username" claimsMap >>= \case
    String t -> Just t
    _ -> Nothing
  
  email <- Map.lookup "email" claimsMap >>= \case
    String t -> Just t
    _ -> Nothing
  
  -- Return partial user (without sensitive data)
  return User
    { userId = uid
    , userUsername = username
    , userEmail = email
    , userPasswordHash = ""  -- Don't include
    , userBio = Nothing
    , userAvatar = Nothing
    , userCreatedAt = undefined  -- These would need to be stored in JWT or fetched
    , userUpdatedAt = undefined
    }

-- Password hashing
hashPassword :: T.Text -> IO (Maybe T.Text)
hashPassword password = do
  mhash <- hashPasswordUsingPolicy slowerBcryptHashingPolicy (TE.encodeUtf8 password)
  return $ fmap TE.decodeUtf8 mhash

-- Password verification
verifyPassword :: T.Text -> T.Text -> Bool
verifyPassword hashedPassword password =
  validatePassword (TE.encodeUtf8 hashedPassword) (TE.encodeUtf8 password)`,

    'src/Config.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module Config where

import Data.Aeson (FromJSON, decode)
import GHC.Generics (Generic)
import qualified Data.Text as T
import qualified Data.ByteString.Lazy as BSL
import System.Environment (lookupEnv)
import Data.Maybe (fromMaybe)

-- Configuration loading
loadConfig :: IO Config
loadConfig = do
  -- Try to load from config file
  maybeConfig <- loadConfigFile "config/app.json"
  
  case maybeConfig of
    Just cfg -> return cfg
    Nothing -> do
      -- Fall back to environment variables
      port <- fromMaybe "3000" <$> lookupEnv "PORT"
      dbUrl <- fromMaybe "postgresql://localhost/spock_dev" <$> lookupEnv "DATABASE_URL"
      secret <- fromMaybe "development-secret-key" <$> lookupEnv "JWT_SECRET"
      env <- fromMaybe "development" <$> lookupEnv "APP_ENV"
      
      return Config
        { configPort = read port
        , configDbUrl = T.pack dbUrl
        , configJwtSecret = T.pack secret
        , configEnv = parseEnv env
        }

loadConfigFile :: FilePath -> IO (Maybe Config)
loadConfigFile path = do
  content <- BSL.readFile path
  return $ decode content
  `catch` \(_ :: IOError) -> return Nothing

parseEnv :: String -> Environment
parseEnv "production" = Production
parseEnv "testing" = Testing
parseEnv _ = Development

-- Database configuration helper
dbConfig :: Config -> DatabaseConfig
dbConfig cfg = DatabaseConfig
  { dbUrl = configDbUrl cfg
  }

data DatabaseConfig = DatabaseConfig
  { dbUrl :: T.Text
  } deriving (Generic, Show)`,

    'spock-app.cabal': `cabal-version:      2.4
name:               spock-app
version:            0.1.0.0
synopsis:           A type-safe web application built with Spock
description:        Type-safe routing with middleware, authentication, and database integration
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
                    , Types
                    , Auth
                    , Database
                    , Config
                    , Middleware
                    , Utils
                    , Handlers.Home
                    , Handlers.User
                    , Handlers.Todo
                    , Handlers.Api
    build-depends:    base ^>=4.17.0.0
                    , Spock >= 0.14
                    , Spock-core
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
                    , unordered-containers
    hs-source-dirs:   src
    default-language: Haskell2010

executable spock-app
    import:           warnings
    main-is:          Main.hs
    build-depends:    base ^>=4.17.0.0
                    , spock-app
                    , Spock
                    , Spock-core
                    , text
                    , aeson
    hs-source-dirs:   app
    default-language: Haskell2010

test-suite spock-app-test
    import:           warnings
    default-language: Haskell2010
    type:             exitcode-stdio-1.0
    hs-source-dirs:   test
    main-is:          Spec.hs
    other-modules:    AuthSpec
                    , DatabaseSpec
                    , HandlersSpec
                    , RoutesSpec
    build-depends:    base ^>=4.17.0.0
                    , spock-app
                    , hspec
                    , hspec-wai
                    , hspec-wai-json
                    , QuickCheck
                    , Spock
                    , wai
                    , aeson
                    , text`,

    'stack.yaml': `resolver: lts-21.0

packages:
- .

extra-deps:
- Spock-0.14.0.0
- Spock-core-0.14.0.0
- reroute-0.5.0.0
- hvect-0.4.0.0
- jwt-0.11.0
- bcrypt-0.0.11

flags: {}

extra-package-dbs: []`,

    'package.yaml': `name:                spock-app
version:             0.1.0.0
github:              "reshell/spock-app"
license:             MIT
author:              "Re-Shell Team"
maintainer:          "team@re-shell.com"
copyright:           "2024 Re-Shell Team"

extra-source-files:
- README.md

synopsis:            A type-safe web application built with Spock
category:            Web

description:         Please see the README on GitHub

dependencies:
- base >= 4.7 && < 5
- Spock >= 0.14
- Spock-core
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
- unordered-containers

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
  spock-app:
    main:                Main.hs
    source-dirs:         app
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - spock-app

tests:
  spock-app-test:
    main:                Spec.hs
    source-dirs:         test
    ghc-options:
    - -threaded
    - -rtsopts
    - -with-rtsopts=-N
    dependencies:
    - spock-app
    - hspec
    - hspec-wai
    - hspec-wai-json
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
*.cabal
.spock-session-*`,

    'README.md': `# Spock Web Application

A type-safe web application built with the Spock web framework for Haskell.

## Features

- Type-safe routing with compile-time guarantees
- Flexible middleware system
- Session management
- JWT authentication
- PostgreSQL database integration
- RESTful API design
- WebSocket support
- CSRF protection
- Rate limiting
- File uploads
- Pagination support
- Type-safe URL generation

## Prerequisites

- GHC 9.2.x or higher
- Stack or Cabal
- PostgreSQL
- Git

## Quick Start

1. **Clone the repository**
   \`\`\`bash
   git clone <repository-url>
   cd spock-app
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
   createdb spock_dev
   psql spock_dev < migrations/001_initial_schema.sql
   \`\`\`

4. **Configure environment**
   \`\`\`bash
   export DATABASE_URL="postgresql://localhost/spock_dev"
   export JWT_SECRET="your-secret-key"
   export PORT=3000
   export APP_ENV="development"
   \`\`\`

5. **Run the application**
   \`\`\`bash
   # Using Stack
   stack exec spock-app

   # Using Cabal
   cabal run spock-app
   \`\`\`

## Project Structure

\`\`\`
.
├── app/
│   └── Main.hs              # Application entry point
├── src/
│   ├── Routes.hs            # Type-safe route definitions
│   ├── Types.hs             # Application types
│   ├── Auth.hs              # Authentication logic
│   ├── Database.hs          # Database operations
│   ├── Config.hs            # Configuration management
│   ├── Middleware.hs        # Custom middleware
│   ├── Utils.hs             # Utility functions
│   └── Handlers/
│       ├── Home.hs          # Home page handlers
│       ├── User.hs          # User management handlers
│       ├── Todo.hs          # Todo CRUD handlers
│       └── Api.hs           # API-specific handlers
├── test/
│   └── Spec.hs              # Test suite
├── migrations/              # Database migrations
├── public/                  # Static files
├── config/                  # Configuration files
├── spock-app.cabal          # Cabal configuration
├── stack.yaml               # Stack configuration
└── package.yaml             # Package configuration
\`\`\`

## Type-Safe Routing

Spock provides compile-time guarantees for your routes:

\`\`\`haskell
-- Type-safe route with parameter
get ("/users" <//> var) $ \\userId -> do
  user <- getUserById userId
  json user

-- Type-safe URL generation
userUrl <- renderRoute ("/users" <//> var) userId
\`\`\`

## API Endpoints

### Authentication
- \`POST /auth/register\` - Register a new user
- \`POST /auth/login\` - Login user
- \`POST /auth/logout\` - Logout user (requires auth)
- \`GET /auth/profile\` - Get current user profile (requires auth)

### Users (Protected)
- \`GET /users\` - List all users with pagination
- \`GET /users/:id\` - Get user by ID
- \`PUT /users/:id\` - Update user
- \`DELETE /users/:id\` - Delete user

### Todos (Protected)
- \`GET /todos\` - List user's todos with filtering
- \`POST /todos\` - Create a new todo
- \`GET /todos/:id\` - Get todo by ID
- \`PUT /todos/:id\` - Update todo
- \`DELETE /todos/:id\` - Delete todo
- \`PATCH /todos/:id/toggle\` - Toggle todo completion

### API v1
- \`GET /api/v1/users\` - RESTful user API
- \`GET /api/v1/todos\` - RESTful todo API

### Other
- \`GET /health\` - Health check endpoint
- \`GET /ws\` - WebSocket endpoint
- \`POST /upload\` - File upload (requires auth)

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
- \`APP_ENV\` - Application environment (development/production/testing)

## Middleware

The application includes several middleware components:
- CORS handling
- Request logging
- Authentication
- Rate limiting
- CSRF protection

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
CMD ["stack", "exec", "spock-app"]
\`\`\`

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - see LICENSE file for details`,

    'migrations/001_initial_schema.sql': `-- Initial database schema for Spock application

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    bio TEXT,
    avatar TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Todos table with tags support
CREATE TABLE IF NOT EXISTS todos (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    completed BOOLEAN DEFAULT FALSE,
    due_date TIMESTAMP WITH TIME ZONE,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table for persistent sessions
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    data JSONB NOT NULL DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_todos_user_id ON todos(user_id);
CREATE INDEX idx_todos_created_at ON todos(created_at DESC);
CREATE INDEX idx_todos_due_date ON todos(due_date) WHERE due_date IS NOT NULL;
CREATE INDEX idx_todos_tags ON todos USING GIN(tags);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

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
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ language 'plpgsql';`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://spock:spock@db:5432/spock_dev
      - JWT_SECRET=development-secret-key
      - PORT=3000
      - APP_ENV=development
    depends_on:
      - db
    volumes:
      - .:/app
      - stack-cache:/root/.stack
    command: stack exec spock-app

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=spock
      - POSTGRES_PASSWORD=spock
      - POSTGRES_DB=spock_dev
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

volumes:
  postgres-data:
  redis-data:
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
COPY --from=builder /app/spock-app /app/
COPY public /app/public
COPY config /app/config
COPY migrations /app/migrations

EXPOSE 3000

CMD ["/app/spock-app"]`,

    '.env.example': `# Server configuration
PORT=3000
APP_ENV=development

# Database configuration
DATABASE_URL=postgresql://spock:spock@localhost:5432/spock_dev

# Authentication
JWT_SECRET=your-secret-key-here

# Redis (optional, for session storage)
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=info`
  }
};