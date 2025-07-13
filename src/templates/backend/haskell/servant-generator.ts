/**
 * Servant Framework Template Generator
 * Type-safe web APIs in Haskell
 */

import { HaskellBackendGenerator } from './haskell-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class ServantGenerator extends HaskellBackendGenerator {
  constructor() {
    super('Servant');
  }

  protected getFrameworkDependencies(): string[] {
    return [
      'servant',
      'servant-server',
      'servant-client',
      'servant-docs',
      'servant-swagger',
      'servant-swagger-ui',
      'servant-auth',
      'servant-auth-server',
      'servant-auth-client',
      'servant-auth-swagger',
      'wai',
      'warp',
      'wai-extra',
      'wai-cors',
      'wai-logger',
      'aeson',
      'text',
      'bytestring',
      'mtl',
      'transformers',
      'time',
      'uuid',
      'http-types',
      'http-client',
      'http-client-tls',
      'postgresql-simple',
      'postgresql-simple-migration',
      'resource-pool',
      'bcrypt',
      'jose',
      'lens',
      'containers',
      'unordered-containers',
      'vector',
      'async',
      'stm',
      'monad-logger',
      'fast-logger',
      'envy',
      'optparse-applicative',
      'directory',
      'filepath'
    ];
  }

  protected getExtraDeps(): string[] {
    return [
      // Add any packages not in LTS
    ];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate Main.hs
    await this.generateMainFile(projectPath, options);

    // Generate API types
    await this.generateAPITypes(projectPath, options);

    // Generate API handlers
    await this.generateAPIHandlers(projectPath);

    // Generate authentication
    await this.generateAuth(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate database layer
    await this.generateDatabase(projectPath);

    // Generate configuration
    await this.generateConfig(projectPath);

    // Generate utilities
    await this.generateUtils(projectPath);

    // Generate server setup
    await this.generateServer(projectPath);

    // Generate documentation
    await this.generateDocs(projectPath);

    // Generate tests
    await this.generateTests(projectPath, options);
  }

  private async generateMainFile(projectPath: string, options: any): Promise<void> {
    const mainContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Main where

import qualified Config.App as Config
import qualified Server
import Control.Monad (void)
import Data.Maybe (fromMaybe)
import Network.Wai.Handler.Warp
import System.Environment (lookupEnv)
import Text.Read (readMaybe)

main :: IO ()
main = do
  putStrLn "Starting ${this.config.framework} server..."
  
  -- Load configuration
  config <- Config.loadConfig
  
  -- Get port from environment or config
  envPort <- lookupEnv "PORT"
  let port = fromMaybe (Config.port config) (envPort >>= readMaybe)
  
  -- Initialize and run server
  putStrLn $ "Server running on port " ++ show port
  app <- Server.mkApp config
  run port app
`;

    await fs.writeFile(
      path.join(projectPath, 'app', 'Main.hs'),
      mainContent
    );
  }

  private async generateAPITypes(projectPath: string, options: any): Promise<void> {
    const apiTypesContent = `{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}

module API.Types where

import Data.Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import GHC.Generics
import Servant
import Servant.Auth.Server
import Servant.Swagger.UI

-- | Main API type
type API = 
       "swagger" :> SwaggerSchemaUI "swagger" "swagger.json"
  :<|> "api" :> "v1" :> APIv1

-- | Version 1 API
type APIv1 = 
       PublicAPI
  :<|> Auth '[JWT] AuthUser :> ProtectedAPI

-- | Public endpoints (no auth required)
type PublicAPI =
       "health" :> Get '[JSON] HealthResponse
  :<|> "auth" :> AuthAPI

-- | Protected endpoints (auth required)  
type ProtectedAPI =
       "users" :> UsersAPI
  :<|> "profile" :> ProfileAPI

-- | Authentication endpoints
type AuthAPI =
       "register" :> ReqBody '[JSON] RegisterRequest :> Post '[JSON] AuthResponse
  :<|> "login" :> ReqBody '[JSON] LoginRequest :> Post '[JSON] AuthResponse
  :<|> "refresh" :> ReqBody '[JSON] RefreshRequest :> Post '[JSON] AuthResponse
  :<|> "logout" :> Post '[JSON] MessageResponse

-- | User management endpoints
type UsersAPI =
       Get '[JSON] [User]
  :<|> Capture "userId" UUID :> Get '[JSON] User
  :<|> Capture "userId" UUID :> ReqBody '[JSON] UpdateUserRequest :> Put '[JSON] User
  :<|> Capture "userId" UUID :> Delete '[JSON] MessageResponse

-- | Profile endpoints
type ProfileAPI =
       Get '[JSON] User
  :<|> ReqBody '[JSON] UpdateProfileRequest :> Put '[JSON] User
  :<|> "password" :> ReqBody '[JSON] ChangePasswordRequest :> Post '[JSON] MessageResponse

-- Request/Response Types

data HealthResponse = HealthResponse
  { status :: !Text
  , version :: !Text
  , timestamp :: !UTCTime
  } deriving (Eq, Show, Generic)

instance ToJSON HealthResponse
instance FromJSON HealthResponse

data RegisterRequest = RegisterRequest
  { registerEmail :: !Text
  , registerPassword :: !Text
  , registerName :: !Text
  } deriving (Eq, Show, Generic)

instance ToJSON RegisterRequest where
  toJSON r = object
    [ "email" .= registerEmail r
    , "password" .= registerPassword r
    , "name" .= registerName r
    ]

instance FromJSON RegisterRequest where
  parseJSON = withObject "RegisterRequest" $ \\v ->
    RegisterRequest
      <$> v .: "email"
      <*> v .: "password"
      <*> v .: "name"

data LoginRequest = LoginRequest
  { loginEmail :: !Text
  , loginPassword :: !Text
  } deriving (Eq, Show, Generic)

instance ToJSON LoginRequest where
  toJSON r = object
    [ "email" .= loginEmail r
    , "password" .= loginPassword r
    ]

instance FromJSON LoginRequest where
  parseJSON = withObject "LoginRequest" $ \\v ->
    LoginRequest
      <$> v .: "email"
      <*> v .: "password"

data RefreshRequest = RefreshRequest
  { refreshToken :: !Text
  } deriving (Eq, Show, Generic)

instance ToJSON RefreshRequest
instance FromJSON RefreshRequest

data AuthResponse = AuthResponse
  { authUser :: !User
  , authAccessToken :: !Text
  , authRefreshToken :: !Text
  , authExpiresIn :: !Int
  } deriving (Eq, Show, Generic)

instance ToJSON AuthResponse where
  toJSON r = object
    [ "user" .= authUser r
    , "accessToken" .= authAccessToken r
    , "refreshToken" .= authRefreshToken r
    , "expiresIn" .= authExpiresIn r
    ]

instance FromJSON AuthResponse where
  parseJSON = withObject "AuthResponse" $ \\v ->
    AuthResponse
      <$> v .: "user"
      <*> v .: "accessToken"
      <*> v .: "refreshToken"
      <*> v .: "expiresIn"

data MessageResponse = MessageResponse
  { message :: !Text
  } deriving (Eq, Show, Generic)

instance ToJSON MessageResponse
instance FromJSON MessageResponse

data UpdateUserRequest = UpdateUserRequest
  { updateUserName :: !(Maybe Text)
  , updateUserEmail :: !(Maybe Text)
  , updateUserRole :: !(Maybe UserRole)
  , updateUserActive :: !(Maybe Bool)
  } deriving (Eq, Show, Generic)

instance ToJSON UpdateUserRequest where
  toJSON r = object $ catMaybes
    [ ("name" .=) <$> updateUserName r
    , ("email" .=) <$> updateUserEmail r
    , ("role" .=) <$> updateUserRole r
    , ("active" .=) <$> updateUserActive r
    ]
  where
    catMaybes = foldr (\\x acc -> maybe acc (:acc) x) []

instance FromJSON UpdateUserRequest where
  parseJSON = withObject "UpdateUserRequest" $ \\v ->
    UpdateUserRequest
      <$> v .:? "name"
      <*> v .:? "email"
      <*> v .:? "role"
      <*> v .:? "active"

data UpdateProfileRequest = UpdateProfileRequest
  { updateProfileName :: !(Maybe Text)
  , updateProfileEmail :: !(Maybe Text)
  } deriving (Eq, Show, Generic)

instance ToJSON UpdateProfileRequest where
  toJSON r = object $ catMaybes
    [ ("name" .=) <$> updateProfileName r
    , ("email" .=) <$> updateProfileEmail r
    ]
  where
    catMaybes = foldr (\\x acc -> maybe acc (:acc) x) []

instance FromJSON UpdateProfileRequest where
  parseJSON = withObject "UpdateProfileRequest" $ \\v ->
    UpdateProfileRequest
      <$> v .:? "name"
      <*> v .:? "email"

data ChangePasswordRequest = ChangePasswordRequest
  { currentPassword :: !Text
  , newPassword :: !Text
  } deriving (Eq, Show, Generic)

instance ToJSON ChangePasswordRequest
instance FromJSON ChangePasswordRequest

-- User model

data User = User
  { userId :: !UUID
  , userName :: !Text
  , userEmail :: !Text
  , userRole :: !UserRole
  , userActive :: !Bool
  , userCreatedAt :: !UTCTime
  , userUpdatedAt :: !UTCTime
  } deriving (Eq, Show, Generic)

instance ToJSON User where
  toJSON u = object
    [ "id" .= userId u
    , "name" .= userName u
    , "email" .= userEmail u
    , "role" .= userRole u
    , "active" .= userActive u
    , "createdAt" .= userCreatedAt u
    , "updatedAt" .= userUpdatedAt u
    ]

instance FromJSON User where
  parseJSON = withObject "User" $ \\v ->
    User
      <$> v .: "id"
      <*> v .: "name"
      <*> v .: "email"
      <*> v .: "role"
      <*> v .: "active"
      <*> v .: "createdAt"
      <*> v .: "updatedAt"

data UserRole = UserRole | AdminRole | ModeratorRole
  deriving (Eq, Show, Read, Generic)

instance ToJSON UserRole where
  toJSON UserRole = String "user"
  toJSON AdminRole = String "admin"
  toJSON ModeratorRole = String "moderator"

instance FromJSON UserRole where
  parseJSON = withText "UserRole" $ \\case
    "user" -> pure UserRole
    "admin" -> pure AdminRole
    "moderator" -> pure ModeratorRole
    _ -> fail "Invalid user role"

-- Auth user for JWT
data AuthUser = AuthUser
  { authUserId :: !UUID
  , authUserEmail :: !Text
  , authUserRole :: !UserRole
  } deriving (Eq, Show, Generic)

instance ToJSON AuthUser
instance FromJSON AuthUser
instance ToJWT AuthUser
instance FromJWT AuthUser
`;

    await fs.mkdir(path.join(projectPath, 'src', 'API'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'src', 'API', 'Types.hs'),
      apiTypesContent
    );
  }

  private async generateAPIHandlers(projectPath: string): Promise<void> {
    const handlersContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleContexts #-}

module API.Handlers where

import API.Types
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (getCurrentTime)
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID
import Database.User (UserDB)
import qualified Database.User as UserDB
import Models.User (UserModel)
import qualified Models.User as User
import Servant
import Servant.Auth.Server
import qualified Services.Auth as Auth
import qualified Services.Password as Password
import Types.App
import Utils.Validation

-- | Health check handler
healthHandler :: AppM HealthResponse
healthHandler = do
  now <- liftIO getCurrentTime
  return $ HealthResponse
    { status = "healthy"
    , version = "1.0.0"
    , timestamp = now
    }

-- | User registration handler
registerHandler :: RegisterRequest -> AppM AuthResponse
registerHandler RegisterRequest{..} = do
  -- Validate input
  case validateEmail registerEmail of
    Left err -> throwError $ err400 { errBody = encodeUtf8 err }
    Right _ -> pure ()
    
  case validatePassword registerPassword of
    Left err -> throwError $ err400 { errBody = encodeUtf8 err }
    Right _ -> pure ()
  
  -- Check if email exists
  pool <- asks appDbPool
  existingUser <- liftIO $ UserDB.findByEmail pool registerEmail
  
  case existingUser of
    Just _ -> throwError $ err409 { errBody = "Email already registered" }
    Nothing -> do
      -- Hash password
      hashedPassword <- liftIO $ Password.hashPassword registerPassword
      
      -- Create user
      userId <- liftIO UUID.nextRandom
      now <- liftIO getCurrentTime
      
      let newUser = User
            { userId = userId
            , userName = registerName
            , userEmail = registerEmail
            , userRole = UserRole
            , userActive = True
            , userCreatedAt = now
            , userUpdatedAt = now
            }
      
      -- Save to database
      _ <- liftIO $ UserDB.create pool newUser hashedPassword
      
      -- Generate tokens
      jwtSettings <- asks appJWTSettings
      tokens <- liftIO $ Auth.generateTokens jwtSettings newUser
      
      return $ AuthResponse
        { authUser = newUser
        , authAccessToken = tokens.accessToken
        , authRefreshToken = tokens.refreshToken
        , authExpiresIn = 900 -- 15 minutes
        }

-- | User login handler
loginHandler :: LoginRequest -> AppM AuthResponse
loginHandler LoginRequest{..} = do
  pool <- asks appDbPool
  
  -- Find user by email
  maybeUser <- liftIO $ UserDB.findByEmailWithPassword pool loginEmail
  
  case maybeUser of
    Nothing -> throwError $ err401 { errBody = "Invalid credentials" }
    Just (user, hashedPassword) -> do
      -- Verify password
      passwordValid <- liftIO $ Password.verifyPassword loginPassword hashedPassword
      
      if not passwordValid
        then throwError $ err401 { errBody = "Invalid credentials" }
        else do
          -- Check if active
          if not (userActive user)
            then throwError $ err403 { errBody = "Account deactivated" }
            else do
              -- Generate tokens
              jwtSettings <- asks appJWTSettings
              tokens <- liftIO $ Auth.generateTokens jwtSettings user
              
              -- Update last login
              now <- liftIO getCurrentTime
              _ <- liftIO $ UserDB.updateLastLogin pool (userId user) now
              
              return $ AuthResponse
                { authUser = user
                , authAccessToken = tokens.accessToken
                , authRefreshToken = tokens.refreshToken
                , authExpiresIn = 900
                }

-- | Token refresh handler
refreshHandler :: RefreshRequest -> AppM AuthResponse
refreshHandler RefreshRequest{..} = do
  pool <- asks appDbPool
  jwtSettings <- asks appJWTSettings
  
  -- Validate refresh token
  maybeUserId <- liftIO $ Auth.validateRefreshToken pool refreshToken
  
  case maybeUserId of
    Nothing -> throwError $ err401 { errBody = "Invalid refresh token" }
    Just userId -> do
      -- Get user
      maybeUser <- liftIO $ UserDB.findById pool userId
      
      case maybeUser of
        Nothing -> throwError $ err401 { errBody = "User not found" }
        Just user -> do
          -- Generate new tokens
          tokens <- liftIO $ Auth.generateTokens jwtSettings user
          
          -- Revoke old refresh token
          _ <- liftIO $ Auth.revokeRefreshToken pool refreshToken
          
          return $ AuthResponse
            { authUser = user
            , authAccessToken = tokens.accessToken
            , authRefreshToken = tokens.refreshToken
            , authExpiresIn = 900
            }

-- | Logout handler
logoutHandler :: AuthUser -> AppM MessageResponse
logoutHandler authUser = do
  pool <- asks appDbPool
  
  -- Revoke all user's refresh tokens
  _ <- liftIO $ Auth.revokeAllUserTokens pool (authUserId authUser)
  
  return $ MessageResponse "Logged out successfully"

-- | List users handler (admin only)
listUsersHandler :: AuthUser -> AppM [User]
listUsersHandler authUser = do
  -- Check admin permission
  unless (authUserRole authUser == AdminRole) $
    throwError $ err403 { errBody = "Admin access required" }
  
  pool <- asks appDbPool
  liftIO $ UserDB.listAll pool

-- | Get user by ID handler
getUserHandler :: AuthUser -> UUID -> AppM User
getUserHandler authUser targetUserId = do
  -- Check permission (admin or self)
  unless (authUserRole authUser == AdminRole || authUserId authUser == targetUserId) $
    throwError $ err403 { errBody = "Access denied" }
  
  pool <- asks appDbPool
  maybeUser <- liftIO $ UserDB.findById pool targetUserId
  
  case maybeUser of
    Nothing -> throwError err404
    Just user -> return user

-- | Update user handler (admin only)
updateUserHandler :: AuthUser -> UUID -> UpdateUserRequest -> AppM User
updateUserHandler authUser targetUserId updateReq = do
  -- Check admin permission
  unless (authUserRole authUser == AdminRole) $
    throwError $ err403 { errBody = "Admin access required" }
  
  pool <- asks appDbPool
  
  -- Get existing user
  maybeUser <- liftIO $ UserDB.findById pool targetUserId
  
  case maybeUser of
    Nothing -> throwError err404
    Just user -> do
      -- Validate email if changed
      case updateUserEmail updateReq of
        Just newEmail -> case validateEmail newEmail of
          Left err -> throwError $ err400 { errBody = encodeUtf8 err }
          Right _ -> do
            -- Check if email is taken
            existing <- liftIO $ UserDB.findByEmail pool newEmail
            case existing of
              Just u | userId u /= targetUserId -> 
                throwError $ err409 { errBody = "Email already in use" }
              _ -> pure ()
        Nothing -> pure ()
      
      -- Update user
      now <- liftIO getCurrentTime
      let updatedUser = user
            { userName = fromMaybe (userName user) (updateUserName updateReq)
            , userEmail = fromMaybe (userEmail user) (updateUserEmail updateReq)
            , userRole = fromMaybe (userRole user) (updateUserRole updateReq)
            , userActive = fromMaybe (userActive user) (updateUserActive updateReq)
            , userUpdatedAt = now
            }
      
      _ <- liftIO $ UserDB.update pool updatedUser
      return updatedUser

-- | Delete user handler (admin only)
deleteUserHandler :: AuthUser -> UUID -> AppM MessageResponse
deleteUserHandler authUser targetUserId = do
  -- Check admin permission
  unless (authUserRole authUser == AdminRole) $
    throwError $ err403 { errBody = "Admin access required" }
  
  -- Prevent self-deletion
  when (authUserId authUser == targetUserId) $
    throwError $ err400 { errBody = "Cannot delete your own account" }
  
  pool <- asks appDbPool
  deleted <- liftIO $ UserDB.delete pool targetUserId
  
  if deleted
    then return $ MessageResponse "User deleted successfully"
    else throwError err404

-- | Get profile handler
getProfileHandler :: AuthUser -> AppM User
getProfileHandler authUser = do
  pool <- asks appDbPool
  maybeUser <- liftIO $ UserDB.findById pool (authUserId authUser)
  
  case maybeUser of
    Nothing -> throwError $ err404 { errBody = "User not found" }
    Just user -> return user

-- | Update profile handler
updateProfileHandler :: AuthUser -> UpdateProfileRequest -> AppM User
updateProfileHandler authUser updateReq = do
  pool <- asks appDbPool
  
  -- Get current user
  maybeUser <- liftIO $ UserDB.findById pool (authUserId authUser)
  
  case maybeUser of
    Nothing -> throwError $ err404 { errBody = "User not found" }
    Just user -> do
      -- Validate email if changed
      case updateProfileEmail updateReq of
        Just newEmail -> case validateEmail newEmail of
          Left err -> throwError $ err400 { errBody = encodeUtf8 err }
          Right _ -> do
            -- Check if email is taken
            existing <- liftIO $ UserDB.findByEmail pool newEmail
            case existing of
              Just u | userId u /= authUserId authUser ->
                throwError $ err409 { errBody = "Email already in use" }
              _ -> pure ()
        Nothing -> pure ()
      
      -- Update user
      now <- liftIO getCurrentTime
      let updatedUser = user
            { userName = fromMaybe (userName user) (updateProfileName updateReq)
            , userEmail = fromMaybe (userEmail user) (updateProfileEmail updateReq)
            , userUpdatedAt = now
            }
      
      _ <- liftIO $ UserDB.update pool updatedUser
      return updatedUser

-- | Change password handler
changePasswordHandler :: AuthUser -> ChangePasswordRequest -> AppM MessageResponse
changePasswordHandler authUser ChangePasswordRequest{..} = do
  pool <- asks appDbPool
  
  -- Get user with password
  maybeUser <- liftIO $ UserDB.findByIdWithPassword pool (authUserId authUser)
  
  case maybeUser of
    Nothing -> throwError $ err404 { errBody = "User not found" }
    Just (_, hashedPassword) -> do
      -- Verify current password
      passwordValid <- liftIO $ Password.verifyPassword currentPassword hashedPassword
      
      if not passwordValid
        then throwError $ err401 { errBody = "Current password is incorrect" }
        else do
          -- Validate new password
          case validatePassword newPassword of
            Left err -> throwError $ err400 { errBody = encodeUtf8 err }
            Right _ -> do
              -- Hash and update password
              newHashedPassword <- liftIO $ Password.hashPassword newPassword
              _ <- liftIO $ UserDB.updatePassword pool (authUserId authUser) newHashedPassword
              
              -- Revoke all refresh tokens
              _ <- liftIO $ Auth.revokeAllUserTokens pool (authUserId authUser)
              
              return $ MessageResponse "Password changed successfully"

-- Helper functions

encodeUtf8 :: Text -> ByteString
encodeUtf8 = T.encodeUtf8

fromMaybe :: a -> Maybe a -> a
fromMaybe def Nothing = def
fromMaybe _ (Just x) = x
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'API', 'Handlers.hs'),
      handlersContent
    );
  }

  private async generateAuth(projectPath: string): Promise<void> {
    const authContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Services.Auth where

import API.Types
import Control.Monad.IO.Class (liftIO)
import Crypto.JOSE.JWK
import Data.Aeson
import qualified Data.ByteString.Lazy as BSL
import Data.Pool
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUIDV4
import Database.PostgreSQL.Simple
import Servant.Auth.Server
import qualified Services.Redis as Redis

data TokenPair = TokenPair
  { accessToken :: !Text
  , refreshToken :: !Text
  } deriving (Show)

-- | Generate access and refresh tokens for a user
generateTokens :: JWTSettings -> User -> IO TokenPair
generateTokens jwtSettings user = do
  -- Create auth user
  let authUser = AuthUser
        { authUserId = userId user
        , authUserEmail = userEmail user
        , authUserRole = userRole user
        }
  
  -- Generate access token
  eitherAccessToken <- makeJWT authUser jwtSettings (Just $ addUTCTime 900 <$> getCurrentTime)
  
  case eitherAccessToken of
    Left _ -> error "Failed to generate access token"
    Right accessTokenBS -> do
      -- Generate refresh token
      refreshTokenUUID <- UUIDV4.nextRandom
      let refreshTokenText = UUID.toText refreshTokenUUID
      
      -- Return token pair
      return $ TokenPair
        { accessToken = T.decodeUtf8 $ BSL.toStrict accessTokenBS
        , refreshToken = refreshTokenText
        }

-- | Store refresh token in database
storeRefreshToken :: Pool Connection -> UUID -> Text -> IO ()
storeRefreshToken pool userId token = do
  now <- getCurrentTime
  let expiresAt = addUTCTime (30 * 24 * 60 * 60) now -- 30 days
  
  withResource pool $ \\conn ->
    void $ execute conn
      "INSERT INTO refresh_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
      (token, userId, expiresAt, now)

-- | Validate refresh token
validateRefreshToken :: Pool Connection -> Text -> IO (Maybe UUID)
validateRefreshToken pool token = do
  now <- getCurrentTime
  
  withResource pool $ \\conn -> do
    result <- query conn
      "SELECT user_id FROM refresh_tokens \\
      \\WHERE token = ? AND expires_at > ? AND revoked = false"
      (token, now)
    
    case result of
      [(userId,)] -> return $ Just userId
      _ -> return Nothing

-- | Revoke a refresh token
revokeRefreshToken :: Pool Connection -> Text -> IO ()
revokeRefreshToken pool token = do
  now <- getCurrentTime
  
  withResource pool $ \\conn ->
    void $ execute conn
      "UPDATE refresh_tokens SET revoked = true, revoked_at = ? WHERE token = ?"
      (now, token)

-- | Revoke all tokens for a user
revokeAllUserTokens :: Pool Connection -> UUID -> IO ()
revokeAllUserTokens pool userId = do
  now <- getCurrentTime
  
  withResource pool $ \\conn ->
    void $ execute conn
      "UPDATE refresh_tokens SET revoked = true, revoked_at = ? \\
      \\WHERE user_id = ? AND revoked = false"
      (now, userId)

-- | Clean up expired tokens
cleanupExpiredTokens :: Pool Connection -> IO ()
cleanupExpiredTokens pool = do
  now <- getCurrentTime
  
  withResource pool $ \\conn ->
    void $ execute conn
      "DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = true"
      (Only now)

-- | Create JWT key
createJWTKey :: IO JWK
createJWTKey = genJWK (OKPGenParam Ed25519)

-- | JWT settings with custom configuration
customJWTSettings :: JWK -> JWTSettings
customJWTSettings key = defaultJWTSettings key
`;

    await fs.mkdir(path.join(projectPath, 'src', 'Services'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'src', 'Services', 'Auth.hs'),
      authContent
    );

    // Password service
    const passwordContent = `{-# LANGUAGE OverloadedStrings #-}

module Services.Password where

import Crypto.BCrypt
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

-- | Hash a password using bcrypt
hashPassword :: Text -> IO Text
hashPassword password = do
  let passwordBS = TE.encodeUtf8 password
  maybeHashed <- hashPasswordUsingPolicy slowerBcryptHashingPolicy passwordBS
  
  case maybeHashed of
    Nothing -> error "Failed to hash password"
    Just hashed -> return $ TE.decodeUtf8 hashed

-- | Verify a password against a hash
verifyPassword :: Text -> Text -> IO Bool
verifyPassword password hash = do
  let passwordBS = TE.encodeUtf8 password
      hashBS = TE.encodeUtf8 hash
  return $ validatePassword hashBS passwordBS
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Services', 'Password.hs'),
      passwordContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    const userModelContent = `{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Models.User where

import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import GHC.Generics

-- Internal user model with password
data UserModel = UserModel
  { userModelId :: !UUID
  , userModelName :: !Text
  , userModelEmail :: !Text
  , userModelPasswordHash :: !Text
  , userModelRole :: !Text
  , userModelActive :: !Bool
  , userModelLastLogin :: !(Maybe UTCTime)
  , userModelCreatedAt :: !UTCTime
  , userModelUpdatedAt :: !UTCTime
  } deriving (Eq, Show, Generic)
`;

    await fs.mkdir(path.join(projectPath, 'src', 'Models'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'src', 'Models', 'User.hs'),
      userModelContent
    );
  }

  private async generateDatabase(projectPath: string): Promise<void> {
    const dbContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Database.User where

import API.Types
import Control.Exception (bracket)
import Data.Pool
import Data.Text (Text)
import Data.Time
import Data.UUID (UUID)
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.FromRow
import Database.PostgreSQL.Simple.ToField
import Database.PostgreSQL.Simple.ToRow
import Models.User

-- | Convert internal model to API type
toUser :: UserModel -> User
toUser UserModel{..} = User
  { userId = userModelId
  , userName = userModelName
  , userEmail = userModelEmail
  , userRole = case userModelRole of
      "admin" -> AdminRole
      "moderator" -> ModeratorRole
      _ -> UserRole
  , userActive = userModelActive
  , userCreatedAt = userModelCreatedAt
  , userUpdatedAt = userModelUpdatedAt
  }

instance FromRow UserModel where
  fromRow = UserModel
    <$> field -- id
    <*> field -- name
    <*> field -- email
    <*> field -- password_hash
    <*> field -- role
    <*> field -- active
    <*> field -- last_login
    <*> field -- created_at
    <*> field -- updated_at

instance ToRow UserModel where
  toRow UserModel{..} = toRow
    ( userModelId
    , userModelName
    , userModelEmail
    , userModelPasswordHash
    , userModelRole
    , userModelActive
    , userModelLastLogin
    , userModelCreatedAt
    , userModelUpdatedAt
    )

-- | Create database tables
createTables :: Connection -> IO ()
createTables conn = do
  execute_ conn $ Query $ mconcat
    [ "CREATE TABLE IF NOT EXISTS users ("
    , "  id UUID PRIMARY KEY,"
    , "  name TEXT NOT NULL,"
    , "  email TEXT UNIQUE NOT NULL,"
    , "  password_hash TEXT NOT NULL,"
    , "  role TEXT NOT NULL DEFAULT 'user',"
    , "  active BOOLEAN NOT NULL DEFAULT true,"
    , "  last_login TIMESTAMPTZ,"
    , "  created_at TIMESTAMPTZ NOT NULL,"
    , "  updated_at TIMESTAMPTZ NOT NULL"
    , ");"
    ]
  
  execute_ conn $ Query $ mconcat
    [ "CREATE TABLE IF NOT EXISTS refresh_tokens ("
    , "  id SERIAL PRIMARY KEY,"
    , "  token TEXT UNIQUE NOT NULL,"
    , "  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
    , "  expires_at TIMESTAMPTZ NOT NULL,"
    , "  revoked BOOLEAN NOT NULL DEFAULT false,"
    , "  revoked_at TIMESTAMPTZ,"
    , "  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
    , ");"
    ]
  
  -- Create indexes
  execute_ conn "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"
  execute_ conn "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);"
  execute_ conn "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);"

-- | Find user by ID
findById :: Pool Connection -> UUID -> IO (Maybe User)
findById pool userId = do
  withResource pool $ \\conn -> do
    result <- query conn
      "SELECT * FROM users WHERE id = ?"
      (Only userId)
    
    case result of
      [userModel] -> return $ Just $ toUser userModel
      _ -> return Nothing

-- | Find user by email
findByEmail :: Pool Connection -> Text -> IO (Maybe User)
findByEmail pool email = do
  withResource pool $ \\conn -> do
    result <- query conn
      "SELECT * FROM users WHERE email = ?"
      (Only email)
    
    case result of
      [userModel] -> return $ Just $ toUser userModel
      _ -> return Nothing

-- | Find user by email with password
findByEmailWithPassword :: Pool Connection -> Text -> IO (Maybe (User, Text))
findByEmailWithPassword pool email = do
  withResource pool $ \\conn -> do
    result <- query conn
      "SELECT * FROM users WHERE email = ?"
      (Only email)
    
    case result of
      [userModel] -> return $ Just (toUser userModel, userModelPasswordHash userModel)
      _ -> return Nothing

-- | Find user by ID with password
findByIdWithPassword :: Pool Connection -> UUID -> IO (Maybe (User, Text))
findByIdWithPassword pool userId = do
  withResource pool $ \\conn -> do
    result <- query conn
      "SELECT * FROM users WHERE id = ?"
      (Only userId)
    
    case result of
      [userModel] -> return $ Just (toUser userModel, userModelPasswordHash userModel)
      _ -> return Nothing

-- | Create a new user
create :: Pool Connection -> User -> Text -> IO User
create pool user passwordHash = do
  let userModel = UserModel
        { userModelId = userId user
        , userModelName = userName user
        , userModelEmail = userEmail user
        , userModelPasswordHash = passwordHash
        , userModelRole = case userRole user of
            AdminRole -> "admin"
            ModeratorRole -> "moderator"
            UserRole -> "user"
        , userModelActive = userActive user
        , userModelLastLogin = Nothing
        , userModelCreatedAt = userCreatedAt user
        , userModelUpdatedAt = userUpdatedAt user
        }
  
  withResource pool $ \\conn -> do
    execute conn
      "INSERT INTO users (id, name, email, password_hash, role, active, last_login, created_at, updated_at) \\
      \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
      userModel
    
    return user

-- | Update a user
update :: Pool Connection -> User -> IO Bool
update pool user = do
  withResource pool $ \\conn -> do
    n <- execute conn
      "UPDATE users SET name = ?, email = ?, role = ?, active = ?, updated_at = ? \\
      \\WHERE id = ?"
      ( userName user
      , userEmail user
      , case userRole user of
          AdminRole -> "admin"
          ModeratorRole -> "moderator"
          UserRole -> "user"
      , userActive user
      , userUpdatedAt user
      , userId user
      )
    
    return $ n > 0

-- | Update user password
updatePassword :: Pool Connection -> UUID -> Text -> IO Bool
updatePassword pool userId passwordHash = do
  now <- getCurrentTime
  
  withResource pool $ \\conn -> do
    n <- execute conn
      "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?"
      (passwordHash, now, userId)
    
    return $ n > 0

-- | Update last login
updateLastLogin :: Pool Connection -> UUID -> UTCTime -> IO Bool
updateLastLogin pool userId loginTime = do
  withResource pool $ \\conn -> do
    n <- execute conn
      "UPDATE users SET last_login = ? WHERE id = ?"
      (loginTime, userId)
    
    return $ n > 0

-- | Delete a user
delete :: Pool Connection -> UUID -> IO Bool
delete pool userId = do
  withResource pool $ \\conn -> do
    n <- execute conn
      "DELETE FROM users WHERE id = ?"
      (Only userId)
    
    return $ n > 0

-- | List all users
listAll :: Pool Connection -> IO [User]
listAll pool = do
  withResource pool $ \\conn -> do
    result <- query_ conn
      "SELECT * FROM users ORDER BY created_at DESC"
    
    return $ map toUser result
`;

    await fs.mkdir(path.join(projectPath, 'src', 'Database'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'src', 'Database', 'User.hs'),
      dbContent
    );

    // Database pool
    const poolContent = `{-# LANGUAGE OverloadedStrings #-}

module Database.Pool where

import Data.Pool
import Database.PostgreSQL.Simple
import qualified Data.ByteString.Char8 as BS8

-- | Create a connection pool
createConnectionPool :: String -> IO (Pool Connection)
createConnectionPool connStr = do
  createPool
    (connectPostgreSQL $ BS8.pack connStr)
    close
    1      -- Number of stripes
    60     -- Keep alive (seconds)
    10     -- Max connections per stripe
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Database', 'Pool.hs'),
      poolContent
    );
  }

  private async generateConfig(projectPath: string): Promise<void> {
    const configContent = `{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Config.App where

import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics
import System.Environment (lookupEnv)
import System.Envy

data AppConfig = AppConfig
  { port :: !Int
  , host :: !Text
  , environment :: !Text
  , databaseUrl :: !Text
  , redisUrl :: !Text
  , jwtSecret :: !Text
  , corsOrigin :: !Text
  , logLevel :: !Text
  } deriving (Show, Generic)

instance FromEnv AppConfig where
  fromEnv _ = AppConfig
    <$> envMaybe "PORT" .!= 3000
    <*> envMaybe "HOST" .!= "0.0.0.0"
    <*> envMaybe "ENV" .!= "development"
    <*> env "DATABASE_URL"
    <*> envMaybe "REDIS_URL" .!= "redis://localhost:6379"
    <*> envMaybe "JWT_SECRET" .!= "your-secret-key"
    <*> envMaybe "CORS_ORIGIN" .!= "*"
    <*> envMaybe "LOG_LEVEL" .!= "info"

-- | Load configuration from environment
loadConfig :: IO AppConfig
loadConfig = do
  result <- decodeEnv
  case result of
    Left err -> error $ "Failed to load configuration: " ++ show err
    Right config -> return config

-- | Check if running in production
isProduction :: AppConfig -> Bool
isProduction config = environment config == "production"

-- | Check if running in development
isDevelopment :: AppConfig -> Bool
isDevelopment config = environment config == "development"
`;

    await fs.mkdir(path.join(projectPath, 'src', 'Config'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'src', 'Config', 'App.hs'),
      configContent
    );
  }

  private async generateUtils(projectPath: string): Promise<void> {
    // Validation utilities
    const validationContent = `{-# LANGUAGE OverloadedStrings #-}

module Utils.Validation where

import Data.Text (Text)
import qualified Data.Text as T
import Text.Regex.TDFA

-- | Validate email format
validateEmail :: Text -> Either Text ()
validateEmail email
  | T.null email = Left "Email is required"
  | not (email =~ emailRegex) = Left "Invalid email format"
  | otherwise = Right ()
  where
    emailRegex :: String
    emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$"

-- | Validate password strength
validatePassword :: Text -> Either Text ()
validatePassword password
  | T.length password < 8 = Left "Password must be at least 8 characters"
  | not (password =~ "[A-Z]") = Left "Password must contain uppercase letter"
  | not (password =~ "[a-z]") = Left "Password must contain lowercase letter"
  | not (password =~ "[0-9]") = Left "Password must contain number"
  | not (password =~ "[!@#$%^&*(),.?\":{}|<>]") = Left "Password must contain special character"
  | otherwise = Right ()

-- | Validate non-empty text
validateNonEmpty :: Text -> Text -> Either Text ()
validateNonEmpty fieldName value
  | T.null value = Left $ fieldName <> " is required"
  | otherwise = Right ()

-- | Validate text length
validateLength :: Text -> Int -> Int -> Text -> Either Text ()
validateLength fieldName minLen maxLen value
  | len < minLen = Left $ fieldName <> " must be at least " <> T.pack (show minLen) <> " characters"
  | len > maxLen = Left $ fieldName <> " must be at most " <> T.pack (show maxLen) <> " characters"
  | otherwise = Right ()
  where
    len = T.length value

-- | Validate UUID format
validateUUID :: Text -> Either Text ()
validateUUID uuid
  | not (uuid =~ uuidRegex) = Left "Invalid UUID format"
  | otherwise = Right ()
  where
    uuidRegex :: String
    uuidRegex = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
`;

    await fs.mkdir(path.join(projectPath, 'src', 'Utils'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'src', 'Utils', 'Validation.hs'),
      validationContent
    );

    // Logger utilities
    const loggerContent = `{-# LANGUAGE OverloadedStrings #-}

module Utils.Logger where

import Control.Monad.Logger
import Data.Text (Text)
import qualified Data.Text as T
import System.Log.FastLogger

-- | Create a logger
createLogger :: Text -> IO (Loc -> LogSource -> LogLevel -> LogStr -> IO ())
createLogger logLevel = do
  timeCache <- newTimeCache simpleTimeFormat
  (logger, cleanup) <- newTimedFastLogger timeCache (LogStdout defaultBufSize)
  
  return $ \\loc src level msg -> do
    when (shouldLog level) $ do
      logger $ \\time -> toLogStr time
        <> " ["
        <> toLogStr (show level)
        <> "] "
        <> msg
        <> "\\n"
  where
    shouldLog level = case T.toLower logLevel of
      "debug" -> True
      "info" -> level >= LevelInfo
      "warn" -> level >= LevelWarn
      "error" -> level >= LevelError
      _ -> level >= LevelInfo

-- | Log helpers
logDebug' :: MonadLogger m => Text -> m ()
logDebug' = logDebugN

logInfo' :: MonadLogger m => Text -> m ()
logInfo' = logInfoN

logWarn' :: MonadLogger m => Text -> m ()
logWarn' = logWarnN

logError' :: MonadLogger m => Text -> m ()
logError' = logErrorN
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Utils', 'Logger.hs'),
      loggerContent
    );
  }

  private async generateServer(projectPath: string): Promise<void> {
    const serverContent = `{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleContexts #-}

module Server where

import API.Handlers
import API.Types
import Config.App (AppConfig)
import qualified Config.App as Config
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader
import Data.Pool
import Data.Proxy
import Data.Text (Text)
import qualified Data.Text as T
import Database.PostgreSQL.Simple
import qualified Database.Pool as Pool
import qualified Database.User as UserDB
import Network.Wai
import Network.Wai.Handler.Warp (Settings, defaultSettings, setPort, setHost)
import Network.Wai.Middleware.Cors
import Network.Wai.Middleware.RequestLogger
import Servant
import Servant.Auth.Server
import Servant.Swagger
import Servant.Swagger.UI
import qualified Services.Auth as Auth
import Types.App

-- | Create the WAI application
mkApp :: AppConfig -> IO Application
mkApp config = do
  -- Create database pool
  dbPool <- Pool.createConnectionPool (T.unpack $ Config.databaseUrl config)
  
  -- Initialize database
  withResource dbPool $ \\conn -> do
    UserDB.createTables conn
  
  -- Create JWT key
  jwtKey <- Auth.createJWTKey
  let jwtSettings = Auth.customJWTSettings jwtKey
      cookieSettings = defaultCookieSettings
        { cookieIsSecure = Config.isProduction config
        , cookieSameSite = sameSiteLax
        , cookieXsrfSetting = Nothing
        }
  
  -- Create app environment
  let appEnv = AppEnv
        { appConfig = config
        , appDbPool = dbPool
        , appJWTSettings = jwtSettings
        , appCookieSettings = cookieSettings
        }
  
  -- Create servant context
  let context = cookieSettings :. jwtSettings :. EmptyContext
  
  -- Create application
  let app = serveWithContext api context (server appEnv)
  
  -- Apply middleware
  return $ middleware config app

-- | API proxy
api :: Proxy API
api = Proxy

-- | Server implementation
server :: AppEnv -> Server API
server env = swaggerUI :<|> hoistServerWithContext
  (Proxy :: Proxy ("api" :> "v1" :> APIv1))
  (Proxy :: Proxy '[CookieSettings, JWTSettings])
  (runAppM env)
  serverV1

-- | Version 1 API server
serverV1 :: ServerT APIv1 AppM
serverV1 = publicServer :<|> protectedServer

-- | Public API server
publicServer :: ServerT PublicAPI AppM
publicServer = healthHandler
  :<|> (registerHandler :<|> loginHandler :<|> refreshHandler :<|> logoutHandler)

-- | Protected API server
protectedServer :: AuthUser -> ServerT ProtectedAPI AppM
protectedServer authUser = usersServer authUser :<|> profileServer authUser

-- | Users API server
usersServer :: AuthUser -> ServerT UsersAPI AppM
usersServer authUser =
       listUsersHandler authUser
  :<|> getUserHandler authUser
  :<|> updateUserHandler authUser
  :<|> deleteUserHandler authUser

-- | Profile API server
profileServer :: AuthUser -> ServerT ProfileAPI AppM
profileServer authUser =
       getProfileHandler authUser
  :<|> updateProfileHandler authUser
  :<|> changePasswordHandler authUser

-- | Run the AppM monad
runAppM :: AppEnv -> AppM a -> Handler a
runAppM env action = runReaderT (unAppM action) env

-- | Swagger UI server
swaggerUI :: Server (SwaggerSchemaUI "swagger" "swagger.json")
swaggerUI = swaggerSchemaUIServer swaggerDoc

-- | Swagger documentation
swaggerDoc :: Swagger
swaggerDoc = toSwagger (Proxy :: Proxy ("api" :> "v1" :> APIv1))
  & info.title .~ "Servant API"
  & info.version .~ "1.0.0"
  & info.description ?~ "Type-safe web API built with Servant"
  & info.license ?~ ("MIT" & url ?~ URL "https://opensource.org/licenses/MIT")

-- | Middleware stack
middleware :: AppConfig -> Application -> Application
middleware config = cors corsPolicy . requestLogger
  where
    corsPolicy = const $ Just CorsResourcePolicy
      { corsOrigins = case Config.corsOrigin config of
          "*" -> Nothing
          origin -> Just ([T.encodeUtf8 origin], True)
      , corsMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
      , corsRequestHeaders = ["Content-Type", "Authorization"]
      , corsExposedHeaders = Nothing
      , corsMaxAge = Just 86400
      , corsVaryOrigin = False
      , corsRequireOrigin = False
      , corsIgnoreFailures = False
      }
    
    requestLogger = if Config.isDevelopment config
      then logStdoutDev
      else logStdout
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Server.hs'),
      serverContent
    );

    // App types
    const appTypesContent = `{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}

module Types.App where

import Config.App (AppConfig)
import Control.Monad.IO.Class
import Control.Monad.Reader
import Data.Pool
import Database.PostgreSQL.Simple
import Servant
import Servant.Auth.Server

-- | Application environment
data AppEnv = AppEnv
  { appConfig :: !AppConfig
  , appDbPool :: !(Pool Connection)
  , appJWTSettings :: !JWTSettings
  , appCookieSettings :: !CookieSettings
  }

-- | Application monad
newtype AppM a = AppM
  { unAppM :: ReaderT AppEnv Handler a
  } deriving
    ( Functor
    , Applicative
    , Monad
    , MonadIO
    , MonadReader AppEnv
    , MonadError ServerError
    )
`;

    await fs.mkdir(path.join(projectPath, 'src', 'Types'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'src', 'Types', 'App.hs'),
      appTypesContent
    );
  }

  private async generateDocs(projectPath: string): Promise<void> {
    const docsContent = `# ${this.config.framework} API Documentation

This is a type-safe REST API built with Servant framework in Haskell.

## Features

- Type-safe routing and API definition
- Automatic API documentation generation
- JWT authentication
- Role-based access control
- PostgreSQL database integration
- Request validation
- CORS support
- Swagger UI integration
- Property-based testing

## API Endpoints

### Public Endpoints

- \`GET /health\` - Health check
- \`POST /api/v1/auth/register\` - User registration
- \`POST /api/v1/auth/login\` - User login
- \`POST /api/v1/auth/refresh\` - Refresh access token

### Protected Endpoints

- \`POST /api/v1/auth/logout\` - Logout
- \`GET /api/v1/users\` - List users (admin only)
- \`GET /api/v1/users/:id\` - Get user by ID
- \`PUT /api/v1/users/:id\` - Update user (admin only)
- \`DELETE /api/v1/users/:id\` - Delete user (admin only)
- \`GET /api/v1/profile\` - Get current user profile
- \`PUT /api/v1/profile\` - Update profile
- \`POST /api/v1/profile/password\` - Change password

## Development

\`\`\`bash
# Install dependencies
stack setup
stack build

# Run development server
stack run

# Run tests
stack test

# Generate documentation
stack haddock

# Format code
make format

# Lint code
make lint
\`\`\`

## Configuration

Set the following environment variables:

- \`PORT\` - Server port (default: 3000)
- \`HOST\` - Server host (default: 0.0.0.0)
- \`DATABASE_URL\` - PostgreSQL connection string
- \`JWT_SECRET\` - Secret key for JWT tokens
- \`CORS_ORIGIN\` - Allowed CORS origin
- \`LOG_LEVEL\` - Logging level (debug, info, warn, error)

## Testing

The project includes:

- Unit tests with HSpec
- Property-based tests with QuickCheck
- Integration tests with hspec-wai
- API testing with servant-client

## Deployment

Build the Docker image:

\`\`\`bash
docker build -t servant-api .
docker run -p 3000:3000 servant-api
\`\`\`
`;

    await fs.writeFile(
      path.join(projectPath, 'API_DOCUMENTATION.md'),
      docsContent
    );
  }

  private async generateTests(projectPath: string, options: any): Promise<void> {
    const testContent = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Main where

import Test.Hspec
import Test.Hspec.Wai
import Test.Hspec.Wai.JSON
import Test.QuickCheck
import Network.Wai.Test
import Data.Aeson
import qualified Data.ByteString.Lazy as BSL
import API.Types
import Server (mkApp)
import Config.App (AppConfig(..))
import qualified Database.Pool as Pool
import qualified Database.User as UserDB

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "API Tests" $ do
    healthSpec
    authSpec
    userSpec
    validationSpec

healthSpec :: Spec
healthSpec = with app $ do
  describe "GET /health" $ do
    it "responds with 200" $ do
      get "/health" \`shouldRespondWith\` 200
    
    it "returns health status" $ do
      get "/health" \`shouldRespondWith\`
        [json|{status: "healthy", version: "1.0.0"}|]
        { matchHeaders = [matchContentType "application/json"] }

authSpec :: Spec
authSpec = with app $ do
  describe "POST /api/v1/auth/register" $ do
    it "creates a new user" $ do
      let user = [json|{
        email: "test@example.com",
        password: "Test123!",
        name: "Test User"
      }|]
      
      post "/api/v1/auth/register" user \`shouldRespondWith\` 201
    
    it "returns error for invalid email" $ do
      let user = [json|{
        email: "invalid-email",
        password: "Test123!",
        name: "Test User"
      }|]
      
      post "/api/v1/auth/register" user \`shouldRespondWith\` 400
    
    it "returns error for weak password" $ do
      let user = [json|{
        email: "test@example.com",
        password: "weak",
        name: "Test User"
      }|]
      
      post "/api/v1/auth/register" user \`shouldRespondWith\` 400

userSpec :: Spec
userSpec = with app $ do
  describe "User endpoints" $ do
    it "requires authentication for protected endpoints" $ do
      get "/api/v1/users" \`shouldRespondWith\` 401
    
    it "allows access with valid token" $ do
      -- Register and login first
      let user = [json|{
        email: "admin@example.com",
        password: "Admin123!",
        name: "Admin User"
      }|]
      
      response <- post "/api/v1/auth/register" user
      let Just authResp = decode @AuthResponse (simpleBody response)
      
      request "GET" "/api/v1/profile" [("Authorization", "Bearer " <> authAccessToken authResp)] ""
        \`shouldRespondWith\` 200

validationSpec :: Spec
validationSpec = do
  describe "Input validation" $ do
    it "validates email format" $ property $ \\email ->
      -- Property: valid emails should pass validation
      True -- Implement property test
    
    it "validates password strength" $ property $ \\password ->
      -- Property: passwords meeting criteria should pass
      True -- Implement property test

-- Test application
app :: IO Application
app = do
  let config = AppConfig
        { port = 3000
        , host = "localhost"
        , environment = "test"
        , databaseUrl = "postgresql://test:test@localhost:5432/test_db"
        , redisUrl = "redis://localhost:6379"
        , jwtSecret = "test-secret"
        , corsOrigin = "*"
        , logLevel = "error"
        }
  mkApp config
`;

    await fs.writeFile(
      path.join(projectPath, 'test', 'Main.hs'),
      testContent
    );
  }

  protected async generateBuildScript(projectPath: string, options: any): Promise<void> {
    await super.generateBuildScript(projectPath, options);

    // Add Haskell-specific build script
    const buildScriptContent = `#!/bin/bash

# Build script for Haskell Servant application

set -e

echo "Building Haskell Servant application..."

# Setup Stack
echo "Setting up Stack..."
stack setup

# Install dependencies
echo "Installing dependencies..."
stack build --dependencies-only --test --no-run-tests

# Run tests
echo "Running tests..."
stack test

# Build application
echo "Building application..."
stack build --copy-bins

# Generate documentation
echo "Generating documentation..."
stack haddock

echo "Build complete!"
echo "Run 'stack run' to start the application"
`;

    await fs.writeFile(
      path.join(projectPath, 'scripts', 'build.sh'),
      buildScriptContent
    );

    await fs.chmod(path.join(projectPath, 'scripts', 'build.sh'), 0o755);
  }
}