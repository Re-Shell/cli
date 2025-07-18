import { BackendTemplate } from '../types';

export const haskellPersistentTemplate: BackendTemplate = {
  id: 'haskell-persistent',
  name: 'haskell-persistent',
  displayName: 'Haskell Persistent ORM',
  description: 'Type-safe database access with Persistent ORM, supporting multiple backends and advanced query capabilities',
  framework: 'persistent',
  language: 'haskell',
  version: '2.14',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🗄️',
  type: 'database',
  complexity: 'intermediate',
  keywords: ['haskell', 'persistent', 'orm', 'database', 'type-safe', 'sql'],
  
  features: [
    'Type-safe database queries',
    'Multiple backend support (PostgreSQL, MySQL, SQLite, MongoDB)',
    'Automatic migrations',
    'Schema definition in Haskell',
    'Query DSL',
    'Raw SQL support',
    'Connection pooling',
    'Transaction support',
    'Joins and relationships',
    'JSON field support',
    'Database introspection',
    'Type-safe updates',
    'Streaming queries',
    'Database seeding'
  ],
  
  structure: {
    'src/Database/Schema.hs': `{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}

module Database.Schema where

import Database.Persist.TH
import Data.Time (UTCTime)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Aeson
import Database.Persist.Sql
import Control.Monad.Reader

-- Define database schema using Template Haskell
share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
User
    email Text
    username Text Maybe
    password Text
    firstName Text
    lastName Text
    avatar Text Maybe
    emailVerified Bool default=False
    active Bool default=True
    role UserRole
    createdAt UTCTime default=CURRENT_TIMESTAMP
    updatedAt UTCTime default=CURRENT_TIMESTAMP
    UniqueEmail email
    UniqueUsername username !force
    deriving Show Eq

UserProfile
    userId UserId
    bio Text Maybe
    website Text Maybe
    location Text Maybe
    timezone Text default="UTC"
    preferences Value
    UniqueUserProfile userId
    deriving Show Eq

BlogPost
    title Text
    slug Text
    content Text
    summary Text Maybe
    authorId UserId
    categoryId CategoryId Maybe
    published Bool default=False
    publishedAt UTCTime Maybe
    views Int default=0
    createdAt UTCTime default=CURRENT_TIMESTAMP
    updatedAt UTCTime default=CURRENT_TIMESTAMP
    UniqueSlug slug
    deriving Show Eq

Category
    name Text
    slug Text
    description Text Maybe
    parentId CategoryId Maybe
    sortOrder Int default=0
    UniqueCategorySlug slug
    deriving Show Eq

Tag
    name Text
    slug Text
    UniqueTagName name
    UniqueTagSlug slug
    deriving Show Eq

PostTag
    postId BlogPostId
    tagId TagId
    UniquePostTag postId tagId
    deriving Show Eq

Comment
    postId BlogPostId
    userId UserId
    parentId CommentId Maybe
    content Text
    approved Bool default=True
    createdAt UTCTime default=CURRENT_TIMESTAMP
    updatedAt UTCTime default=CURRENT_TIMESTAMP
    deriving Show Eq

Session
    userId UserId
    token Text
    expiresAt UTCTime
    createdAt UTCTime default=CURRENT_TIMESTAMP
    UniqueToken token
    deriving Show Eq

AuditLog
    userId UserId Maybe
    action Text
    entityType Text
    entityId Text
    oldValue Value Maybe
    newValue Value Maybe
    ipAddress Text Maybe
    userAgent Text Maybe
    createdAt UTCTime default=CURRENT_TIMESTAMP
    deriving Show Eq
|]

-- Custom types
data UserRole = Admin | Editor | Author | Subscriber
    deriving (Show, Read, Eq, Enum, Bounded)

instance PersistField UserRole where
    toPersistValue = PersistText . T.pack . show
    fromPersistValue (PersistText t) = case reads (T.unpack t) of
        [(r, "")] -> Right r
        _ -> Left "Invalid UserRole"
    fromPersistValue _ = Left "Expected PersistText for UserRole"

instance PersistFieldSql UserRole where
    sqlType _ = SqlString

-- JSON instances
instance ToJSON UserRole where
    toJSON = toJSON . show

instance FromJSON UserRole where
    parseJSON = withText "UserRole" $ \\t ->
        case reads (T.unpack t) of
            [(r, "")] -> return r
            _ -> fail "Invalid UserRole"

-- Entity JSON instances (excluding sensitive fields)
instance ToJSON (Entity User) where
    toJSON (Entity uid user) = object
        [ "id" .= uid
        , "email" .= userEmail user
        , "username" .= userUsername user
        , "firstName" .= userFirstName user
        , "lastName" .= userLastName user
        , "avatar" .= userAvatar user
        , "emailVerified" .= userEmailVerified user
        , "active" .= userActive user
        , "role" .= userRole user
        , "createdAt" .= userCreatedAt user
        ]

instance ToJSON (Entity BlogPost) where
    toJSON (Entity pid post) = object
        [ "id" .= pid
        , "title" .= blogPostTitle post
        , "slug" .= blogPostSlug post
        , "content" .= blogPostContent post
        , "summary" .= blogPostSummary post
        , "authorId" .= blogPostAuthorId post
        , "categoryId" .= blogPostCategoryId post
        , "published" .= blogPostPublished post
        , "publishedAt" .= blogPostPublishedAt post
        , "views" .= blogPostViews post
        , "createdAt" .= blogPostCreatedAt post
        , "updatedAt" .= blogPostUpdatedAt post
        ]`,

    'src/Database/Models.hs': `{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

module Database.Models where

import Database.Persist
import Database.Persist.Sql
import Database.Schema
import Data.Text (Text)
import Data.Time (UTCTime, getCurrentTime)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader (ReaderT)
import qualified Data.Text as T
import Data.Maybe (listToMaybe)

-- User operations
createUser :: MonadIO m => Text -> Text -> Text -> Text -> UserRole -> ReaderT SqlBackend m (Entity User)
createUser email password firstName lastName role = do
    now <- liftIO getCurrentTime
    insertEntity User
        { userEmail = email
        , userUsername = Nothing
        , userPassword = password  -- Should be hashed!
        , userFirstName = firstName
        , userLastName = lastName
        , userAvatar = Nothing
        , userEmailVerified = False
        , userActive = True
        , userRole = role
        , userCreatedAt = now
        , userUpdatedAt = now
        }

getUserByEmail :: MonadIO m => Text -> ReaderT SqlBackend m (Maybe (Entity User))
getUserByEmail email = selectFirst [UserEmail ==. email] []

getUserWithProfile :: MonadIO m => UserId -> ReaderT SqlBackend m (Maybe (Entity User, Maybe (Entity UserProfile)))
getUserWithProfile userId = do
    mUser <- get userId
    case mUser of
        Nothing -> return Nothing
        Just user -> do
            mProfile <- selectFirst [UserProfileUserId ==. userId] []
            return $ Just (Entity userId user, mProfile)

updateUserProfile :: MonadIO m => UserId -> Maybe Text -> Maybe Text -> Maybe Text -> ReaderT SqlBackend m ()
updateUserProfile userId bio website location = do
    now <- liftIO getCurrentTime
    mProfile <- selectFirst [UserProfileUserId ==. userId] []
    case mProfile of
        Nothing -> insert_ UserProfile
            { userProfileUserId = userId
            , userProfileBio = bio
            , userProfileWebsite = website
            , userProfileLocation = location
            , userProfileTimezone = "UTC"
            , userProfilePreferences = object []
            }
        Just (Entity profileId _) -> update profileId
            [ UserProfileBio =. bio
            , UserProfileWebsite =. website
            , UserProfileLocation =. location
            ]

-- Blog post operations
createPost :: MonadIO m => Text -> Text -> Text -> UserId -> ReaderT SqlBackend m (Entity BlogPost)
createPost title slug content authorId = do
    now <- liftIO getCurrentTime
    insertEntity BlogPost
        { blogPostTitle = title
        , blogPostSlug = slug
        , blogPostContent = content
        , blogPostSummary = Nothing
        , blogPostAuthorId = authorId
        , blogPostCategoryId = Nothing
        , blogPostPublished = False
        , blogPostPublishedAt = Nothing
        , blogPostViews = 0
        , blogPostCreatedAt = now
        , blogPostUpdatedAt = now
        }

getPostBySlug :: MonadIO m => Text -> ReaderT SqlBackend m (Maybe (Entity BlogPost))
getPostBySlug slug = selectFirst [BlogPostSlug ==. slug] []

getPublishedPosts :: MonadIO m => Int -> Int -> ReaderT SqlBackend m [Entity BlogPost]
getPublishedPosts limit offset = selectList
    [BlogPostPublished ==. True]
    [Desc BlogPostPublishedAt, LimitTo limit, OffsetBy offset]

getPostsWithAuthor :: MonadIO m => ReaderT SqlBackend m [(Entity BlogPost, Entity User)]
getPostsWithAuthor = 
    select $ from $ \\(post, user) -> do
        where_ (post ^. BlogPostAuthorId ==. user ^. UserId)
        orderBy [desc (post ^. BlogPostCreatedAt)]
        return (post, user)

publishPost :: MonadIO m => BlogPostId -> ReaderT SqlBackend m ()
publishPost postId = do
    now <- liftIO getCurrentTime
    update postId
        [ BlogPostPublished =. True
        , BlogPostPublishedAt =. Just now
        , BlogPostUpdatedAt =. now
        ]

incrementPostViews :: MonadIO m => BlogPostId -> ReaderT SqlBackend m ()
incrementPostViews postId = 
    update postId [BlogPostViews +=. 1]

-- Category operations
createCategory :: MonadIO m => Text -> Text -> Maybe Text -> Maybe CategoryId -> ReaderT SqlBackend m (Entity Category)
createCategory name slug description parentId = insertEntity Category
    { categoryName = name
    , categorySlug = slug
    , categoryDescription = description
    , categoryParentId = parentId
    , categorySortOrder = 0
    }

getCategoryTree :: MonadIO m => ReaderT SqlBackend m [Entity Category]
getCategoryTree = do
    categories <- selectList [] [Asc CategorySortOrder, Asc CategoryName]
    return $ buildTree categories
  where
    buildTree = id  -- Simplified; implement actual tree building logic

-- Tag operations
addTagsToPost :: MonadIO m => BlogPostId -> [Text] -> ReaderT SqlBackend m ()
addTagsToPost postId tagNames = do
    -- Delete existing tags
    deleteWhere [PostTagPostId ==. postId]
    
    -- Insert new tags
    forM_ tagNames $ \\tagName -> do
        let slug = T.toLower $ T.replace " " "-" tagName
        mTag <- selectFirst [TagName ==. tagName] []
        tagId <- case mTag of
            Just (Entity tid _) -> return tid
            Nothing -> insert Tag
                { tagName = tagName
                , tagSlug = slug
                }
        insert_ PostTag
            { postTagPostId = postId
            , postTagTagId = tagId
            }

getPostTags :: MonadIO m => BlogPostId -> ReaderT SqlBackend m [Entity Tag]
getPostTags postId = 
    select $ from $ \\(postTag, tag) -> do
        where_ (postTag ^. PostTagPostId ==. val postId
            &&. postTag ^. PostTagTagId ==. tag ^. TagId)
        return tag

-- Comment operations
createComment :: MonadIO m => BlogPostId -> UserId -> Maybe CommentId -> Text -> ReaderT SqlBackend m (Entity Comment)
createComment postId userId parentId content = do
    now <- liftIO getCurrentTime
    insertEntity Comment
        { commentPostId = postId
        , commentUserId = userId
        , commentParentId = parentId
        , commentContent = content
        , commentApproved = True
        , commentCreatedAt = now
        , commentUpdatedAt = now
        }

getPostComments :: MonadIO m => BlogPostId -> ReaderT SqlBackend m [Entity Comment]
getPostComments postId = selectList
    [CommentPostId ==. postId, CommentApproved ==. True]
    [Asc CommentCreatedAt]

-- Session management
createSession :: MonadIO m => UserId -> Text -> UTCTime -> ReaderT SqlBackend m (Entity Session)
createSession userId token expiresAt = do
    now <- liftIO getCurrentTime
    insertEntity Session
        { sessionUserId = userId
        , sessionToken = token
        , sessionExpiresAt = expiresAt
        , sessionCreatedAt = now
        }

validateSession :: MonadIO m => Text -> ReaderT SqlBackend m (Maybe (Entity User))
validateSession token = do
    now <- liftIO getCurrentTime
    mSession <- selectFirst
        [SessionToken ==. token, SessionExpiresAt >. now]
        []
    case mSession of
        Nothing -> return Nothing
        Just (Entity _ session) -> get (sessionUserId session) >>= \\case
            Nothing -> return Nothing
            Just user -> return $ Just $ Entity (sessionUserId session) user

-- Audit logging
logAction :: MonadIO m => Maybe UserId -> Text -> Text -> Text -> Maybe Value -> Maybe Value -> ReaderT SqlBackend m ()
logAction userId action entityType entityId oldValue newValue = do
    now <- liftIO getCurrentTime
    insert_ AuditLog
        { auditLogUserId = userId
        , auditLogAction = action
        , auditLogEntityType = entityType
        , auditLogEntityId = entityId
        , auditLogOldValue = oldValue
        , auditLogNewValue = newValue
        , auditLogIpAddress = Nothing
        , auditLogUserAgent = Nothing
        , auditLogCreatedAt = now
        }`,

    'src/Database/Queries.hs': `{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

module Database.Queries where

import Database.Persist
import Database.Persist.Sql
import Database.Esqueleto.Experimental
import Database.Schema
import Data.Text (Text)
import Data.Time (UTCTime, getCurrentTime, addDays)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader (ReaderT)
import qualified Data.Text as T

-- Advanced Esqueleto queries
-- Get posts with author and category information
getPostsWithDetails :: MonadIO m => ReaderT SqlBackend m [(Entity BlogPost, Entity User, Maybe (Entity Category))]
getPostsWithDetails = 
    select $ do
        (post :& author :& category) <- 
            from $ table @BlogPost
            \`innerJoin\` table @User
            \`on\` (\\(post :& author) -> post ^. BlogPostAuthorId ==. author ^. UserId)
            \`leftJoin\` table @Category
            \`on\` (\\(post :& _ :& category) -> post ^. BlogPostCategoryId ==. category ?. CategoryId)
        where_ (post ^. BlogPostPublished ==. val True)
        orderBy [desc (post ^. BlogPostPublishedAt)]
        limit 10
        return (post, author, category)

-- Get popular posts by view count
getPopularPosts :: MonadIO m => Int -> ReaderT SqlBackend m [Entity BlogPost]
getPopularPosts days = do
    now <- liftIO getCurrentTime
    let since = addDays (fromIntegral $ -days) now
    select $ do
        post <- from $ table @BlogPost
        where_ $ (post ^. BlogPostPublished ==. val True)
            &&. (post ^. BlogPostPublishedAt >=. just (val since))
        orderBy [desc (post ^. BlogPostViews)]
        limit 10
        return post

-- Get posts by tag
getPostsByTag :: MonadIO m => Text -> ReaderT SqlBackend m [Entity BlogPost]
getPostsByTag tagSlug =
    select $ do
        (post :& postTag :& tag) <-
            from $ table @BlogPost
            \`innerJoin\` table @PostTag
            \`on\` (\\(post :& postTag) -> post ^. BlogPostId ==. postTag ^. PostTagPostId)
            \`innerJoin\` table @Tag
            \`on\` (\\(_ :& postTag :& tag) -> postTag ^. PostTagTagId ==. tag ^. TagId)
        where_ $ (tag ^. TagSlug ==. val tagSlug)
            &&. (post ^. BlogPostPublished ==. val True)
        orderBy [desc (post ^. BlogPostPublishedAt)]
        return post

-- Complex aggregation: post count by category
getPostCountByCategory :: MonadIO m => ReaderT SqlBackend m [(Entity Category, Value Int)]
getPostCountByCategory =
    select $ do
        (category :& post) <-
            from $ table @Category
            \`leftJoin\` table @BlogPost
            \`on\` (\\(category :& post) -> just (category ^. CategoryId) ==. post ?. BlogPostCategoryId)
        groupBy (category ^. CategoryId)
        let postCount = count (post ?. BlogPostId)
        orderBy [desc postCount]
        return (category, postCount)

-- Search posts with full-text search (PostgreSQL specific)
searchPosts :: MonadIO m => Text -> ReaderT SqlBackend m [Entity BlogPost]
searchPosts query = rawSql
    "SELECT ?? FROM blog_post \\
    \\WHERE to_tsvector('english', title || ' ' || content) @@ plainto_tsquery('english', ?) \\
    \\AND published = TRUE \\
    \\ORDER BY ts_rank(to_tsvector('english', title || ' ' || content), plainto_tsquery('english', ?)) DESC"
    [toPersistValue query, toPersistValue query]

-- User activity statistics
getUserStats :: MonadIO m => UserId -> ReaderT SqlBackend m (Int, Int, Int)
getUserStats userId = do
    postCount <- count [BlogPostAuthorId ==. userId]
    commentCount <- count [CommentUserId ==. userId]
    
    viewCount <- select $ do
        post <- from $ table @BlogPost
        where_ (post ^. BlogPostAuthorId ==. val userId)
        return $ sum_ (post ^. BlogPostViews)
    
    let totalViews = case viewCount of
            [Value (Just v)] -> v
            _ -> 0
    
    return (postCount, commentCount, totalViews)

-- Recent comments with post and user info
getRecentComments :: MonadIO m => Int -> ReaderT SqlBackend m [(Entity Comment, Entity BlogPost, Entity User)]
getRecentComments limit =
    select $ do
        (comment :& post :& user) <-
            from $ table @Comment
            \`innerJoin\` table @BlogPost
            \`on\` (\\(comment :& post) -> comment ^. CommentPostId ==. post ^. BlogPostId)
            \`innerJoin\` table @User
            \`on\` (\\(comment :& _ :& user) -> comment ^. CommentUserId ==. user ^. UserId)
        where_ (comment ^. CommentApproved ==. val True)
        orderBy [desc (comment ^. CommentCreatedAt)]
        limit (fromIntegral limit)
        return (comment, post, user)

-- Subquery example: users who have written posts
getActiveAuthors :: MonadIO m => ReaderT SqlBackend m [Entity User]
getActiveAuthors =
    select $ do
        author <- from $ table @User
        where_ $ exists $ do
            post <- from $ table @BlogPost
            where_ (post ^. BlogPostAuthorId ==. author ^. UserId)
        return author

-- Window function example (requires PostgreSQL)
getPostsWithRank :: MonadIO m => ReaderT SqlBackend m [(Entity BlogPost, Value Int)]
getPostsWithRank = rawSql
    "SELECT ??, RANK() OVER (ORDER BY views DESC) as rank \\
    \\FROM blog_post \\
    \\WHERE published = TRUE"
    []

-- Transaction example
publishPostWithNotification :: MonadIO m => BlogPostId -> ReaderT SqlBackend m ()
publishPostWithNotification postId = do
    -- Start transaction implicitly
    now <- liftIO getCurrentTime
    
    -- Update post
    update postId
        [ BlogPostPublished =. True
        , BlogPostPublishedAt =. Just now
        ]
    
    -- Log the action
    mPost <- get postId
    case mPost of
        Nothing -> error "Post not found"
        Just post -> logAction
            (Just $ blogPostAuthorId post)
            "publish"
            "BlogPost"
            (T.pack $ show postId)
            (Just $ object ["published" .= False])
            (Just $ object ["published" .= True])
    
    -- Could add notification logic here
    -- Transaction commits automatically if no exception`,

    'src/Database/Migration.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Database.Migration where

import Database.Persist
import Database.Persist.Sql
import Database.Persist.Postgresql
import Database.Schema
import Control.Monad.Reader
import Control.Monad.Logger
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time

-- Run all migrations
runMigrations :: ConnectionString -> IO ()
runMigrations connStr = runStderrLoggingT $
    withPostgresqlPool connStr 10 $ \\pool ->
        liftIO $ runSqlPool doMigrations pool

doMigrations :: ReaderT SqlBackend IO ()
doMigrations = do
    -- Run auto-generated migrations
    runMigration migrateAll
    
    -- Run custom migrations
    runCustomMigrations

-- Custom migrations that can't be expressed in the schema
runCustomMigrations :: ReaderT SqlBackend IO ()
runCustomMigrations = do
    -- Add indexes
    rawExecute "CREATE INDEX IF NOT EXISTS idx_blog_post_published_at ON blog_post(published_at) WHERE published = true" []
    rawExecute "CREATE INDEX IF NOT EXISTS idx_blog_post_slug ON blog_post(slug)" []
    rawExecute "CREATE INDEX IF NOT EXISTS idx_user_email ON user(email)" []
    rawExecute "CREATE INDEX IF NOT EXISTS idx_session_token ON session(token)" []
    rawExecute "CREATE INDEX IF NOT EXISTS idx_session_expires ON session(expires_at)" []
    
    -- Add full-text search (PostgreSQL)
    rawExecute "CREATE EXTENSION IF NOT EXISTS unaccent" []
    rawExecute "CREATE EXTENSION IF NOT EXISTS pg_trgm" []
    
    -- Create search index
    rawExecute 
        "CREATE INDEX IF NOT EXISTS idx_blog_post_search ON blog_post \\
        \\USING gin(to_tsvector('english', title || ' ' || content))"
        []
    
    -- Add triggers for updated_at
    createUpdatedAtTrigger "user"
    createUpdatedAtTrigger "blog_post"
    createUpdatedAtTrigger "comment"
    
    -- Add check constraints
    rawExecute 
        "ALTER TABLE blog_post ADD CONSTRAINT check_published_at \\
        \\CHECK (published = false OR published_at IS NOT NULL)"
        []

-- Helper to create updated_at trigger
createUpdatedAtTrigger :: Text -> ReaderT SqlBackend IO ()
createUpdatedAtTrigger tableName = do
    -- Create trigger function if not exists
    rawExecute
        "CREATE OR REPLACE FUNCTION update_updated_at_column() \\
        \\RETURNS TRIGGER AS $$ \\
        \\BEGIN \\
        \\    NEW.updated_at = CURRENT_TIMESTAMP; \\
        \\    RETURN NEW; \\
        \\END; \\
        \\$$ language 'plpgsql'"
        []
    
    -- Create trigger
    rawExecute
        ("CREATE TRIGGER update_" <> tableName <> "_updated_at \\
        \\BEFORE UPDATE ON " <> tableName <> " \\
        \\FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()")
        []

-- Seed initial data
seedDatabase :: ReaderT SqlBackend IO ()
seedDatabase = do
    -- Check if already seeded
    userCount <- count ([] :: [Filter User])
    when (userCount == 0) $ do
        now <- liftIO getCurrentTime
        
        -- Create admin user
        adminId <- insert User
            { userEmail = "admin@example.com"
            , userUsername = Just "admin"
            , userPassword = "hashed_password_here"  -- Use proper hashing!
            , userFirstName = "Admin"
            , userLastName = "User"
            , userAvatar = Nothing
            , userEmailVerified = True
            , userActive = True
            , userRole = Admin
            , userCreatedAt = now
            , userUpdatedAt = now
            }
        
        -- Create categories
        techId <- insert Category
            { categoryName = "Technology"
            , categorySlug = "technology"
            , categoryDescription = Just "Technology related posts"
            , categoryParentId = Nothing
            , categorySortOrder = 1
            }
        
        lifeId <- insert Category
            { categoryName = "Lifestyle"
            , categorySlug = "lifestyle"
            , categoryDescription = Just "Lifestyle and personal posts"
            , categoryParentId = Nothing
            , categorySortOrder = 2
            }
        
        -- Create sample post
        postId <- insert BlogPost
            { blogPostTitle = "Welcome to Our Blog"
            , blogPostSlug = "welcome-to-our-blog"
            , blogPostContent = "This is the first post on our new blog!"
            , blogPostSummary = Just "Welcome post"
            , blogPostAuthorId = adminId
            , blogPostCategoryId = Just techId
            , blogPostPublished = True
            , blogPostPublishedAt = Just now
            , blogPostViews = 0
            , blogPostCreatedAt = now
            , blogPostUpdatedAt = now
            }
        
        -- Create tags
        welcomeTagId <- insert Tag
            { tagName = "Welcome"
            , tagSlug = "welcome"
            }
        
        announcementTagId <- insert Tag
            { tagName = "Announcement"
            , tagSlug = "announcement"
            }
        
        -- Associate tags with post
        insert_ PostTag
            { postTagPostId = postId
            , postTagTagId = welcomeTagId
            }
        
        insert_ PostTag
            { postTagPostId = postId
            , postTagTagId = announcementTagId
            }

-- Rollback a specific migration
rollbackMigration :: Text -> ReaderT SqlBackend IO ()
rollbackMigration migrationName = case migrationName of
    "add_search_index" -> 
        rawExecute "DROP INDEX IF EXISTS idx_blog_post_search" []
    "add_triggers" -> do
        rawExecute "DROP TRIGGER IF EXISTS update_user_updated_at ON user" []
        rawExecute "DROP TRIGGER IF EXISTS update_blog_post_updated_at ON blog_post" []
        rawExecute "DROP TRIGGER IF EXISTS update_comment_updated_at ON comment" []
    _ -> error $ "Unknown migration: " <> T.unpack migrationName`,

    'src/Database/Config.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Database.Config where

import Database.Persist.Postgresql
import Database.Persist.MySQL
import Database.Persist.Sqlite
import Control.Monad.Logger
import Control.Monad.Reader
import Data.Pool
import Data.Text (Text)
import qualified Data.Text as T
import System.Environment

-- Database configuration
data DbConfig = DbConfig
    { dbBackend :: DbBackend
    , dbConnStr :: Text
    , dbPoolSize :: Int
    , dbIdleTimeout :: Int  -- seconds
    } deriving (Show)

data DbBackend = PostgreSQL | MySQL | SQLite
    deriving (Show, Read, Eq)

-- Load config from environment
loadDbConfig :: IO DbConfig
loadDbConfig = do
    backend <- read <$> getEnvDefault "DB_BACKEND" "PostgreSQL"
    connStr <- T.pack <$> getEnvDefault "DATABASE_URL" defaultConnStr
    poolSize <- read <$> getEnvDefault "DB_POOL_SIZE" "10"
    idleTimeout <- read <$> getEnvDefault "DB_IDLE_TIMEOUT" "600"
    
    return DbConfig{..}
  where
    defaultConnStr = case backend of
        PostgreSQL -> "host=localhost dbname=myapp user=postgres password=postgres"
        MySQL -> "mysql://root:password@localhost:3306/myapp"
        SQLite -> "myapp.db"
    
    backend = read $ unsafePerformIO $ getEnvDefault "DB_BACKEND" "PostgreSQL"

getEnvDefault :: String -> String -> IO String
getEnvDefault key def = lookupEnv key >>= \\case
    Nothing -> return def
    Just val -> return val

-- Create connection pool based on backend
createDbPool :: DbConfig -> IO ConnectionPool
createDbPool DbConfig{..} = case dbBackend of
    PostgreSQL -> runStderrLoggingT $
        createPostgresqlPool (T.encodeUtf8 dbConnStr) dbPoolSize
    
    MySQL -> runStderrLoggingT $
        createMySQLPool defaultConnectInfo
            { connectHost = "localhost"
            , connectDatabase = "myapp"
            , connectUser = "root"
            , connectPassword = "password"
            } dbPoolSize
    
    SQLite -> runStderrLoggingT $
        createSqlitePool dbConnStr dbPoolSize

-- Run database action with pool
runDb :: ConnectionPool -> ReaderT SqlBackend IO a -> IO a
runDb pool action = runSqlPool action pool

-- Run database action with logging
runDbWithLog :: ConnectionPool -> ReaderT SqlBackend (LoggingT IO) a -> IO a
runDbWithLog pool action = runStderrLoggingT $ runSqlPool action pool

-- Database configuration for different environments
data Environment = Development | Testing | Production
    deriving (Show, Read, Eq)

getDbConfigForEnv :: Environment -> DbConfig
getDbConfigForEnv env = case env of
    Development -> DbConfig
        { dbBackend = PostgreSQL
        , dbConnStr = "host=localhost dbname=myapp_dev user=postgres"
        , dbPoolSize = 5
        , dbIdleTimeout = 600
        }
    
    Testing -> DbConfig
        { dbBackend = SQLite
        , dbConnStr = ":memory:"
        , dbPoolSize = 1
        , dbIdleTimeout = 60
        }
    
    Production -> DbConfig
        { dbBackend = PostgreSQL
        , dbConnStr = "host=db.example.com dbname=myapp user=myapp password=secret"
        , dbPoolSize = 20
        , dbIdleTimeout = 1800
        }

-- Connection pool with health checks
createHealthCheckPool :: DbConfig -> IO ConnectionPool
createHealthCheckPool config = do
    pool <- createDbPool config
    -- Add health check
    _ <- runDb pool $ rawSql "SELECT 1" []
    return pool

-- Read-only replica support
data ReplicatedDbConfig = ReplicatedDbConfig
    { masterConfig :: DbConfig
    , replicaConfigs :: [DbConfig]
    }

createReplicatedPools :: ReplicatedDbConfig -> IO (ConnectionPool, [ConnectionPool])
createReplicatedPools ReplicatedDbConfig{..} = do
    masterPool <- createDbPool masterConfig
    replicaPools <- mapM createDbPool replicaConfigs
    return (masterPool, replicaPools)`,

    'app/Main.hs': `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Main where

import Database.Persist
import Database.Persist.Sql
import Database.Schema
import Database.Models
import Database.Queries
import Database.Migration
import Database.Config
import Control.Monad.Logger
import Control.Monad.Reader
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time

main :: IO ()
main = do
    -- Load configuration
    config <- loadDbConfig
    
    -- Create connection pool
    pool <- createDbPool config
    
    -- Run migrations
    runDb pool $ do
        runMigration migrateAll
        runCustomMigrations
    
    -- Seed database if empty
    runDb pool seedDatabase
    
    -- Example operations
    runStderrLoggingT $ runDb pool $ do
        -- Create a user
        now <- liftIO getCurrentTime
        Entity userId user <- createUser
            "john@example.com"
            "hashed_password"
            "John"
            "Doe"
            Author
        
        liftIO $ putStrLn $ "Created user: " ++ show userId
        
        -- Create a post
        Entity postId post <- createPost
            "My First Post"
            "my-first-post"
            "This is the content of my first post."
            userId
        
        -- Add tags
        addTagsToPost postId ["haskell", "persistent", "database"]
        
        -- Publish the post
        publishPost postId
        
        -- Query posts with details
        postsWithDetails <- getPostsWithDetails
        liftIO $ putStrLn $ "Posts with details: " ++ show (length postsWithDetails)
        
        -- Search posts
        searchResults <- searchPosts "haskell"
        liftIO $ putStrLn $ "Search results: " ++ show (length searchResults)
        
        -- Get user statistics
        (posts, comments, views) <- getUserStats userId
        liftIO $ putStrLn $ "User stats - Posts: " ++ show posts ++ 
                           ", Comments: " ++ show comments ++ 
                           ", Views: " ++ show views
    
    -- Example with raw SQL
    runDb pool $ do
        users <- rawSql
            "SELECT ?? FROM user WHERE created_at > ?"
            [toPersistValue $ addDays (-7) now]
        liftIO $ putStrLn $ "Recent users: " ++ show (length (users :: [Entity User]))
    
    -- Transaction example
    result <- runDb pool $ do
        -- This entire block runs in a transaction
        Entity catId _ <- createCategory "Programming" "programming" Nothing Nothing
        Entity postId2 _ <- createPost
            "Haskell Tutorial"
            "haskell-tutorial"
            "Learn Haskell programming"
            userId
        
        -- Update post with category
        update postId2 [BlogPostCategoryId =. Just catId]
        
        -- If any operation fails, entire transaction is rolled back
        return (catId, postId2)
    
    liftIO $ putStrLn $ "Transaction result: " ++ show result
    
    putStrLn "Done!"`,

    'README.md': `# Haskell Persistent ORM

Type-safe database access for Haskell applications using the Persistent library.

## Features

- **Type Safety**: Database schema defined in Haskell with compile-time guarantees
- **Multiple Backends**: PostgreSQL, MySQL, SQLite, MongoDB support
- **Automatic Migrations**: Schema changes handled automatically
- **Query DSL**: Type-safe query construction
- **Raw SQL**: Escape hatch for complex queries
- **Relationships**: One-to-many, many-to-many support
- **Transactions**: ACID compliance
- **Connection Pooling**: Efficient resource management

## Quick Start

### Define Schema

\`\`\`haskell
share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
User
    email Text
    username Text Maybe
    UniqueEmail email
    deriving Show
|]
\`\`\`

### Basic Operations

\`\`\`haskell
-- Insert
userId <- insert $ User "john@example.com" (Just "john")

-- Select
user <- get userId
users <- selectList [UserEmail ==. "john@example.com"] []

-- Update
update userId [UserUsername =. Just "johndoe"]

-- Delete
delete userId
\`\`\`

### Query DSL with Esqueleto

\`\`\`haskell
-- Complex queries
posts <- select $ do
    (post :& author) <- 
        from $ table @BlogPost
        \`innerJoin\` table @User
        \`on\` (\\(post :& author) -> 
            post ^. BlogPostAuthorId ==. author ^. UserId)
    where_ (post ^. BlogPostPublished ==. val True)
    orderBy [desc (post ^. BlogPostCreatedAt)]
    limit 10
    return (post, author)
\`\`\`

## Backend Configuration

### PostgreSQL
\`\`\`haskell
connStr = "host=localhost dbname=myapp user=postgres password=postgres"
pool <- runStderrLoggingT $ createPostgresqlPool connStr 10
\`\`\`

### MySQL
\`\`\`haskell
connInfo = defaultConnectInfo
    { connectHost = "localhost"
    , connectDatabase = "myapp"
    }
pool <- runStderrLoggingT $ createMySQLPool connInfo 10
\`\`\`

### SQLite
\`\`\`haskell
pool <- runStderrLoggingT $ createSqlitePool "myapp.db" 10
\`\`\`

## Migrations

### Auto-migration
\`\`\`haskell
runSqlPool (runMigration migrateAll) pool
\`\`\`

### Custom migrations
\`\`\`haskell
runSqlPool customMigration pool
  where
    customMigration = rawExecute
        "CREATE INDEX idx_user_email ON user(email)" []
\`\`\`

## Advanced Features

### Transactions
\`\`\`haskell
runSqlPool (do
    userId <- insert user
    postId <- insert $ BlogPost "Title" userId
    -- Automatic rollback on exception
    ) pool
\`\`\`

### JSON Fields
\`\`\`haskell
Settings
    userId UserId
    preferences Value  -- Stores JSON
    deriving Show
\`\`\`

### Custom Types
\`\`\`haskell
data UserRole = Admin | User
    deriving (Show, Read, Eq)

instance PersistField UserRole where
    toPersistValue = PersistText . T.pack . show
    fromPersistValue (PersistText t) = 
        case readMaybe (T.unpack t) of
            Just r -> Right r
            Nothing -> Left "Invalid role"

instance PersistFieldSql UserRole where
    sqlType _ = SqlString
\`\`\`

### Streaming Queries
\`\`\`haskell
-- Process large result sets efficiently
runSqlPool (selectSource [] [] $$ mapM_C process) pool
\`\`\`

## Performance Tips

1. **Use Indexes**: Add indexes for frequently queried columns
2. **Connection Pooling**: Configure pool size based on load
3. **Batch Operations**: Use \`insertMany\` for bulk inserts
4. **Raw SQL**: For complex queries that Esqueleto can't express
5. **Lazy Loading**: Be aware of N+1 query problems

## Testing

### In-Memory Database
\`\`\`haskell
-- Use SQLite :memory: for tests
testPool <- runNoLoggingT $ createSqlitePool ":memory:" 1
\`\`\`

### Fixtures
\`\`\`haskell
setupFixtures :: ReaderT SqlBackend IO ()
setupFixtures = do
    userId <- insert $ User "test@example.com" Nothing
    insert_ $ BlogPost "Test Post" userId
\`\`\`

## Common Patterns

### Repository Pattern
\`\`\`haskell
class Monad m => UserRepository m where
    createUser :: Text -> m UserId
    findUser :: UserId -> m (Maybe User)
    findUserByEmail :: Text -> m (Maybe (Entity User))
\`\`\`

### Pagination
\`\`\`haskell
paginate :: Int -> Int -> [SelectOpt record] -> [SelectOpt record]
paginate page size opts = LimitTo size : OffsetBy ((page-1)*size) : opts
\`\`\`

### Soft Deletes
\`\`\`haskell
User
    ...
    deletedAt UTCTime Maybe
    deriving Show

-- Query only active records
selectList [UserDeletedAt ==. Nothing] []
\`\`\`

## Troubleshooting

- **Migration Conflicts**: Use \`--force\` flag carefully
- **Connection Leaks**: Always use connection pools
- **Type Errors**: Check schema definition matches database
- **Performance**: Enable query logging in development

## Resources

- [Persistent Documentation](https://www.yesodweb.com/book/persistent)
- [Esqueleto Documentation](https://hackage.haskell.org/package/esqueleto)
- [Yesod Book Database Chapter](https://www.yesodweb.com/book/persistent)`
  }
};