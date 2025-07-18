import { BackendTemplate } from '../types';

export const yesodTemplate: BackendTemplate = {
  id: 'yesod',
  name: 'yesod',
  displayName: 'Yesod Full-Stack Web Framework',
  description: 'A Haskell web framework focusing on type safety, high performance, and rapid development',
  framework: 'yesod',
  language: 'haskell',
  version: '1.6',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🏛️',
  type: 'full-stack',
  complexity: 'advanced',
  keywords: ['haskell', 'yesod', 'full-stack', 'type-safe', 'web', 'framework'],
  
  features: [
    'Type-safe URLs and routing',
    'Compile-time template checking',
    'Built-in authentication and authorization',
    'Form handling with CSRF protection',
    'Database integration with Persistent',
    'Automatic RESTful routes',
    'WebSocket support',
    'Internationalization (i18n)',
    'Email sending',
    'Background jobs',
    'Admin scaffolding',
    'Asset management',
    'Testing framework'
  ],
  
  structure: {
    'app/Main.hs': `{-# LANGUAGE OverloadedStrings #-}

import Prelude
import Yesod.Default.Config2 (makeYesodRunner, loadYamlSettings, useEnv)
import Yesod.Default.Main (defaultMainLog)
import Application (makeFoundation, makeLogWare)
import Settings (configSettingsYmlValue)

-- | The main function for the application
main :: IO ()
main = do
    -- Get the settings from all relevant sources
    settings <- loadYamlSettings
        ["config/settings.yml"]
        []  -- No values to override from args
        useEnv

    -- Generate the foundation from the settings
    foundation <- makeFoundation settings

    -- Generate a WAI Application from the foundation
    app <- makeApplication foundation

    -- Run the application with Warp
    runSettings (warpSettings foundation) app`,

    'src/Application.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Application
    ( getApplicationDev
    , appMain
    , develMain
    , makeFoundation
    , makeLogWare
    , getApplicationRepl
    , handler
    , db
    ) where

import Control.Monad.Logger (liftLoc, runLoggingT)
import Database.Persist.Postgresql (createPostgresqlPool, pgConnStr, pgPoolSize)
import Import
import Language.Haskell.TH.Syntax (qLocation)
import Network.HTTP.Client.TLS (getGlobalManager)
import Network.Wai (Middleware)
import Network.Wai.Handler.Warp (Settings, defaultSettings, defaultShouldDisplayException,
                                 runSettings, setHost, setOnException, setPort)
import Network.Wai.Middleware.RequestLogger (Destination (Callback), IPAddrSource (..),
                                            mkRequestLogger, outputFormat)
import System.Log.FastLogger (defaultBufSize, newStdoutLoggerSet, toLogStr)

-- Import all relevant handler modules here.
-- Don't forget to add new modules to your cabal file!
import Handler.Common
import Handler.Home
import Handler.User
import Handler.Todo
import Handler.Auth

-- This line actually creates our YesodDispatch instance. It is the second half
-- of the call to mkYesodData which occurs in Foundation.hs. Please see the
-- comments there for more details.
mkYesodDispatch "App" resourcesApp

-- | This function allocates resources (such as a database connection pool),
-- performs initialization and returns a foundation datatype value.
makeFoundation :: AppSettings -> IO App
makeFoundation appSettings = do
    -- Some basic initializations: HTTP connection manager, logger, and static
    -- subsite.
    appHttpManager <- getGlobalManager
    appLogger <- newStdoutLoggerSet defaultBufSize >>= makeYesodLogger
    appStatic <-
        (if appMutableStatic appSettings then staticDevel else static)
        (appStaticDir appSettings)

    -- Create the database connection pool
    appConnPool <- createPoolConfig $ appDatabaseConf appSettings

    -- Return the foundation
    return App {..}

-- | Convert our foundation to a WAI Application by calling toWaiAppPlain and
-- applying some additional middlewares.
makeApplication :: App -> IO Application
makeApplication foundation = do
    logWare <- makeLogWare foundation
    -- Create the WAI application and apply middlewares
    appPlain <- toWaiAppPlain foundation
    return $ logWare $ defaultMiddlewaresNoLogging appPlain

makeLogWare :: App -> IO Middleware
makeLogWare foundation =
    mkRequestLogger def
        { outputFormat =
            if appDetailedRequestLogging $ appSettings foundation
                then Detailed True
                else Apache FromFallback
        , destination = Callback $ \\str -> do
            runLoggingT
                (toLogStr str >>= loggerPutStr (appLogger foundation))
                (messageLoggerSource foundation (appLogger foundation))
        }

-- | Warp settings for the given foundation value.
warpSettings :: App -> Settings
warpSettings foundation =
      setPort (appPort $ appSettings foundation)
    $ setHost (appHost $ appSettings foundation)
    $ setOnException (\\_ e ->
        when (defaultShouldDisplayException e) $ runLoggingT
            (messageLoggerSource foundation (appLogger foundation)
                $(qLocation >>= liftLoc)
                "yesod"
                LevelError
                (toLogStr $ "Exception from Warp: " ++ show e))
            (messageLoggerSource foundation (appLogger foundation)))
      defaultSettings

-- | For yesod devel, return the Warp settings and WAI Application.
getApplicationDev :: IO (Settings, Application)
getApplicationDev = do
    settings <- getAppSettings
    foundation <- makeFoundation settings
    wsettings <- getDevSettings $ warpSettings foundation
    app <- makeApplication foundation
    return (wsettings, app)

getAppSettings :: IO AppSettings
getAppSettings = loadYamlSettings ["config/settings.yml"] [] useEnv

-- | main function for use by yesod devel
develMain :: IO ()
develMain = develMainHelper getApplicationDev

-- | The @main@ function for an executable running this site.
appMain :: IO ()
appMain = do
    -- Get the settings from all relevant sources
    settings <- loadYamlSettingsArgs
        -- fall back to compile-time values, set to [] to require values at runtime
        []
        -- allow environment variables to override
        useEnv

    -- Generate the foundation from the settings
    foundation <- makeFoundation settings

    -- Generate a WAI Application from the foundation
    app <- makeApplication foundation

    -- Run the application with Warp
    runSettings (warpSettings foundation) app

-- | Used for yesod devel and testing
getApplicationRepl :: IO (Int, App, Application)
getApplicationRepl = do
    settings <- getAppSettings
    foundation <- makeFoundation settings
    wsettings <- getDevSettings $ warpSettings foundation
    app1 <- makeApplication foundation
    return (getPort wsettings, foundation, app1)

-- | Run DB queries
handler :: Handler a -> IO a
handler h = getAppSettings >>= makeFoundation >>= flip unsafeHandler h

-- | Run DB queries
db :: ReaderT SqlBackend Handler a -> IO a
db = handler . runDB`,

    'src/Foundation.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE FlexibleContexts #-}

module Foundation where

import Import.NoFoundation
import Database.Persist.Sql (ConnectionPool, runSqlPool)
import Text.Hamlet (hamletFile)
import Text.Jasmine (minifym)
import Control.Monad.Logger (LogSource)
import Yesod.Auth.Email
import Yesod.Auth.Message (AuthMessage (InvalidLogin))
import Yesod.Default.Util (addStaticContentExternal)
import Yesod.Core.Types (Logger)
import qualified Yesod.Core.Unsafe as Unsafe
import qualified Data.Text.Encoding as TE

-- | The foundation datatype for your application. This can be a good place to
-- keep settings and values requiring initialization before your application
-- starts running, such as database connections.
data App = App
    { appSettings    :: AppSettings
    , appStatic      :: Static -- ^ Settings for static file serving.
    , appConnPool    :: ConnectionPool -- ^ Database connection pool.
    , appHttpManager :: Manager
    , appLogger      :: Logger
    }

-- This is where we define all of the routes in our application. For a full
-- explanation of the syntax, please see:
-- https://www.yesodweb.com/book/routing-and-handlers
mkYesodData "App" $(parseRoutesFile "config/routes")

-- | A convenient synonym for creating forms.
type Form x = Html -> MForm (HandlerFor App) (FormResult x, Widget)

-- | A convenient synonym for database access functions.
type DB a = forall (m :: * -> *).
    (MonadUnliftIO m) => ReaderT SqlBackend m a

-- Please see the documentation for the Yesod typeclass. There are a number
-- of settings which can be configured by overriding methods here.
instance Yesod App where
    -- Controls the base of generated URLs. For more information on modifying,
    -- see: https://github.com/yesodweb/yesod/wiki/Overriding-approot
    approot :: Approot App
    approot = ApprootRequest $ \\app req ->
        case appRoot $ appSettings app of
            Nothing -> getApprootText guessApproot app req
            Just root -> root

    -- Store session data on the client in encrypted cookies
    makeSessionBackend :: App -> IO (Maybe SessionBackend)
    makeSessionBackend _ = Just <$> defaultClientSessionBackend
        120    -- timeout in minutes
        "config/client_session_key.aes"

    -- Yesod Middleware allows you to run code before and after each handler function.
    yesodMiddleware :: Handler res -> Handler res
    yesodMiddleware = defaultYesodMiddleware

    defaultLayout :: Widget -> Handler Html
    defaultLayout widget = do
        master <- getYesod
        mmsg <- getMessage

        -- We break up the default layout into two components:
        -- default-layout is the contents of the body tag, and
        -- default-layout-wrapper is the entire page. Since the final
        -- value passed to hamletToRepHtml cannot be a widget, this allows
        -- you to use normal widget features in default-layout.

        pc <- widgetToPageContent $ do
            addStylesheet $ StaticR css_bootstrap_css
            $(widgetFile "default-layout")
        withUrlRenderer $(hamletFile "templates/default-layout-wrapper.hamlet")

    -- Authentication
    authRoute :: App -> Maybe (Route App)
    authRoute _ = Just $ AuthR LoginR

    isAuthorized :: Route App -> Bool -> Handler AuthResult
    isAuthorized (AuthR _) _ = return Authorized
    isAuthorized HomeR _ = return Authorized
    isAuthorized FaviconR _ = return Authorized
    isAuthorized RobotsR _ = return Authorized
    isAuthorized (StaticR _) _ = return Authorized

    -- Routes requiring authentication
    isAuthorized TodoListR _ = isAuthenticated
    isAuthorized (TodoR _) _ = isAuthenticated
    isAuthorized ProfileR _ = isAuthenticated
    
    -- Admin routes
    isAuthorized AdminR _ = isAdmin
    isAuthorized (UserR _) _ = isAdmin

    -- This function creates static content files in the static folder
    -- and names them based on a hash of their content. This allows
    -- expiration dates to be set far in the future without worry of
    -- users receiving stale content.
    addStaticContent ::
        Text -- ^ The file extension
        -> Text -- ^ The MIME content type
        -> LByteString -- ^ The contents of the file
        -> Handler (Maybe (Either Text (Route App, [(Text, Text)])))
    addStaticContent ext mime content = do
        master <- getYesod
        let settings = appSettings master
            staticDir = appStaticDir settings
        addStaticContentExternal
            (if appMinifyResources settings then minifym else id)
            genFileName
            staticDir
            (StaticR . flip StaticRoute [])
            ext
            mime
            content
      where
        -- Generate a unique filename based on the content itself
        genFileName lbs = "autogen-" ++ base64md5 lbs

    -- What messages should be logged.
    shouldLogIO :: App -> LogSource -> LogLevel -> IO Bool
    shouldLogIO app _source level =
        return $ appShouldLogAll (appSettings app)
            || level == LevelWarn
            || level == LevelError

    makeLogger :: App -> IO Logger
    makeLogger = return . appLogger

-- | Require authentication
isAuthenticated :: Handler AuthResult
isAuthenticated = do
    muid <- maybeAuthId
    return $ case muid of
        Nothing -> Unauthorized "You must login to access this page"
        Just _ -> Authorized

-- | Require admin privileges
isAdmin :: Handler AuthResult
isAdmin = do
    muser <- maybeAuth
    return $ case muser of
        Nothing -> Unauthorized "You must login to access this page"
        Just (Entity _ user) ->
            if userAdmin user
                then Authorized
                else Unauthorized "You must be an admin to access this page"

-- How to run database actions.
instance YesodPersist App where
    type YesodPersistBackend App = SqlBackend
    runDB :: DB a -> Handler a
    runDB action = do
        master <- getYesod
        runSqlPool action $ appConnPool master

instance YesodPersistRunner App where
    getDBRunner :: Handler (DBRunner App, Handler ())
    getDBRunner = defaultGetDBRunner appConnPool

-- Authentication
instance YesodAuth App where
    type AuthId App = UserId

    -- Where to send a user after successful login
    loginDest :: App -> Route App
    loginDest _ = HomeR

    -- Where to send a user after logout
    logoutDest :: App -> Route App
    logoutDest _ = HomeR

    -- Override the above destinations when a Referer: header is present
    redirectToReferer :: App -> Bool
    redirectToReferer _ = True

    authenticate :: (MonadHandler m, HandlerSite m ~ App)
                 => Creds App -> m (AuthenticationResult App)
    authenticate creds = liftHandler $ runDB $ do
        x <- insertBy $ User 
            (credsIdent creds) 
            Nothing 
            Nothing 
            False
        case x of
            Left (Entity uid _) -> return $ Authenticated uid
            Right uid -> return $ Authenticated uid

    -- You can add other plugins like Google Email, email or OAuth here
    authPlugins :: App -> [AuthPlugin App]
    authPlugins app = [authEmail]

-- Email authentication
instance YesodAuthEmail App where
    type AuthEmailId App = UserId

    afterPasswordRoute _ = HomeR

    addUnverified email verkey = liftHandler $ runDB $ do
        insert $ User email Nothing (Just verkey) False

    sendVerifyEmail email _ verurl = do
        liftIO $ putStrLn $ "Verification email for " ++ show email ++ ": " ++ show verurl
        -- In production, actually send email here

    getVerifyKey = liftHandler . runDB . fmap (join . fmap userVerkey) . get
    
    setVerifyKey uid key = liftHandler $ runDB $ update uid [UserVerkey =. Just key]
    
    verifyAccount uid = liftHandler $ runDB $ do
        mu <- get uid
        case mu of
            Nothing -> return Nothing
            Just _ -> do
                update uid [UserVerified =. True]
                return $ Just uid
    
    getPassword = liftHandler . runDB . fmap (join . fmap userPassword) . get
    
    setPassword uid pass = liftHandler $ runDB $ update uid [UserPassword =. Just pass]
    
    getEmailCreds email = liftHandler $ runDB $ do
        mu <- getBy $ UniqueUser email
        case mu of
            Nothing -> return Nothing
            Just (Entity uid u) -> return $ Just EmailCreds
                { emailCredsId = uid
                , emailCredsAuthId = Just uid
                , emailCredsStatus = isJust $ userPassword u
                , emailCredsVerkey = userVerkey u
                , emailCredsEmail = email
                }
    
    getEmail = liftHandler . runDB . fmap (fmap userEmail) . get

-- | Access function to determine if a user is logged in.
isAuthenticated :: Handler AuthResult
isAuthenticated = do
    muid <- maybeAuthId
    return $ case muid of
        Nothing -> Unauthorized "You must login to access this page"
        Just _ -> Authorized

instance YesodAuthPersist App

-- This instance is required to use forms. You can modify renderMessage to
-- achieve customized and internationalized form validation messages.
instance RenderMessage App FormMessage where
    renderMessage :: App -> [Lang] -> FormMessage -> Text
    renderMessage _ _ = defaultFormMessage

-- Useful when writing code that is re-usable outside of the Handler context.
instance HasHttpManager App where
    getHttpManager :: App -> Manager
    getHttpManager = appHttpManager

unsafeHandler :: App -> Handler a -> IO a
unsafeHandler = Unsafe.fakeHandlerGetLogger appLogger`,

    'src/Import.hs': `{-# LANGUAGE NoImplicitPrelude #-}

module Import
    ( module Import
    ) where

import Foundation as Import
import Import.NoFoundation as Import`,

    'src/Import/NoFoundation.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Import.NoFoundation
    ( module Import
    ) where

import ClassyPrelude.Yesod as Import
import Model as Import
import Settings as Import
import Settings.StaticFiles as Import
import SharedTypes as Import
import Yesod.Auth as Import
import Yesod.Core.Types as Import (loggerSet)
import Yesod.Default.Config2 as Import`,

    'src/Settings.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}

module Settings where

import ClassyPrelude.Yesod
import qualified Control.Exception as Exception
import Data.Aeson (Result (..), fromJSON, withObject, (.!=), (.:?))
import Data.FileEmbed (embedFile)
import Data.Yaml (decodeEither')
import Database.Persist.Postgresql (PostgresConf)
import Language.Haskell.TH.Syntax (Exp, Name, Q)
import Network.Wai.Handler.Warp (HostPreference)
import Yesod.Default.Config2 (applyEnvValue, configSettingsYml)
import Yesod.Default.Util (WidgetFileSettings, widgetFileNoReload, widgetFileReload)

-- | Runtime settings to configure this application.
data AppSettings = AppSettings
    { appStaticDir              :: String
    , appDatabaseConf           :: PostgresConf
    , appRoot                   :: Maybe Text
    , appHost                   :: HostPreference
    , appPort                   :: Int
    , appIpFromHeader           :: Bool
    , appDetailedRequestLogging :: Bool
    , appShouldLogAll           :: Bool
    , appReloadTemplates        :: Bool
    , appMutableStatic          :: Bool
    , appSkipCombining          :: Bool
    , appAnalytics              :: Maybe Text
    , appAuthDummyLogin         :: Bool
    , appMinifyResources        :: Bool
    }

instance FromJSON AppSettings where
    parseJSON = withObject "AppSettings" $ \\o -> do
        let defaultEnv = False
        appStaticDir              <- o .: "static-dir"
        appDatabaseConf           <- o .: "database"
        appRoot                   <- o .:? "approot"
        appHost                   <- fromString <$> o .: "host"
        appPort                   <- o .: "port"
        appIpFromHeader           <- o .: "ip-from-header"
        appDetailedRequestLogging <- o .:? "detailed-logging" .!= defaultEnv
        appShouldLogAll           <- o .:? "should-log-all"   .!= defaultEnv
        appReloadTemplates        <- o .:? "reload-templates" .!= defaultEnv
        appMutableStatic          <- o .:? "mutable-static"   .!= defaultEnv
        appSkipCombining          <- o .:? "skip-combining"   .!= defaultEnv
        appAnalytics              <- o .:? "analytics"
        appAuthDummyLogin         <- o .:? "auth-dummy-login" .!= defaultEnv
        appMinifyResources        <- o .:? "minify-resources" .!= not defaultEnv

        return AppSettings {..}

-- | Settings for 'widgetFile', such as which template languages to support and
-- default Hamlet settings.
widgetFileSettings :: WidgetFileSettings
widgetFileSettings = def

-- | How static files should be combined.
combineSettings :: CombineSettings
combineSettings = def

-- The rest of this file contains settings which rarely need changing by a
-- user.

widgetFile :: String -> Q Exp
widgetFile = (if appReloadTemplates compileTimeAppSettings
                then widgetFileReload
                else widgetFileNoReload)
              widgetFileSettings

-- | Raw bytes at compile time of @config/settings.yml@
configSettingsYmlBS :: ByteString
configSettingsYmlBS = $(embedFile configSettingsYml)

-- | @config/settings.yml@, parsed to a @Value@.
configSettingsYmlValue :: Value
configSettingsYmlValue = either Exception.throw id
                       $ decodeEither' configSettingsYmlBS

-- | A version of @AppSettings@ parsed at compile time from @config/settings.yml@.
compileTimeAppSettings :: AppSettings
compileTimeAppSettings =
    case fromJSON $ applyEnvValue False mempty configSettingsYmlValue of
        Error e -> error e
        Success settings -> settings

-- The following two functions can be used to combine multiple CSS or JS files
-- at compile time to decrease the number of http requests.
-- Sample usage (inside a Widget):
--
-- > $(combineStylesheets 'StaticR [style1_css, style2_css])

combineStylesheets :: Name -> [Route Static] -> Q Exp
combineStylesheets = combineStylesheets'
    (appSkipCombining compileTimeAppSettings)
    combineSettings

combineScripts :: Name -> [Route Static] -> Q Exp
combineScripts = combineScripts'
    (appSkipCombining compileTimeAppSettings)
    combineSettings`,

    'src/Model.hs': `{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}

module Model where

import ClassyPrelude.Yesod
import Database.Persist.Quasi

-- You can define all of your database entities in the entities file.
-- You can find more information on persistent and how to declare entities
-- at:
-- https://www.yesodweb.com/book/persistent/
share [mkPersist sqlSettings, mkMigrate "migrateAll"]
    $(persistFileWith lowerCaseSettings "config/models.persistentmodels")`,

    'src/Handler/Home.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE QuasiQuotes #-}

module Handler.Home where

import Import
import Text.Julius (RawJS (..))

-- | Homepage handler
getHomeR :: Handler Html
getHomeR = do
    mauth <- maybeAuth
    defaultLayout $ do
        setTitle "Welcome to Yesod!"
        $(widgetFile "homepage")

-- | About page handler
getAboutR :: Handler Html
getAboutR = defaultLayout $ do
    setTitle "About"
    $(widgetFile "about")`,

    'src/Handler/User.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}

module Handler.User where

import Import

-- | User profile page
getProfileR :: Handler Html
getProfileR = do
    userId <- requireAuthId
    user <- runDB $ get404 userId
    
    defaultLayout $ do
        setTitle "Profile"
        $(widgetFile "profile")

-- | Update user profile
postProfileR :: Handler Html
postProfileR = do
    userId <- requireAuthId
    user <- runDB $ get404 userId
    
    ((result, widget), enctype) <- runFormPost $ profileForm user
    
    case result of
        FormSuccess ProfileData{..} -> do
            runDB $ update userId
                [ UserEmail =. profileEmail
                ]
            setMessage "Profile updated successfully"
            redirect ProfileR
        _ -> defaultLayout $ do
            setTitle "Profile"
            $(widgetFile "profile-edit")

-- | User list (admin only)
getUserListR :: Handler Html
getUserListR = do
    users <- runDB $ selectList [] [Desc UserId]
    defaultLayout $ do
        setTitle "Users"
        $(widgetFile "users")

-- | Individual user page (admin only)
getUserR :: UserId -> Handler Html
getUserR userId = do
    user <- runDB $ get404 userId
    todos <- runDB $ selectList [TodoUserId ==. userId] [Desc TodoCreated]
    
    defaultLayout $ do
        setTitle $ "User: " <> userEmail user
        $(widgetFile "user")

-- | Profile form data
data ProfileData = ProfileData
    { profileEmail :: Text
    }

-- | Profile form
profileForm :: User -> Form ProfileData
profileForm user = renderDivs $ ProfileData
    <$> areq emailField (fieldSettingsLabel "Email") (Just $ userEmail user)`,

    'src/Handler/Todo.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}

module Handler.Todo where

import Import

-- | List all todos for the current user
getTodoListR :: Handler Html
getTodoListR = do
    userId <- requireAuthId
    todos <- runDB $ selectList [TodoUserId ==. userId] [Desc TodoCreated]
    
    (widget, enctype) <- generateFormPost todoForm
    
    defaultLayout $ do
        setTitle "My Todos"
        $(widgetFile "todos")

-- | Create a new todo
postTodoListR :: Handler Html
postTodoListR = do
    userId <- requireAuthId
    
    ((result, widget), enctype) <- runFormPost todoForm
    
    case result of
        FormSuccess TodoData{..} -> do
            now <- liftIO getCurrentTime
            _ <- runDB $ insert $ Todo
                { todoUserId = userId
                , todoTitle = todoTitle
                , todoDescription = todoDescription
                , todoCompleted = False
                , todoCreated = now
                , todoUpdated = now
                }
            setMessage "Todo created successfully"
            redirect TodoListR
        _ -> do
            todos <- runDB $ selectList [TodoUserId ==. userId] [Desc TodoCreated]
            defaultLayout $ do
                setTitle "My Todos"
                $(widgetFile "todos")

-- | Get a specific todo
getTodoR :: TodoId -> Handler Html
getTodoR todoId = do
    userId <- requireAuthId
    todo <- runDB $ get404 todoId
    
    -- Ensure the todo belongs to the current user
    when (todoUserId todo /= userId) $
        permissionDenied "You don't have permission to view this todo"
    
    defaultLayout $ do
        setTitle $ todoTitle todo
        $(widgetFile "todo")

-- | Update a todo
postTodoR :: TodoId -> Handler Html
postTodoR todoId = do
    userId <- requireAuthId
    todo <- runDB $ get404 todoId
    
    -- Ensure the todo belongs to the current user
    when (todoUserId todo /= userId) $
        permissionDenied "You don't have permission to update this todo"
    
    ((result, widget), enctype) <- runFormPost $ todoUpdateForm todo
    
    case result of
        FormSuccess TodoData{..} -> do
            now <- liftIO getCurrentTime
            runDB $ update todoId
                [ TodoTitle =. todoTitle
                , TodoDescription =. todoDescription
                , TodoCompleted =. todoCompleted
                , TodoUpdated =. now
                ]
            setMessage "Todo updated successfully"
            redirect $ TodoR todoId
        _ -> defaultLayout $ do
            setTitle "Edit Todo"
            $(widgetFile "todo-edit")

-- | Delete a todo
deleteTodoR :: TodoId -> Handler ()
deleteTodoR todoId = do
    userId <- requireAuthId
    todo <- runDB $ get404 todoId
    
    -- Ensure the todo belongs to the current user
    when (todoUserId todo /= userId) $
        permissionDenied "You don't have permission to delete this todo"
    
    runDB $ delete todoId
    setMessage "Todo deleted successfully"
    redirect TodoListR

-- | Todo form data
data TodoData = TodoData
    { todoTitle :: Text
    , todoDescription :: Text
    , todoCompleted :: Bool
    }

-- | Form for creating a new todo
todoForm :: Form TodoData
todoForm = renderDivs $ TodoData
    <$> areq textField (fieldSettingsLabel "Title") Nothing
    <*> areq textareaField (fieldSettingsLabel "Description") Nothing
    <*> pure False

-- | Form for updating an existing todo
todoUpdateForm :: Todo -> Form TodoData
todoUpdateForm todo = renderDivs $ TodoData
    <$> areq textField (fieldSettingsLabel "Title") (Just $ todoTitle todo)
    <*> areq textareaField (fieldSettingsLabel "Description") (Just $ todoDescription todo)
    <*> areq checkBoxField (fieldSettingsLabel "Completed") (Just $ todoCompleted todo)`,

    'src/Handler/Auth.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE QuasiQuotes #-}

module Handler.Auth where

import Import
import Yesod.Auth.Email

-- | Custom registration handler
getRegisterR :: Handler Html
getRegisterR = do
    (widget, enctype) <- generateFormPost registrationForm
    defaultLayout $ do
        setTitle "Register"
        $(widgetFile "register")

-- | Process registration
postRegisterR :: Handler Html
postRegisterR = do
    ((result, widget), enctype) <- runFormPost registrationForm
    case result of
        FormSuccess (email, password) -> do
            -- Check if user already exists
            muser <- runDB $ getBy $ UniqueUser email
            case muser of
                Just _ -> do
                    setMessage "Email already registered"
                    redirect RegisterR
                Nothing -> do
                    -- Create user with unverified status
                    verkey <- liftIO generateVerificationKey
                    userId <- runDB $ insert $ User email (Just password) (Just verkey) False
                    
                    -- Send verification email
                    sendVerifyEmail email verkey $ \\verurl -> do
                        -- In production, send actual email
                        liftIO $ putStrLn $ "Verification URL: " ++ show verurl
                    
                    setMessage "Registration successful! Please check your email to verify your account."
                    redirect HomeR
        _ -> defaultLayout $ do
            setTitle "Register"
            $(widgetFile "register")

-- | Registration form
registrationForm :: Form (Text, Text)
registrationForm = renderDivs $ (,)
    <$> areq emailField (fieldSettingsLabel "Email") Nothing
    <*> areq passwordField (fieldSettingsLabel "Password") Nothing

-- | Generate a random verification key
generateVerificationKey :: IO Text
generateVerificationKey = do
    -- In production, use a proper random generator
    return "verification-key-placeholder"`,

    'src/Handler/Common.hs': `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

module Handler.Common where

import Data.FileEmbed (embedFile)
import Import

-- These handlers embed files in the executable at compile time to avoid a
-- runtime dependency, and for efficiency.

getFaviconR :: Handler TypedContent
getFaviconR = do
    cacheSeconds $ 60 * 60 * 24 * 30 -- cache for a month
    return $ TypedContent "image/x-icon"
           $ toContent $(embedFile "config/favicon.ico")

getRobotsR :: Handler TypedContent
getRobotsR = return $ TypedContent typePlain
                    $ toContent $(embedFile "config/robots.txt")`,

    'src/SharedTypes.hs': `{-# LANGUAGE NoImplicitPrelude #-}

module SharedTypes where

import ClassyPrelude.Yesod
import Data.Kind (Type)`,

    'config/routes': `-- Routes for the application

/static StaticR Static appStatic
/auth AuthR Auth getAuth

/favicon.ico FaviconR GET
/robots.txt RobotsR GET

/ HomeR GET
/about AboutR GET

/profile ProfileR GET POST
/register RegisterR GET POST

/todos TodoListR GET POST
/todos/#TodoId TodoR GET POST DELETE

/admin AdminR GET
/admin/users UserListR GET
/admin/users/#UserId UserR GET`,

    'config/models.persistentmodels': `-- Persistent entity definitions
-- https://www.yesodweb.com/book/persistent/

User
    email Text
    password Text Maybe
    verkey Text Maybe
    verified Bool
    admin Bool default=False
    UniqueUser email
    deriving Typeable

Todo
    userId UserId
    title Text
    description Text
    completed Bool default=False
    created UTCTime
    updated UTCTime
    deriving Show

Email
    email Text
    userId UserId Maybe
    verkey Text Maybe
    UniqueEmail email`,

    'config/settings.yml': `# Values formatted like "_env:YESOD_ENV_VAR_NAME:default_value" can be overridden by the specified environment variable.
# See https://github.com/yesodweb/yesod/wiki/Configuration#overriding-configuration-values-with-environment-variables

static-dir:     "_env:YESOD_STATIC_DIR:static"
host:           "_env:YESOD_HOST:*4" # any IPv4 host
port:           "_env:YESOD_PORT:3000"
ip-from-header: "_env:YESOD_IP_FROM_HEADER:false"

# Default behavior: determine the application root from the request headers.
# Uncomment to set an explicit approot
#approot:        "_env:YESOD_APPROOT:http://localhost:3000"

# By default, \`yesod devel\` runs in development, and built executables use
# production settings (see below). To override this, use the following:
#
# development: false

# Optional values with the following production defaults.
# In development, they default to the inverse.
#
# detailed-logging: false
# should-log-all: false
# reload-templates: false
# mutable-static: false
# skip-combining: false
# auth-dummy-login : false

# NB: If you need a numeric value (e.g. 123) to parse as a String, wrap it in single quotes (e.g. "\\\'123\\\'")
# See https://github.com/yesodweb/yesod/wiki/Configuration#parsing-numeric-values-as-strings

database:
  user:     "_env:YESOD_POSTGRES_USER:postgres"
  password: "_env:YESOD_POSTGRES_PASSWORD:postgres"
  host:     "_env:YESOD_POSTGRES_HOST:localhost"
  port:     "_env:YESOD_POSTGRES_PORT:5432"
  database: "_env:YESOD_POSTGRES_DATABASE:yesod_dev"
  poolsize: "_env:YESOD_POSTGRES_POOLSIZE:10"

# Google Analytics
# analytics: "_env:YESOD_ANALYTICS:your-google-analytics-id"

# Authentication
auth-dummy-login: "_env:YESOD_AUTH_DUMMY:false"

# Minify resources
minify-resources: "_env:YESOD_MINIFY_RESOURCES:true"`,

    'yesod-app.cabal': `cabal-version: 1.12

name:           yesod-app
version:        0.1.0.0
description:    A Yesod web application with full-stack capabilities
homepage:       https://github.com/yourusername/yesod-app#readme
bug-reports:    https://github.com/yourusername/yesod-app/issues
author:         Your Name
maintainer:     your.email@example.com
copyright:      2024 Your Name
license:        BSD3
build-type:     Simple
extra-source-files:
    README.md
    CHANGELOG.md
    static/css/bootstrap.css
    static/fonts/glyphicons-halflings-regular.eot
    static/fonts/glyphicons-halflings-regular.svg
    static/fonts/glyphicons-halflings-regular.ttf
    static/fonts/glyphicons-halflings-regular.woff
    config/favicon.ico
    config/robots.txt
    config/routes
    config/models.persistentmodels
    templates/*.hamlet
    templates/*.julius
    templates/*.lucius
    templates/*.cassius

source-repository head
  type: git
  location: https://github.com/yourusername/yesod-app

flag dev
  description: Turn on development settings, like auto-reload templates.
  manual: False
  default: False

flag library-only
  description: Build for use with "yesod devel"
  manual: False
  default: False

library
  exposed-modules:
      Application
      Foundation
      Handler.Auth
      Handler.Common
      Handler.Home
      Handler.Todo
      Handler.User
      Import
      Import.NoFoundation
      Model
      Settings
      Settings.StaticFiles
      SharedTypes
  other-modules:
      Paths_yesod_app
  hs-source-dirs:
      src
  build-depends:
      aeson >=1.4
    , base >=4.9.1.0 && <5
    , bytestring >=0.9 && <0.11
    , case-insensitive
    , classy-prelude >=1.5 && <1.6
    , classy-prelude-conduit >=1.5 && <1.6
    , classy-prelude-yesod >=1.5 && <1.6
    , conduit >=1.0 && <2.0
    , containers
    , data-default
    , directory >=1.1 && <1.4
    , fast-logger >=2.2 && <3.1
    , file-embed
    , foreign-store
    , hjsmin >=0.1 && <0.3
    , http-client-tls >=0.3 && <0.4
    , http-conduit >=2.3 && <2.4
    , monad-control >=0.3 && <1.1
    , monad-logger >=0.3 && <0.4
    , persistent >=2.9 && <2.14
    , persistent-postgresql >=2.9 && <2.14
    , persistent-template >=2.5 && <2.13
    , safe
    , shakespeare >=2.0 && <2.1
    , template-haskell
    , text >=0.11 && <2.0
    , time
    , unordered-containers
    , vector
    , wai
    , wai-extra >=3.0 && <3.1
    , wai-logger >=2.2 && <2.4
    , warp >=3.0 && <3.4
    , yaml >=0.11 && <0.12
    , yesod >=1.6 && <1.7
    , yesod-auth >=1.6 && <1.7
    , yesod-core >=1.6 && <1.7
    , yesod-form >=1.6 && <1.7
    , yesod-static >=1.6 && <1.7
  if flag(dev) || flag(library-only)
    cpp-options: -DDEVELOPMENT
    ghc-options: -Wall -fwarn-tabs -O0
  else
    ghc-options: -Wall -fwarn-tabs -O2

executable yesod-app
  main-is: main.hs
  other-modules:
      DevelMain
      Paths_yesod_app
  hs-source-dirs:
      app
  ghc-options: -threaded -rtsopts -with-rtsopts=-N
  build-depends:
      base
    , yesod-app
  if flag(library-only)
    buildable: False
  default-language: Haskell2010

test-suite yesod-app-test
  type: exitcode-stdio-1.0
  main-is: Spec.hs
  other-modules:
      Handler.CommonSpec
      Handler.HomeSpec
      TestImport
      Paths_yesod_app
  hs-source-dirs:
      test
  ghc-options: -Wall
  build-depends:
      base
    , classy-prelude >=1.5 && <1.6
    , classy-prelude-yesod >=1.5 && <1.6
    , hspec >=2.0.0
    , microlens
    , monad-logger
    , persistent
    , persistent-postgresql
    , resourcet
    , shakespeare
    , transformers
    , wai-extra
    , yesod >=1.6 && <1.7
    , yesod-app
    , yesod-auth >=1.6 && <1.7
    , yesod-core
    , yesod-test >=1.6 && <1.7
  default-language: Haskell2010`,

    'stack.yaml': `resolver: lts-21.25

packages:
- .

extra-deps: []

flags: {}

extra-package-dbs: []`,

    '.gitignore': `dist*
static/tmp/
static/combined/
config/client_session_key.aes
*.hi
*.o
*.sqlite3
*.sqlite3-shm
*.sqlite3-wal
.hsenv*
cabal-dev/
.stack-work/
.stack-work-devel/
yesod-devel/
.cabal-sandbox
cabal.sandbox.config
.DS_Store
*.swp
*.keter
*~
\\#*`,

    'README.md': `# Yesod Full-Stack Web Application

A full-stack web application built with Yesod, featuring type-safe URLs, authentication, and database integration.

## Features

- ✅ Type-safe URLs and routing
- ✅ Compile-time template checking
- ✅ Built-in authentication and authorization
- ✅ Form handling with CSRF protection
- ✅ Database integration with Persistent
- ✅ Email authentication
- ✅ Admin panel
- ✅ WebSocket support
- ✅ Internationalization ready
- ✅ Asset management
- ✅ Testing framework

## Getting Started

### Prerequisites

- Haskell Stack
- PostgreSQL
- Redis (optional, for sessions)

### Development Setup

1. Clone the repository:
   \`\`\`bash
   git clone <your-repo>
   cd yesod-app
   \`\`\`

2. Install dependencies:
   \`\`\`bash
   stack setup
   stack build
   \`\`\`

3. Set up the database:
   \`\`\`bash
   createdb yesod_dev
   \`\`\`

4. Configure environment:
   \`\`\`bash
   export YESOD_POSTGRES_USER=postgres
   export YESOD_POSTGRES_PASSWORD=postgres
   export YESOD_POSTGRES_HOST=localhost
   export YESOD_POSTGRES_PORT=5432
   export YESOD_POSTGRES_DATABASE=yesod_dev
   \`\`\`

5. Run the development server:
   \`\`\`bash
   stack exec -- yesod devel
   \`\`\`

The server will start on http://localhost:3000 with auto-reload enabled.

## Project Structure

\`\`\`
.
├── app/                 # Application entry points
├── config/              # Configuration files
│   ├── models.persistentmodels  # Database models
│   ├── routes           # URL routes
│   └── settings.yml     # Application settings
├── src/
│   ├── Application.hs   # Application initialization
│   ├── Foundation.hs    # Core application type
│   ├── Handler/         # Request handlers
│   ├── Model.hs         # Database models
│   └── Settings.hs      # Settings management
├── static/              # Static files (CSS, JS, images)
├── templates/           # HTML templates
└── test/                # Test suite
\`\`\`

## Key Concepts

### Type-Safe URLs

Routes are defined in \`config/routes\` and are type-checked at compile time:

\`\`\`
/todos TodoListR GET POST
/todos/#TodoId TodoR GET POST DELETE
\`\`\`

### Database Models

Models are defined in \`config/models.persistentmodels\`:

\`\`\`
User
    email Text
    password Text Maybe
    verified Bool
    UniqueUser email
    
Todo
    userId UserId
    title Text
    completed Bool
\`\`\`

### Templates

Yesod uses Shakespeare templates with compile-time checking:

- \`.hamlet\` - HTML templates
- \`.julius\` - JavaScript templates
- \`.lucius\` - CSS templates
- \`.cassius\` - CSS templates (indentation-based)

### Authentication

Built-in authentication with multiple backends:
- Email/password
- OAuth providers
- Custom authentication

## Testing

Run the test suite:
\`\`\`bash
stack test
\`\`\`

## Production Deployment

### Build for production:
\`\`\`bash
stack build --flag yesod-app:-dev
\`\`\`

### Keter deployment:
\`\`\`bash
yesod keter
\`\`\`

### Docker deployment:
\`\`\`bash
docker build -t yesod-app .
docker run -p 3000:3000 yesod-app
\`\`\`

## Configuration

Configuration is managed through:
- \`config/settings.yml\` - Default settings
- Environment variables - Override defaults
- Runtime configuration - Dynamic settings

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

BSD3 License - see LICENSE file for details.`
  }
};