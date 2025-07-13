/**
 * Yesod Framework Template Generator
 * A full-featured web framework with type-safe URLs and forms
 */

import { HaskellBackendGenerator } from './haskell-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class YesodGenerator extends HaskellBackendGenerator {
  constructor() {
    super('Yesod');
  }

  protected getFrameworkDependencies(): string[] {
    return [
      'yesod: ^1.6',
      'yesod-core: ^1.6',
      'yesod-auth: ^1.6',
      'yesod-static: ^1.6',
      'yesod-form: ^1.7',
      'yesod-persistent: ^1.6',
      'persistent: ^2.14',
      'persistent-postgresql: ^2.13',
      'persistent-template: ^2.12',
      'monad-control: ^1.0',
      'monad-logger: ^0.3',
      'fast-logger: ^3.1',
      'wai: ^3.2',
      'wai-extra: ^3.1',
      'wai-logger: ^2.4',
      'warp: ^3.3',
      'http-types: ^0.12',
      'http-conduit: ^2.3',
      'conduit: ^1.3',
      'directory: ^1.3',
      'text: ^2.0',
      'bytestring: ^0.11',
      'time: ^1.12',
      'case-insensitive: ^1.2',
      'unordered-containers: ^0.2',
      'containers: ^0.6',
      'vector: ^0.13',
      'aeson: ^2.1',
      'yaml: ^0.11',
      'template-haskell: ^2.19',
      'shakespeare: ^2.0',
      'hjsmin: ^0.2',
      'blaze-html: ^0.9',
      'blaze-markup: ^0.8',
      'data-default: ^0.7',
      'file-embed: ^0.0.15',
      'safe: ^0.3',
      'esqueleto: ^3.5',
      'classy-prelude-yesod: ^1.5'
    ];
  }

  protected getExtraDeps(): string[] {
    return [];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate Foundation.hs
    await this.generateFoundation(projectPath, options);

    // Generate Application.hs
    await this.generateApplication(projectPath);

    // Generate Settings.hs
    await this.generateSettings(projectPath);

    // Generate Import files
    await this.generateImports(projectPath);

    // Generate routes
    await this.generateRoutes(projectPath);

    // Generate handlers
    await this.generateHandlers(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate templates
    await this.generateTemplates(projectPath);

    // Generate static files
    await this.generateStaticFiles(projectPath);

    // Generate main app
    await this.generateMainApp(projectPath, options);

    // Generate test helpers
    await this.generateTestHelpers(projectPath, options);
  }

  private async generateFoundation(projectPath: string, options: any): Promise<void> {
    const foundationContent = `{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE RankNTypes #-}

module Foundation where

import Database.Persist.Sql (ConnectionPool, runSqlPool)
import Import.NoFoundation
import Text.Hamlet (hamletFile)
import Text.Jasmine (minifym)
import Yesod.Auth.Dummy
import Yesod.Auth.OpenId (authOpenId, IdentifierType (Claimed))
import Yesod.Core.Types (Logger)
import qualified Yesod.Core.Unsafe as Unsafe
import Yesod.Default.Util (addStaticContentExternal)

data App = App
    { appSettings :: AppSettings
    , appStatic :: Static
    , appConnPool :: ConnectionPool
    , appHttpManager :: Manager
    , appLogger :: Logger
    }

data MenuItem = MenuItem
    { menuItemLabel :: Text
    , menuItemRoute :: Route App
    , menuItemAccessCallback :: Bool
    }

data MenuTypes
    = NavbarLeft MenuItem
    | NavbarRight MenuItem

mkYesodData "App" $(parseRoutesFile "config/routes")

type Form x = Html -> MForm (HandlerFor App) (FormResult x, Widget)

type DB = YesodPersistBackend App

instance Yesod App where
    approot = ApprootRequest $ \\app req ->
        case appRoot $ appSettings app of
            Nothing -> getApprootText guessApproot app req
            Just root -> root

    makeSessionBackend _ = Just <$> defaultClientSessionBackend
        120 -- timeout in minutes
        "config/client_session_key.aes"

    yesodMiddleware = defaultYesodMiddleware

    defaultLayout widget = do
        master <- getYesod
        mmsg <- getMessage
        muser <- maybeAuthPair
        mcurrentRoute <- getCurrentRoute

        let menuItems =
                [ NavbarLeft $ MenuItem "Home" HomeR True
                , NavbarLeft $ MenuItem "Profile" ProfileR (isJust muser)
                ]

        let navbarLeftMenuItems = [x | NavbarLeft x <- menuItems]
        let navbarRightMenuItems = [x | NavbarRight x <- menuItems]

        let navbarLeftFilteredMenuItems = [x | x <- navbarLeftMenuItems, menuItemAccessCallback x]
        let navbarRightFilteredMenuItems = [x | x <- navbarRightMenuItems, menuItemAccessCallback x]

        pc <- widgetToPageContent $ do
            addStylesheet $ StaticR css_bootstrap_css
            $(widgetFile "default-layout")
        withUrlRenderer $(hamletFile "templates/default-layout-wrapper.hamlet")

    authRoute _ = Just $ AuthR LoginR

    isAuthorized (AuthR _) _ = return Authorized
    isAuthorized CommentR _ = return Authorized
    isAuthorized HomeR _ = return Authorized
    isAuthorized FaviconR _ = return Authorized
    isAuthorized RobotsR _ = return Authorized
    isAuthorized (StaticR _) _ = return Authorized
    isAuthorized ProfileR _ = isAuthenticated

    addStaticContent ext mime content = do
        master <- getYesod
        let staticDir = appStaticDir $ appSettings master
        addStaticContentExternal
            minifym
            genFileName
            staticDir
            (StaticR . flip StaticRoute [])
            ext
            mime
            content
      where
        genFileName lbs = "autogen-" ++ base64md5 lbs

    shouldLogIO app _source level =
        return $
            appShouldLogAll (appSettings app)
                || level == LevelWarn
                || level == LevelError

    makeLogger = return . appLogger

instance YesodPersist App where
    type YesodPersistBackend App = SqlBackend
    runDB action = do
        master <- getYesod
        runSqlPool action $ appConnPool master

instance YesodPersistRunner App where
    getDBRunner = defaultGetDBRunner appConnPool

instance YesodAuth App where
    type AuthId App = UserId

    loginDest _ = HomeR
    logoutDest _ = HomeR
    redirectToReferer _ = True

    authenticate creds = liftHandler $ runDB $ do
        x <- getBy $ UniqueUser $ credsIdent creds
        case x of
            Just (Entity uid _) -> return $ Authenticated uid
            Nothing -> do
                fmap Authenticated $ insert User
                    { userIdent = credsIdent creds
                    , userPassword = Nothing
                    }

    authPlugins app = [authOpenId Claimed []] ++ extraAuthPlugins
        where extraAuthPlugins = [authDummy | appAuthDummyLogin $ appSettings app]

isAuthenticated :: Handler AuthResult
isAuthenticated = do
    muid <- maybeAuthId
    return $ case muid of
        Nothing -> Unauthorized "You must login to access this page"
        Just _ -> Authorized

instance YesodAuthPersist App

instance RenderMessage App FormMessage where
    renderMessage _ _ = defaultFormMessage

instance HasHttpManager App where
    getHttpManager = appHttpManager

unsafeHandler :: App -> Handler a -> IO a
unsafeHandler = Unsafe.fakeHandlerGetLogger appLogger
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Foundation.hs'),
      foundationContent
    );
  }

  private async generateApplication(projectPath: string): Promise<void> {
    const appContent = `{-# LANGUAGE NoImplicitPrelude #-}
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
    , shutdownApp
    , handler
    , db
    ) where

import Control.Monad.Logger (liftLoc, runLoggingT)
import Database.Persist.Postgresql (createPostgresqlPool, pgConnStr,
                                     pgPoolSize, runSqlPool)
import Import
import Language.Haskell.TH.Syntax (qLocation)
import Network.HTTP.Client.TLS
import Network.Wai (Middleware)
import Network.Wai.Handler.Warp (Settings, defaultSettings,
                                 defaultShouldDisplayException,
                                 runSettings, setHost,
                                 setOnException, setPort, getPort)
import Network.Wai.Middleware.RequestLogger (Destination (Logger),
                                             IPAddrSource (..),
                                             OutputFormat (..), destination,
                                             mkRequestLogger, outputFormat)
import System.Log.FastLogger (defaultBufSize, newStdoutLoggerSet,
                              toLogStr)

import Handler.Common
import Handler.Home
import Handler.Comment
import Handler.Profile

mkYesodDispatch "App" resourcesApp

makeFoundation :: AppSettings -> IO App
makeFoundation appSettings = do
    appHttpManager <- getGlobalManager
    appLogger <- newStdoutLoggerSet defaultBufSize >>= makeYesodLogger
    appStatic <-
        (if appMutableStatic appSettings then staticDevel else static)
        (appStaticDir appSettings)

    let mkFoundation appConnPool = App {..}
        tempFoundation = mkFoundation $ error "connPool forced in tempFoundation"
        logFunc = messageLoggerSource tempFoundation appLogger

    pool <- flip runLoggingT logFunc $ createPostgresqlPool
        (pgConnStr  $ appDatabaseConf appSettings)
        (pgPoolSize $ appDatabaseConf appSettings)

    runLoggingT (runSqlPool (runMigration migrateAll) pool) logFunc

    return $ mkFoundation pool

makeApplication :: App -> IO Application
makeApplication foundation = do
    logWare <- makeLogWare foundation
    appPlain <- toWaiAppPlain foundation
    return $ logWare $ defaultMiddlewaresNoLogging appPlain

makeLogWare :: App -> IO Middleware
makeLogWare foundation =
    mkRequestLogger def
        { outputFormat =
            if appDetailedRequestLogging $ appSettings foundation
                then Detailed True
                else Apache
                        (if appIpFromHeader $ appSettings foundation
                            then FromFallback
                            else FromSocket)
        , destination = Logger $ loggerSet $ appLogger foundation
        }

warpSettings :: App -> Settings
warpSettings foundation =
      setPort (appPort $ appSettings foundation)
    $ setHost (appHost $ appSettings foundation)
    $ setOnException (defaultOnException foundation)
      defaultSettings

getApplicationDev :: IO (Settings, Application)
getApplicationDev = do
    settings <- getAppSettings
    foundation <- makeFoundation settings
    wsettings <- getDevSettings $ warpSettings foundation
    app <- makeApplication foundation
    return (wsettings, app)

getAppSettings :: IO AppSettings
getAppSettings = loadYamlSettings [configSettingsYml] [] useEnv

develMain :: IO ()
develMain = develMainHelper getApplicationDev

appMain :: IO ()
appMain = do
    settings <- loadYamlSettingsArgs
        [configSettingsYmlValue]
        useEnv

    foundation <- makeFoundation settings
    app <- makeApplication foundation
    runSettings (warpSettings foundation) app

getApplicationRepl :: IO (Int, App, Application)
getApplicationRepl = do
    settings <- getAppSettings
    foundation <- makeFoundation settings
    wsettings <- getDevSettings $ warpSettings foundation
    app1 <- makeApplication foundation
    return (getPort wsettings, foundation, app1)

shutdownApp :: App -> IO ()
shutdownApp _ = return ()

handler :: Handler a -> IO a
handler h = getAppSettings >>= makeFoundation >>= flip unsafeHandler h

db :: ReaderT SqlBackend Handler a -> IO a
db = handler . runDB
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Application.hs'),
      appContent
    );
  }

  private async generateSettings(projectPath: string): Promise<void> {
    const settingsContent = `{-# LANGUAGE CPP #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}

module Settings where

import ClassyPrelude.Yesod
import qualified Control.Exception as Exception
import Data.Aeson (Result (..), fromJSON, withObject, (.!=),
                    (.:?))
import Data.FileEmbed (embedFile)
import Data.Yaml (decodeEither')
import Database.Persist.Postgresql (PostgresConf)
import Language.Haskell.TH.Syntax (Exp, Name, Q)
import Network.Wai.Handler.Warp (HostPreference)
import Yesod.Default.Config2 (applyEnvValue, configSettingsYml)
import Yesod.Default.Util (WidgetFileSettings, widgetFileNoReload,
                           widgetFileReload)

data AppSettings = AppSettings
    { appStaticDir :: String
    , appDatabaseConf :: PostgresConf
    , appRoot :: Maybe Text
    , appHost :: HostPreference
    , appPort :: Int
    , appIpFromHeader :: Bool
    , appDetailedRequestLogging :: Bool
    , appShouldLogAll :: Bool
    , appReloadTemplates :: Bool
    , appMutableStatic :: Bool
    , appSkipCombining :: Bool
    , appCopyright :: Text
    , appAnalytics :: Maybe Text
    , appAuthDummyLogin :: Bool
    }

instance FromJSON AppSettings where
    parseJSON = withObject "AppSettings" $ \\o -> do
        let defaultDev =
#ifdef DEVELOPMENT
                True
#else
                False
#endif
        appStaticDir <- o .: "static-dir"
        appDatabaseConf <- o .: "database"
        appRoot <- o .:? "approot"
        appHost <- fromString <$> o .: "host"
        appPort <- o .: "port"
        appIpFromHeader <- o .: "ip-from-header"

        dev <- o .:? "development" .!= defaultDev

        appDetailedRequestLogging <- o .:? "detailed-logging" .!= dev
        appShouldLogAll <- o .:? "should-log-all" .!= dev
        appReloadTemplates <- o .:? "reload-templates" .!= dev
        appMutableStatic <- o .:? "mutable-static" .!= dev
        appSkipCombining <- o .:? "skip-combining" .!= dev

        appCopyright <- o .:? "copyright" .!= "Insert copyright statement here"
        appAnalytics <- o .:? "analytics"

        appAuthDummyLogin <- o .:? "auth-dummy-login" .!= dev

        return AppSettings {..}

widgetFileSettings :: WidgetFileSettings
widgetFileSettings = def

widgetFile :: String -> Q Exp
widgetFile = (if appReloadTemplates compileTimeAppSettings
                then widgetFileReload
                else widgetFileNoReload)
              widgetFileSettings

configSettingsYmlBS :: ByteString
configSettingsYmlBS = $(embedFile configSettingsYml)

configSettingsYmlValue :: Value
configSettingsYmlValue = either Exception.throw id $ decodeEither' configSettingsYmlBS

compileTimeAppSettings :: AppSettings
compileTimeAppSettings =
    case fromJSON $ applyEnvValue False mempty configSettingsYmlValue of
        Error e -> error e
        Success settings -> settings

combineSettings :: Value -> Value -> Value
combineSettings (Object o1) (Object o2) = Object $ o2 <> o1
combineSettings _ y = y

combineScripts :: Name -> Name -> Name
combineScripts = combineSettings
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Settings.hs'),
      settingsContent
    );
  }

  private async generateImports(projectPath: string): Promise<void> {
    // Import.hs
    const importContent = `module Import
    ( module Import
    ) where

import Foundation as Import
import Import.NoFoundation as Import
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Import.hs'),
      importContent
    );

    // Import.NoFoundation
    const noFoundationContent = `{-# LANGUAGE CPP #-}

module Import.NoFoundation
    ( module Import
    ) where

import ClassyPrelude.Yesod as Import
import Model as Import
import Settings as Import
import Settings.StaticFiles as Import
import Yesod.Auth as Import
import Yesod.Core.Types as Import (loggerSet)
import Yesod.Default.Config2 as Import
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Import', 'NoFoundation.hs'),
      noFoundationContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'config'), { recursive: true });
    
    const routesContent = `-- Routes
-- By default this file is used by Yesod to generate types and routes

/static StaticR Static appStatic
/auth AuthR Auth getAuth

/favicon.ico FaviconR GET
/robots.txt RobotsR GET

/ HomeR GET POST
/comments CommentR POST
/profile ProfileR GET

/api/v1/health HealthR GET
/api/v1/users UsersR GET POST
/api/v1/users/#UserId UserR GET PUT DELETE
`;

    await fs.writeFile(
      path.join(projectPath, 'config', 'routes'),
      routesContent
    );
  }

  private async generateHandlers(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'src', 'Handler'), { recursive: true });

    // Home handler
    const homeContent = `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

module Handler.Home where

import Import
import Yesod.Form.Bootstrap3 (BootstrapFormLayout (..), renderBootstrap3)
import Text.Julius (RawJS (..))

getHomeR :: Handler Html
getHomeR = do
    (formWidget, formEnctype) <- generateFormPost sampleForm
    let submission = Nothing :: Maybe FileForm
        handlerName = "getHomeR" :: Text
    allComments <- runDB $ getAllComments

    defaultLayout $ do
        let (commentFormId, commentTextareaId, commentListId) = commentIds
        aDomId <- newIdent
        setTitle "Welcome To Yesod!"
        $(widgetFile "homepage")

postHomeR :: Handler Html
postHomeR = do
    ((result, formWidget), formEnctype) <- runFormPost sampleForm
    let handlerName = "postHomeR" :: Text
        submission = case result of
            FormSuccess res -> Just res
            _ -> Nothing
    allComments <- runDB $ getAllComments

    defaultLayout $ do
        let (commentFormId, commentTextareaId, commentListId) = commentIds
        aDomId <- newIdent
        setTitle "Welcome To Yesod!"
        $(widgetFile "homepage")

sampleForm :: Form FileForm
sampleForm = renderBootstrap3 BootstrapBasicForm $ FileForm
    <$> areq textField textSettings Nothing
    <*> areq fileField fileSettings Nothing
  where
    textSettings = FieldSettings
        { fsLabel = "What's on the file?"
        , fsTooltip = Nothing
        , fsId = Nothing
        , fsName = Nothing
        , fsAttrs =
            [ ("class", "form-control")
            , ("placeholder", "File description")
            ]
        }
    fileSettings = FieldSettings
        { fsLabel = "Choose a file"
        , fsTooltip = Nothing
        , fsId = Nothing
        , fsName = Nothing
        , fsAttrs = [("class", "form-control-file")]
        }

commentIds :: (Text, Text, Text)
commentIds = ("js-commentForm", "js-createCommentTextarea", "js-commentList")

getAllComments :: DB [Entity Comment]
getAllComments = selectList [] [Asc CommentId]
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Handler', 'Home.hs'),
      homeContent
    );

    // Comment handler
    const commentContent = `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

module Handler.Comment where

import Import

postCommentR :: Handler Value
postCommentR = do
    comment <- requireCheckJsonBody :: Handler Comment
    maybeCurrentUserId <- maybeAuthId
    let comment' = comment { commentUserId = maybeCurrentUserId }
    insertedComment <- runDB $ insertEntity comment'
    returnJson insertedComment
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Handler', 'Comment.hs'),
      commentContent
    );

    // Profile handler
    const profileContent = `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

module Handler.Profile where

import Import

getProfileR :: Handler Html
getProfileR = do
    (_, user) <- requireAuthPair
    defaultLayout $ do
        setTitle . toHtml $ userIdent user <> "'s User page"
        $(widgetFile "profile")
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Handler', 'Profile.hs'),
      profileContent
    );

    // Common handler
    const commonContent = `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

module Handler.Common where

import Data.FileEmbed (embedFile)
import Import

getFaviconR :: Handler TypedContent
getFaviconR = do cacheSeconds $ 60 * 60 * 24 * 30 -- cache for a month
                 return $ TypedContent "image/x-icon"
                        $ toContent $(embedFile "config/favicon.ico")

getRobotsR :: Handler TypedContent
getRobotsR = return $ TypedContent typePlain
                    $ toContent $(embedFile "config/robots.txt")

getHealthR :: Handler Value
getHealthR = do
    return $ object
        [ "status" .= ("healthy" :: Text)
        , "version" .= ("1.0.0" :: Text)
        , "timestamp" .= (getCurrentTime :: Handler UTCTime)
        ]
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Handler', 'Common.hs'),
      commonContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    const modelsContent = `{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}

module Model where

import ClassyPrelude.Yesod
import Database.Persist.Quasi

share [mkPersist sqlSettings, mkMigrate "migrateAll"]
    $(persistFileWith lowerCaseSettings "config/models.persistentmodels")
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'Model.hs'),
      modelsContent
    );

    // Create models definition file
    const modelsDefContent = `-- By default this file is used by \`persistFileWith\` in Model.hs
-- Syntax for this file is documented here:
-- https://github.com/yesodweb/persistent/blob/master/docs/Persistent-entity-syntax.md

User
    ident Text
    password Text Maybe
    UniqueUser ident
    deriving Typeable

Email
    email Text
    userId UserId Maybe
    verkey Text Maybe
    UniqueEmail email

Comment json
    message Text
    userId UserId Maybe
    created UTCTime default=now()
    deriving Eq
    deriving Show

-- Example of more complex models
Post json
    title Text
    content Text
    authorId UserId
    published Bool default=false
    created UTCTime default=now()
    updated UTCTime default=now()
    deriving Eq
    deriving Show

Tag json
    name Text
    UniqueTag name
    deriving Eq
    deriving Show

PostTag
    postId PostId
    tagId TagId
    UniquePostTag postId tagId
`;

    await fs.writeFile(
      path.join(projectPath, 'config', 'models.persistentmodels'),
      modelsDefContent
    );
  }

  private async generateTemplates(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'templates'), { recursive: true });

    // Default layout wrapper
    const layoutWrapperContent = `<!doctype html>
<html class="no-js" lang="en">
    <head>
        <meta charset="UTF-8">

        <title>#{pageTitle pc}
        <meta name="description" content="">
        <meta name="author" content="">

        <meta name="viewport" content="width=device-width,initial-scale=1">

        ^{pageHead pc}

        <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js">
        <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/js-cookie/3.0.5/js.cookie.min.js">

        <script>
          /* The \`defaultCsrfMiddleware\` Middleware added in Foundation.hs */
          /* https://github.com/yesodweb/yesod/wiki/AJAX-CSRF */
          /* takes care of getting CSRF token from cookie */
          /* via header (see https://github.com/yesodweb/yesod/blob/master/yesod-core/src/Yesod/Core/Handler.hs#L1570) */
          /* and it also works for PUT and DELETE ajax requests (see https://github.com/yesodweb/yesod/blob/master/yesod-core/src/Yesod/Core/Handler.hs#L1626) */

    <body>
        <div class="container">
            <header>
            <div id="main" role="main">
              ^{pageBody pc}
            <footer>

        $maybe analytics <- appAnalytics $ appSettings master
            <script>
              if(!window.location.href.match(/localhost/)){
                (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
                (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
                m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
                })(window,document,'script','//www.google-analytics.com/analytics.js','ga');

                ga('create', '#{analytics}', 'auto');
                ga('send', 'pageview');
              }
`;

    await fs.writeFile(
      path.join(projectPath, 'templates', 'default-layout-wrapper.hamlet'),
      layoutWrapperContent
    );

    // Default layout
    const layoutContent = `$maybe msg <- mmsg
    <div .alert.alert-info #message>#{msg}

<nav .navbar.navbar-light.navbar-expand-md>
    <div .container>
        <button type="button" .navbar-toggler.collapsed data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span .sr-only>Toggle navigation
            <span .navbar-toggler-icon>

        <div .collapse.navbar-collapse #navbar>
            <ul .navbar-nav.mr-auto>
                $forall MenuItem label route _ <- navbarLeftFilteredMenuItems
                    <li .nav-item :Just route == mcurrentRoute:.active>
                        <a .nav-link href="@{route}">#{label}

            <ul .navbar-nav.ml-auto>
                $forall MenuItem label route _ <- navbarRightFilteredMenuItems
                    <li .nav-item :Just route == mcurrentRoute:.active>
                        <a .nav-link href="@{route}">#{label}

<div .container>
    <div .row>
        <div .col-md-12>
            ^{widget}

<footer .footer>
    <div .container>
        <p .text-muted>
            #{appCopyright $ appSettings master}
`;

    await fs.writeFile(
      path.join(projectPath, 'templates', 'default-layout.hamlet'),
      layoutContent
    );

    // Homepage template
    const homepageContent = `<div .jumbotron>
    <div .container>
        <h1 .display-4>Welcome to Yesod!
        <p .lead>
            <a href="http://www.yesodweb.com/" .btn.btn-primary.btn-lg>Learn more

<div .container>
    <div .row>
        <div .col-md-8>
            <h2>Starting
            <p>
                This is a Yesod application generated by the Re-Shell CLI.
            <p>
                Get started by editing the templates and handlers in the
                <code>templates/</code> and <code>src/Handler/</code> directories.

            <h2 ##{aDomId}>Form Example
            <p>
                This example form accepts a file upload.
            <form method=post action=@{HomeR}#form enctype=#{formEnctype}>
                ^{formWidget}
                <button .btn.btn-primary type="submit">
                    Submit
                    <i .fa.fa-upload>
            $maybe (FileForm info con) <- submission
                <div .alert.alert-success>
                    <p>
                        File received:
                        <em>#{info}

        <div .col-md-4>
            <h2>JSON API
            <p>
                This application includes a JSON API at:
                <ul>
                    <li>
                        <code>GET /api/v1/health</code>
                    <li>
                        <code>GET /api/v1/users</code>
                    <li>
                        <code>POST /api/v1/users</code>

    <hr>

    <div .row>
        <div .col-md-12>
            <h2>Comments
            <div ##{commentListId}>
                $forall Entity commentId comment <- allComments
                    <div .comment>
                        <p>#{commentMessage comment}
                        <p .text-muted>
                            <small>#{show $ commentCreated comment}

            <h3>Add a Comment
            <form ##{commentFormId}>
                <div .form-group>
                    <textarea ##{commentTextareaId} .form-control placeholder="Enter your comment..." required>
                <button .btn.btn-primary type=submit>
                    Post Comment
`;

    await fs.writeFile(
      path.join(projectPath, 'templates', 'homepage.hamlet'),
      homepageContent
    );

    // Profile template
    const profileContent = `<div .container>
    <div .row>
        <div .col-md-12>
            <h1>User Profile
            <p>
                Your account ID is: <strong>#{userIdent user}</strong>
            <p>
                <a href=@{AuthR LogoutR} .btn.btn-danger>Logout
`;

    await fs.writeFile(
      path.join(projectPath, 'templates', 'profile.hamlet'),
      profileContent
    );
  }

  private async generateStaticFiles(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'static', 'css'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'static', 'js'), { recursive: true });

    // Create Settings/StaticFiles.hs
    const staticFilesContent = `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Settings.StaticFiles where

import Settings (appStaticDir, compileTimeAppSettings)
import Yesod.Static (staticFiles)

staticFiles (appStaticDir compileTimeAppSettings)
`;

    await fs.mkdir(path.join(projectPath, 'src', 'Settings'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'src', 'Settings', 'StaticFiles.hs'),
      staticFilesContent
    );

    // Create a sample CSS file
    const cssContent = `/* Bootstrap is included via CDN in the layout */

body {
    padding-top: 5rem;
}

.footer {
    position: absolute;
    bottom: 0;
    width: 100%;
    height: 60px;
    background-color: #f5f5f5;
}

.footer p {
    margin: 20px 0;
}

.comment {
    border-bottom: 1px solid #e3e3e3;
    padding: 10px 0;
    margin-bottom: 10px;
}
`;

    await fs.writeFile(
      path.join(projectPath, 'static', 'css', 'bootstrap.css'),
      cssContent
    );
  }

  private async generateMainApp(projectPath: string, options: any): Promise<void> {
    const mainContent = `module Main where

import Prelude (IO)
import Application (appMain)

main :: IO ()
main = appMain
`;

    await fs.writeFile(
      path.join(projectPath, 'app', 'Main.hs'),
      mainContent
    );

    // Generate config files
    const settingsYmlContent = `# Values formatted like "_env:ENV_VAR_NAME:default_value" can be overridden by the specified environment variable.
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

database:
  user:     "_env:PGUSER:postgres"
  password: "_env:PGPASS:postgres"
  host:     "_env:PGHOST:localhost"
  port:     "_env:PGPORT:5432"
  database: "_env:PGDATABASE:${options.name}"
  poolsize: "_env:PGPOOLSIZE:10"

copyright: ${options.name}
#analytics: UA-YOURCODE`;

    await fs.writeFile(
      path.join(projectPath, 'config', 'settings.yml'),
      settingsYmlContent
    );

    // Create other config files
    await fs.writeFile(
      path.join(projectPath, 'config', 'favicon.ico'),
      ''
    );

    await fs.writeFile(
      path.join(projectPath, 'config', 'robots.txt'),
      'User-agent: *\n'
    );
  }

  private async generateTestHelpers(projectPath: string, options: any): Promise<void> {
    const testImportContent = `{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module TestImport
    ( module TestImport
    , module X
    ) where

import Application (makeFoundation, makeLogWare)
import ClassyPrelude as X hiding (delete, deleteBy, Handler)
import Database.Persist as X hiding (get)
import Database.Persist.Sql (SqlPersistM, SqlBackend, runSqlPersistMPool, rawExecute, rawSql, unSingle, connEscapeName)
import Foundation as X
import Model as X
import Test.Hspec as X
import Yesod.Default.Config2 (useEnv, loadYamlSettings)
import Yesod.Auth as X
import Yesod.Test as X
import Yesod.Core.Unsafe (fakeHandlerGetLogger)

runDB :: SqlPersistM a -> YesodExample App a
runDB query = do
    app <- getTestYesod
    liftIO $ runDBWithApp app query

runDBWithApp :: App -> SqlPersistM a -> IO a
runDBWithApp app query = runSqlPersistMPool query (appConnPool app)

runHandler :: Handler a -> YesodExample App a
runHandler handler = do
    app <- getTestYesod
    fakeHandlerGetLogger appLogger app handler

withApp :: SpecWith (TestApp App) -> Spec
withApp = before $ do
    settings <- loadYamlSettings
        ["config/test-settings.yml", "config/settings.yml"]
        []
        useEnv
    foundation <- makeFoundation settings
    wipeDB foundation
    logWare <- liftIO $ makeLogWare foundation
    return (foundation, logWare)

spec :: Spec
spec = withApp $ do
    yesodSpec $ do
        ydescribe "These tests access the database." $ do
            yit "creates a valid user" $ do
                let user = User "foo" Nothing
                userId <- runDB $ insert user
                maybeUser <- runDB $ get userId
                maybeUser \`shouldBe\` Just user

wipeDB :: App -> IO ()
wipeDB app = runDBWithApp app $ do
    tables <- getTables
    sqlBackend <- ask

    let escapedTables = map (connEscapeName sqlBackend . DBName) tables
        query = "TRUNCATE TABLE " ++ intercalate ", " escapedTables
    rawExecute query []

getTables :: DB [Text]
getTables = do
    tables <- rawSql
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
        []
    return $ map unSingle tables
`;

    await fs.writeFile(
      path.join(projectPath, 'test', 'TestImport.hs'),
      testImportContent
    );

    // Test settings
    const testSettingsContent = `database:
  database: ${options.name}_test
`;

    await fs.writeFile(
      path.join(projectPath, 'config', 'test-settings.yml'),
      testSettingsContent
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is implemented in Handler.Common
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // Yesod uses type-safe routes, so API docs are generated from the routes file
    const apiDocsContent = `# API Documentation

## Routes

All routes are defined in \`config/routes\`.

### Authentication
- \`GET /auth\` - Authentication page
- \`POST /auth/login\` - Login
- \`GET /auth/logout\` - Logout

### API Endpoints

#### Health Check
- \`GET /api/v1/health\` - Returns server health status

#### Users
- \`GET /api/v1/users\` - List all users
- \`POST /api/v1/users\` - Create a new user
- \`GET /api/v1/users/:id\` - Get user by ID
- \`PUT /api/v1/users/:id\` - Update user
- \`DELETE /api/v1/users/:id\` - Delete user

### Static Resources
- \`GET /static/*\` - Serve static files
- \`GET /favicon.ico\` - Favicon
- \`GET /robots.txt\` - Robots.txt

## Request/Response Format

All API endpoints accept and return JSON.

### Example User Object
\`\`\`json
{
  "id": 1,
  "ident": "user@example.com",
  "created": "2024-01-01T00:00:00Z"
}
\`\`\`
`;

    await fs.writeFile(
      path.join(projectPath, 'docs', 'API.md'),
      apiDocsContent
    );
  }
}