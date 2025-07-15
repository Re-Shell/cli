import { ScalaBackendGenerator } from './scala-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class PlayGenerator extends ScalaBackendGenerator {
  constructor() {
    super('Play Framework');
  }

  protected getFrameworkSettings(): string {
    return `lazy val root = (project in file("."))
  .enablePlugins(PlayScala)
  .settings(
    PlayKeys.playDefaultPort := ${options => options.port || 9000}
  )`;
  }

  protected getFrameworkPlugins(): string {
    return `addSbtPlugin("com.typesafe.play" % "sbt-plugin" % "2.9.0")
addSbtPlugin("org.scalameta" % "sbt-scalafmt" % "2.5.2")
addSbtPlugin("com.github.sbt" % "sbt-digest" % "2.0.0")
addSbtPlugin("com.github.sbt" % "sbt-gzip" % "2.0.0")`;
  }

  protected getFrameworkDependencies(): string {
    return `// Play Framework
      "com.typesafe.play" %% "play" % "2.9.0",
      "com.typesafe.play" %% "play-json" % "2.10.3",
      "com.typesafe.play" %% "play-ws" % "2.9.0",
      "com.typesafe.play" %% "play-cache" % "2.9.0",
      "com.typesafe.play" %% "play-cache-caffeine" % "2.9.0",
      "com.typesafe.play" %% "filters-helpers" % "2.9.0",
      
      // Database
      "com.typesafe.play" %% "play-slick" % "5.1.0",
      "com.typesafe.play" %% "play-slick-evolutions" % "5.1.0",
      "com.typesafe.slick" %% "slick" % slickVersion,
      "com.typesafe.slick" %% "slick-hikaricp" % slickVersion,
      postgresql,
      
      // Redis
      "com.github.karelcemus" %% "play-redis" % "2.7.0",
      jedis,
      
      // JWT
      "com.pauldijou" %% "jwt-play" % "5.0.0",
      jwtScala,
      
      // Swagger
      "com.iheart" %% "play-swagger" % "0.10.14",
      "org.webjars" % "swagger-ui" % "5.10.3",
      
      // Validation
      "com.typesafe.play" %% "play-json-joda" % "2.10.0-RC9",
      
      // Metrics
      "com.kenshoo" %% "metrics-play" % "2.7.3_0.8.2",
      prometheusClient,
      prometheusHotspot,
      
      // Testing
      "com.typesafe.play" %% "play-test" % "2.9.0" % Test,
      "org.scalatestplus.play" %% "scalatestplus-play" % "6.0.0" % Test,
      scalaTest,
      scalaCheck,
      
      // Logging
      logback,
      scalaLogging,
      
      // Guice DI
      "com.typesafe.play" %% "play-guice" % "2.9.0"`;
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const appDir = path.join(projectPath, 'app');
    await fs.mkdir(appDir, { recursive: true });

    await this.generateControllers(appDir, options);
    await this.generateServices(appDir);
    await this.generateRepositories(appDir);
    await this.generateModels(appDir);
    await this.generateFilters(appDir);
    await this.generateUtils(appDir);
    await this.generateViews(appDir);
    await this.generateConfig(projectPath);
    await this.generateRoutes(projectPath);
    await this.generateEvolutions(projectPath);
    await this.generatePublic(projectPath);
    await this.generateTests(projectPath);
  }

  private async generateControllers(appDir: string, options: any): Promise<void> {
    const controllersDir = path.join(appDir, 'controllers');
    await fs.mkdir(controllersDir, { recursive: true });

    // HomeController.scala
    const homeControllerContent = `package controllers

import javax.inject._
import play.api.mvc._
import play.api.libs.json.Json

@Singleton
class HomeController @Inject()(
  val controllerComponents: ControllerComponents
) extends BaseController {

  def index(): Action[AnyContent] = Action { implicit request: Request[AnyContent] =>
    Ok(Json.obj(
      "message" -> "Welcome to ${options.name} API",
      "version" -> "1.0.0",
      "timestamp" -> System.currentTimeMillis()
    ))
  }

  def health(): Action[AnyContent] = Action {
    Ok(Json.obj(
      "status" -> "UP",
      "timestamp" -> System.currentTimeMillis()
    ))
  }
}`;

    await fs.writeFile(
      path.join(controllersDir, 'HomeController.scala'),
      homeControllerContent
    );

    // AuthController.scala
    const authControllerContent = `package controllers

import javax.inject._
import play.api.mvc._
import play.api.libs.json._
import services.{AuthService, UserService}
import models._
import utils.JsonFormats._
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class AuthController @Inject()(
  val controllerComponents: ControllerComponents,
  authService: AuthService,
  userService: UserService
)(implicit ec: ExecutionContext) extends BaseController {

  def register(): Action[JsValue] = Action.async(parse.json) { implicit request =>
    request.body.validate[RegisterRequest].fold(
      errors => Future.successful(BadRequest(Json.obj("errors" -> JsError.toJson(errors)))),
      registerRequest => {
        userService.createUser(registerRequest).map { user =>
          val token = authService.generateToken(user)
          Created(Json.obj(
            "token" -> token,
            "user" -> user
          ))
        }.recover {
          case _: IllegalArgumentException =>
            BadRequest(Json.obj("error" -> "Email already exists"))
          case ex =>
            InternalServerError(Json.obj("error" -> ex.getMessage))
        }
      }
    )
  }

  def login(): Action[JsValue] = Action.async(parse.json) { implicit request =>
    request.body.validate[LoginRequest].fold(
      errors => Future.successful(BadRequest(Json.obj("errors" -> JsError.toJson(errors)))),
      loginRequest => {
        userService.authenticate(loginRequest.email, loginRequest.password).map {
          case Some(user) =>
            val token = authService.generateToken(user)
            Ok(Json.obj(
              "token" -> token,
              "user" -> user
            ))
          case None =>
            Unauthorized(Json.obj("error" -> "Invalid credentials"))
        }
      }
    )
  }

  def refreshToken(): Action[JsValue] = Action.async(parse.json) { implicit request =>
    request.body.validate[RefreshTokenRequest].fold(
      errors => Future.successful(BadRequest(Json.obj("errors" -> JsError.toJson(errors)))),
      refreshRequest => {
        authService.validateToken(refreshRequest.refreshToken) match {
          case Some(userId) =>
            userService.findById(userId).map {
              case Some(user) =>
                val token = authService.generateToken(user)
                Ok(Json.obj(
                  "token" -> token,
                  "user" -> user
                ))
              case None =>
                Unauthorized(Json.obj("error" -> "User not found"))
            }
          case None =>
            Future.successful(Unauthorized(Json.obj("error" -> "Invalid token")))
        }
      }
    )
  }

  def logout(): Action[AnyContent] = authAction { implicit request =>
    // In a real app, you might want to blacklist the token
    Ok(Json.obj("message" -> "Logged out successfully"))
  }
}`;

    await fs.writeFile(
      path.join(controllersDir, 'AuthController.scala'),
      authControllerContent
    );

    // UserController.scala
    const userControllerContent = `package controllers

import javax.inject._
import play.api.mvc._
import play.api.libs.json._
import services.UserService
import models._
import utils.JsonFormats._
import actions.AuthAction
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class UserController @Inject()(
  val controllerComponents: ControllerComponents,
  userService: UserService,
  authAction: AuthAction
)(implicit ec: ExecutionContext) extends BaseController {

  def getUsers(page: Int, size: Int): Action[AnyContent] = authAction.async { implicit request =>
    userService.listUsers(page, size).map { users =>
      Ok(Json.toJson(users))
    }
  }

  def getUser(id: Long): Action[AnyContent] = authAction.async { implicit request =>
    userService.findById(id).map {
      case Some(user) => Ok(Json.toJson(user))
      case None => NotFound(Json.obj("error" -> "User not found"))
    }
  }

  def getCurrentUser(): Action[AnyContent] = authAction { implicit request =>
    Ok(Json.toJson(request.user))
  }

  def updateUser(): Action[JsValue] = authAction.async(parse.json) { implicit request =>
    request.body.validate[UpdateUserRequest].fold(
      errors => Future.successful(BadRequest(Json.obj("errors" -> JsError.toJson(errors)))),
      updateRequest => {
        userService.updateUser(request.user.id, updateRequest).map { updated =>
          Ok(Json.toJson(updated))
        }
      }
    )
  }

  def deleteUser(id: Long): Action[AnyContent] = authAction.async { implicit request =>
    if (request.user.id != id && !request.user.isAdmin) {
      Future.successful(Forbidden(Json.obj("error" -> "Insufficient permissions")))
    } else {
      userService.deleteUser(id).map { _ =>
        NoContent
      }
    }
  }
}`;

    await fs.writeFile(
      path.join(controllersDir, 'UserController.scala'),
      userControllerContent
    );

    // WebSocketController.scala
    const wsControllerContent = `package controllers

import javax.inject._
import play.api.mvc._
import play.api.libs.json._
import play.api.libs.streams.ActorFlow
import akka.actor.ActorSystem
import akka.stream.Materializer
import actors.WebSocketActor
import services.AuthService

@Singleton
class WebSocketController @Inject()(
  val controllerComponents: ControllerComponents,
  authService: AuthService
)(implicit system: ActorSystem, mat: Materializer) extends BaseController {

  def socket: WebSocket = WebSocket.acceptOrResult[JsValue, JsValue] { request =>
    request.headers.get("Authorization").flatMap { auth =>
      val token = auth.replace("Bearer ", "")
      authService.validateToken(token)
    } match {
      case Some(userId) =>
        Right(ActorFlow.actorRef { out =>
          WebSocketActor.props(out, userId)
        })
      case None =>
        Left(Unauthorized("Invalid token"))
    }
  }
}`;

    await fs.writeFile(
      path.join(controllersDir, 'WebSocketController.scala'),
      wsControllerContent
    );
  }

  private async generateServices(appDir: string): Promise<void> {
    const servicesDir = path.join(appDir, 'services');
    await fs.mkdir(servicesDir, { recursive: true });

    // UserService.scala
    const userServiceContent = `package services

import javax.inject._
import models._
import repositories.UserRepository
import org.mindrot.jbcrypt.BCrypt
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class UserService @Inject()(
  userRepository: UserRepository
)(implicit ec: ExecutionContext) {

  def createUser(request: RegisterRequest): Future[User] = {
    val hashedPassword = BCrypt.hashpw(request.password, BCrypt.gensalt())
    val user = User(
      id = 0,
      email = request.email,
      name = request.name,
      passwordHash = hashedPassword,
      isAdmin = false,
      createdAt = System.currentTimeMillis(),
      updatedAt = System.currentTimeMillis()
    )
    userRepository.create(user)
  }

  def authenticate(email: String, password: String): Future[Option[User]] = {
    userRepository.findByEmail(email).map {
      case Some(user) if BCrypt.checkpw(password, user.passwordHash) => Some(user)
      case _ => None
    }
  }

  def findById(id: Long): Future[Option[User]] = {
    userRepository.findById(id)
  }

  def findByEmail(email: String): Future[Option[User]] = {
    userRepository.findByEmail(email)
  }

  def listUsers(page: Int, size: Int): Future[PagedResult[User]] = {
    for {
      users <- userRepository.list(offset = (page - 1) * size, limit = size)
      total <- userRepository.count()
    } yield PagedResult(users, page, size, total)
  }

  def updateUser(id: Long, request: UpdateUserRequest): Future[User] = {
    userRepository.update(id, request)
  }

  def deleteUser(id: Long): Future[Unit] = {
    userRepository.delete(id)
  }
}`;

    await fs.writeFile(
      path.join(servicesDir, 'UserService.scala'),
      userServiceContent
    );

    // AuthService.scala
    const authServiceContent = `package services

import javax.inject._
import models.User
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}
import play.api.Configuration
import play.api.libs.json._
import scala.util.Try
import java.time.Clock

@Singleton
class AuthService @Inject()(config: Configuration) {
  private val secret = config.get[String]("jwt.secret")
  private val expiration = config.get[Long]("jwt.expirationInSeconds")
  private implicit val clock: Clock = Clock.systemUTC

  def generateToken(user: User): String = {
    val claim = JwtClaim(
      subject = Some(user.id.toString),
      expiration = Some(System.currentTimeMillis() / 1000 + expiration),
      issuedAt = Some(System.currentTimeMillis() / 1000),
      content = Json.obj(
        "email" -> user.email,
        "name" -> user.name,
        "isAdmin" -> user.isAdmin
      ).toString()
    )
    
    Jwt.encode(claim, secret, JwtAlgorithm.HS256)
  }

  def validateToken(token: String): Option[Long] = {
    Try {
      Jwt.decode(token, secret, Seq(JwtAlgorithm.HS256)).map { claim =>
        claim.subject.flatMap(s => Try(s.toLong).toOption)
      }.get
    }.toOption.flatten
  }

  def extractUserId(token: String): Option[Long] = {
    validateToken(token)
  }
}`;

    await fs.writeFile(
      path.join(servicesDir, 'AuthService.scala'),
      authServiceContent
    );

    // CacheService.scala
    const cacheServiceContent = `package services

import javax.inject._
import play.api.cache.AsyncCacheApi
import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._
import scala.reflect.ClassTag

@Singleton
class CacheService @Inject()(
  cache: AsyncCacheApi
)(implicit ec: ExecutionContext) {

  def get[T: ClassTag](key: String): Future[Option[T]] = {
    cache.get[T](key)
  }

  def set[T](key: String, value: T, expiration: Duration = 1.hour): Future[Unit] = {
    cache.set(key, value, expiration)
  }

  def remove(key: String): Future[Unit] = {
    cache.remove(key)
  }

  def getOrElseUpdate[T: ClassTag](key: String, expiration: Duration = 1.hour)(orElse: => Future[T]): Future[T] = {
    cache.get[T](key).flatMap {
      case Some(value) => Future.successful(value)
      case None => 
        orElse.flatMap { value =>
          cache.set(key, value, expiration).map(_ => value)
        }
    }
  }
}`;

    await fs.writeFile(
      path.join(servicesDir, 'CacheService.scala'),
      cacheServiceContent
    );
  }

  private async generateRepositories(appDir: string): Promise<void> {
    const reposDir = path.join(appDir, 'repositories');
    await fs.mkdir(reposDir, { recursive: true });

    // UserRepository.scala
    const userRepoContent = `package repositories

import javax.inject._
import models._
import play.api.db.slick.{DatabaseConfigProvider, HasDatabaseConfigProvider}
import slick.jdbc.JdbcProfile
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class UserRepository @Inject()(
  protected val dbConfigProvider: DatabaseConfigProvider
)(implicit ec: ExecutionContext) extends HasDatabaseConfigProvider[JdbcProfile] {
  
  import profile.api._

  private class UsersTable(tag: Tag) extends Table[User](tag, "users") {
    def id = column[Long]("id", O.PrimaryKey, O.AutoInc)
    def email = column[String]("email", O.Unique)
    def name = column[String]("name")
    def passwordHash = column[String]("password_hash")
    def isAdmin = column[Boolean]("is_admin", O.Default(false))
    def createdAt = column[Long]("created_at")
    def updatedAt = column[Long]("updated_at")

    def * = (id, email, name, passwordHash, isAdmin, createdAt, updatedAt).mapTo[User]
  }

  private val users = TableQuery[UsersTable]

  def create(user: User): Future[User] = {
    val insertQuery = users returning users.map(_.id) into ((user, id) => user.copy(id = id))
    db.run(insertQuery += user)
  }

  def findById(id: Long): Future[Option[User]] = {
    db.run(users.filter(_.id === id).result.headOption)
  }

  def findByEmail(email: String): Future[Option[User]] = {
    db.run(users.filter(_.email === email).result.headOption)
  }

  def list(offset: Int, limit: Int): Future[Seq[User]] = {
    db.run(users.drop(offset).take(limit).result)
  }

  def count(): Future[Long] = {
    db.run(users.length.result.map(_.toLong))
  }

  def update(id: Long, request: UpdateUserRequest): Future[User] = {
    val updateQuery = for {
      userOpt <- users.filter(_.id === id).result.headOption
      updated = userOpt.map { user =>
        user.copy(
          name = request.name.getOrElse(user.name),
          updatedAt = System.currentTimeMillis()
        )
      }
      _ <- users.filter(_.id === id).update(updated.get) if updated.isDefined
    } yield updated

    db.run(updateQuery.transactionally).map(_.get)
  }

  def delete(id: Long): Future[Unit] = {
    db.run(users.filter(_.id === id).delete).map(_ => ())
  }
}`;

    await fs.writeFile(
      path.join(reposDir, 'UserRepository.scala'),
      userRepoContent
    );
  }

  private async generateModels(appDir: string): Promise<void> {
    const modelsDir = path.join(appDir, 'models');
    await fs.mkdir(modelsDir, { recursive: true });

    const modelsContent = `package models

// Domain models
case class User(
  id: Long,
  email: String,
  name: String,
  passwordHash: String,
  isAdmin: Boolean = false,
  createdAt: Long,
  updatedAt: Long
)

// Request models
case class RegisterRequest(
  email: String,
  name: String,
  password: String
)

case class LoginRequest(
  email: String,
  password: String
)

case class UpdateUserRequest(
  name: Option[String] = None
)

case class RefreshTokenRequest(
  refreshToken: String
)

// Response models
case class AuthResponse(
  token: String,
  user: User
)

case class ErrorResponse(
  error: String,
  timestamp: Long = System.currentTimeMillis()
)

case class PagedResult[T](
  data: Seq[T],
  page: Int,
  size: Int,
  total: Long
) {
  def totalPages: Int = Math.ceil(total.toDouble / size).toInt
  def hasNext: Boolean = page < totalPages
  def hasPrevious: Boolean = page > 1
}

// WebSocket models
case class WebSocketMessage(
  messageType: String,
  payload: play.api.libs.json.JsValue,
  timestamp: Long = System.currentTimeMillis()
)`;

    await fs.writeFile(
      path.join(modelsDir, 'Models.scala'),
      modelsContent
    );
  }

  private async generateFilters(appDir: string): Promise<void> {
    const filtersDir = path.join(appDir, 'filters');
    await fs.mkdir(filtersDir, { recursive: true });

    // LoggingFilter.scala
    const loggingFilterContent = `package filters

import javax.inject._
import play.api.mvc._
import play.api.Logging
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class LoggingFilter @Inject()(implicit val mat: akka.stream.Materializer, ec: ExecutionContext) 
  extends Filter with Logging {

  def apply(nextFilter: RequestHeader => Future[Result])(requestHeader: RequestHeader): Future[Result] = {
    val startTime = System.currentTimeMillis

    nextFilter(requestHeader).map { result =>
      val requestTime = System.currentTimeMillis - startTime
      logger.info(s"\${requestHeader.method} \${requestHeader.uri} \${result.header.status} \${requestTime}ms")
      result.withHeaders("X-Response-Time" -> requestTime.toString)
    }
  }
}`;

    await fs.writeFile(
      path.join(filtersDir, 'LoggingFilter.scala'),
      loggingFilterContent
    );

    // Filters.scala
    const filtersContent = `package filters

import javax.inject._
import play.api._
import play.api.http.HttpFilters
import play.api.mvc._
import play.filters.cors.CORSFilter
import play.filters.csrf.CSRFFilter
import play.filters.headers.SecurityHeadersFilter
import play.filters.gzip.GzipFilter

@Singleton
class Filters @Inject()(
  env: Environment,
  corsFilter: CORSFilter,
  csrfFilter: CSRFFilter,
  securityHeadersFilter: SecurityHeadersFilter,
  gzipFilter: GzipFilter,
  loggingFilter: LoggingFilter
) extends HttpFilters {

  override val filters: Seq[EssentialFilter] = {
    Seq(corsFilter, securityHeadersFilter, gzipFilter, loggingFilter) ++ 
    (if (env.mode == Mode.Prod) Seq(csrfFilter) else Seq.empty)
  }
}`;

    await fs.writeFile(
      path.join(filtersDir, 'Filters.scala'),
      filtersContent
    );
  }

  private async generateUtils(appDir: string): Promise<void> {
    const utilsDir = path.join(appDir, 'utils');
    await fs.mkdir(utilsDir, { recursive: true });

    // JsonFormats.scala
    const jsonFormatsContent = `package utils

import play.api.libs.json._
import models._

object JsonFormats {
  // User formats
  implicit val userFormat: Format[User] = Json.format[User]
  implicit val registerRequestFormat: Format[RegisterRequest] = Json.format[RegisterRequest]
  implicit val loginRequestFormat: Format[LoginRequest] = Json.format[LoginRequest]
  implicit val updateUserRequestFormat: Format[UpdateUserRequest] = Json.format[UpdateUserRequest]
  implicit val refreshTokenRequestFormat: Format[RefreshTokenRequest] = Json.format[RefreshTokenRequest]
  
  // Response formats
  implicit val authResponseFormat: Format[AuthResponse] = Json.format[AuthResponse]
  implicit val errorResponseFormat: Format[ErrorResponse] = Json.format[ErrorResponse]
  implicit def pagedResultFormat[T: Format]: Format[PagedResult[T]] = Json.format[PagedResult[T]]
  
  // WebSocket formats
  implicit val webSocketMessageFormat: Format[WebSocketMessage] = Json.format[WebSocketMessage]
}`;

    await fs.writeFile(
      path.join(utilsDir, 'JsonFormats.scala'),
      jsonFormatsContent
    );

    // Validators.scala
    const validatorsContent = `package utils

import play.api.libs.json._

object Validators {
  val emailRegex = """^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$""".r
  
  def validateEmail(email: String): Boolean = {
    emailRegex.findFirstIn(email).isDefined
  }
  
  def validatePassword(password: String): Boolean = {
    password.length >= 8
  }
  
  val emailValidator: Reads[String] = Reads.StringReads.filter(JsonValidationError("Invalid email"))(validateEmail)
  val passwordValidator: Reads[String] = Reads.StringReads.filter(JsonValidationError("Password must be at least 8 characters"))(validatePassword)
}`;

    await fs.writeFile(
      path.join(utilsDir, 'Validators.scala'),
      validatorsContent
    );
  }

  private async generateViews(appDir: string): Promise<void> {
    const viewsDir = path.join(appDir, 'views');
    await fs.mkdir(viewsDir, { recursive: true });

    // swagger.scala.html
    const swaggerViewContent = `@()
<!DOCTYPE html>
<html>
<head>
    <title>API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.10.3/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.10.3/swagger-ui-bundle.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.10.3/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "/api-docs/swagger.json",
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                layout: "StandaloneLayout"
            });
        }
    </script>
</body>
</html>`;

    await fs.writeFile(
      path.join(viewsDir, 'swagger.scala.html'),
      swaggerViewContent
    );
  }

  private async generateConfig(projectPath: string): Promise<void> {
    const confDir = path.join(projectPath, 'conf');
    await fs.mkdir(confDir, { recursive: true });

    // application.conf
    const appConf = `# This is the main configuration file for the application.
# https://www.playframework.com/documentation/latest/ConfigFile

play {
  http.secret.key = "changeme"
  http.secret.key = \${?APPLICATION_SECRET}
  
  i18n.langs = ["en"]
  
  modules {
    enabled += "play.api.db.DBModule"
    enabled += "play.api.db.slick.SlickModule"
    enabled += "play.modules.swagger.SwaggerModule"
    enabled += "modules.AppModule"
  }
  
  filters {
    enabled += "play.filters.cors.CORSFilter"
    enabled += "play.filters.csrf.CSRFFilter"
    enabled += "play.filters.headers.SecurityHeadersFilter"
    enabled += "play.filters.gzip.GzipFilter"
    enabled += "filters.Filters"
    
    cors {
      allowedOrigins = ["http://localhost:3000", "http://localhost:4200"]
      allowedOrigins = \${?CORS_ALLOWED_ORIGINS}
      allowedHttpMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
      allowedHttpHeaders = ["Accept", "Content-Type", "Authorization"]
    }
    
    csrf {
      header.bypassHeaders {
        Authorization = "*"
      }
    }
  }
  
  evolutions {
    db.default.enabled = true
    db.default.autoApply = true
  }
}

slick.dbs.default {
  profile = "slick.jdbc.PostgresProfile$"
  db {
    driver = "org.postgresql.Driver"
    url = "jdbc:postgresql://localhost:5432/app_db"
    url = \${?DATABASE_URL}
    user = "postgres"
    user = \${?DB_USER}
    password = "postgres"
    password = \${?DB_PASSWORD}
    numThreads = 10
    maxConnections = 10
  }
}

jwt {
  secret = "your-secret-key-here"
  secret = \${?JWT_SECRET}
  expirationInSeconds = 86400
  expirationInSeconds = \${?JWT_EXPIRATION}
}

play.cache.redis {
  host = localhost
  host = \${?REDIS_HOST}
  port = 6379
  port = \${?REDIS_PORT}
  database = 0
  password = null
  password = \${?REDIS_PASSWORD}
}

swagger.api {
  basepath = "/api"
  host = "localhost:9000"
  schemes = ["http", "https"]
  info {
    title = "Play Framework API"
    version = "1.0.0"
    description = "REST API Documentation"
  }
}`;

    await fs.writeFile(
      path.join(confDir, 'application.conf'),
      appConf
    );

    // logback.xml
    const logbackXml = `<configuration>
  <conversionRule conversionWord="coloredLevel" converterClass="play.api.libs.logback.ColoredLevel" />

  <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
    <encoder>
      <pattern>%coloredLevel %logger{15} - %message%n%xException{10}</pattern>
    </encoder>
  </appender>

  <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>logs/application.log</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
      <fileNamePattern>logs/application.%d{yyyy-MM-dd}.log</fileNamePattern>
      <maxHistory>30</maxHistory>
    </rollingPolicy>
    <encoder>
      <pattern>%date [%level] from %logger in %thread - %message%n%xException</pattern>
    </encoder>
  </appender>

  <logger name="play" level="INFO" />
  <logger name="application" level="DEBUG" />
  <logger name="slick" level="INFO" />
  <logger name="com.zaxxer.hikari" level="INFO" />

  <root level="WARN">
    <appender-ref ref="STDOUT" />
    <appender-ref ref="FILE" />
  </root>
</configuration>`;

    await fs.writeFile(
      path.join(confDir, 'logback.xml'),
      logbackXml
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    const confDir = path.join(projectPath, 'conf');
    
    const routesContent = `# Routes
# This file defines all application routes (Higher priority routes first)
# https://www.playframework.com/documentation/latest/ScalaRouting

# Home page
GET     /                           controllers.HomeController.index()
GET     /health                     controllers.HomeController.health()

# Authentication
POST    /api/auth/register          controllers.AuthController.register()
POST    /api/auth/login             controllers.AuthController.login()
POST    /api/auth/refresh           controllers.AuthController.refreshToken()
POST    /api/auth/logout            controllers.AuthController.logout()

# Users
GET     /api/users                  controllers.UserController.getUsers(page: Int ?= 1, size: Int ?= 10)
GET     /api/users/me               controllers.UserController.getCurrentUser()
GET     /api/users/:id              controllers.UserController.getUser(id: Long)
PUT     /api/users/me               controllers.UserController.updateUser()
DELETE  /api/users/:id              controllers.UserController.deleteUser(id: Long)

# WebSocket
GET     /ws                         controllers.WebSocketController.socket

# Swagger
GET     /docs                       controllers.Assets.at(path="/public", file="swagger-ui/index.html")
GET     /api-docs/swagger.json      controllers.ApiHelpController.getResources

# Map static resources from the /public folder to the /assets URL path
GET     /assets/*file               controllers.Assets.versioned(path="/public", file: Asset)`;

    await fs.writeFile(
      path.join(confDir, 'routes'),
      routesContent
    );
  }

  private async generateEvolutions(projectPath: string): Promise<void> {
    const evolutionsDir = path.join(projectPath, 'conf/evolutions/default');
    await fs.mkdir(evolutionsDir, { recursive: true });

    const evolution1 = `# Users schema

# --- !Ups

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);

# --- !Downs

DROP TABLE IF EXISTS users;`;

    await fs.writeFile(
      path.join(evolutionsDir, '1.sql'),
      evolution1
    );
  }

  private async generatePublic(projectPath: string): Promise<void> {
    const publicDir = path.join(projectPath, 'public');
    await fs.mkdir(publicDir, { recursive: true });

    // Create directories for static assets
    await fs.mkdir(path.join(publicDir, 'stylesheets'), { recursive: true });
    await fs.mkdir(path.join(publicDir, 'javascripts'), { recursive: true });
    await fs.mkdir(path.join(publicDir, 'images'), { recursive: true });
  }

  private async generateTests(projectPath: string): Promise<void> {
    const testDir = path.join(projectPath, 'test');
    await fs.mkdir(testDir, { recursive: true });

    // ApplicationSpec.scala
    const appSpecContent = `import org.scalatestplus.play._
import org.scalatestplus.play.guice._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import models._
import utils.JsonFormats._

class ApplicationSpec extends PlaySpec with GuiceOneAppPerTest with Injecting {

  "Application" should {

    "send 404 on a bad request" in {
      val request = FakeRequest(GET, "/boum")
      val result = route(app, request).get

      status(result) mustBe NOT_FOUND
    }

    "render the index page" in {
      val request = FakeRequest(GET, "/")
      val result = route(app, request).get

      status(result) mustBe OK
      contentType(result) mustBe Some("application/json")
    }

    "return health status" in {
      val request = FakeRequest(GET, "/health")
      val result = route(app, request).get

      status(result) mustBe OK
      val json = contentAsJson(result)
      (json \\ "status").head.as[String] mustBe "UP"
    }
  }

  "AuthController" should {

    "register a new user" in {
      val registerRequest = RegisterRequest("test@example.com", "Test User", "password123")
      val request = FakeRequest(POST, "/api/auth/register")
        .withHeaders("Content-Type" -> "application/json")
        .withJsonBody(Json.toJson(registerRequest))
      
      val result = route(app, request).get

      status(result) mustBe CREATED
      val json = contentAsJson(result)
      (json \\ "user" \\ "email").head.as[String] mustBe "test@example.com"
      (json \\ "token").head.as[String] must not be empty
    }

    "login with valid credentials" in {
      val loginRequest = LoginRequest("test@example.com", "password123")
      val request = FakeRequest(POST, "/api/auth/login")
        .withHeaders("Content-Type" -> "application/json")
        .withJsonBody(Json.toJson(loginRequest))
      
      val result = route(app, request).get

      status(result) mustBe OK
      val json = contentAsJson(result)
      (json \\ "token").head.as[String] must not be empty
    }

    "reject invalid credentials" in {
      val loginRequest = LoginRequest("test@example.com", "wrongpassword")
      val request = FakeRequest(POST, "/api/auth/login")
        .withHeaders("Content-Type" -> "application/json")
        .withJsonBody(Json.toJson(loginRequest))
      
      val result = route(app, request).get

      status(result) mustBe UNAUTHORIZED
    }
  }
}`;

    await fs.writeFile(
      path.join(testDir, 'ApplicationSpec.scala'),
      appSpecContent
    );

    // Create actions directory
    const actionsDir = path.join(projectPath, 'app/actions');
    await fs.mkdir(actionsDir, { recursive: true });

    // AuthAction.scala
    const authActionContent = `package actions

import javax.inject._
import play.api.mvc._
import services.{AuthService, UserService}
import models.User
import scala.concurrent.{ExecutionContext, Future}

case class AuthRequest[A](user: User, request: Request[A]) extends WrappedRequest[A](request)

@Singleton
class AuthAction @Inject()(
  val parser: BodyParsers.Default,
  authService: AuthService,
  userService: UserService
)(implicit val executionContext: ExecutionContext) extends ActionBuilder[AuthRequest, AnyContent] {

  override def invokeBlock[A](request: Request[A], block: AuthRequest[A] => Future[Result]): Future[Result] = {
    request.headers.get("Authorization").flatMap { authHeader =>
      val token = authHeader.replace("Bearer ", "")
      authService.extractUserId(token)
    } match {
      case Some(userId) =>
        userService.findById(userId).flatMap {
          case Some(user) => block(AuthRequest(user, request))
          case None => Future.successful(Results.Unauthorized("User not found"))
        }
      case None =>
        Future.successful(Results.Unauthorized("Invalid or missing token"))
    }
  }
}`;

    await fs.writeFile(
      path.join(actionsDir, 'AuthAction.scala'),
      authActionContent
    );

    // Create actors directory
    const actorsDir = path.join(projectPath, 'app/actors');
    await fs.mkdir(actorsDir, { recursive: true });

    // WebSocketActor.scala
    const wsActorContent = `package actors

import akka.actor._
import play.api.libs.json._
import models.WebSocketMessage
import utils.JsonFormats._

object WebSocketActor {
  def props(out: ActorRef, userId: Long) = Props(new WebSocketActor(out, userId))
}

class WebSocketActor(out: ActorRef, userId: Long) extends Actor {
  
  override def preStart(): Unit = {
    context.system.eventStream.subscribe(self, classOf[WebSocketMessage])
    sendMessage("connected", Json.obj("userId" -> userId))
  }

  override def postStop(): Unit = {
    context.system.eventStream.unsubscribe(self)
  }

  def receive: Receive = {
    case msg: JsValue =>
      handleClientMessage(msg)
    
    case msg: WebSocketMessage =>
      out ! Json.toJson(msg)
  }

  private def handleClientMessage(msg: JsValue): Unit = {
    (msg \\ "type").headOption.map(_.as[String]) match {
      case Some("ping") =>
        sendMessage("pong", Json.obj("timestamp" -> System.currentTimeMillis()))
      
      case Some("broadcast") =>
        val payload = (msg \\ "payload").headOption.getOrElse(JsNull)
        context.system.eventStream.publish(
          WebSocketMessage("broadcast", payload)
        )
      
      case _ =>
        sendMessage("error", Json.obj("message" -> "Unknown message type"))
    }
  }

  private def sendMessage(messageType: String, payload: JsValue): Unit = {
    out ! Json.toJson(WebSocketMessage(messageType, payload))
  }
}`;

    await fs.writeFile(
      path.join(actorsDir, 'WebSocketActor.scala'),
      wsActorContent
    );

    // Create modules directory
    const modulesDir = path.join(projectPath, 'app/modules');
    await fs.mkdir(modulesDir, { recursive: true });

    // AppModule.scala
    const appModuleContent = `package modules

import com.google.inject.AbstractModule
import play.api.libs.concurrent.AkkaGuiceSupport

class AppModule extends AbstractModule with AkkaGuiceSupport {
  override def configure(): Unit = {
    // Bind any custom implementations here
  }
}`;

    await fs.writeFile(
      path.join(modulesDir, 'AppModule.scala'),
      appModuleContent
    );
  }
}

export default PlayGenerator;