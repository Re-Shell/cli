import { ScalaBackendGenerator } from './scala-base-generator';

export class PlayGenerator extends ScalaBackendGenerator {
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      "com.typesafe.play::play_2.13": "2.8.19",
      "com.typesafe.play::play-guice_2.13": "2.8.19",
      "com.typesafe.play::play-json_2.13": "2.9.4",
      "com.typesafe.play::play-slick_2.13": "5.0.0",
      "com.typesafe.play::play-slick-evolutions_2.13": "5.0.0",
      "com.typesafe.slick::slick-hikaricp_2.13": "3.4.1",
      "com.mohiva::play-silhouette_2.13": "7.0.0",
      "com.mohiva::play-silhouette-password-bcrypt_2.13": "7.0.0",
      "com.mohiva::play-silhouette-crypto-jca_2.13": "7.0.0",
      "com.mohiva::play-silhouette-persistence_2.13": "7.0.0",
      "com.mohiva::play-silhouette-testkit_2.13": "7.0.0"
    };
  }

  protected generateMainFile(): string {
    return `package com.example

import play.api.{Application, ApplicationLoader, LoggerConfigurator}
import play.api.ApplicationLoader.Context

class AppApplicationLoader extends ApplicationLoader {
  def load(context: Context): Application = {
    LoggerConfigurator(context.environment.classLoader).foreach {
      _.configure(context.environment, context.initialConfiguration, Map.empty)
    }
    new AppComponents(context).application
  }
}`;
  }

  protected generateRoutingFile(): string {
    return `# Routes
# This file defines all application routes (Higher priority routes first)

# Health check
GET     /health                           controllers.HealthController.health()

# Authentication routes
POST    /api/auth/register                controllers.AuthController.register()
POST    /api/auth/login                   controllers.AuthController.login()
POST    /api/auth/refresh                 controllers.AuthController.refresh()
POST    /api/auth/logout                  controllers.AuthController.logout()

# User routes
GET     /api/users                        controllers.UserController.getAllUsers(page: Int ?= 0, size: Int ?= 20)
GET     /api/users/me                     controllers.UserController.getCurrentUser()
GET     /api/users/:id                    controllers.UserController.getUserById(id: Int)
PUT     /api/users/:id                    controllers.UserController.updateUser(id: Int)
DELETE  /api/users/:id                    controllers.UserController.deleteUser(id: Int)

# Static assets
GET     /assets/*file                     controllers.Assets.versioned(path="/public", file: Asset)

# Default route
GET     /                                 controllers.HomeController.index()`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/services/UserService.scala',
        content: `package services

import models.{User, UserDAO}
import dto.{CreateUserRequest, UpdateUserRequest}
import play.api.Logging
import utils.PasswordUtils
import exceptions.{ValidationException, NotFoundException}

import scala.concurrent.{ExecutionContext, Future}
import javax.inject.{Inject, Singleton}

@Singleton
class UserService @Inject()(
  userDAO: UserDAO,
  passwordUtils: PasswordUtils
)(implicit ec: ExecutionContext) extends Logging {

  def createUser(request: CreateUserRequest): Future[User] = {
    for {
      // Check if email already exists
      existingUser <- userDAO.findByEmail(request.email)
      _ <- if (existingUser.isDefined) {
        Future.failed(ValidationException("Email already exists"))
      } else {
        Future.successful(())
      }
      
      // Hash password
      hashedPassword <- passwordUtils.hashPassword(request.password)
      
      // Create user
      user <- userDAO.create(request.email, hashedPassword, request.name, "user")
    } yield user
  }

  def findById(id: Int): Future[Option[User]] = {
    userDAO.findById(id)
  }

  def findByEmail(email: String): Future[Option[User]] = {
    userDAO.findByEmail(email)
  }

  def getAllUsers(page: Int = 0, size: Int = 20): Future[Seq[User]] = {
    userDAO.findAll(page, size)
  }

  def updateUser(id: Int, request: UpdateUserRequest): Future[User] = {
    for {
      user <- userDAO.findById(id).flatMap {
        case Some(u) => Future.successful(u)
        case None => Future.failed(NotFoundException("User not found"))
      }
      
      // Check email uniqueness if changing
      _ <- request.email match {
        case Some(newEmail) if newEmail != user.email =>
          userDAO.findByEmail(newEmail).flatMap {
            case Some(_) => Future.failed(ValidationException("Email already exists"))
            case None => Future.successful(())
          }
        case _ => Future.successful(())
      }
      
      // Hash password if provided
      hashedPassword <- request.password match {
        case Some(pwd) => passwordUtils.hashPassword(pwd).map(Some(_))
        case None => Future.successful(None)
      }
      
      // Update user
      updatedUser <- userDAO.update(id, request.copy(password = hashedPassword))
    } yield updatedUser
  }

  def deleteUser(id: Int): Future[Unit] = {
    for {
      user <- userDAO.findById(id).flatMap {
        case Some(_) => Future.successful(())
        case None => Future.failed(NotFoundException("User not found"))
      }
      _ <- userDAO.delete(id)
    } yield ()
  }

  def validateCredentials(email: String, password: String): Future[Option[User]] = {
    for {
      user <- userDAO.findByEmail(email)
      result <- user match {
        case Some(u) => 
          passwordUtils.verifyPassword(password, u.password).map {
            case true => Some(u)
            case false => None
          }
        case None => Future.successful(None)
      }
    } yield result
  }
}`
      },
      {
        path: 'app/services/AuthService.scala',
        content: `package services

import models.User
import dto._
import utils.{JwtUtils, ValidationUtils}
import exceptions.{UnauthorizedException, ValidationException}
import play.api.Logging
import play.api.cache.AsyncCacheApi

import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._
import javax.inject.{Inject, Singleton}

@Singleton
class AuthService @Inject()(
  userService: UserService,
  jwtUtils: JwtUtils,
  cache: AsyncCacheApi,
  validationUtils: ValidationUtils
)(implicit ec: ExecutionContext) extends Logging {

  private val RefreshTokenExpiration = 7.days

  def register(request: CreateUserRequest): Future[AuthResponse] = {
    for {
      // Validate request
      _ <- validationUtils.validateCreateUserRequest(request).flatMap {
        case Left(error) => Future.failed(ValidationException(error))
        case Right(_) => Future.successful(())
      }
      
      // Create user
      user <- userService.createUser(request)
      
      // Generate auth response
      response <- generateAuthResponse(user)
    } yield response
  }

  def login(request: LoginRequest): Future[AuthResponse] = {
    for {
      // Validate credentials
      user <- userService.validateCredentials(request.email, request.password).flatMap {
        case Some(u) => Future.successful(u)
        case None => Future.failed(UnauthorizedException("Invalid email or password"))
      }
      
      // Check if user is active
      _ <- if (user.isActive) Future.successful(())
           else Future.failed(UnauthorizedException("Account is disabled"))
      
      // Generate auth response
      response <- generateAuthResponse(user)
    } yield response
  }

  def refreshToken(request: RefreshTokenRequest): Future[AuthResponse] = {
    for {
      // Get user ID from refresh token cache
      userId <- cache.get[Int](s"refresh:${'$'}{request.refreshToken}").flatMap {
        case Some(id) => Future.successful(id)
        case None => Future.failed(UnauthorizedException("Invalid refresh token"))
      }
      
      // Get user
      user <- userService.findById(userId).flatMap {
        case Some(u) => Future.successful(u)
        case None => Future.failed(UnauthorizedException("User not found"))
      }
      
      // Remove old refresh token
      _ <- cache.remove(s"refresh:${'$'}{request.refreshToken}")
      
      // Generate new auth response
      response <- generateAuthResponse(user)
    } yield response
  }

  def logout(refreshToken: String): Future[Unit] = {
    cache.remove(s"refresh:$refreshToken").map(_ => ())
  }

  private def generateAuthResponse(user: User): Future[AuthResponse] = {
    for {
      token <- jwtUtils.generateToken(user)
      refreshToken <- jwtUtils.generateRefreshToken(user)
      
      // Store refresh token in cache
      _ <- cache.set(s"refresh:$refreshToken", user.id, RefreshTokenExpiration)
      
      response = AuthResponse(
        token = token,
        refreshToken = refreshToken,
        user = UserResponse.fromUser(user)
      )
    } yield response
  }
}`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/models/UserDAO.scala',
        content: `package models

import play.api.db.slick.DatabaseConfigProvider
import slick.jdbc.JdbcProfile
import dto.UpdateUserRequest

import scala.concurrent.{ExecutionContext, Future}
import javax.inject.{Inject, Singleton}
import java.time.Instant

@Singleton
class UserDAO @Inject()(dbConfigProvider: DatabaseConfigProvider)(implicit ec: ExecutionContext) {
  
  private val dbConfig = dbConfigProvider.get[JdbcProfile]
  
  import dbConfig._
  import profile.api._

  private class UsersTable(tag: Tag) extends Table[User](tag, "users") {
    def id = column[Int]("id", O.PrimaryKey, O.AutoInc)
    def email = column[String]("email", O.Unique)
    def password = column[String]("password")
    def name = column[String]("name")
    def role = column[String]("role")
    def isActive = column[Boolean]("is_active")
    def createdAt = column[Instant]("created_at")
    def updatedAt = column[Instant]("updated_at")

    def * = (id, email, password, name, role, isActive, createdAt, updatedAt) <> ((User.apply _).tupled, User.unapply)
  }

  private val users = TableQuery[UsersTable]

  def create(email: String, password: String, name: String, role: String): Future[User] = {
    val now = Instant.now()
    val insertQuery = users returning users.map(_.id) into ((user, id) => user.copy(id = id))
    
    val user = User(0, email, password, name, role, isActive = true, now, now)
    
    db.run(insertQuery += user)
  }

  def findById(id: Int): Future[Option[User]] = {
    db.run(users.filter(_.id === id).result.headOption)
  }

  def findByEmail(email: String): Future[Option[User]] = {
    db.run(users.filter(_.email === email).result.headOption)
  }

  def findAll(page: Int = 0, size: Int = 20): Future[Seq[User]] = {
    val offset = page * size
    db.run(users.sortBy(_.createdAt.desc).drop(offset).take(size).result)
  }

  def update(id: Int, request: UpdateUserRequest): Future[User] = {
    val now = Instant.now()
    
    val updateQuery = for {
      user <- users.filter(_.id === id)
    } yield (user.name, user.email, user.password, user.updatedAt)
    
    val updatedValues = (
      request.name.getOrElse(""),
      request.email.getOrElse(""), 
      request.password.getOrElse(""),
      now
    )
    
    for {
      _ <- db.run(updateQuery.update(updatedValues))
      user <- findById(id).map(_.get)
    } yield user
  }

  def delete(id: Int): Future[Unit] = {
    db.run(users.filter(_.id === id).delete).map(_ => ())
  }
}`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/models/User.scala',
        content: `package models

import play.api.libs.json._
import java.time.Instant

case class User(
  id: Int,
  email: String,
  password: String,
  name: String,
  role: String,
  isActive: Boolean,
  createdAt: Instant,
  updatedAt: Instant
)

object User {
  implicit val userWrites: Writes[User] = Json.writes[User]
  implicit val userReads: Reads[User] = Json.reads[User]
}

case class UserResponse(
  id: Int,
  email: String,
  name: String,
  role: String,
  isActive: Boolean,
  createdAt: String,
  updatedAt: String
)

object UserResponse {
  implicit val userResponseWrites: Writes[UserResponse] = Json.writes[UserResponse]
  implicit val userResponseReads: Reads[UserResponse] = Json.reads[UserResponse]
  
  def fromUser(user: User): UserResponse = UserResponse(
    id = user.id,
    email = user.email,
    name = user.name,
    role = user.role,
    isActive = user.isActive,
    createdAt = user.createdAt.toString,
    updatedAt = user.updatedAt.toString
  )
}`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'conf/application.conf',
        content: `# Application configuration

# The application name
play.application.name = "\${this.options?.name || 'play-service'}"

# Database configuration
db.default.driver = "org.postgresql.Driver"
db.default.url = "jdbc:postgresql://localhost:5432/app_db"
db.default.url = \${?DATABASE_URL}
db.default.username = "postgres"
db.default.username = \${?DATABASE_USER}
db.default.password = "postgres"
db.default.password = \${?DATABASE_PASSWORD}

# Connection pool settings
db.default.hikaricp.maximumPoolSize = 10
db.default.hikaricp.maximumPoolSize = \${?DATABASE_MAX_POOL_SIZE}

# Slick configuration
slick.dbs.default.profile = "slick.jdbc.PostgresProfile$"
slick.dbs.default.db.driver = "org.postgresql.Driver"
slick.dbs.default.db.url = "jdbc:postgresql://localhost:5432/app_db"
slick.dbs.default.db.url = \${?DATABASE_URL}
slick.dbs.default.db.user = "postgres"
slick.dbs.default.db.user = \${?DATABASE_USER}
slick.dbs.default.db.password = "postgres"
slick.dbs.default.db.password = \${?DATABASE_PASSWORD}

# JWT configuration
jwt.secret = "your-secret-key-change-in-production"
jwt.secret = \${?JWT_SECRET}
jwt.expiration = 86400
jwt.expiration = \${?JWT_EXPIRATION}

# Server configuration
http.port = 9000
http.port = \${?SERVER_PORT}
http.address = "0.0.0.0"

# Play modules
play.modules.enabled += "modules.DatabaseModule"
play.modules.enabled += "modules.ServicesModule"

# Filters
play.filters.enabled += "play.filters.cors.CORSFilter"
play.filters.enabled += "play.filters.headers.SecurityHeadersFilter"
play.filters.enabled += "play.filters.hosts.AllowedHostsFilter"

# CORS configuration
play.filters.cors {
  pathPrefixes = ["/api"]
  allowedOrigins = ["http://localhost:3000", "http://localhost:5173"]
  allowedHttpMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowedHttpHeaders = ["Accept", "Content-Type", "Authorization"]
  preflightMaxAge = 3.days
}

# Security headers
play.filters.headers {
  frameOptions = "DENY"
  xssProtection = "1; mode=block"
  contentTypeOptions = "nosniff"
  permittedCrossDomainPolicies = "master-only"
}

# Cache configuration
play.cache.bindCaches = ["session-cache"]

# Evolutions
play.evolutions.db.default.enabled = true
play.evolutions.db.default.autoApply = true
play.evolutions.db.default.autoApplyDowns = false

# Logging
logger.root = INFO
logger.com.example = INFO
logger.play = INFO
logger.slick = INFO`
      },
      {
        path: 'conf/evolutions/default/1.sql',
        content: `# Users schema

# --- !Ups

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);

# --- !Downs

DROP TABLE users;`
      },
      {
        path: 'conf/logback.xml',
        content: `<configuration>

  <conversionRule conversionWord="coloredLevel" converterClass="play.api.libs.logback.ColoredLevel" />

  <appender name="FILE" class="ch.qos.logback.core.FileAppender">
    <file>logs/application.log</file>
    <encoder>
      <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
    </encoder>
  </appender>

  <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
    <encoder>
      <pattern>%coloredLevel %logger{15} - %message%n%xException{10}</pattern>
    </encoder>
  </appender>

  <appender name="ASYNCFILE" class="ch.qos.logback.classic.AsyncAppender">
    <appender-ref ref="FILE" />
  </appender>

  <appender name="ASYNCSTDOUT" class="ch.qos.logback.classic.AsyncAppender">
    <appender-ref ref="STDOUT" />
  </appender>

  <logger name="com.example" level="INFO" />
  <logger name="play" level="INFO" />
  <logger name="akka" level="INFO" />
  <logger name="slick" level="INFO" />

  <root level="WARN">
    <appender-ref ref="ASYNCFILE" />
    <appender-ref ref="ASYNCSTDOUT" />
  </root>

</configuration>`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/controllers/AuthController.scala',
        content: `package controllers

import play.api.mvc._
import play.api.libs.json._
import services.AuthService
import dto._
import exceptions._

import scala.concurrent.{ExecutionContext, Future}
import javax.inject.{Inject, Singleton}

@Singleton
class AuthController @Inject()(
  cc: ControllerComponents,
  authService: AuthService
)(implicit ec: ExecutionContext) extends AbstractController(cc) {

  def register(): Action[JsValue] = Action.async(parse.json) { implicit request =>
    request.body.validate[CreateUserRequest].fold(
      errors => Future.successful(BadRequest(Json.obj("error" -> "Invalid JSON"))),
      createUserRequest => {
        authService.register(createUserRequest).map { response =>
          Created(Json.toJson(response))
        }.recover {
          case ValidationException(msg) => BadRequest(Json.obj("error" -> msg))
          case _ => InternalServerError(Json.obj("error" -> "Internal server error"))
        }
      }
    )
  }

  def login(): Action[JsValue] = Action.async(parse.json) { implicit request =>
    request.body.validate[LoginRequest].fold(
      errors => Future.successful(BadRequest(Json.obj("error" -> "Invalid JSON"))),
      loginRequest => {
        authService.login(loginRequest).map { response =>
          Ok(Json.toJson(response))
        }.recover {
          case UnauthorizedException(msg) => Unauthorized(Json.obj("error" -> msg))
          case _ => InternalServerError(Json.obj("error" -> "Internal server error"))
        }
      }
    )
  }

  def refresh(): Action[JsValue] = Action.async(parse.json) { implicit request =>
    request.body.validate[RefreshTokenRequest].fold(
      errors => Future.successful(BadRequest(Json.obj("error" -> "Invalid JSON"))),
      refreshRequest => {
        authService.refreshToken(refreshRequest).map { response =>
          Ok(Json.toJson(response))
        }.recover {
          case UnauthorizedException(msg) => Unauthorized(Json.obj("error" -> msg))
          case _ => InternalServerError(Json.obj("error" -> "Internal server error"))
        }
      }
    )
  }

  def logout(): Action[AnyContent] = Action.async { implicit request =>
    request.headers.get("X-Refresh-Token") match {
      case Some(refreshToken) =>
        authService.logout(refreshToken).map { _ =>
          Ok(Json.obj("message" -> "Logged out successfully"))
        }
      case None =>
        Future.successful(BadRequest(Json.obj("error" -> "Refresh token required")))
    }
  }
}`
      },
      {
        path: 'app/controllers/UserController.scala',
        content: `package controllers

import play.api.mvc._
import play.api.libs.json._
import services.UserService
import models.{User, UserResponse}
import dto.UpdateUserRequest
import exceptions._

import scala.concurrent.{ExecutionContext, Future}
import javax.inject.{Inject, Singleton}

@Singleton
class UserController @Inject()(
  cc: ControllerComponents,
  userService: UserService
)(implicit ec: ExecutionContext) extends AbstractController(cc) {

  def getAllUsers(page: Int, size: Int): Action[AnyContent] = Action.async { implicit request =>
    // This should include admin role check in real implementation
    userService.getAllUsers(page, size).map { users =>
      val userResponses = users.map(UserResponse.fromUser)
      Ok(Json.toJson(userResponses))
    }.recover {
      case _ => InternalServerError(Json.obj("error" -> "Internal server error"))
    }
  }

  def getCurrentUser(): Action[AnyContent] = Action.async { implicit request =>
    // This should extract user from JWT token in real implementation
    Future.successful(Ok(Json.obj("message" -> "Current user endpoint")))
  }

  def getUserById(id: Int): Action[AnyContent] = Action.async { implicit request =>
    userService.findById(id).map {
      case Some(user) => Ok(Json.toJson(UserResponse.fromUser(user)))
      case None => NotFound(Json.obj("error" -> "User not found"))
    }.recover {
      case _ => InternalServerError(Json.obj("error" -> "Internal server error"))
    }
  }

  def updateUser(id: Int): Action[JsValue] = Action.async(parse.json) { implicit request =>
    request.body.validate[UpdateUserRequest].fold(
      errors => Future.successful(BadRequest(Json.obj("error" -> "Invalid JSON"))),
      updateRequest => {
        userService.updateUser(id, updateRequest).map { user =>
          Ok(Json.toJson(UserResponse.fromUser(user)))
        }.recover {
          case NotFoundException(msg) => NotFound(Json.obj("error" -> msg))
          case ValidationException(msg) => BadRequest(Json.obj("error" -> msg))
          case _ => InternalServerError(Json.obj("error" -> "Internal server error"))
        }
      }
    )
  }

  def deleteUser(id: Int): Action[AnyContent] = Action.async { implicit request =>
    userService.deleteUser(id).map { _ =>
      NoContent
    }.recover {
      case NotFoundException(msg) => NotFound(Json.obj("error" -> msg))
      case _ => InternalServerError(Json.obj("error" -> "Internal server error"))
    }
  }
}`
      },
      {
        path: 'app/controllers/HealthController.scala',
        content: `package controllers

import play.api.mvc._
import play.api.libs.json._

import javax.inject.{Inject, Singleton}
import scala.concurrent.Future

@Singleton
class HealthController @Inject()(cc: ControllerComponents) extends AbstractController(cc) {

  def health(): Action[AnyContent] = Action.async { implicit request =>
    val runtime = Runtime.getRuntime
    val totalMemory = runtime.totalMemory()
    val freeMemory = runtime.freeMemory()
    val usedMemory = totalMemory - freeMemory
    val memoryPercentage = (usedMemory.toDouble / totalMemory.toDouble) * 100

    val healthResponse = Json.obj(
      "status" -> "OK",
      "timestamp" -> System.currentTimeMillis(),
      "uptime" -> java.lang.management.ManagementFactory.getRuntimeMXBean.getUptime,
      "memory" -> Json.obj(
        "total" -> totalMemory,
        "free" -> freeMemory,
        "used" -> usedMemory,
        "percentage" -> memoryPercentage
      )
    )

    Future.successful(Ok(healthResponse))
  }
}`
      },
      {
        path: 'app/controllers/HomeController.scala',
        content: `package controllers

import play.api.mvc._

import javax.inject.{Inject, Singleton}

@Singleton
class HomeController @Inject()(cc: ControllerComponents) extends AbstractController(cc) {

  def index(): Action[AnyContent] = Action { implicit request =>
    Ok(views.html.index("Welcome to Play Framework"))
  }
}`
      }
    ];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'test/controllers/UserControllerSpec.scala',
        content: `package controllers

import org.scalatestplus.play._
import org.scalatestplus.play.guice._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._

class UserControllerSpec extends PlaySpec with GuiceOneAppPerTest with Injecting {

  "UserController GET /api/users/:id" should {

    "return user when user exists" in {
      val controller = inject[UserController]
      val request = FakeRequest(GET, "/api/users/1")
      
      val result = controller.getUserById(1).apply(request)

      status(result) mustBe OK
      contentType(result) mustBe Some("application/json")
    }

    "return 404 when user does not exist" in {
      val controller = inject[UserController]
      val request = FakeRequest(GET, "/api/users/999")
      
      val result = controller.getUserById(999).apply(request)

      status(result) mustBe NOT_FOUND
    }
  }
}`
      }
    ];
  }

  protected generateBuildSbt(): string {
    const dependencies = this.getFrameworkDependencies();
    const depList = Object.entries(dependencies)
      .map(([org, artifact]) => `    "${org}" %% "${artifact}" % playVersion`)
      .join(',\n');

    return `ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / scalaVersion := "2.13.12"

lazy val playVersion = "2.8.19"

lazy val root = (project in file("."))
  .enablePlugins(PlayScala)
  .settings(
    name := "${this.options?.name || 'play-service'}",
    libraryDependencies ++= Seq(
${depList},
      
      // Additional Play dependencies
      guice,
      caffeine,
      ws,
      specs2 % Test,
      
      // Database
      "org.postgresql" % "postgresql" % "42.7.1",
      "com.typesafe.slick" %% "slick-hikaricp" % "3.4.1",
      
      // Testing
      "org.scalatestplus.play" %% "scalatestplus-play" % "5.1.0" % Test,
      "org.mockito" %% "mockito-scala" % "1.17.12" % Test
    ),
    
    // Compiler options
    scalacOptions ++= Seq(
      "-deprecation",
      "-encoding", "UTF-8",
      "-language:higherKinds",
      "-language:postfixOps",
      "-feature",
      "-Xfatal-warnings"
    ),
    
    // Play settings
    Assets / pipelineStages := Seq(digest, gzip),
    
    // Test settings
    Test / testOptions += Tests.Argument(TestFrameworks.ScalaTest, "-oDF")
  )

// Add Play plugin
addSbtPlugin("com.typesafe.play" % "sbt-plugin" % "2.8.19")
addSbtPlugin("org.foundweekends.giter8" % "sbt-giter8-scaffold" % "0.13.1")`;
  }
}