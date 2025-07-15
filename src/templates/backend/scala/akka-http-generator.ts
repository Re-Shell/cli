import { ScalaBackendGenerator } from './scala-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class AkkaHttpGenerator extends ScalaBackendGenerator {
  constructor() {
    super('Akka HTTP');
  }

  protected getFrameworkSettings(): string {
    return `resolvers += "Akka library repository".at("https://repo.akka.io/maven")`;
  }

  protected getFrameworkPlugins(): string {
    return `// Akka gRPC plugin
addSbtPlugin("com.lightbend.akka.grpc" % "sbt-akka-grpc" % "2.4.0")`;
  }

  protected getFrameworkDependencies(): string {
    return `// Akka HTTP
      "com.typesafe.akka" %% "akka-http" % akkaHttpVersion,
      "com.typesafe.akka" %% "akka-http-spray-json" % akkaHttpVersion,
      "com.typesafe.akka" %% "akka-http-xml" % akkaHttpVersion,
      "com.typesafe.akka" %% "akka-http-testkit" % akkaHttpVersion % Test,
      
      // Akka
      "com.typesafe.akka" %% "akka-actor-typed" % akkaVersion,
      "com.typesafe.akka" %% "akka-stream" % akkaVersion,
      "com.typesafe.akka" %% "akka-stream-testkit" % akkaVersion % Test,
      "com.typesafe.akka" %% "akka-actor-testkit-typed" % akkaVersion % Test,
      
      // Akka Management
      "com.lightbend.akka.management" %% "akka-management" % "1.4.1",
      "com.lightbend.akka.management" %% "akka-management-cluster-http" % "1.4.1",
      
      // JSON
      "io.circe" %% "circe-core" % circeVersion,
      "io.circe" %% "circe-generic" % circeVersion,
      "io.circe" %% "circe-parser" % circeVersion,
      "de.heikoseeberger" %% "akka-http-circe" % "1.39.2",
      
      // Database
      "com.typesafe.slick" %% "slick" % slickVersion,
      "com.typesafe.slick" %% "slick-hikaricp" % slickVersion,
      postgresql,
      hikariCP,
      
      // Redis
      jedis,
      
      // JWT
      jwtScala,
      
      // Validation
      "com.wix" %% "accord-core" % "0.8.1",
      
      // Swagger
      "com.github.swagger-akka-http" %% "swagger-akka-http" % "2.11.0",
      "com.github.swagger-akka-http" %% "swagger-scala-module" % "2.11.0",
      "io.swagger.core.v3" % "swagger-annotations" % "2.2.19",
      "io.swagger.core.v3" % "swagger-core" % "2.2.19",
      "io.swagger.core.v3" % "swagger-jaxrs2" % "2.2.19",
      "jakarta.ws.rs" % "jakarta.ws.rs-api" % "3.1.0",
      
      // Metrics
      prometheusClient,
      prometheusHotspot,
      prometheusHttpserver,
      
      // Testing
      scalaTest,
      scalaCheck,
      
      // Logging
      logback,
      scalaLogging,
      
      // Config
      config`;
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const basePackage = options.organization || 'com.example';
    const srcDir = path.join(projectPath, 'src/main/scala', ...basePackage.split('.'));
    await fs.mkdir(srcDir, { recursive: true });

    await this.generateMain(srcDir, basePackage, options);
    await this.generateServer(srcDir, basePackage, options);
    await this.generateRoutes(srcDir, basePackage);
    await this.generateControllers(srcDir, basePackage);
    await this.generateServices(srcDir, basePackage);
    await this.generateRepositories(srcDir, basePackage);
    await this.generateModels(srcDir, basePackage);
    await this.generateDatabase(srcDir, basePackage);
    await this.generateAuth(srcDir, basePackage);
    await this.generateMiddleware(srcDir, basePackage);
    await this.generateWebSocket(srcDir, basePackage);
    await this.generateUtils(srcDir, basePackage);
    await this.generateConfig(projectPath);
    await this.generateResources(projectPath);
    await this.generateTests(projectPath, basePackage);
  }

  private async generateMain(srcDir: string, basePackage: string, options: any): Promise<void> {
    const mainContent = `package ${basePackage}

import akka.actor.typed.ActorSystem
import akka.actor.typed.scaladsl.Behaviors
import com.typesafe.config.ConfigFactory
import com.typesafe.scalalogging.LazyLogging

import scala.concurrent.ExecutionContext
import scala.util.{Failure, Success}

object Main extends App with LazyLogging {
  val rootBehavior = Behaviors.setup[Nothing] { context =>
    implicit val system: ActorSystem[Nothing] = context.system
    implicit val ec: ExecutionContext = system.executionContext
    
    val config = ConfigFactory.load()
    val host = config.getString("server.host")
    val port = config.getInt("server.port")
    
    // Initialize database
    val database = new Database(config)
    database.migrate()
    
    // Initialize services
    val userRepository = new UserRepository(database.db)
    val userService = new UserService(userRepository)
    val authService = new AuthService(config)
    
    // Initialize server
    val server = new Server(
      host = host,
      port = port,
      userService = userService,
      authService = authService
    )
    
    server.start().onComplete {
      case Success(binding) =>
        logger.info(s"Server started at http://\${binding.localAddress.getHostString}:\${binding.localAddress.getPort}")
      case Failure(ex) =>
        logger.error("Failed to start server", ex)
        system.terminate()
    }
    
    Behaviors.empty
  }
  
  ActorSystem[Nothing](rootBehavior, "${options.name}")
}`;

    await fs.writeFile(
      path.join(srcDir, 'Main.scala'),
      mainContent
    );
  }

  private async generateServer(srcDir: string, basePackage: string, options: any): Promise<void> {
    const serverContent = `package ${basePackage}

import akka.actor.typed.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import ${basePackage}.routes._
import ${basePackage}.middleware._
import ${basePackage}.services._
import com.typesafe.scalalogging.LazyLogging

import scala.concurrent.{ExecutionContext, Future}

class Server(
  host: String,
  port: Int,
  userService: UserService,
  authService: AuthService
)(implicit system: ActorSystem[_]) extends LazyLogging {
  
  implicit val ec: ExecutionContext = system.executionContext
  
  // Initialize routes
  private val healthRoutes = new HealthRoutes()
  private val authRoutes = new AuthRoutes(authService, userService)
  private val userRoutes = new UserRoutes(userService, authService)
  private val wsRoutes = new WebSocketRoutes()
  private val swaggerRoutes = new SwaggerRoutes()
  
  // Combine all routes
  val routes: Route = 
    handleRejections(RejectionHandler.default) {
      handleExceptions(ExceptionHandler.handler) {
        CorsMiddleware.cors {
          LoggingMiddleware.logRequestResult {
            RateLimitMiddleware.rateLimited {
              pathPrefix("api" / "v1") {
                healthRoutes.routes ~
                authRoutes.routes ~
                authenticateJWT(authService) { user =>
                  userRoutes.routes(user)
                }
              } ~
              pathPrefix("ws") {
                wsRoutes.routes
              } ~
              swaggerRoutes.routes
            }
          }
        }
      }
    }
  
  def start(): Future[Http.ServerBinding] = {
    logger.info(s"Starting server on \$host:\$port")
    Http().newServerAt(host, port).bind(routes)
  }
  
  def stop(binding: Http.ServerBinding): Future[Unit] = {
    binding.terminate(hardDeadline = java.time.Duration.ofSeconds(30))
      .map(_ => logger.info("Server stopped"))
  }
}`;

    await fs.writeFile(
      path.join(srcDir, 'Server.scala'),
      serverContent
    );
  }

  private async generateRoutes(srcDir: string, basePackage: string): Promise<void> {
    const routesDir = path.join(srcDir, 'routes');
    await fs.mkdir(routesDir, { recursive: true });

    // HealthRoutes.scala
    const healthRoutesContent = `package ${basePackage}.routes

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import de.heikoseeberger.akkahttpcirce.FailFastCirceSupport._
import io.circe.generic.auto._

import java.lang.management.ManagementFactory
import scala.concurrent.duration._

class HealthRoutes {
  case class HealthStatus(
    status: String,
    uptime: Long,
    timestamp: Long,
    version: String
  )

  val routes: Route = pathPrefix("health") {
    get {
      val runtime = ManagementFactory.getRuntimeMXBean
      val health = HealthStatus(
        status = "UP",
        uptime = runtime.getUptime,
        timestamp = System.currentTimeMillis(),
        version = "1.0.0"
      )
      complete(StatusCodes.OK, health)
    }
  }
}`;

    await fs.writeFile(
      path.join(routesDir, 'HealthRoutes.scala'),
      healthRoutesContent
    );

    // AuthRoutes.scala
    const authRoutesContent = `package ${basePackage}.routes

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import ${basePackage}.models._
import ${basePackage}.services._
import de.heikoseeberger.akkahttpcirce.FailFastCirceSupport._
import io.circe.generic.auto._

import scala.concurrent.ExecutionContext

class AuthRoutes(
  authService: AuthService,
  userService: UserService
)(implicit ec: ExecutionContext) {

  val routes: Route = pathPrefix("auth") {
    path("register") {
      post {
        entity(as[RegisterRequest]) { request =>
          onSuccess(userService.createUser(request)) { user =>
            val token = authService.generateToken(user)
            complete(StatusCodes.Created, AuthResponse(token, user))
          }
        }
      }
    } ~
    path("login") {
      post {
        entity(as[LoginRequest]) { request =>
          onSuccess(userService.authenticate(request.email, request.password)) {
            case Some(user) =>
              val token = authService.generateToken(user)
              complete(StatusCodes.OK, AuthResponse(token, user))
            case None =>
              complete(StatusCodes.Unauthorized, ErrorResponse("Invalid credentials"))
          }
        }
      }
    } ~
    path("refresh") {
      post {
        entity(as[RefreshTokenRequest]) { request =>
          authService.validateToken(request.refreshToken) match {
            case Some(userId) =>
              onSuccess(userService.findById(userId)) {
                case Some(user) =>
                  val token = authService.generateToken(user)
                  complete(StatusCodes.OK, AuthResponse(token, user))
                case None =>
                  complete(StatusCodes.Unauthorized, ErrorResponse("User not found"))
              }
            case None =>
              complete(StatusCodes.Unauthorized, ErrorResponse("Invalid token"))
          }
        }
      }
    }
  }
}`;

    await fs.writeFile(
      path.join(routesDir, 'AuthRoutes.scala'),
      authRoutesContent
    );

    // UserRoutes.scala
    const userRoutesContent = `package ${basePackage}.routes

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import ${basePackage}.models._
import ${basePackage}.services._
import de.heikoseeberger.akkahttpcirce.FailFastCirceSupport._
import io.circe.generic.auto._

import scala.concurrent.ExecutionContext

class UserRoutes(
  userService: UserService,
  authService: AuthService
)(implicit ec: ExecutionContext) {

  def routes(currentUser: User): Route = pathPrefix("users") {
    pathEnd {
      get {
        parameters("page".as[Int].?, "size".as[Int].?) { (page, size) =>
          onSuccess(userService.listUsers(page.getOrElse(1), size.getOrElse(10))) { users =>
            complete(StatusCodes.OK, users)
          }
        }
      }
    } ~
    path("me") {
      get {
        complete(StatusCodes.OK, currentUser)
      } ~
      put {
        entity(as[UpdateUserRequest]) { request =>
          onSuccess(userService.updateUser(currentUser.id, request)) { updated =>
            complete(StatusCodes.OK, updated)
          }
        }
      } ~
      delete {
        onSuccess(userService.deleteUser(currentUser.id)) { _ =>
          complete(StatusCodes.NoContent)
        }
      }
    } ~
    path(LongNumber) { userId =>
      get {
        onSuccess(userService.findById(userId)) {
          case Some(user) => complete(StatusCodes.OK, user)
          case None => complete(StatusCodes.NotFound, ErrorResponse("User not found"))
        }
      }
    }
  }
}`;

    await fs.writeFile(
      path.join(routesDir, 'UserRoutes.scala'),
      userRoutesContent
    );

    // WebSocketRoutes.scala
    const wsRoutesContent = `package ${basePackage}.routes

import akka.http.scaladsl.model.ws.{Message, TextMessage}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import akka.stream.scaladsl.{Flow, Sink, Source}
import akka.stream.{Materializer, OverflowStrategy}
import akka.{Done, NotUsed}

import scala.concurrent.{ExecutionContext, Future}

class WebSocketRoutes(implicit mat: Materializer, ec: ExecutionContext) {
  
  val routes: Route = path("echo") {
    handleWebSocketMessages(echoFlow)
  } ~
  path("broadcast") {
    handleWebSocketMessages(broadcastFlow)
  }
  
  private def echoFlow: Flow[Message, Message, NotUsed] =
    Flow[Message].mapConcat {
      case tm: TextMessage =>
        TextMessage(s"Echo: \${tm.getStrictText}") :: Nil
      case _ =>
        Nil
    }
  
  private def broadcastFlow: Flow[Message, Message, NotUsed] = {
    val (sink, source) = Source.queue[Message](100, OverflowStrategy.dropHead)
      .preMaterialize()
    
    Flow.fromSinkAndSourceCoupled(
      sink = Flow[Message].to(Sink.foreach { msg =>
        source.offer(msg)
      }),
      source = source
    )
  }
}`;

    await fs.writeFile(
      path.join(routesDir, 'WebSocketRoutes.scala'),
      wsRoutesContent
    );

    // SwaggerRoutes.scala
    const swaggerRoutesContent = `package ${basePackage}.routes

import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import com.github.swagger.akka.SwaggerHttpService
import com.github.swagger.akka.model.Info
import io.swagger.v3.oas.models.ExternalDocumentation

object SwaggerRoutes extends SwaggerHttpService {
  override def apiClasses: Set[Class[_]] = Set(
    classOf[HealthRoutes],
    classOf[AuthRoutes],
    classOf[UserRoutes]
  )
  
  override def apiDocsPath: String = "api-docs"
  
  override def info: Info = Info(
    version = "1.0.0",
    title = "Akka HTTP API",
    description = "REST API Documentation"
  )
  
  val routes: Route = 
    path("swagger") { getFromResource("swagger-ui/index.html") } ~
    getFromResourceDirectory("swagger-ui") ~
    super.routes
}`;

    await fs.writeFile(
      path.join(routesDir, 'SwaggerRoutes.scala'),
      swaggerRoutesContent
    );
  }

  private async generateControllers(srcDir: string, basePackage: string): Promise<void> {
    // Controllers are implemented as routes in Akka HTTP
  }

  private async generateServices(srcDir: string, basePackage: string): Promise<void> {
    const servicesDir = path.join(srcDir, 'services');
    await fs.mkdir(servicesDir, { recursive: true });

    // UserService.scala
    const userServiceContent = `package ${basePackage}.services

import ${basePackage}.models._
import ${basePackage}.repositories.UserRepository
import org.mindrot.jbcrypt.BCrypt

import scala.concurrent.{ExecutionContext, Future}

class UserService(
  userRepository: UserRepository
)(implicit ec: ExecutionContext) {
  
  def createUser(request: RegisterRequest): Future[User] = {
    val hashedPassword = BCrypt.hashpw(request.password, BCrypt.gensalt())
    val user = User(
      id = 0,
      email = request.email,
      name = request.name,
      passwordHash = hashedPassword,
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
  
  def listUsers(page: Int, size: Int): Future[Seq[User]] = {
    userRepository.list(offset = (page - 1) * size, limit = size)
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
    const authServiceContent = `package ${basePackage}.services

import ${basePackage}.models.User
import com.github.jwt.{Jwt, JwtAlgorithm}
import com.typesafe.config.Config
import io.circe.generic.auto._
import io.circe.parser._
import io.circe.syntax._

import scala.util.Try

class AuthService(config: Config) {
  private val secret = config.getString("jwt.secret")
  private val expiration = config.getDuration("jwt.expiration").toMillis
  
  case class JwtClaims(
    sub: Long,
    email: String,
    exp: Long,
    iat: Long
  )
  
  def generateToken(user: User): String = {
    val now = System.currentTimeMillis()
    val claims = JwtClaims(
      sub = user.id,
      email = user.email,
      exp = now + expiration,
      iat = now
    )
    
    Jwt.encode(claims.asJson.noSpaces, secret, JwtAlgorithm.HS256)
  }
  
  def validateToken(token: String): Option[Long] = {
    Try {
      Jwt.decodeRaw(token, secret, Seq(JwtAlgorithm.HS256)).toOption.flatMap { payload =>
        decode[JwtClaims](payload).toOption.filter { claims =>
          claims.exp > System.currentTimeMillis()
        }.map(_.sub)
      }
    }.getOrElse(None)
  }
  
  def extractUserId(token: String): Option[Long] = {
    validateToken(token)
  }
}`;

    await fs.writeFile(
      path.join(servicesDir, 'AuthService.scala'),
      authServiceContent
    );
  }

  private async generateRepositories(srcDir: string, basePackage: string): Promise<void> {
    const reposDir = path.join(srcDir, 'repositories');
    await fs.mkdir(reposDir, { recursive: true });

    const userRepoContent = `package ${basePackage}.repositories

import ${basePackage}.models._
import slick.jdbc.PostgresProfile.api._

import scala.concurrent.{ExecutionContext, Future}

class UserRepository(db: Database)(implicit ec: ExecutionContext) {
  import UserTable._
  
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
  
  def update(id: Long, request: UpdateUserRequest): Future[User] = {
    val updateQuery = for {
      user <- users.filter(_.id === id).result.headOption
      updated = user.map { u =>
        u.copy(
          name = request.name.getOrElse(u.name),
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
}

object UserTable {
  class Users(tag: Tag) extends Table[User](tag, "users") {
    def id = column[Long]("id", O.PrimaryKey, O.AutoInc)
    def email = column[String]("email", O.Unique)
    def name = column[String]("name")
    def passwordHash = column[String]("password_hash")
    def createdAt = column[Long]("created_at")
    def updatedAt = column[Long]("updated_at")
    
    def * = (id, email, name, passwordHash, createdAt, updatedAt).mapTo[User]
  }
  
  val users = TableQuery[Users]
}`;

    await fs.writeFile(
      path.join(reposDir, 'UserRepository.scala'),
      userRepoContent
    );
  }

  private async generateModels(srcDir: string, basePackage: string): Promise<void> {
    const modelsDir = path.join(srcDir, 'models');
    await fs.mkdir(modelsDir, { recursive: true });

    const modelsContent = `package ${basePackage}.models

// Domain models
case class User(
  id: Long,
  email: String,
  name: String,
  passwordHash: String,
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

case class PagedResponse[T](
  data: Seq[T],
  page: Int,
  size: Int,
  total: Long
)`;

    await fs.writeFile(
      path.join(modelsDir, 'Models.scala'),
      modelsContent
    );
  }

  private async generateDatabase(srcDir: string, basePackage: string): Promise<void> {
    const dbContent = `package ${basePackage}

import com.typesafe.config.Config
import com.typesafe.scalalogging.LazyLogging
import slick.jdbc.PostgresProfile.api._
import slick.migration.api._

import scala.concurrent.{ExecutionContext, Future}

class Database(config: Config)(implicit ec: ExecutionContext) extends LazyLogging {
  
  val db = Database.forConfig("database", config)
  
  def migrate(): Future[Unit] = {
    logger.info("Running database migrations...")
    
    val migrations = TableMigration(UserTable.users)
      .create
      .addColumns(_.id, _.email, _.name, _.passwordHash, _.createdAt, _.updatedAt)
      .addIndexes(_.email)
    
    db.run(migrations())
  }
  
  def close(): Future[Unit] = {
    Future.successful(db.close())
  }
}`;

    await fs.writeFile(
      path.join(srcDir, 'Database.scala'),
      dbContent
    );
  }

  private async generateAuth(srcDir: string, basePackage: string): Promise<void> {
    const authDir = path.join(srcDir, 'middleware');
    await fs.mkdir(authDir, { recursive: true });

    const authMiddlewareContent = `package ${basePackage}.middleware

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.model.headers.{Authorization, OAuth2BearerToken}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.{Directive1, Route}
import ${basePackage}.models.{ErrorResponse, User}
import ${basePackage}.services.{AuthService, UserService}
import de.heikoseeberger.akkahttpcirce.FailFastCirceSupport._
import io.circe.generic.auto._

import scala.concurrent.{ExecutionContext, Future}

object authenticateJWT {
  def apply(authService: AuthService)(implicit ec: ExecutionContext): Directive1[User] = {
    optionalHeaderValueByType(classOf[Authorization]).flatMap {
      case Some(Authorization(OAuth2BearerToken(token))) =>
        authService.extractUserId(token) match {
          case Some(userId) =>
            onSuccess(Future.successful(User(
              id = userId,
              email = "",
              name = "",
              passwordHash = "",
              createdAt = 0,
              updatedAt = 0
            ))).flatMap(provide)
          case None =>
            complete(StatusCodes.Unauthorized, ErrorResponse("Invalid token"))
        }
      case _ =>
        complete(StatusCodes.Unauthorized, ErrorResponse("Missing authorization header"))
    }
  }
}`;

    await fs.writeFile(
      path.join(authDir, 'AuthMiddleware.scala'),
      authMiddlewareContent
    );
  }

  private async generateMiddleware(srcDir: string, basePackage: string): Promise<void> {
    const middlewareDir = path.join(srcDir, 'middleware');
    await fs.mkdir(middlewareDir, { recursive: true });

    // CorsMiddleware.scala
    const corsContent = `package ${basePackage}.middleware

import akka.http.scaladsl.model.HttpMethods._
import akka.http.scaladsl.model.headers._
import akka.http.scaladsl.model.{HttpResponse, StatusCodes}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.{Directive0, Route}

object CorsMiddleware {
  private val corsResponseHeaders = List(
    \`Access-Control-Allow-Origin\`.*,
    \`Access-Control-Allow-Credentials\`(true),
    \`Access-Control-Allow-Headers\`("Authorization", "Content-Type", "X-Requested-With"),
    \`Access-Control-Max-Age\`(86400)
  )

  def cors: Directive0 = {
    extractRequest.flatMap { request =>
      request.method match {
        case OPTIONS =>
          complete(HttpResponse(StatusCodes.OK).withHeaders(
            corsResponseHeaders :+ \`Access-Control-Allow-Methods\`(GET, POST, PUT, DELETE, OPTIONS, HEAD)
          ))
        case _ =>
          mapResponseHeaders(_ ++ corsResponseHeaders)
      }
    }
  }
}`;

    await fs.writeFile(
      path.join(middlewareDir, 'CorsMiddleware.scala'),
      corsContent
    );

    // LoggingMiddleware.scala
    const loggingContent = `package ${basePackage}.middleware

import akka.event.Logging.LogLevel
import akka.event.{Logging, LoggingAdapter}
import akka.http.scaladsl.model.{HttpRequest, HttpResponse}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.{Directive0, RouteResult}
import akka.http.scaladsl.server.directives.{DebuggingDirectives, LogEntry}

import scala.concurrent.duration._

object LoggingMiddleware {
  def logRequestResult: Directive0 = {
    DebuggingDirectives.logRequestResult(
      marker = "HTTP",
      level = Logging.InfoLevel,
      formatRequestResponse = requestResponseFormat
    )
  }
  
  private def requestResponseFormat(request: HttpRequest)(response: RouteResult): LogEntry = {
    val entry = response match {
      case RouteResult.Complete(res) =>
        s"\${request.method} \${request.uri} => \${res.status} in \${System.currentTimeMillis()}ms"
      case RouteResult.Rejected(rejections) =>
        s"\${request.method} \${request.uri} => Rejected: \$rejections"
    }
    LogEntry(entry, Logging.InfoLevel)
  }
}`;

    await fs.writeFile(
      path.join(middlewareDir, 'LoggingMiddleware.scala'),
      loggingContent
    );

    // RateLimitMiddleware.scala
    const rateLimitContent = `package ${basePackage}.middleware

import akka.http.scaladsl.model.{HttpResponse, StatusCodes}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Directive0
import com.github.blemale.scaffeine.{Cache, Scaffeine}

import scala.concurrent.duration._

object RateLimitMiddleware {
  private val requestCounts: Cache[String, Int] = 
    Scaffeine()
      .recordStats()
      .expireAfterWrite(1.minute)
      .maximumSize(10000)
      .build[String, Int]()
  
  def rateLimited(limit: Int = 100): Directive0 = {
    extractClientIP.flatMap { ip =>
      val key = ip.toOption.map(_.getHostAddress).getOrElse("unknown")
      val count = requestCounts.get(key, _ => 0) + 1
      
      if (count > limit) {
        complete(HttpResponse(
          StatusCodes.TooManyRequests,
          entity = "Rate limit exceeded"
        ))
      } else {
        requestCounts.put(key, count)
        pass
      }
    }
  }
}`;

    await fs.writeFile(
      path.join(middlewareDir, 'RateLimitMiddleware.scala'),
      rateLimitContent
    );

    // ExceptionHandler.scala
    const exceptionHandlerContent = `package ${basePackage}.middleware

import akka.http.scaladsl.model.{HttpResponse, StatusCodes}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.ExceptionHandler
import ${basePackage}.models.ErrorResponse
import com.typesafe.scalalogging.LazyLogging
import de.heikoseeberger.akkahttpcirce.FailFastCirceSupport._
import io.circe.generic.auto._

object ExceptionHandler extends LazyLogging {
  val handler: ExceptionHandler = ExceptionHandler {
    case ex: IllegalArgumentException =>
      logger.warn("Bad request", ex)
      complete(StatusCodes.BadRequest, ErrorResponse(ex.getMessage))
    
    case ex: NoSuchElementException =>
      logger.warn("Not found", ex)
      complete(StatusCodes.NotFound, ErrorResponse("Resource not found"))
    
    case ex: Exception =>
      logger.error("Internal server error", ex)
      complete(StatusCodes.InternalServerError, ErrorResponse("Internal server error"))
  }
}`;

    await fs.writeFile(
      path.join(middlewareDir, 'ExceptionHandler.scala'),
      exceptionHandlerContent
    );
  }

  private async generateWebSocket(srcDir: string, basePackage: string): Promise<void> {
    // WebSocket implementation is already in WebSocketRoutes.scala
  }

  private async generateUtils(srcDir: string, basePackage: string): Promise<void> {
    const utilsDir = path.join(srcDir, 'utils');
    await fs.mkdir(utilsDir, { recursive: true });

    const validationContent = `package ${basePackage}.utils

import com.wix.accord.Validator
import com.wix.accord.dsl._

object Validation {
  implicit val registerRequestValidator: Validator[RegisterRequest] = validator { req =>
    req.email should matchRegex("""^[^@]+@[^@]+\\.[^@]+$""".r)
    req.password.length should be >= 8
    req.name.length should be >= 2
  }
  
  implicit val loginRequestValidator: Validator[LoginRequest] = validator { req =>
    req.email should matchRegex("""^[^@]+@[^@]+\\.[^@]+$""".r)
    req.password.length should be >= 1
  }
}`;

    await fs.writeFile(
      path.join(utilsDir, 'Validation.scala'),
      validationContent
    );
  }

  private async generateConfig(projectPath: string): Promise<void> {
    const resourcesDir = path.join(projectPath, 'src/main/resources');
    await fs.mkdir(resourcesDir, { recursive: true });

    const appConf = `akka {
  loglevel = INFO
  loglevel = \${?LOG_LEVEL}
  
  http {
    server {
      idle-timeout = 60s
      request-timeout = 20s
      bind-timeout = 1s
      max-connections = 1024
      pipelining-limit = 16
      
      parsing {
        max-content-length = 10m
        max-uri-length = 4k
        max-header-value-length = 8k
      }
    }
    
    client {
      connecting-timeout = 10s
      idle-timeout = 60s
    }
    
    host-connection-pool {
      max-connections = 32
      max-open-requests = 128
      idle-timeout = 30s
    }
  }
}

server {
  host = "0.0.0.0"
  host = \${?HOST}
  port = 8080
  port = \${?PORT}
}

database {
  driver = "org.postgresql.Driver"
  url = "jdbc:postgresql://localhost:5432/app_db"
  url = \${?DATABASE_URL}
  user = "postgres"
  user = \${?DB_USER}
  password = "postgres"
  password = \${?DB_PASSWORD}
  
  connectionPool = "HikariCP"
  properties {
    maximumPoolSize = 10
    minimumIdle = 2
    idleTimeout = 600000
    connectionTimeout = 30000
    maxLifetime = 1800000
  }
}

jwt {
  secret = "your-secret-key-here"
  secret = \${?JWT_SECRET}
  expiration = 24 hours
  expiration = \${?JWT_EXPIRATION}
}

redis {
  host = "localhost"
  host = \${?REDIS_HOST}
  port = 6379
  port = \${?REDIS_PORT}
  password = ""
  password = \${?REDIS_PASSWORD}
}`;

    await fs.writeFile(
      path.join(resourcesDir, 'application.conf'),
      appConf
    );

    const logbackXml = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/application.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/application.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <logger name="akka" level="INFO"/>
    <logger name="akka.http" level="INFO"/>
    <logger name="com.example" level="DEBUG"/>

    <root level="INFO">
        <appender-ref ref="STDOUT"/>
        <appender-ref ref="FILE"/>
    </root>
</configuration>`;

    await fs.writeFile(
      path.join(resourcesDir, 'logback.xml'),
      logbackXml
    );
  }

  private async generateResources(projectPath: string): Promise<void> {
    // Additional resources if needed
  }

  private async generateTests(projectPath: string, basePackage: string): Promise<void> {
    const testDir = path.join(projectPath, 'src/test/scala', ...basePackage.split('.'));
    await fs.mkdir(testDir, { recursive: true });

    const serverSpecContent = `package ${basePackage}

import akka.actor.testkit.typed.scaladsl.ActorTestKit
import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.testkit.ScalatestRouteTest
import ${basePackage}.models._
import ${basePackage}.services._
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatest.BeforeAndAfterAll

class ServerSpec extends AnyWordSpec 
  with Matchers 
  with ScalatestRouteTest 
  with BeforeAndAfterAll {
  
  lazy val testKit = ActorTestKit()
  implicit def typedSystem = testKit.system
  override def afterAll(): Unit = testKit.shutdownTestKit()
  
  "Health endpoint" should {
    "return OK status" in {
      Get("/api/v1/health") ~> routes ~> check {
        status shouldBe StatusCodes.OK
        responseAs[HealthStatus].status shouldBe "UP"
      }
    }
  }
  
  "Auth endpoints" should {
    "register new user" in {
      val request = RegisterRequest("test@example.com", "Test User", "password123")
      Post("/api/v1/auth/register", request) ~> routes ~> check {
        status shouldBe StatusCodes.Created
        responseAs[AuthResponse].user.email shouldBe "test@example.com"
      }
    }
    
    "login with valid credentials" in {
      val request = LoginRequest("test@example.com", "password123")
      Post("/api/v1/auth/login", request) ~> routes ~> check {
        status shouldBe StatusCodes.OK
        responseAs[AuthResponse].token should not be empty
      }
    }
  }
}`;

    await fs.writeFile(
      path.join(testDir, 'ServerSpec.scala'),
      serverSpecContent
    );
  }
}

export default AkkaHttpGenerator;