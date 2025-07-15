import { ScalaBackendGenerator } from './scala-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class Http4sGenerator extends ScalaBackendGenerator {
  constructor() {
    super('http4s');
  }

  protected getFrameworkSettings(): string {
    return `addCompilerPlugin("org.typelevel" % "kind-projector" % "0.13.2" cross CrossVersion.full)
    addCompilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1")`;
  }

  protected getFrameworkPlugins(): string {
    return `// No additional plugins needed for http4s`;
  }

  protected getFrameworkDependencies(): string {
    return `// http4s
      "org.http4s" %% "http4s-ember-server" % http4sVersion,
      "org.http4s" %% "http4s-ember-client" % http4sVersion,
      "org.http4s" %% "http4s-circe" % http4sVersion,
      "org.http4s" %% "http4s-dsl" % http4sVersion,
      "org.http4s" %% "http4s-prometheus-metrics" % http4sVersion,
      
      // Cats and Cats Effect
      "org.typelevel" %% "cats-core" % catsVersion,
      "org.typelevel" %% "cats-effect" % "3.5.2",
      
      // JSON
      "io.circe" %% "circe-core" % circeVersion,
      "io.circe" %% "circe-generic" % circeVersion,
      "io.circe" %% "circe-parser" % circeVersion,
      "io.circe" %% "circe-refined" % circeVersion,
      
      // Database
      "org.tpolecat" %% "doobie-core" % doobieVersion,
      "org.tpolecat" %% "doobie-postgres" % doobieVersion,
      "org.tpolecat" %% "doobie-hikari" % doobieVersion,
      "org.tpolecat" %% "doobie-postgres-circe" % doobieVersion,
      "org.tpolecat" %% "doobie-refined" % doobieVersion,
      postgresql,
      
      // Redis
      "dev.profunktor" %% "redis4cats-effects" % "1.5.1",
      
      // JWT
      jwtScala,
      "com.auth0" % "java-jwt" % "4.4.0",
      
      // Config
      "com.github.pureconfig" %% "pureconfig" % "0.17.4",
      "com.github.pureconfig" %% "pureconfig-cats-effect" % "0.17.4",
      
      // Refined types
      "eu.timepit" %% "refined" % "0.11.0",
      "eu.timepit" %% "refined-cats" % "0.11.0",
      
      // OpenAPI
      "com.github.ghostdogpr" %% "tapir-core" % "1.9.0",
      "com.github.ghostdogpr" %% "tapir-http4s-server" % "1.9.0",
      "com.github.ghostdogpr" %% "tapir-swagger-ui-bundle" % "1.9.0",
      "com.github.ghostdogpr" %% "tapir-json-circe" % "1.9.0",
      
      // Logging
      logback,
      scalaLogging,
      "org.typelevel" %% "log4cats-slf4j" % "2.6.0",
      
      // Testing
      "org.http4s" %% "http4s-circe" % http4sVersion % Test,
      "org.typelevel" %% "cats-effect-testing-scalatest" % "1.5.0" % Test,
      "org.typelevel" %% "munit-cats-effect-3" % "1.0.7" % Test,
      scalaTest,
      
      // Streaming
      "co.fs2" %% "fs2-core" % "3.9.3",
      "co.fs2" %% "fs2-io" % "3.9.3"`;
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const basePackage = options.organization || 'com.example';
    const srcDir = path.join(projectPath, 'src/main/scala', ...basePackage.split('.'));
    await fs.mkdir(srcDir, { recursive: true });

    await this.generateMain(srcDir, basePackage, options);
    await this.generateServer(srcDir, basePackage, options);
    await this.generateConfig(srcDir, basePackage);
    await this.generateRoutes(srcDir, basePackage);
    await this.generateServices(srcDir, basePackage);
    await this.generateRepositories(srcDir, basePackage);
    await this.generateModels(srcDir, basePackage);
    await this.generateDatabase(srcDir, basePackage);
    await this.generateAuth(srcDir, basePackage);
    await this.generateMiddleware(srcDir, basePackage);
    await this.generateWebSocket(srcDir, basePackage);
    await this.generateUtils(srcDir, basePackage);
    await this.generateResources(projectPath);
    await this.generateTests(projectPath, basePackage);
  }

  private async generateMain(srcDir: string, basePackage: string, options: any): Promise<void> {
    const mainContent = `package ${basePackage}

import cats.effect._
import com.comcast.ip4s._
import org.http4s.ember.server.EmberServerBuilder
import org.typelevel.log4cats.LoggerFactory
import org.typelevel.log4cats.slf4j.Slf4jFactory

object Main extends IOApp {
  implicit val loggerFactory: LoggerFactory[IO] = Slf4jFactory.create[IO]

  def run(args: List[String]): IO[ExitCode] = {
    for {
      config <- Config.load[IO]
      _ <- AppResources.make(config).use { resources =>
        for {
          repositories <- Repositories.make(resources.postgres)
          services <- Services.make(repositories, config)
          api = new Api(services)
          _ <- EmberServerBuilder
            .default[IO]
            .withHost(Host.fromString(config.server.host).getOrElse(ipv4"0.0.0.0"))
            .withPort(Port.fromInt(config.server.port).getOrElse(port"8080"))
            .withHttpApp(api.httpApp)
            .build
            .useForever
        } yield ()
      }
    } yield ExitCode.Success
  }
}`;

    await fs.writeFile(
      path.join(srcDir, 'Main.scala'),
      mainContent
    );

    // AppResources.scala
    const appResourcesContent = `package ${basePackage}

import cats.effect._
import cats.syntax.all._
import doobie.hikari.HikariTransactor
import doobie.util.ExecutionContexts
import dev.profunktor.redis4cats.{Redis, RedisCommands}
import org.typelevel.log4cats.LoggerFactory

case class AppResources[F[_]](
  postgres: HikariTransactor[F],
  redis: RedisCommands[F, String, String]
)

object AppResources {
  def make[F[_]: Async: LoggerFactory](config: Config): Resource[F, AppResources[F]] = {
    for {
      ec <- ExecutionContexts.fixedThreadPool[F](config.database.connections)
      postgres <- DatabaseConfig.transactor(config.database, ec)
      redis <- Redis[F].utf8(config.redis.uri).widen[RedisCommands[F, String, String]]
    } yield AppResources(postgres, redis)
  }
}`;

    await fs.writeFile(
      path.join(srcDir, 'AppResources.scala'),
      appResourcesContent
    );
  }

  private async generateServer(srcDir: string, basePackage: string, options: any): Promise<void> {
    const apiContent = `package ${basePackage}

import cats.effect._
import cats.syntax.all._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.server.Router
import org.http4s.server.middleware._
import org.http4s.metrics.prometheus._
import org.http4s.implicits._
import sttp.tapir.swagger.bundle.SwaggerInterpreter
import sttp.tapir.server.http4s.Http4sServerInterpreter
import ${basePackage}.routes._
import ${basePackage}.services._
import ${basePackage}.middleware._
import scala.concurrent.duration._
import org.typelevel.log4cats.LoggerFactory

class Api[F[_]: Async: LoggerFactory](services: Services[F]) extends Http4sDsl[F] {
  
  private val healthRoutes = new HealthRoutes[F]()
  private val authRoutes = new AuthRoutes[F](services.authService, services.userService)
  private val userRoutes = new UserRoutes[F](services.userService, services.authService)
  private val wsRoutes = new WebSocketRoutes[F]()
  
  // Tapir endpoints for Swagger
  private val endpoints = 
    authRoutes.endpoints ++ 
    userRoutes.endpoints ++ 
    healthRoutes.endpoints
  
  private val swaggerRoutes = Http4sServerInterpreter[F]().toRoutes(
    SwaggerInterpreter()
      .fromEndpoints[F](endpoints, "http4s API", "1.0.0")
  )
  
  private val routes: HttpRoutes[F] = Router(
    "/api/v1" -> (healthRoutes.routes <+> authRoutes.routes <+> authMiddleware(services.authService)(userRoutes.routes)),
    "/ws" -> wsRoutes.routes,
    "/docs" -> swaggerRoutes
  )
  
  private val middleware: HttpApp[F] => HttpApp[F] = { http =>
    RequestLogger.httpApp(true, true)(
      ResponseLogger.httpApp(true, true)(
        Timeout.httpApp(30.seconds)(
          ErrorHandler.handle(
            CORS.policy.withAllowOriginAll(
              GZip(
                Metrics[F](Prometheus.metricsOps[F], "http4s_server")(
                  http
                )
              )
            )
          )
        )
      )
    )
  }
  
  val httpApp: HttpApp[F] = middleware(routes.orNotFound)
}`;

    await fs.writeFile(
      path.join(srcDir, 'Api.scala'),
      apiContent
    );
  }

  private async generateConfig(srcDir: string, basePackage: string): Promise<void> {
    const configDir = path.join(srcDir, 'config');
    await fs.mkdir(configDir, { recursive: true });

    const configContent = `package ${basePackage}

import cats.effect._
import pureconfig._
import pureconfig.generic.auto._
import pureconfig.module.catseffect.syntax._
import scala.concurrent.duration._

case class Config(
  server: ServerConfig,
  database: DatabaseConfig,
  redis: RedisConfig,
  jwt: JwtConfig
)

case class ServerConfig(
  host: String,
  port: Int
)

case class DatabaseConfig(
  driver: String,
  url: String,
  user: String,
  password: String,
  connections: Int
)

case class RedisConfig(
  uri: String
)

case class JwtConfig(
  secret: String,
  expiration: FiniteDuration
)

object Config {
  def load[F[_]: Async]: F[Config] =
    ConfigSource.default.loadF[F, Config]
}`;

    await fs.writeFile(
      path.join(srcDir, 'Config.scala'),
      configContent
    );

    // DatabaseConfig.scala
    const dbConfigContent = `package ${basePackage}

import cats.effect._
import doobie._
import doobie.hikari._
import doobie.implicits._
import org.flywaydb.core.Flyway

object DatabaseConfig {
  def transactor[F[_]: Async](
    config: DatabaseConfig,
    ec: ExecutionContext
  ): Resource[F, HikariTransactor[F]] = {
    HikariTransactor.newHikariTransactor[F](
      config.driver,
      config.url,
      config.user,
      config.password,
      ec
    )
  }
  
  def migrate[F[_]: Sync](transactor: HikariTransactor[F]): F[Unit] = {
    transactor.configure { dataSource =>
      Sync[F].delay {
        val flyway = Flyway.configure()
          .dataSource(dataSource)
          .locations("classpath:db/migration")
          .load()
        flyway.migrate()
        ()
      }
    }
  }
}`;

    await fs.writeFile(
      path.join(srcDir, 'DatabaseConfig.scala'),
      dbConfigContent
    );
  }

  private async generateRoutes(srcDir: string, basePackage: string): Promise<void> {
    const routesDir = path.join(srcDir, 'routes');
    await fs.mkdir(routesDir, { recursive: true });

    // HealthRoutes.scala
    const healthRoutesContent = `package ${basePackage}.routes

import cats.effect._
import cats.syntax.all._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe._
import io.circe.generic.auto._
import io.circe.syntax._
import sttp.tapir._
import sttp.tapir.json.circe._
import sttp.tapir.generic.auto._

class HealthRoutes[F[_]: Sync] extends Http4sDsl[F] {
  
  case class HealthStatus(
    status: String,
    timestamp: Long,
    version: String
  )
  
  implicit val healthEncoder: EntityEncoder[F, HealthStatus] = jsonEncoderOf[F, HealthStatus]
  
  val healthEndpoint: PublicEndpoint[Unit, Unit, HealthStatus, Any] =
    endpoint
      .get
      .in("health")
      .out(jsonBody[HealthStatus])
      .description("Health check endpoint")
  
  val routes: HttpRoutes[F] = HttpRoutes.of[F] {
    case GET -> Root / "health" =>
      Ok(HealthStatus(
        status = "UP",
        timestamp = System.currentTimeMillis(),
        version = "1.0.0"
      ))
  }
  
  val endpoints = List(healthEndpoint)
}`;

    await fs.writeFile(
      path.join(routesDir, 'HealthRoutes.scala'),
      healthRoutesContent
    );

    // AuthRoutes.scala
    const authRoutesContent = `package ${basePackage}.routes

import cats.data._
import cats.effect._
import cats.syntax.all._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe._
import ${basePackage}.models._
import ${basePackage}.services._
import io.circe.generic.auto._
import io.circe.syntax._
import sttp.tapir._
import sttp.tapir.json.circe._
import sttp.tapir.generic.auto._

class AuthRoutes[F[_]: Concurrent](
  authService: AuthService[F],
  userService: UserService[F]
) extends Http4sDsl[F] {
  
  implicit val registerDecoder: EntityDecoder[F, RegisterRequest] = jsonOf[F, RegisterRequest]
  implicit val loginDecoder: EntityDecoder[F, LoginRequest] = jsonOf[F, LoginRequest]
  implicit val authEncoder: EntityEncoder[F, AuthResponse] = jsonEncoderOf[F, AuthResponse]
  implicit val errorEncoder: EntityEncoder[F, ErrorResponse] = jsonEncoderOf[F, ErrorResponse]
  
  val registerEndpoint = endpoint
    .post
    .in("auth" / "register")
    .in(jsonBody[RegisterRequest])
    .out(statusCode(StatusCode.Created).and(jsonBody[AuthResponse]))
    .errorOut(statusCode(StatusCode.BadRequest).and(jsonBody[ErrorResponse]))
    .description("Register a new user")
  
  val loginEndpoint = endpoint
    .post
    .in("auth" / "login")
    .in(jsonBody[LoginRequest])
    .out(jsonBody[AuthResponse])
    .errorOut(statusCode(StatusCode.Unauthorized).and(jsonBody[ErrorResponse]))
    .description("Login with credentials")
  
  val routes: HttpRoutes[F] = HttpRoutes.of[F] {
    case req @ POST -> Root / "auth" / "register" =>
      req.as[RegisterRequest].flatMap { registerReq =>
        userService.createUser(registerReq).flatMap { user =>
          authService.generateToken(user).flatMap { token =>
            Created(AuthResponse(token, user))
          }
        }
      }.handleErrorWith {
        case _: IllegalArgumentException =>
          BadRequest(ErrorResponse("Email already exists"))
        case err =>
          InternalServerError(ErrorResponse(err.getMessage))
      }
    
    case req @ POST -> Root / "auth" / "login" =>
      req.as[LoginRequest].flatMap { loginReq =>
        userService.authenticate(loginReq.email, loginReq.password).flatMap {
          case Some(user) =>
            authService.generateToken(user).flatMap { token =>
              Ok(AuthResponse(token, user))
            }
          case None =>
            Unauthorized(ErrorResponse("Invalid credentials"))
        }
      }
  }
  
  val endpoints = List(registerEndpoint, loginEndpoint)
}`;

    await fs.writeFile(
      path.join(routesDir, 'AuthRoutes.scala'),
      authRoutesContent
    );

    // UserRoutes.scala
    const userRoutesContent = `package ${basePackage}.routes

import cats.effect._
import cats.syntax.all._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe._
import ${basePackage}.models._
import ${basePackage}.services._
import io.circe.generic.auto._
import io.circe.syntax._
import sttp.tapir._
import sttp.tapir.json.circe._
import sttp.tapir.generic.auto._

class UserRoutes[F[_]: Concurrent](
  userService: UserService[F],
  authService: AuthService[F]
) extends Http4sDsl[F] {
  
  implicit val userEncoder: EntityEncoder[F, User] = jsonEncoderOf[F, User]
  implicit val usersEncoder: EntityEncoder[F, List[User]] = jsonEncoderOf[F, List[User]]
  implicit val updateDecoder: EntityDecoder[F, UpdateUserRequest] = jsonOf[F, UpdateUserRequest]
  implicit val errorEncoder: EntityEncoder[F, ErrorResponse] = jsonEncoderOf[F, ErrorResponse]
  
  val auth = auth.bearer[String]()
  
  val getUsersEndpoint = endpoint
    .get
    .in("users")
    .in(query[Option[Int]]("page"))
    .in(query[Option[Int]]("size"))
    .in(auth)
    .out(jsonBody[List[User]])
    .description("Get all users")
  
  val getUserEndpoint = endpoint
    .get
    .in("users" / path[Long]("userId"))
    .in(auth)
    .out(jsonBody[User])
    .errorOut(statusCode(StatusCode.NotFound).and(jsonBody[ErrorResponse]))
    .description("Get user by ID")
  
  val updateUserEndpoint = endpoint
    .put
    .in("users" / path[Long]("userId"))
    .in(auth)
    .in(jsonBody[UpdateUserRequest])
    .out(jsonBody[User])
    .errorOut(statusCode(StatusCode.NotFound).and(jsonBody[ErrorResponse]))
    .description("Update user")
  
  def routes(implicit authUser: AuthedRequest[F, User]): HttpRoutes[F] = HttpRoutes.of[F] {
    case GET -> Root / "users" :? PageQueryParamMatcher(page) +& SizeQueryParamMatcher(size) =>
      userService.listUsers(page.getOrElse(1), size.getOrElse(10)).flatMap { users =>
        Ok(users)
      }
    
    case GET -> Root / "users" / LongVar(userId) =>
      userService.findById(userId).flatMap {
        case Some(user) => Ok(user)
        case None => NotFound(ErrorResponse("User not found"))
      }
    
    case req @ PUT -> Root / "users" / LongVar(userId) =>
      if (authUser.context.id != userId) {
        Forbidden(ErrorResponse("Cannot update other users"))
      } else {
        req.req.as[UpdateUserRequest].flatMap { updateReq =>
          userService.updateUser(userId, updateReq).flatMap { updated =>
            Ok(updated)
          }
        }
      }
    
    case DELETE -> Root / "users" / LongVar(userId) =>
      if (authUser.context.id != userId) {
        Forbidden(ErrorResponse("Cannot delete other users"))
      } else {
        userService.deleteUser(userId).flatMap { _ =>
          NoContent()
        }
      }
  }
  
  val endpoints = List(getUsersEndpoint, getUserEndpoint, updateUserEndpoint)
}

object PageQueryParamMatcher extends OptionalQueryParamDecoderMatcher[Int]("page")
object SizeQueryParamMatcher extends OptionalQueryParamDecoderMatcher[Int]("size")`;

    await fs.writeFile(
      path.join(routesDir, 'UserRoutes.scala'),
      userRoutesContent
    );

    // WebSocketRoutes.scala
    const wsRoutesContent = `package ${basePackage}.routes

import cats.effect._
import cats.syntax.all._
import fs2._
import fs2.concurrent.Queue
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.server.websocket.WebSocketBuilder
import org.http4s.websocket.WebSocketFrame
import io.circe.generic.auto._
import io.circe.syntax._
import io.circe.parser._

class WebSocketRoutes[F[_]: Concurrent] extends Http4sDsl[F] {
  
  case class WsMessage(messageType: String, payload: io.circe.Json)
  
  val routes: HttpRoutes[F] = HttpRoutes.of[F] {
    case GET -> Root / "echo" =>
      val echoRoute = WebSocketBuilder[F].build(
        receive = _.evalMap {
          case WebSocketFrame.Text(text, _) =>
            WebSocketFrame.Text(s"Echo: \$text").pure[F]
          case frame =>
            frame.pure[F]
        },
        send = Stream.empty
      )
      echoRoute
    
    case GET -> Root / "chat" =>
      for {
        queue <- Queue.unbounded[F, WebSocketFrame]
        response <- WebSocketBuilder[F].build(
          receive = _.evalMap {
            case WebSocketFrame.Text(text, _) =>
              decode[WsMessage](text) match {
                case Right(msg) if msg.messageType == "broadcast" =>
                  queue.offer(WebSocketFrame.Text(text))
                case _ =>
                  ().pure[F]
              }
            case _ =>
              ().pure[F]
          },
          send = queue.dequeue
        )
      } yield response
  }
}`;

    await fs.writeFile(
      path.join(routesDir, 'WebSocketRoutes.scala'),
      wsRoutesContent
    );
  }

  private async generateServices(srcDir: string, basePackage: string): Promise<void> {
    const servicesDir = path.join(srcDir, 'services');
    await fs.mkdir(servicesDir, { recursive: true });

    // Services.scala
    const servicesContent = `package ${basePackage}.services

import cats.effect._
import ${basePackage}.repositories._

case class Services[F[_]](
  authService: AuthService[F],
  userService: UserService[F]
)

object Services {
  def make[F[_]: Sync](
    repositories: Repositories[F],
    config: Config
  ): F[Services[F]] = {
    for {
      authService <- AuthService.make[F](config.jwt)
      userService <- UserService.make[F](repositories.userRepository)
    } yield Services(authService, userService)
  }
}`;

    await fs.writeFile(
      path.join(servicesDir, 'Services.scala'),
      servicesContent
    );

    // UserService.scala
    const userServiceContent = `package ${basePackage}.services

import cats.effect._
import cats.syntax.all._
import ${basePackage}.models._
import ${basePackage}.repositories.UserRepository
import org.mindrot.jbcrypt.BCrypt

trait UserService[F[_]] {
  def createUser(request: RegisterRequest): F[User]
  def authenticate(email: String, password: String): F[Option[User]]
  def findById(id: Long): F[Option[User]]
  def listUsers(page: Int, size: Int): F[List[User]]
  def updateUser(id: Long, request: UpdateUserRequest): F[User]
  def deleteUser(id: Long): F[Unit]
}

object UserService {
  def make[F[_]: Sync](userRepository: UserRepository[F]): F[UserService[F]] = {
    Sync[F].pure(new UserService[F] {
      override def createUser(request: RegisterRequest): F[User] = {
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
      
      override def authenticate(email: String, password: String): F[Option[User]] = {
        userRepository.findByEmail(email).map {
          case Some(user) if BCrypt.checkpw(password, user.passwordHash) => Some(user)
          case _ => None
        }
      }
      
      override def findById(id: Long): F[Option[User]] = {
        userRepository.findById(id)
      }
      
      override def listUsers(page: Int, size: Int): F[List[User]] = {
        userRepository.list(offset = (page - 1) * size, limit = size)
      }
      
      override def updateUser(id: Long, request: UpdateUserRequest): F[User] = {
        userRepository.findById(id).flatMap {
          case Some(user) =>
            val updated = user.copy(
              name = request.name.getOrElse(user.name),
              updatedAt = System.currentTimeMillis()
            )
            userRepository.update(updated)
          case None =>
            Sync[F].raiseError(new NoSuchElementException(s"User \$id not found"))
        }
      }
      
      override def deleteUser(id: Long): F[Unit] = {
        userRepository.delete(id)
      }
    })
  }
}`;

    await fs.writeFile(
      path.join(servicesDir, 'UserService.scala'),
      userServiceContent
    );

    // AuthService.scala
    const authServiceContent = `package ${basePackage}.services

import cats.effect._
import cats.syntax.all._
import ${basePackage}.models.User
import ${basePackage}.JwtConfig
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.time.Instant
import scala.util.Try

trait AuthService[F[_]] {
  def generateToken(user: User): F[String]
  def validateToken(token: String): F[Option[Long]]
}

object AuthService {
  def make[F[_]: Sync](config: JwtConfig): F[AuthService[F]] = {
    Sync[F].pure(new AuthService[F] {
      private val algorithm = Algorithm.HMAC256(config.secret)
      
      override def generateToken(user: User): F[String] = {
        Sync[F].delay {
          JWT.create()
            .withSubject(user.id.toString)
            .withClaim("email", user.email)
            .withClaim("name", user.name)
            .withExpiresAt(Instant.now().plusSeconds(config.expiration.toSeconds))
            .withIssuedAt(Instant.now())
            .sign(algorithm)
        }
      }
      
      override def validateToken(token: String): F[Option[Long]] = {
        Sync[F].delay {
          Try {
            val verifier = JWT.require(algorithm).build()
            val decoded = verifier.verify(token)
            decoded.getSubject.toLong
          }.toOption
        }
      }
    })
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

    // Repositories.scala
    const repositoriesContent = `package ${basePackage}.repositories

import cats.effect._
import doobie._
import doobie.implicits._

case class Repositories[F[_]](
  userRepository: UserRepository[F]
)

object Repositories {
  def make[F[_]: Sync](postgres: Transactor[F]): F[Repositories[F]] = {
    for {
      userRepo <- UserRepository.make(postgres)
    } yield Repositories(userRepo)
  }
}`;

    await fs.writeFile(
      path.join(reposDir, 'Repositories.scala'),
      repositoriesContent
    );

    // UserRepository.scala
    const userRepoContent = `package ${basePackage}.repositories

import cats.effect._
import cats.syntax.all._
import doobie._
import doobie.implicits._
import doobie.postgres.implicits._
import ${basePackage}.models._

trait UserRepository[F[_]] {
  def create(user: User): F[User]
  def findById(id: Long): F[Option[User]]
  def findByEmail(email: String): F[Option[User]]
  def list(offset: Int, limit: Int): F[List[User]]
  def update(user: User): F[User]
  def delete(id: Long): F[Unit]
}

object UserRepository {
  def make[F[_]: Sync](postgres: Transactor[F]): F[UserRepository[F]] = {
    Sync[F].pure(new UserRepository[F] {
      
      override def create(user: User): F[User] = {
        sql"""
          INSERT INTO users (email, name, password_hash, created_at, updated_at)
          VALUES (\${user.email}, \${user.name}, \${user.passwordHash}, \${user.createdAt}, \${user.updatedAt})
        """.update
          .withUniqueGeneratedKeys[Long]("id")
          .map(id => user.copy(id = id))
          .transact(postgres)
      }
      
      override def findById(id: Long): F[Option[User]] = {
        sql"""
          SELECT id, email, name, password_hash, created_at, updated_at
          FROM users
          WHERE id = \$id
        """.query[User].option.transact(postgres)
      }
      
      override def findByEmail(email: String): F[Option[User]] = {
        sql"""
          SELECT id, email, name, password_hash, created_at, updated_at
          FROM users
          WHERE email = \$email
        """.query[User].option.transact(postgres)
      }
      
      override def list(offset: Int, limit: Int): F[List[User]] = {
        sql"""
          SELECT id, email, name, password_hash, created_at, updated_at
          FROM users
          ORDER BY created_at DESC
          LIMIT \$limit OFFSET \$offset
        """.query[User].to[List].transact(postgres)
      }
      
      override def update(user: User): F[User] = {
        sql"""
          UPDATE users
          SET email = \${user.email},
              name = \${user.name},
              updated_at = \${user.updatedAt}
          WHERE id = \${user.id}
        """.update.run
          .transact(postgres)
          .map(_ => user)
      }
      
      override def delete(id: Long): F[Unit] = {
        sql"""
          DELETE FROM users WHERE id = \$id
        """.update.run
          .transact(postgres)
          .void
      }
    })
  }
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

import io.circe.generic.semiauto._
import io.circe.{Decoder, Encoder}

// Domain models
case class User(
  id: Long,
  email: String,
  name: String,
  passwordHash: String,
  createdAt: Long,
  updatedAt: Long
)

object User {
  implicit val decoder: Decoder[User] = deriveDecoder[User]
  implicit val encoder: Encoder[User] = deriveEncoder[User]
}

// Request models
case class RegisterRequest(
  email: String,
  name: String,
  password: String
)

object RegisterRequest {
  implicit val decoder: Decoder[RegisterRequest] = deriveDecoder[RegisterRequest]
  implicit val encoder: Encoder[RegisterRequest] = deriveEncoder[RegisterRequest]
}

case class LoginRequest(
  email: String,
  password: String
)

object LoginRequest {
  implicit val decoder: Decoder[LoginRequest] = deriveDecoder[LoginRequest]
  implicit val encoder: Encoder[LoginRequest] = deriveEncoder[LoginRequest]
}

case class UpdateUserRequest(
  name: Option[String] = None
)

object UpdateUserRequest {
  implicit val decoder: Decoder[UpdateUserRequest] = deriveDecoder[UpdateUserRequest]
  implicit val encoder: Encoder[UpdateUserRequest] = deriveEncoder[UpdateUserRequest]
}

// Response models
case class AuthResponse(
  token: String,
  user: User
)

object AuthResponse {
  implicit val decoder: Decoder[AuthResponse] = deriveDecoder[AuthResponse]
  implicit val encoder: Encoder[AuthResponse] = deriveEncoder[AuthResponse]
}

case class ErrorResponse(
  error: String,
  timestamp: Long = System.currentTimeMillis()
)

object ErrorResponse {
  implicit val decoder: Decoder[ErrorResponse] = deriveDecoder[ErrorResponse]
  implicit val encoder: Encoder[ErrorResponse] = deriveEncoder[ErrorResponse]
}`;

    await fs.writeFile(
      path.join(modelsDir, 'Models.scala'),
      modelsContent
    );
  }

  private async generateDatabase(srcDir: string, basePackage: string): Promise<void> {
    // Database configuration is in DatabaseConfig.scala
  }

  private async generateAuth(srcDir: string, basePackage: string): Promise<void> {
    // Auth is implemented in AuthService and middleware
  }

  private async generateMiddleware(srcDir: string, basePackage: string): Promise<void> {
    const middlewareDir = path.join(srcDir, 'middleware');
    await fs.mkdir(middlewareDir, { recursive: true });

    const authMiddlewareContent = `package ${basePackage}.middleware

import cats.data._
import cats.effect._
import cats.syntax.all._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.server.AuthMiddleware
import org.http4s.headers.Authorization
import ${basePackage}.models._
import ${basePackage}.services._

object authMiddleware {
  def apply[F[_]: Sync](authService: AuthService[F]): AuthMiddleware[F, User] = {
    val authUser: Kleisli[OptionT[F, *], Request[F], User] = Kleisli { request =>
      request.headers.get[Authorization] match {
        case Some(Authorization(Credentials.Token(AuthScheme.Bearer, token))) =>
          OptionT(authService.validateToken(token)).flatMap { userId =>
            OptionT(Sync[F].pure(Some(User(
              id = userId,
              email = "",
              name = "",
              passwordHash = "",
              createdAt = 0,
              updatedAt = 0
            ))))
          }
        case _ =>
          OptionT.none
      }
    }
    
    val onFailure: AuthedRoutes[String, F] = Kleisli { _ =>
      OptionT.liftF(Response[F](Status.Unauthorized).pure[F])
    }
    
    AuthMiddleware(authUser, onFailure)
  }
}`;

    await fs.writeFile(
      path.join(middlewareDir, 'AuthMiddleware.scala'),
      authMiddlewareContent
    );

    // ErrorHandler.scala
    const errorHandlerContent = `package ${basePackage}.middleware

import cats.effect._
import cats.syntax.all._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe._
import ${basePackage}.models.ErrorResponse
import io.circe.syntax._
import org.typelevel.log4cats.LoggerFactory

object ErrorHandler {
  def handle[F[_]: Sync: LoggerFactory]: HttpApp[F] => HttpApp[F] = { app =>
    HttpApp[F] { request =>
      app.run(request).handleErrorWith { error =>
        LoggerFactory[F].create.flatMap { logger =>
          logger.error(error)(s"Error handling request: \${request.method} \${request.uri}") *>
          Response[F](
            status = Status.InternalServerError,
            body = EntityEncoder[F, String].toEntity(
              ErrorResponse(error.getMessage).asJson.noSpaces
            ).body
          ).pure[F]
        }
      }
    }
  }
}`;

    await fs.writeFile(
      path.join(middlewareDir, 'ErrorHandler.scala'),
      errorHandlerContent
    );
  }

  private async generateWebSocket(srcDir: string, basePackage: string): Promise<void> {
    // WebSocket implementation is in WebSocketRoutes.scala
  }

  private async generateUtils(srcDir: string, basePackage: string): Promise<void> {
    const utilsDir = path.join(srcDir, 'utils');
    await fs.mkdir(utilsDir, { recursive: true });

    const validationContent = `package ${basePackage}.utils

import cats.data._
import cats.syntax.all._
import eu.timepit.refined._
import eu.timepit.refined.api.Refined
import eu.timepit.refined.string._
import eu.timepit.refined.numeric._

object Validation {
  type Email = String Refined MatchesRegex["^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$"]
  type Password = String Refined MinSize[8]
  type NonEmptyString = String Refined NonEmpty
  
  def validateEmail(email: String): Either[String, Email] = {
    refineV[MatchesRegex["^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$"]](email)
      .leftMap(_ => "Invalid email format")
  }
  
  def validatePassword(password: String): Either[String, Password] = {
    refineV[MinSize[8]](password)
      .leftMap(_ => "Password must be at least 8 characters")
  }
  
  def validateNonEmpty(str: String): Either[String, NonEmptyString] = {
    refineV[NonEmpty](str)
      .leftMap(_ => "Value cannot be empty")
  }
}`;

    await fs.writeFile(
      path.join(utilsDir, 'Validation.scala'),
      validationContent
    );
  }

  private async generateResources(projectPath: string): Promise<void> {
    const resourcesDir = path.join(projectPath, 'src/main/resources');
    await fs.mkdir(resourcesDir, { recursive: true });

    const appConf = `server {
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
  connections = 10
  connections = \${?DB_CONNECTIONS}
}

redis {
  uri = "redis://localhost:6379"
  uri = \${?REDIS_URI}
}

jwt {
  secret = "your-secret-key-here"
  secret = \${?JWT_SECRET}
  expiration = 24 hours
  expiration = \${?JWT_EXPIRATION}
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

    <logger name="org.http4s" level="INFO"/>
    <logger name="doobie" level="INFO"/>
    <logger name="com.example" level="DEBUG"/>

    <root level="INFO">
        <appender-ref ref="STDOUT"/>
    </root>
</configuration>`;

    await fs.writeFile(
      path.join(resourcesDir, 'logback.xml'),
      logbackXml
    );

    // Create db migration directory
    const migrationDir = path.join(resourcesDir, 'db/migration');
    await fs.mkdir(migrationDir, { recursive: true });

    const migration1 = `-- V1__Create_users_table.sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);`;

    await fs.writeFile(
      path.join(migrationDir, 'V1__Create_users_table.sql'),
      migration1
    );
  }

  private async generateTests(projectPath: string, basePackage: string): Promise<void> {
    const testDir = path.join(projectPath, 'src/test/scala', ...basePackage.split('.'));
    await fs.mkdir(testDir, { recursive: true });

    const apiSpecContent = `package ${basePackage}

import cats.effect._
import org.http4s._
import org.http4s.implicits._
import munit.CatsEffectSuite
import ${basePackage}.models._
import ${basePackage}.services._
import io.circe.syntax._
import org.http4s.circe._

class ApiSpec extends CatsEffectSuite {
  
  test("GET /api/v1/health returns 200") {
    val api = new Api[IO](createServices())
    val request = Request[IO](Method.GET, uri"/api/v1/health")
    
    api.httpApp.run(request).map { response =>
      assertEquals(response.status, Status.Ok)
    }
  }
  
  test("POST /api/v1/auth/register creates new user") {
    val api = new Api[IO](createServices())
    val registerRequest = RegisterRequest("test@example.com", "Test User", "password123")
    val request = Request[IO](Method.POST, uri"/api/v1/auth/register")
      .withEntity(registerRequest.asJson)
    
    api.httpApp.run(request).map { response =>
      assertEquals(response.status, Status.Created)
    }
  }
  
  private def createServices(): Services[IO] = {
    // Create mock services for testing
    Services[IO](
      authService = new AuthService[IO] {
        def generateToken(user: User): IO[String] = IO.pure("test-token")
        def validateToken(token: String): IO[Option[Long]] = IO.pure(Some(1L))
      },
      userService = new UserService[IO] {
        def createUser(request: RegisterRequest): IO[User] = IO.pure(
          User(1, request.email, request.name, "hash", 0L, 0L)
        )
        def authenticate(email: String, password: String): IO[Option[User]] = IO.pure(None)
        def findById(id: Long): IO[Option[User]] = IO.pure(None)
        def listUsers(page: Int, size: Int): IO[List[User]] = IO.pure(List.empty)
        def updateUser(id: Long, request: UpdateUserRequest): IO[User] = IO.pure(
          User(id, "test@example.com", "Test", "hash", 0L, 0L)
        )
        def deleteUser(id: Long): IO[Unit] = IO.unit
      }
    )
  }
}`;

    await fs.writeFile(
      path.join(testDir, 'ApiSpec.scala'),
      apiSpecContent
    );
  }
}

export default Http4sGenerator;