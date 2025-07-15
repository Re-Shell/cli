import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class ScalaBackendGenerator extends BackendTemplateGenerator {
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Scala',
      framework,
      packageManager: 'sbt',
      buildTool: 'sbt',
      testFramework: 'ScalaTest',
      orm: framework === 'Play' ? 'Slick' : framework === 'http4s' ? 'Doobie' : 'Slick',
      features: [
        'functional-programming',
        'type-safety',
        'async-await',
        'websocket',
        'graphql',
        'grpc',
        'swagger',
        'health-check',
        'rate-limiting',
        'compression',
        'security-headers',
        'authentication',
        'authorization',
        'database',
        'caching',
        'docker',
        'kubernetes',
        'monitoring'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'dev': 'sbt ~reStart',
        'build': 'sbt compile',
        'test': 'sbt test',
        'clean': 'sbt clean',
        'package': 'sbt assembly'
      }
    };
    
    super(config);
  }

  async generate(projectPath: string, options: any): Promise<void> {
    await super.generate(projectPath, options);
    await this.generateBaseFiles(projectPath, options);
    await this.generateFrameworkFiles(projectPath, options);
  }

  protected abstract generateFrameworkFiles(projectPath: string, options: any): Promise<void>;

  private async generateBaseFiles(projectPath: string, options: any): Promise<void> {
    await this.generateSbtConfig(projectPath, options);
    await this.generateProjectConfig(projectPath);
    await this.generateScalafmtConfig(projectPath);
    await this.generateDockerfile(projectPath, options);
    await this.generateGitignore(projectPath);
    await this.generateReadme(projectPath, options);
    await this.generateEnvExample(projectPath);
  }

  private async generateSbtConfig(projectPath: string, options: any): Promise<void> {
    const buildSbt = `import Dependencies._

ThisBuild / scalaVersion := "2.13.12"
ThisBuild / version := "0.1.0"
ThisBuild / organization := "${options.organization || 'com.example'}"
ThisBuild / organizationName := "${options.organizationName || 'Example'}"

lazy val root = (project in file("."))
  .settings(
    name := "${options.name}",
    ${this.getFrameworkSettings()},
    libraryDependencies ++= Seq(
      ${this.getFrameworkDependencies()}
    ),
    scalacOptions ++= Seq(
      "-deprecation",
      "-encoding", "UTF-8",
      "-language:higherKinds",
      "-language:postfixOps",
      "-feature",
      "-Xfatal-warnings",
      "-Xlint",
      "-Ywarn-dead-code",
      "-Ywarn-numeric-widen",
      "-Ywarn-value-discard",
      "-Ywarn-unused"
    ),
    testFrameworks += new TestFramework("scalatest.Framework"),
    assembly / assemblyMergeStrategy := {
      case PathList("META-INF", xs @ _*) => MergeStrategy.discard
      case x => MergeStrategy.first
    },
    assembly / mainClass := Some("${options.organization || 'com.example'}.Main"),
    assembly / assemblyJarName := "${options.name}.jar"
  )

// Enable hot reloading
addCommandAlias("dev", "~reStart")

// Docker settings
enablePlugins(JavaAppPackaging)
enablePlugins(DockerPlugin)
dockerBaseImage := "openjdk:11-jre-slim"
dockerExposedPorts := Seq(${options.port || 8080})
`;

    await fs.writeFile(
      path.join(projectPath, 'build.sbt'),
      buildSbt
    );

    // Dependencies.scala
    const dependenciesScala = `import sbt._

object Dependencies {
  // Versions
  val akkaHttpVersion = "10.5.3"
  val akkaVersion = "2.8.5"
  val circeVersion = "0.14.6"
  val slickVersion = "3.4.1"
  val doobieVersion = "1.0.0-RC4"
  val http4sVersion = "0.23.23"
  val catsVersion = "2.10.0"
  val scalaTestVersion = "3.2.17"
  val logbackVersion = "1.4.11"
  val jwtVersion = "9.4.4"
  val postgresVersion = "42.6.0"
  val redisVersion = "5.0.2"
  val prometheusVersion = "0.16.0"
  
  // Libraries
  val scalaTest = "org.scalatest" %% "scalatest" % scalaTestVersion % Test
  val scalaCheck = "org.scalacheck" %% "scalacheck" % "1.17.0" % Test
  val logback = "ch.qos.logback" % "logback-classic" % logbackVersion
  val scalaLogging = "com.typesafe.scala-logging" %% "scala-logging" % "3.9.5"
  val config = "com.typesafe" % "config" % "1.4.2"
  
  // Database
  val postgresql = "org.postgresql" % "postgresql" % postgresVersion
  val hikariCP = "com.zaxxer" % "HikariCP" % "5.0.1"
  
  // Redis
  val jedis = "redis.clients" % "jedis" % redisVersion
  
  // JWT
  val jwtScala = "com.github.jwt-scala" %% "jwt-core" % jwtVersion
  
  // Metrics
  val prometheusClient = "io.prometheus" % "simpleclient" % prometheusVersion
  val prometheusHotspot = "io.prometheus" % "simpleclient_hotspot" % prometheusVersion
  val prometheusHttpserver = "io.prometheus" % "simpleclient_httpserver" % prometheusVersion
}
`;

    const projectDir = path.join(projectPath, 'project');
    await fs.mkdir(projectDir, { recursive: true });
    
    await fs.writeFile(
      path.join(projectDir, 'Dependencies.scala'),
      dependenciesScala
    );
  }

  protected abstract getFrameworkSettings(): string;
  protected abstract getFrameworkDependencies(): string;

  private async generateProjectConfig(projectPath: string): Promise<void> {
    const projectDir = path.join(projectPath, 'project');
    await fs.mkdir(projectDir, { recursive: true });

    // build.properties
    const buildProperties = `sbt.version=1.9.7`;
    await fs.writeFile(
      path.join(projectDir, 'build.properties'),
      buildProperties
    );

    // plugins.sbt
    const pluginsSbt = `addSbtPlugin("com.github.sbt" % "sbt-native-packager" % "1.9.16")
addSbtPlugin("io.spray" % "sbt-revolver" % "0.10.0")
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "2.1.5")
addSbtPlugin("org.scalameta" % "sbt-scalafmt" % "2.5.2")
addSbtPlugin("org.scoverage" % "sbt-scoverage" % "2.0.9")
addSbtPlugin("ch.epfl.scala" % "sbt-scalafix" % "0.11.1")
addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.6.4")
addSbtPlugin("net.virtual-void" % "sbt-dependency-graph" % "0.10.0-RC1")
${this.getFrameworkPlugins()}`;

    await fs.writeFile(
      path.join(projectDir, 'plugins.sbt'),
      pluginsSbt
    );
  }

  protected abstract getFrameworkPlugins(): string;

  private async generateScalafmtConfig(projectPath: string): Promise<void> {
    const scalafmtConf = `version = 3.7.15
runner.dialect = scala213

maxColumn = 120
align.preset = more
align.stripMargin = true

rewrite.rules = [
  RedundantBraces,
  RedundantParens,
  SortImports,
  PreferCurlyFors,
  SortModifiers
]

spaces.inImportCurlyBraces = true
includeNoParensInSelectChains = true
optIn.breakChainOnFirstMethodDot = true

newlines.source = keep
newlines.beforeCurlyLambdaParams = multilineWithCaseOnly
newlines.afterCurlyLambdaParams = squash`;

    await fs.writeFile(
      path.join(projectPath, '.scalafmt.conf'),
      scalafmtConf
    );
  }

  // Implement abstract methods from BackendTemplateGenerator
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Scala language files are generated in generateBaseFiles
    await this.generateBaseFiles(projectPath, options);
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    const testDir = path.join(projectPath, 'src/test/scala');
    await fs.mkdir(testDir, { recursive: true });
    
    const testResourcesDir = path.join(projectPath, 'src/test/resources');
    await fs.mkdir(testResourcesDir, { recursive: true });
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check endpoints are implemented in framework-specific files
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are configured in framework-specific files (Swagger/OpenAPI)
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    await this.generateDockerfile(projectPath, options);
    await this.generateDockerCompose(projectPath, options);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    await this.generateReadme(projectPath, options);
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      'target/',
      'project/target/',
      'project/project/',
      '.bsp/',
      '.idea/',
      '*.class',
      '*.log',
      '.metals/',
      '.bloop/',
      'metals.sbt',
      '.vscode/',
      '*.jar'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'JDK 11+, Scala 2.13+, SBT 1.9+';
  }

  protected getInstallCommand(): string {
    return 'sbt compile';
  }

  protected getDevCommand(): string {
    return 'sbt ~reStart';
  }

  protected getProdCommand(): string {
    return 'java -jar target/scala-2.13/*.jar';
  }

  protected getTestCommand(): string {
    return 'sbt test';
  }

  protected getCoverageCommand(): string {
    return 'sbt coverage test coverageReport';
  }

  protected getLintCommand(): string {
    return 'sbt scalafmtCheck';
  }

  protected getBuildCommand(): string {
    return 'sbt assembly';
  }

  protected getSetupAction(): string {
    return 'sbt clean compile';
  }

  private async generateDockerfile(projectPath: string, options: any): Promise<void> {
    const dockerfile = `FROM hseeberger/scala-sbt:11.0.20.1_1.9.7_2.13.12 AS build
WORKDIR /app
COPY build.sbt .
COPY project project
RUN sbt update
COPY . .
RUN sbt assembly

FROM openjdk:11-jre-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/scala-2.13/${options.name}.jar app.jar
EXPOSE ${options.port || 8080}
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \\
  CMD curl -f http://localhost:${options.port || 8080}/health || exit 1
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]`;

    await fs.writeFile(
      path.join(projectPath, 'Dockerfile'),
      dockerfile
    );
  }

  private async generateDockerCompose(projectPath: string, options: any): Promise<void> {
    const dockerCompose = `version: '3.8'

services:
  app:
    build: .
    ports:
      - "${options.port || 8080}:${options.port || 8080}"
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_NAME=${options.name}_db
      - DB_USER=postgres
      - DB_PASSWORD=postgres
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - LOG_LEVEL=INFO
    depends_on:
      - postgres
      - redis
    networks:
      - app-network

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=${options.name}_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - app-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - app-network

volumes:
  postgres-data:

networks:
  app-network:
    driver: bridge`;

    await fs.writeFile(
      path.join(projectPath, 'docker-compose.yml'),
      dockerCompose
    );
  }

  protected async generateGitignore(projectPath: string): Promise<void> {
    const gitignore = `.bsp/
target/
project/target/
project/project/
.idea/
.idea_modules/
*.class
*.log
.cache
.history
.lib/
dist/*
lib_managed/
src_managed/
.scala_dependencies
.worksheet
.metals/
.bloop/
metals.sbt
.vscode/
*.jar
.DS_Store
.env
node_modules/`;

    await fs.writeFile(
      path.join(projectPath, '.gitignore'),
      gitignore
    );
  }

  protected async generateReadme(projectPath: string, options: any): Promise<void> {
    const readme = `# ${options.name}

## ${this.config.framework} Backend Service

### Prerequisites
- JDK 11+
- Scala 2.13+
- SBT 1.9+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Development
\`\`\`bash
# Install dependencies
sbt compile

# Run with hot reload
sbt ~reStart

# Run tests
sbt test

# Run with coverage
sbt coverage test coverageReport
\`\`\`

### Building
\`\`\`bash
# Create assembly JAR
sbt assembly

# Build Docker image
docker build -t ${options.name} .
\`\`\`

### Running
\`\`\`bash
# Run with SBT
sbt run

# Run JAR
java -jar target/scala-2.13/${options.name}.jar

# Run with Docker
docker run -p ${options.port || 8080}:${options.port || 8080} ${options.name}

# Run with Docker Compose
docker-compose up
\`\`\`

### API Documentation
- Swagger UI: http://localhost:${options.port || 8080}/docs
- OpenAPI Spec: http://localhost:${options.port || 8080}/api-docs

### Health & Metrics
- Health Check: http://localhost:${options.port || 8080}/health
- Prometheus Metrics: http://localhost:${options.port || 8080}/metrics

### Configuration
Application configuration is managed through \`application.conf\` using Typesafe Config.
Environment variables can override configuration values.

### Testing
\`\`\`bash
# Run all tests
sbt test

# Run specific test
sbt "testOnly *UserServiceSpec"

# Run integration tests
sbt "it:test"
\`\`\`

### Code Quality
\`\`\`bash
# Format code
sbt scalafmt

# Check formatting
sbt scalafmtCheck

# Run scalafix
sbt "scalafix RemoveUnused"

# Check dependencies
sbt dependencyUpdates
\`\`\``;

    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readme
    );
  }

  private async generateEnvExample(projectPath: string): Promise<void> {
    const envExample = `# Application
APP_ENV=development
APP_PORT=8080
LOG_LEVEL=INFO

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=app_db
DB_USER=postgres
DB_PASSWORD=postgres
DB_POOL_SIZE=10

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT
JWT_SECRET=your-secret-key-here
JWT_EXPIRATION=3600

# External Services
API_KEY=your-api-key
SERVICE_URL=http://localhost:9000

# Monitoring
METRICS_ENABLED=true
PROMETHEUS_PORT=9090`;

    await fs.writeFile(
      path.join(projectPath, '.env.example'),
      envExample
    );
  }
}