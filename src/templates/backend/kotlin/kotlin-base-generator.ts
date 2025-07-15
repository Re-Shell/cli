import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class KotlinBackendGenerator extends BackendTemplateGenerator {
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Kotlin',
      framework,
      packageManager: 'gradle',
      buildTool: 'gradle',
      testFramework: 'JUnit',
      orm: framework === 'Spring Boot' ? 'JPA' : framework === 'Micronaut' ? 'Micronaut Data' : 'Exposed',
      features: [
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
        'dev': './gradlew run',
        'build': './gradlew build',
        'test': './gradlew test',
        'clean': './gradlew clean'
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
    await this.generateGradleConfig(projectPath, options);
    await this.generateDockerfile(projectPath, options);
    await this.generateGitignore(projectPath);
    await this.generateReadme(projectPath, options);
    await this.generateEnvExample(projectPath);
  }

  private async generateGradleConfig(projectPath: string, options: any): Promise<void> {
    const buildGradle = `import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.9.20"
    ${this.getFrameworkPlugins()}
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("io.gitlab.arturbosch.detekt") version "1.23.3"
    id("org.jlleitschuh.gradle.ktlint") version "11.6.1"
}

group = "${options.organization || 'com.example'}"
version = "0.0.1"
java.sourceCompatibility = JavaVersion.VERSION_17

repositories {
    mavenCentral()
    maven { url = uri("https://repo.spring.io/milestone") }
    maven { url = uri("https://repo.spring.io/snapshot") }
}

dependencies {
    ${this.getFrameworkDependencies()}
    
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor:1.7.3")
    
    implementation("io.jsonwebtoken:jjwt-api:0.12.3")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.3")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.3")
    
    implementation("org.postgresql:postgresql:42.6.0")
    implementation("com.zaxxer:HikariCP:5.0.1")
    implementation("redis.clients:jedis:5.0.2")
    
    implementation("io.micrometer:micrometer-registry-prometheus:1.11.5")
    implementation("ch.qos.logback:logback-classic:1.4.11")
    implementation("net.logstash.logback:logstash-logback-encoder:7.4")
    
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    testImplementation("io.mockk:mockk:1.13.8")
    testImplementation("org.testcontainers:testcontainers:1.19.1")
    testImplementation("org.testcontainers:postgresql:1.19.1")
    testImplementation("org.testcontainers:junit-jupiter:1.19.1")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs = listOf("-Xjsr305=strict")
        jvmTarget = "17"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

${this.getFrameworkTasks()}

detekt {
    buildUponDefaultConfig = true
    allRules = false
    config.setFrom("$projectDir/detekt.yml")
}`;

    await fs.writeFile(
      path.join(projectPath, 'build.gradle.kts'),
      buildGradle
    );

    const settingsGradle = `rootProject.name = "${options.name}"`;
    await fs.writeFile(
      path.join(projectPath, 'settings.gradle.kts'),
      settingsGradle
    );

    const gradleProperties = `kotlin.code.style=official
org.gradle.jvmargs=-Xmx2048m -XX:MaxPermSize=512m -XX:+HeapDumpOnOutOfMemoryError -Dfile.encoding=UTF-8
org.gradle.parallel=true
org.gradle.caching=true
kotlin.incremental=true`;
    
    await fs.writeFile(
      path.join(projectPath, 'gradle.properties'),
      gradleProperties
    );
  }

  protected abstract getFrameworkPlugins(): string;
  protected abstract getFrameworkDependencies(): string;
  protected abstract getFrameworkTasks(): string;

  // Implement abstract methods from BackendTemplateGenerator
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Kotlin language files are generated in generateBaseFiles
    await this.generateBaseFiles(projectPath, options);
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    const testDir = path.join(projectPath, 'src/test/kotlin');
    await fs.mkdir(testDir, { recursive: true });
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check endpoints are implemented in framework-specific files
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are configured in framework-specific files (Swagger/OpenAPI)
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    await this.generateDockerfile(projectPath, options);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    await this.generateReadme(projectPath, options);
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '.gradle',
      'build/',
      '*.class',
      '*.jar',
      '*.war',
      '.idea',
      '*.iml',
      'out/',
      '.kotlin_cache'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'JDK 17+, Gradle 8+';
  }

  protected getInstallCommand(): string {
    return './gradlew dependencies';
  }

  protected getDevCommand(): string {
    return './gradlew run';
  }

  protected getProdCommand(): string {
    return 'java -jar build/libs/*.jar';
  }

  protected getTestCommand(): string {
    return './gradlew test';
  }

  protected getCoverageCommand(): string {
    return './gradlew test jacocoTestReport';
  }

  protected getLintCommand(): string {
    return './gradlew ktlintCheck';
  }

  protected getBuildCommand(): string {
    return './gradlew build';
  }

  protected getSetupAction(): string {
    return './gradlew clean build';
  }

  private async generateDockerfile(projectPath: string, options: any): Promise<void> {
    const dockerfile = `FROM gradle:8.4-jdk17 AS build
WORKDIR /app
COPY gradle gradle
COPY build.gradle.kts settings.gradle.kts gradlew ./
COPY src src
RUN gradle shadowJar --no-daemon

FROM eclipse-temurin:17-jre-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar
EXPOSE ${options.port || 8080}
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \\
  CMD curl -f http://localhost:${options.port || 8080}/health || exit 1
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]`;

    await fs.writeFile(
      path.join(projectPath, 'Dockerfile'),
      dockerfile
    );
  }

  protected async generateGitignore(projectPath: string): Promise<void> {
    const gitignore = `.gradle
build/
!gradle/wrapper/gradle-wrapper.jar
!**/src/main/**/build/
!**/src/test/**/build/
.idea
*.iws
*.iml
*.ipr
out/
!**/src/main/**/out/
!**/src/test/**/out/
.vscode/
/src/main/resources/application-local.yml
/src/main/resources/application-local.properties
.DS_Store
*.log
.env
target/
pom.xml.tag
pom.xml.releaseBackup
pom.xml.versionsBackup
pom.xml.next
release.properties
dependency-reduced-pom.xml
buildNumber.properties
.mvn/timing.properties
.mvn/wrapper/maven-wrapper.jar`;

    await fs.writeFile(
      path.join(projectPath, '.gitignore'),
      gitignore
    );
  }

  protected async generateReadme(projectPath: string, options: any): Promise<void> {
    const readme = `# ${options.name}

## ${this.config.framework} Backend Service

### Prerequisites
- JDK 17+
- Docker & Docker Compose
- PostgreSQL 14+
- Redis 6+

### Development
\`\`\`bash
./gradlew run
\`\`\`

### Testing
\`\`\`bash
./gradlew test
./gradlew integrationTest
\`\`\`

### Building
\`\`\`bash
./gradlew build
./gradlew shadowJar
\`\`\`

### Docker
\`\`\`bash
docker build -t ${options.name} .
docker run -p ${options.port || 8080}:${options.port || 8080} ${options.name}
\`\`\`

### API Documentation
- Swagger UI: http://localhost:${options.port || 8080}/swagger-ui
- OpenAPI Spec: http://localhost:${options.port || 8080}/v3/api-docs

### Health Check
- http://localhost:${options.port || 8080}/health
- http://localhost:${options.port || 8080}/metrics

### Environment Variables
See \`.env.example\` for required configuration.`;

    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readme
    );
  }

  private async generateEnvExample(projectPath: string): Promise<void> {
    const envExample = `PORT=8080
ENVIRONMENT=development
DB_HOST=localhost
DB_PORT=5432
DB_NAME=app_db
DB_USER=postgres
DB_PASSWORD=postgres
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET=your-secret-key-here
JWT_EXPIRATION=86400
LOG_LEVEL=INFO
CORS_ORIGINS=http://localhost:3000`;

    await fs.writeFile(
      path.join(projectPath, '.env.example'),
      envExample
    );
  }
}