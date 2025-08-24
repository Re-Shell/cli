import { BackendTemplate } from '../types';

export const clojureReititTemplate: BackendTemplate = {
  id: 'clojure-reitit',
  name: 'clojure-reitit',
  displayName: 'Clojure Reitit Data-Driven Router',
  description: 'High-performance data-driven router for Clojure with schema validation, middleware composition, and OpenAPI support',
  framework: 'reitit',
  language: 'clojure',
  version: '0.6.0',
  author: 'Re-Shell Team',


  icon: '🗺️',
  type: 'rest-api',
  complexity: 'intermediate',
  keywords: ['clojure', 'reitit', 'router', 'data-driven', 'schema', 'middleware', 'openapi'],
  
  features: [
    'Data-driven routing',
    'Schema validation',
    'Middleware composition',
    'OpenAPI/Swagger support',
    'High performance',
    'Bidirectional routing',
    'Route compilation',
    'Interceptor support',
    'Coercion and validation',
    'Documentation generation',
    'Ring compatibility',
    'ClojureScript support',
    'Development tools',
    'Type safety'
  ],
  
  structure: {
    'project.clj': `(defproject reitit-app "0.1.0-SNAPSHOT"
  :description "A Clojure web application using Reitit router"
  :url "http://example.com"
  :min-lein-version "2.0.0"
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [metosin/reitit "0.6.0"]
                 [metosin/reitit-ring "0.6.0"]
                 [metosin/reitit-http "0.6.0"]
                 [metosin/reitit-middleware "0.6.0"]
                 [metosin/reitit-spec "0.6.0"]
                 [metosin/reitit-swagger "0.6.0"]
                 [metosin/reitit-swagger-ui "0.6.0"]
                 [metosin/reitit-dev "0.6.0"]
                 [metosin/malli "0.10.1"]
                 [metosin/muuntaja "0.6.8"]
                 [metosin/ring-http-response "0.9.3"]
                 [ring/ring-core "1.9.6"]
                 [ring/ring-jetty-adapter "1.9.6"]
                 [ring/ring-json "0.5.1"]
                 [ring/ring-cors "0.1.13"]
                 [buddy/buddy-auth "3.0.323"]
                 [buddy/buddy-hashers "1.8.158"]
                 [buddy/buddy-sign "3.4.333"]
                 [cheshire "5.11.0"]
                 [com.stuartsierra/component "1.1.0"]
                 [environ "1.2.0"]
                 [org.clojure/tools.logging "1.2.4"]
                 [ch.qos.logback/logback-classic "1.4.5"]
                 [org.clojure/java.jdbc "0.7.12"]
                 [org.postgresql/postgresql "42.5.1"]
                 [clj-time "0.15.2"]]
  :plugins [[lein-ring "0.12.6"]
            [lein-environ "1.2.0"]]
  :ring {:handler reitit-app.core/app}
  :profiles
  {:dev {:dependencies [[ring/ring-mock "0.4.0"]
                        [midje "1.10.4"]]
         :plugins [[lein-midje "3.2.1"]]}
   :uberjar {:aot :all}})`,

    'src/reitit_app/core.clj': `(ns reitit-app.core
  (:require [reitit.ring :as ring]
            [reitit.ring.middleware.muuntaja :as muuntaja]
            [reitit.ring.middleware.parameters :as parameters]
            [reitit.ring.middleware.multipart :as multipart]
            [reitit.ring.middleware.exception :as exception]
            [reitit.ring.coercion :as coercion]
            [reitit.coercion.malli]
            [reitit.swagger :as swagger]
            [reitit.swagger-ui :as swagger-ui]
            [reitit.dev.pretty :as pretty]
            [ring.adapter.jetty :as jetty]
            [ring.middleware.cors :refer [wrap-cors]]
            [muuntaja.core :as m]
            [malli.core :as malli]
            [environ.core :refer [env]]
            [clojure.tools.logging :as log]
            [reitit-app.handlers.users :as users]
            [reitit-app.handlers.auth :as auth]
            [reitit-app.handlers.health :as health]
            [reitit-app.middleware.auth :as auth-middleware]
            [reitit-app.db.core :as db])
  (:gen-class))

;; Malli schemas for validation
(def User
  [:map
   [:id :int]
   [:name :string]
   [:email [:re #".+@.+\..+"]]
   [:created-at :string]])

(def CreateUserRequest
  [:map
   [:name [:string {:min 1 :max 100}]]
   [:email [:re #".+@.+\..+"]]
   [:password [:string {:min 6}]]])

(def LoginRequest
  [:map
   [:email [:re #".+@.+\..+"]]
   [:password [:string {:min 1}]]])

;; Exception handling
(defn exception-handler [message exception request]
  (log/error exception message)
  {:status 500
   :body {:error "Internal server error"}})

;; Routes definition
(def routes
  [["/api"
    {:middleware [muuntaja/format-middleware
                  parameters/parameters-middleware
                  multipart/multipart-middleware
                  coercion/coerce-exceptions-middleware
                  coercion/coerce-request-middleware
                  coercion/coerce-response-middleware]}
    
    ;; Health check
    ["/health"
     {:get {:summary "Health check endpoint"
            :responses {200 {:body [:map [:status :string]]}}
            :handler health/health-check}}]
    
    ;; Authentication
    ["/auth"
     ["/login"
      {:post {:summary "User login"
              :parameters {:body LoginRequest}
              :responses {200 {:body [:map [:token :string]]}
                         401 {:body [:map [:error :string]]}}
              :handler auth/login}}]
     
     ["/register"
      {:post {:summary "User registration"
              :parameters {:body CreateUserRequest}
              :responses {201 {:body User}
                         400 {:body [:map [:error :string]]}}
              :handler auth/register}}]]
    
    ;; Users (protected routes)
    ["/users"
     {:middleware [auth-middleware/wrap-auth]}
     
     ["" 
      {:get {:summary "Get all users"
             :responses {200 {:body [:vector User]}}
             :handler users/get-users}
       :post {:summary "Create user"
              :parameters {:body CreateUserRequest}
              :responses {201 {:body User}}
              :handler users/create-user}}]
     
     ["/:id"
      {:get {:summary "Get user by ID"
             :parameters {:path [:map [:id :int]]}
             :responses {200 {:body User}
                        404 {:body [:map [:error :string]]}}
             :handler users/get-user}
       :put {:summary "Update user"
             :parameters {:path [:map [:id :int]]
                         :body [:map [:name {:optional true} :string]
                                     [:email {:optional true} [:re #".+@.+\..+"]]]}
             :responses {200 {:body User}
                        404 {:body [:map [:error :string]]}}
             :handler users/update-user}
       :delete {:summary "Delete user"
                :parameters {:path [:map [:id :int]]}
                :responses {204 {:body nil}
                           404 {:body [:map [:error :string]]}}
                :handler users/delete-user}}]]]
   
   ;; Swagger documentation
   ["/swagger.json"
    {:get {:no-doc true
           :swagger {:info {:title "Reitit API"
                           :description "REST API built with Reitit"
                           :version "1.0.0"}}
           :handler (swagger/create-swagger-handler)}}]
   
   ;; Swagger UI
   ["/swagger-ui/*"
    {:get {:no-doc true
           :handler (swagger-ui/create-swagger-ui-handler
                     {:url "/swagger.json"
                      :config {:validatorUrl nil}})}}]])

;; Application setup
(def app
  (ring/ring-handler
    (ring/router
      routes
      {:exception pretty/exception
       :data {:coercion reitit.coercion.malli/coercion
              :muuntaja m/instance
              :middleware [;; swagger feature
                          swagger/swagger-feature
                          ;; query-params & form-params
                          parameters/parameters-middleware
                          ;; content-negotiation
                          muuntaja/format-negotiate-middleware
                          ;; encoding response body
                          muuntaja/format-response-middleware
                          ;; exception handling
                          exception/exception-middleware
                          ;; decoding request body
                          muuntaja/format-request-middleware
                          ;; coercing response bodys
                          coercion/coerce-response-middleware
                          ;; coercing request parameters
                          coercion/coerce-request-middleware
                          ;; multipart
                          multipart/multipart-middleware]}})
    (ring/routes
      (ring/create-resource-handler {:path "/" :root "public"})
      (ring/create-default-handler))
    {:middleware [[wrap-cors
                   :access-control-allow-origin [#".*"]
                   :access-control-allow-methods [:get :put :post :delete]]]}))

;; Server startup
(defn get-port []
  (Integer. (or (env :port) 3000)))

(defn -main [& args]
  (let [port (get-port)]
    (log/info (str "Starting Reitit server on port " port))
    (jetty/run-jetty app {:port port :join? false})))`,

    'src/reitit_app/handlers/users.clj': `(ns reitit-app.handlers.users
  (:require [ring.util.http-response :as response]
            [reitit-app.db.core :as db]
            [clojure.tools.logging :as log]
            [clj-time.core :as time]
            [clj-time.format :as format]))

(defn get-users [request]
  (try
    (let [users (db/get-all-users)]
      (response/ok users))
    (catch Exception e
      (log/error e "Error getting users")
      (response/internal-server-error {:error "Failed to get users"}))))

(defn get-user [request]
  (try
    (let [user-id (get-in request [:path-params :id])
          user (db/get-user-by-id user-id)]
      (if user
        (response/ok user)
        (response/not-found {:error "User not found"})))
    (catch Exception e
      (log/error e "Error getting user")
      (response/internal-server-error {:error "Failed to get user"}))))

(defn create-user [request]
  (try
    (let [user-data (get-in request [:body-params])
          now (format/unparse (format/formatters :date-time) (time/now))
          user-with-timestamp (assoc user-data :created-at now)
          created-user (db/create-user user-with-timestamp)]
      (response/created created-user))
    (catch Exception e
      (log/error e "Error creating user")
      (response/internal-server-error {:error "Failed to create user"}))))

(defn update-user [request]
  (try
    (let [user-id (get-in request [:path-params :id])
          user-data (get-in request [:body-params])
          existing-user (db/get-user-by-id user-id)]
      (if existing-user
        (let [updated-user (db/update-user user-id user-data)]
          (response/ok updated-user))
        (response/not-found {:error "User not found"})))
    (catch Exception e
      (log/error e "Error updating user")
      (response/internal-server-error {:error "Failed to update user"}))))

(defn delete-user [request]
  (try
    (let [user-id (get-in request [:path-params :id])
          existing-user (db/get-user-by-id user-id)]
      (if existing-user
        (do
          (db/delete-user user-id)
          (response/no-content))
        (response/not-found {:error "User not found"})))
    (catch Exception e
      (log/error e "Error deleting user")
      (response/internal-server-error {:error "Failed to delete user"}))))`,

    'src/reitit_app/handlers/auth.clj': `(ns reitit-app.handlers.auth
  (:require [ring.util.http-response :as response]
            [buddy.hashers :as hashers]
            [buddy.sign.jwt :as jwt]
            [reitit-app.db.core :as db]
            [clojure.tools.logging :as log]
            [clj-time.core :as time]
            [clj-time.format :as format]
            [environ.core :refer [env]]))

(def jwt-secret (or (env :jwt-secret) "your-super-secret-key"))

(defn generate-token [user]
  (let [exp (time/plus (time/now) (time/hours 24))]
    (jwt/sign {:user-id (:id user)
               :email (:email user)
               :exp (time/to-long exp)}
              jwt-secret)))

(defn login [request]
  (try
    (let [{:keys [email password]} (get-in request [:body-params])
          user (db/get-user-by-email email)]
      (if (and user (hashers/check password (:password user)))
        (let [token (generate-token user)]
          (response/ok {:token token}))
        (response/unauthorized {:error "Invalid credentials"})))
    (catch Exception e
      (log/error e "Error during login")
      (response/internal-server-error {:error "Login failed"}))))

(defn register [request]
  (try
    (let [{:keys [name email password]} (get-in request [:body-params])
          existing-user (db/get-user-by-email email)]
      (if existing-user
        (response/bad-request {:error "User already exists"})
        (let [hashed-password (hashers/derive password)
              now (format/unparse (format/formatters :date-time) (time/now))
              user-data {:name name
                        :email email
                        :password hashed-password
                        :created-at now}
              created-user (db/create-user user-data)
              user-response (dissoc created-user :password)]
          (response/created user-response))))
    (catch Exception e
      (log/error e "Error during registration")
      (response/internal-server-error {:error "Registration failed"}))))`,

    'src/reitit_app/handlers/health.clj': `(ns reitit-app.handlers.health
  (:require [ring.util.http-response :as response]
            [reitit-app.db.core :as db]
            [clojure.tools.logging :as log]))

(defn health-check [request]
  (try
    ;; Check database connection
    (db/health-check)
    
    (response/ok {:status "ok"
                  :timestamp (str (java.time.Instant/now))
                  :service "reitit-app"
                  :version "1.0.0"})
    (catch Exception e
      (log/error e "Health check failed")
      (response/service-unavailable {:status "error"
                                    :error "Service unavailable"}))))`,

    'src/reitit_app/middleware/auth.clj': `(ns reitit-app.middleware.auth
  (:require [buddy.auth :refer [authenticated?]]
            [buddy.auth.backends.token :refer [jws-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]
            [buddy.sign.jwt :as jwt]
            [ring.util.http-response :as response]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]))

(def jwt-secret (or (env :jwt-secret) "your-super-secret-key"))

(defn token-authfn [request token]
  (try
    (jwt/unsign token jwt-secret)
    (catch Exception e
      (log/warn "Invalid token:" (.getMessage e))
      false)))

(def auth-backend (jws-backend {:secret jwt-secret
                                :token-name "Bearer"
                                :authfn token-authfn}))

(defn unauthorized-handler [request metadata]
  (response/unauthorized {:error "Unauthorized"}))

(defn wrap-auth [handler]
  (-> handler
      (wrap-authentication auth-backend)
      (wrap-authorization auth-backend)))

(defn authenticated-user [request]
  (:identity request))`,

    'src/reitit_app/db/core.clj': `(ns reitit-app.db.core
  (:require [clojure.java.jdbc :as jdbc]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]))

;; Database configuration
(def db-spec {:classname "org.postgresql.Driver"
              :subprotocol "postgresql"
              :subname (or (env :database-url) "//localhost:5432/reitit_app")
              :user (or (env :database-user) "postgres")
              :password (or (env :database-password) "postgres")})

;; In-memory storage for demo (replace with real database)
(def users-store (atom {}))
(def user-counter (atom 0))

;; Database operations
(defn health-check []
  ;; Simple health check - in production, check actual database
  true)

(defn get-all-users []
  (vals @users-store))

(defn get-user-by-id [id]
  (get @users-store id))

(defn get-user-by-email [email]
  (first (filter #(= (:email %) email) (vals @users-store))))

(defn create-user [user-data]
  (let [id (swap! user-counter inc)
        user (assoc user-data :id id)]
    (swap! users-store assoc id user)
    user))

(defn update-user [id user-data]
  (when-let [existing-user (get @users-store id)]
    (let [updated-user (merge existing-user user-data)]
      (swap! users-store assoc id updated-user)
      updated-user)))

(defn delete-user [id]
  (swap! users-store dissoc id)
  true)

;; Initialize with sample data
(defn init-db []
  (reset! users-store {})
  (reset! user-counter 0)
  (create-user {:name "John Doe"
                :email "john@example.com"
                :password "$2a$10$example.hash"
                :created-at "2024-01-01T12:00:00Z"})
  (create-user {:name "Jane Smith"
                :email "jane@example.com"
                :password "$2a$10$example.hash"
                :created-at "2024-01-01T12:00:00Z"})
  (log/info "Database initialized with sample data"))

;; Initialize on namespace load
(init-db)`,

    'resources/logback.xml': `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/app.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/app.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <root level="INFO">
        <appender-ref ref="STDOUT" />
        <appender-ref ref="FILE" />
    </root>
</configuration>`,

    'test/reitit_app/core_test.clj': `(ns reitit-app.core-test
  (:require [clojure.test :refer :all]
            [ring.mock.request :as mock]
            [reitit-app.core :refer [app]]
            [cheshire.core :as json]))

(deftest test-health-endpoint
  (testing "health check endpoint"
    (let [response (app (mock/request :get "/api/health"))]
      (is (= 200 (:status response)))
      (is (= "ok" (get-in (json/parse-string (:body response) true) [:status]))))))

(deftest test-swagger-endpoint
  (testing "swagger documentation endpoint"
    (let [response (app (mock/request :get "/swagger.json"))]
      (is (= 200 (:status response)))
      (is (string? (:body response))))))

(deftest test-users-endpoint
  (testing "get users endpoint"
    (let [response (app (mock/request :get "/api/users"))]
      ;; This will fail without auth - that's expected
      (is (= 401 (:status response)))))

  (testing "create user endpoint validation"
    (let [user-data {:name "Test User"
                    :email "test@example.com"
                    :password "password123"}
          response (app (-> (mock/request :post "/api/users")
                           (mock/content-type "application/json")
                           (mock/body (json/generate-string user-data))))]
      ;; This will fail without auth - that's expected
      (is (= 401 (:status response))))))

(deftest test-auth-endpoints
  (testing "login endpoint structure"
    (let [login-data {:email "test@example.com"
                     :password "wrongpassword"}
          response (app (-> (mock/request :post "/api/auth/login")
                           (mock/content-type "application/json")
                           (mock/body (json/generate-string login-data))))]
      (is (= 401 (:status response)))))

  (testing "register endpoint structure"
    (let [register-data {:name "New User"
                        :email "new@example.com"
                        :password "password123"}
          response (app (-> (mock/request :post "/api/auth/register")
                           (mock/content-type "application/json")
                           (mock/body (json/generate-string register-data))))]
      (is (= 201 (:status response))))))`,

    'test/reitit_app/handlers/users_test.clj': `(ns reitit-app.handlers.users-test
  (:require [clojure.test :refer :all]
            [reitit-app.handlers.users :as users]
            [reitit-app.db.core :as db]
            [ring.mock.request :as mock]))

(deftest test-get-users
  (testing "get all users"
    (let [request (mock/request :get "/api/users")
          response (users/get-users request)]
      (is (= 200 (:status response)))
      (is (vector? (:body response))))))

(deftest test-user-creation
  (testing "create user with valid data"
    (let [user-data {:name "Test User"
                    :email "test@example.com"
                    :password "password123"}
          request (-> (mock/request :post "/api/users")
                     (assoc :body-params user-data))
          response (users/create-user request)]
      (is (= 201 (:status response)))
      (is (= "Test User" (get-in response [:body :name])))))

  (testing "get user by id"
    (let [user-id 1
          request (-> (mock/request :get (str "/api/users/" user-id))
                     (assoc-in [:path-params :id] user-id))
          response (users/get-user request)]
      (is (or (= 200 (:status response))
              (= 404 (:status response)))))))`,

    'README.md': `# Reitit Web Application

A modern Clojure web application built with Reitit router, featuring data-driven routing, schema validation, and OpenAPI documentation.

## Features

- **Data-Driven Routing**: Routes defined as data structures
- **Schema Validation**: Request/response validation with Malli
- **OpenAPI Documentation**: Auto-generated Swagger docs
- **JWT Authentication**: Token-based authentication
- **Middleware Composition**: Layered middleware architecture
- **High Performance**: Compiled routes for optimal performance
- **Development Tools**: Hot reload and debugging support

## Quick Start

\`\`\`bash
# Install dependencies
lein deps

# Run the application
lein ring server-headless

# Or run with auto-reload
lein ring server
\`\`\`

The application will be available at:
- API: http://localhost:3000/api
- Swagger UI: http://localhost:3000/swagger-ui
- Health Check: http://localhost:3000/api/health

## API Endpoints

### Authentication
- \`POST /api/auth/register\` - User registration
- \`POST /api/auth/login\` - User login

### Users (Protected)
- \`GET /api/users\` - Get all users
- \`POST /api/users\` - Create user
- \`GET /api/users/:id\` - Get user by ID
- \`PUT /api/users/:id\` - Update user
- \`DELETE /api/users/:id\` - Delete user

### Health
- \`GET /api/health\` - Health check

## Schema Validation

The application uses Malli for schema validation:

\`\`\`clojure
(def User
  [:map
   [:id :int]
   [:name :string]
   [:email [:re #".+@.+\..+"]]
   [:created-at :string]])

(def CreateUserRequest
  [:map
   [:name [:string {:min 1 :max 100}]]
   [:email [:re #".+@.+\..+"]]
   [:password [:string {:min 6}]]])
\`\`\`

## Authentication

The application uses JWT tokens for authentication:

\`\`\`bash
# Register a new user
curl -X POST http://localhost:3000/api/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"name": "John Doe", "email": "john@example.com", "password": "password123"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "john@example.com", "password": "password123"}'

# Use token for protected endpoints
curl -X GET http://localhost:3000/api/users \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
\`\`\`

## Development

### Running Tests

\`\`\`bash
# Run all tests
lein test

# Run specific test namespace
lein test reitit-app.core-test

# Run tests with coverage
lein cloverage
\`\`\`

### REPL Development

\`\`\`bash
# Start REPL
lein repl

# In REPL
(require '[reitit-app.core :as core])
(def server (core/-main))
\`\`\`

## Configuration

Environment variables:
- \`PORT\` - Server port (default: 3000)
- \`JWT_SECRET\` - JWT signing secret
- \`DATABASE_URL\` - Database connection URL
- \`DATABASE_USER\` - Database username
- \`DATABASE_PASSWORD\` - Database password

## Docker Support

\`\`\`bash
# Build image
docker build -t reitit-app .

# Run container
docker run -p 3000:3000 reitit-app
\`\`\`

## Production Deployment

\`\`\`bash
# Create uberjar
lein uberjar

# Run production server
java -jar target/reitit-app-0.1.0-standalone.jar
\`\`\`

## OpenAPI Documentation

The application automatically generates OpenAPI documentation available at:
- JSON: http://localhost:3000/swagger.json
- UI: http://localhost:3000/swagger-ui

## Architecture

### Route Structure
Routes are defined as data structures with middleware and validation:

\`\`\`clojure
["/api/users"
 {:middleware [auth-middleware/wrap-auth]}
 ["" {:get {:handler users/get-users
            :responses {200 {:body [:vector User]}}}}]]
\`\`\`

### Middleware Stack
- Muuntaja for content negotiation
- Malli for coercion and validation
- Buddy for authentication
- Ring for HTTP handling

### Error Handling
Comprehensive error handling with proper HTTP status codes and structured error responses.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

Copyright © 2024 Re-Shell Team
`,

    'Dockerfile': `FROM clojure:openjdk-17-lein-alpine

WORKDIR /app

# Copy project files
COPY project.clj .
COPY src src
COPY resources resources
COPY test test

# Install dependencies
RUN lein deps

# Build the application
RUN lein uberjar

# Expose port
EXPOSE 3000

# Run the application
CMD ["java", "-jar", "target/reitit-app-0.1.0-standalone.jar"]`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - PORT=3000
      - DATABASE_URL=//postgres:5432/reitit_app
      - DATABASE_USER=postgres
      - DATABASE_PASSWORD=postgres
      - JWT_SECRET=your-super-secret-key
    depends_on:
      - postgres
  
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=reitit_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:`,

    '.gitignore': `target/
.lein-*
.nrepl-*
.repl-*
logs/
*.jar
*.class
.env
.DS_Store
node_modules/
npm-debug.log*`,

    'profiles.clj': `{:dev {:env {:dev true}
        :dependencies [[ring/ring-mock "0.4.0"]
                       [midje "1.10.4"]]
        :plugins [[lein-midje "3.2.1"]
                  [lein-cloverage "1.2.4"]]}
 :test {:env {:test true}}
 :production {:env {:production true}}}`,

    'examples/curl-examples.sh': `#!/bin/bash

# Reitit API Examples

BASE_URL="http://localhost:3000"

echo "=== Health Check ==="
curl -X GET $BASE_URL/api/health

echo -e "\n\n=== Register User ==="
curl -X POST $BASE_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123"
  }'

echo -e "\n\n=== Login ==="
TOKEN=$(curl -s -X POST $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }' | jq -r '.token')

echo "Token: $TOKEN"

echo -e "\n\n=== Get Users (Protected) ==="
curl -X GET $BASE_URL/api/users \
  -H "Authorization: Bearer $TOKEN"

echo -e "\n\n=== Create User (Protected) ==="
curl -X POST $BASE_URL/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Jane Smith",
    "email": "jane@example.com",
    "password": "password456"
  }'

echo -e "\n\n=== Get User by ID (Protected) ==="
curl -X GET $BASE_URL/api/users/1 \
  -H "Authorization: Bearer $TOKEN"

echo -e "\n\n=== Update User (Protected) ==="
curl -X PUT $BASE_URL/api/users/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Updated"
  }'

echo -e "\n\n=== Swagger JSON ==="
curl -X GET $BASE_URL/swagger.json

echo -e "\n\nDone!"`,

    'examples/performance-test.clj': `(ns performance-test
  (:require [clj-http.client :as client]
            [clojure.core.async :as async]
            [clojure.tools.logging :as log]
            [cheshire.core :as json]))

(def base-url "http://localhost:3000")

(defn make-request [method url & [opts]]
  (try
    (client/request (merge {:method method
                           :url url
                           :accept :json
                           :content-type :json
                           :socket-timeout 1000
                           :connection-timeout 1000}
                          opts))
    (catch Exception e
      {:error (.getMessage e)})))

(defn register-user [user-data]
  (make-request :post (str base-url "/api/auth/register")
                {:body (json/generate-string user-data)}))

(defn login-user [credentials]
  (make-request :post (str base-url "/api/auth/login")
                {:body (json/generate-string credentials)}))

(defn get-users [token]
  (make-request :get (str base-url "/api/users")
                {:headers {"Authorization" (str "Bearer " token)}}))

(defn run-load-test [concurrent-requests]
  (let [start-time (System/currentTimeMillis)
        results-chan (async/chan concurrent-requests)
        
        test-user {:name "Load Test User"
                  :email "loadtest@example.com"
                  :password "password123"}]
    
    (log/info (str "Starting load test with " concurrent-requests " concurrent requests"))
    
    ;; Register and login to get token
    (register-user test-user)
    (let [login-response (login-user {:email (:email test-user)
                                     :password (:password test-user)})
          token (get-in login-response [:body :token])]
      
      ;; Launch concurrent requests
      (dotimes [i concurrent-requests]
        (async/go
          (let [result (get-users token)]
            (async/>! results-chan result))))
      
      ;; Collect results
      (let [results (async/<!! (async/into [] (async/take concurrent-requests results-chan)))
            end-time (System/currentTimeMillis)
            duration (- end-time start-time)
            successful (count (filter #(= 200 (:status %)) results))
            failed (- concurrent-requests successful)]
        
        (log/info (str "Load test completed in " duration "ms"))
        (log/info (str "Successful requests: " successful))
        (log/info (str "Failed requests: " failed))
        (log/info (str "Requests per second: " (/ concurrent-requests (/ duration 1000.0))))
        
        {:duration duration
         :successful successful
         :failed failed
         :rps (/ concurrent-requests (/ duration 1000.0))}))))

;; Run performance tests
(defn -main []
  (log/info "Starting performance tests...")
  
  ;; Test different concurrency levels
  (doseq [concurrency [1 10 50 100]]
    (log/info (str "Testing with " concurrency " concurrent requests"))
    (run-load-test concurrency)
    (Thread/sleep 2000))) ; Wait between tests

;; Example usage:
;; lein run -m performance-test`,

    'examples/schema-examples.clj': `(ns schema-examples
  (:require [malli.core :as m]
            [malli.transform :as mt]
            [malli.error :as me]
            [malli.generator :as mg]))

;; Schema definitions
(def User
  [:map
   [:id :int]
   [:name [:string {:min 1 :max 100}]]
   [:email [:re #".+@.+\..+"]]
   [:age {:optional true} [:int {:min 0 :max 150}]]
   [:created-at :string]])

(def CreateUserRequest
  [:map
   [:name [:string {:min 1 :max 100}]]
   [:email [:re #".+@.+\..+"]]
   [:password [:string {:min 6}]]
   [:age {:optional true} [:int {:min 0 :max 150}]]])

(def UpdateUserRequest
  [:map
   [:name {:optional true} [:string {:min 1 :max 100}]]
   [:email {:optional true} [:re #".+@.+\..+"]]
   [:age {:optional true} [:int {:min 0 :max 150}]]])

;; Validation examples
(defn validate-user [user-data]
  (if (m/validate User user-data)
    {:valid true :data user-data}
    {:valid false :errors (me/humanize (m/explain User user-data))}))

(defn validate-create-request [request-data]
  (if (m/validate CreateUserRequest request-data)
    {:valid true :data request-data}
    {:valid false :errors (me/humanize (m/explain CreateUserRequest request-data))}))

;; Transformation examples
(defn transform-user [user-data]
  (m/decode User user-data mt/string-transformer))

;; Generation examples
(defn generate-sample-user []
  (mg/generate User))

(defn generate-sample-users [count]
  (repeatedly count #(mg/generate User)))

;; Examples
(defn run-examples []
  (println "=== Schema Validation Examples ===")
  
  ;; Valid user
  (let [valid-user {:id 1
                   :name "John Doe"
                   :email "john@example.com"
                   :created-at "2024-01-01T12:00:00Z"}]
    (println "Valid user:" (validate-user valid-user)))
  
  ;; Invalid user
  (let [invalid-user {:id "not-a-number"
                     :name ""
                     :email "invalid-email"
                     :created-at "2024-01-01T12:00:00Z"}]
    (println "Invalid user:" (validate-user invalid-user)))
  
  ;; Valid create request
  (let [valid-request {:name "Jane Smith"
                      :email "jane@example.com"
                      :password "password123"}]
    (println "Valid create request:" (validate-create-request valid-request)))
  
  ;; Invalid create request
  (let [invalid-request {:name ""
                        :email "invalid"
                        :password "123"}]
    (println "Invalid create request:" (validate-create-request invalid-request)))
  
  ;; Transformation
  (let [string-data {:id "42"
                    :name "John Doe"
                    :email "john@example.com"
                    :age "30"
                    :created-at "2024-01-01T12:00:00Z"}]
    (println "Transformed data:" (transform-user string-data)))
  
  ;; Generation
  (println "Generated user:" (generate-sample-user))
  (println "Generated users:" (generate-sample-users 3)))

;; Custom schemas
(def ApiResponse
  [:map
   [:success :boolean]
   [:data {:optional true} :any]
   [:error {:optional true} :string]
   [:timestamp :string]])

(def PaginatedResponse
  [:map
   [:items [:vector User]]
   [:page :int]
   [:per-page :int]
   [:total :int]
   [:total-pages :int]])

;; Complex validation
(defn validate-api-response [response]
  (m/validate ApiResponse response))

(defn validate-paginated-response [response]
  (m/validate PaginatedResponse response))

;; Run examples
(comment
  (run-examples))`,

    'examples/middleware-examples.clj': `(ns middleware-examples
  (:require [reitit.ring :as ring]
            [reitit.ring.middleware.muuntaja :as muuntaja]
            [reitit.ring.middleware.parameters :as parameters]
            [reitit.ring.middleware.exception :as exception]
            [reitit.ring.coercion :as coercion]
            [reitit.coercion.malli]
            [muuntaja.core :as m]
            [ring.util.http-response :as response]
            [clojure.tools.logging :as log]))

;; Custom middleware examples

(defn wrap-logging [handler]
  (fn [request]
    (let [start-time (System/currentTimeMillis)
          response (handler request)
          end-time (System/currentTimeMillis)
          duration (- end-time start-time)]
      (log/info (format "%s %s - %d (%dms)"
                       (name (:request-method request))
                       (:uri request)
                       (:status response)
                       duration))
      response)))

(defn wrap-request-id [handler]
  (fn [request]
    (let [request-id (str (java.util.UUID/randomUUID))
          request-with-id (assoc request :request-id request-id)
          response (handler request-with-id)]
      (assoc-in response [:headers "X-Request-ID"] request-id))))

(defn wrap-rate-limiting [handler & [{:keys [max-requests window-ms]
                                     :or {max-requests 100
                                          window-ms 60000}}]]
  (let [requests (atom {})]
    (fn [request]
      (let [client-ip (or (get-in request [:headers "x-forwarded-for"])
                         (get-in request [:headers "x-real-ip"])
                         (:remote-addr request))
            current-time (System/currentTimeMillis)
            client-requests (get @requests client-ip [])]
        
        ;; Clean old requests
        (let [recent-requests (filter #(> (+ % window-ms) current-time) client-requests)]
          (swap! requests assoc client-ip recent-requests)
          
          ;; Check rate limit
          (if (>= (count recent-requests) max-requests)
            (response/too-many-requests {:error "Rate limit exceeded"})
            (do
              (swap! requests update client-ip (fnil conj []) current-time)
              (handler request))))))))

(defn wrap-cors-headers [handler]
  (fn [request]
    (let [response (handler request)]
      (-> response
          (assoc-in [:headers "Access-Control-Allow-Origin"] "*")
          (assoc-in [:headers "Access-Control-Allow-Methods"] "GET, POST, PUT, DELETE, OPTIONS")
          (assoc-in [:headers "Access-Control-Allow-Headers"] "Content-Type, Authorization")))))

(defn wrap-security-headers [handler]
  (fn [request]
    (let [response (handler request)]
      (-> response
          (assoc-in [:headers "X-Content-Type-Options"] "nosniff")
          (assoc-in [:headers "X-Frame-Options"] "DENY")
          (assoc-in [:headers "X-XSS-Protection"] "1; mode=block")
          (assoc-in [:headers "Strict-Transport-Security"] "max-age=31536000; includeSubDomains")))))

(defn wrap-error-handling [handler]
  (fn [request]
    (try
      (handler request)
      (catch Exception e
        (log/error e "Unhandled exception")
        (response/internal-server-error 
          {:error "Internal server error"
           :request-id (:request-id request)})))))

;; Middleware composition examples

(def common-middleware
  [wrap-logging
   wrap-request-id
   wrap-cors-headers
   wrap-security-headers
   wrap-error-handling])

(def api-middleware
  [muuntaja/format-middleware
   parameters/parameters-middleware
   coercion/coerce-exceptions-middleware
   coercion/coerce-request-middleware
   coercion/coerce-response-middleware])

(def protected-middleware
  [wrap-rate-limiting])

;; Route with middleware
(def example-routes
  [["/api"
    {:middleware (concat common-middleware api-middleware)}
    
    ["/public"
     ["/health"
      {:get {:handler (fn [_] (response/ok {:status "ok"}))}}]]
    
    ["/protected"
     {:middleware protected-middleware}
     
     ["/users"
      {:get {:handler (fn [_] (response/ok {:users []}))}}]]]
   
   ["/admin"
    {:middleware (concat common-middleware api-middleware protected-middleware)}
    
    ["/stats"
     {:get {:handler (fn [_] (response/ok {:stats {}}))}}]]])

;; Custom coercion
(defn custom-coercion-middleware [handler]
  (fn [request]
    (let [coerced-request (update request :path-params
                                 (fn [params]
                                   (into {} (for [[k v] params]
                                             [k (cond
                                                  (re-matches #"\\d+" v) (Integer/parseInt v)
                                                  (= v "true") true
                                                  (= v "false") false
                                                  :else v)]))))]
      (handler coerced-request))))

;; Conditional middleware
(defn conditional-middleware [condition middleware]
  (fn [handler]
    (if condition
      (middleware handler)
      handler)))

;; Example usage
(defn create-app []
  (ring/ring-handler
    (ring/router
      example-routes
      {:data {:coercion reitit.coercion.malli/coercion
              :muuntaja m/instance}})))

;; Development vs Production middleware
(defn dev-middleware []
  [wrap-logging
   wrap-request-id
   wrap-cors-headers
   wrap-error-handling])

(defn prod-middleware []
  [wrap-logging
   wrap-request-id
   wrap-security-headers
   wrap-rate-limiting
   wrap-error-handling])

;; Environment-specific setup
(defn create-app-with-env [env]
  (let [middleware (case env
                    :dev (dev-middleware)
                    :prod (prod-middleware)
                    (dev-middleware))]
    (ring/ring-handler
      (ring/router
        example-routes
        {:data {:coercion reitit.coercion.malli/coercion
                :muuntaja m/instance
                :middleware middleware}}))))

;; Example of middleware with state
(defn wrap-metrics [handler]
  (let [metrics (atom {:requests 0
                      :errors 0
                      :total-time 0})]
    (fn [request]
      (let [start-time (System/currentTimeMillis)]
        (try
          (let [response (handler request)
                end-time (System/currentTimeMillis)
                duration (- end-time start-time)]
            (swap! metrics update :requests inc)
            (swap! metrics update :total-time + duration)
            (assoc response :metrics @metrics))
          (catch Exception e
            (swap! metrics update :errors inc)
            (throw e)))))))

;; Usage examples
(comment
  ;; Create app with middleware
  (def app (create-app))
  
  ;; Test middleware
  (app {:request-method :get :uri "/api/public/health"})
  
  ;; Create environment-specific app
  (def dev-app (create-app-with-env :dev))
  (def prod-app (create-app-with-env :prod)))`
  },

  dependencies: {
    'Clojure': '^1.11.1',
    'Reitit': '^0.6.0',
    'Malli': '^0.10.1',
    'Muuntaja': '^0.6.8',
    'Buddy': '^3.0.0',
    'Ring': '^1.9.6',
    'Cheshire': '^5.11.0'
  },

  commands: {
    dev: 'lein ring server',
    build: 'lein uberjar',
    test: 'lein test',
    lint: 'lein eastwood',
    format: 'lein cljfmt fix',
    repl: 'lein repl',
    clean: 'lein clean',
    deps: 'lein deps',
    'dev:watch': 'lein ring server-headless',
    'test:watch': 'lein test-refresh',
    'test:coverage': 'lein cloverage',
    'docker:build': 'docker build -t reitit-app .',
    'docker:run': 'docker run -p 3000:3000 reitit-app',
    'docker:up': 'docker-compose up -d',
    'docker:down': 'docker-compose down'
  },

  ports: {
    dev: 3000,
    prod: 3000
  },

  examples: [
    {
      title: 'Data-Driven Routes',
      description: 'Define routes as data with middleware and validation',
      code: `["/api/users"
 {:middleware [auth-middleware/wrap-auth]}
 ["" {:get {:handler users/get-users
            :responses {200 {:body [:vector User]}}}}]]`
    },
    {
      title: 'Schema Validation',
      description: 'Malli schema validation for requests and responses',
      code: `(def User
  [:map
   [:id :int]
   [:name :string]
   [:email [:re #".+@.+\..+"]]
   [:created-at :string]])`
    },
    {
      title: 'Middleware Composition',
      description: 'Composable middleware with data-driven configuration',
      code: `:middleware [muuntaja/format-middleware
          parameters/parameters-middleware
          coercion/coerce-request-middleware]`
    }
  ]
};