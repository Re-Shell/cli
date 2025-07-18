import { BackendTemplate } from '../types';

export const clojurePedestalTemplate: BackendTemplate = {
  id: 'clojure-pedestal',
  name: 'clojure-pedestal',
  displayName: 'Clojure Pedestal Web Framework',
  description: 'High-performance web framework with interceptors, async support, and production-ready features for enterprise applications',
  framework: 'pedestal',
  language: 'clojure',
  version: '0.6.0',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '🏛️',
  type: 'web-framework',
  complexity: 'advanced',
  keywords: ['clojure', 'pedestal', 'interceptors', 'async', 'enterprise', 'performance'],
  
  features: [
    'Interceptor architecture',
    'Async request handling',
    'Route-based development',
    'Production-ready features',
    'Content negotiation',
    'Error handling',
    'Metrics and monitoring',
    'Security interceptors',
    'WebSocket support',
    'Server-sent events',
    'Chain processing',
    'High performance',
    'Enterprise features',
    'Debugging tools'
  ],
  
  structure: {
    'project.clj': `(defproject pedestal-app "0.1.0-SNAPSHOT"
  :description "A Clojure web application using Pedestal"
  :url "http://example.com"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [io.pedestal/pedestal.service "0.6.0"]
                 [io.pedestal/pedestal.jetty "0.6.0"]
                 [io.pedestal/pedestal.route "0.6.0"]
                 [io.pedestal/pedestal.log "0.6.0"]
                 [ch.qos.logback/logback-classic "1.4.5"]
                 [org.slf4j/jul-to-slf4j "2.0.6"]
                 [org.slf4j/jcl-over-slf4j "2.0.6"]
                 [org.slf4j/log4j-over-slf4j "2.0.6"]
                 [cheshire "5.11.0"]
                 [com.stuartsierra/component "1.1.0"]
                 [environ "1.2.0"]
                 [buddy/buddy-auth "3.0.323"]
                 [buddy/buddy-hashers "1.8.158"]
                 [buddy/buddy-sign "3.4.333"]
                 [org.clojure/java.jdbc "0.7.12"]
                 [org.postgresql/postgresql "42.5.1"]
                 [clj-time "0.15.2"]
                 [ring/ring-core "1.9.6"]
                 [ring-cors "0.1.13"]
                 [prismatic/schema "1.4.1"]
                 [org.clojure/core.async "1.6.673"]
                 [org.clojure/core.match "1.0.0"]]
  :min-lein-version "2.0.0"
  :resource-paths ["config", "resources"]
  :profiles {:dev {:aliases {"run-dev" ["trampoline" "run" "-m" "pedestal-app.server/run-dev"]}
                   :dependencies [[io.pedestal/pedestal.service-tools "0.6.0"]]}
             :uberjar {:aot [pedestal-app.server]}}
  :main ^{:skip-aot true} pedestal-app.server)`,

    'src/pedestal_app/server.clj': `(ns pedestal-app.server
  (:gen-class)
  (:require [io.pedestal.http :as server]
            [io.pedestal.http.route :as route]
            [io.pedestal.log :as log]
            [pedestal-app.service :as service]
            [pedestal-app.system :as system]
            [com.stuartsierra.component :as component]
            [environ.core :refer [env]]))

(defonce runnable-service (server/create-server service/service))

(defn run-dev
  "The entry-point for 'lein run-dev'"
  [& args]
  (println "\\nCreating your [DEV] server...")
  (-> service/service
      (merge {:env :dev
              ::server/join? false
              ::server/routes #(route/expand-routes (deref #'service/routes))
              ::server/allowed-origins {:creds true :allowed-origins (constantly true)}
              ::server/secure-headers {:content-type-options :nosniff}})
      server/default-interceptors
      server/dev-interceptors
      server/create-server
      server/start))

(defn -main
  "The entry-point for 'lein run'"
  [& args]
  (println "\\nCreating your server...")
  (let [system (system/create-system {:port (Integer/parseInt (or (env :port) "8080"))})]
    (component/start system)
    (log/info "Server started on port" (or (env :port) "8080"))))`,

    'src/pedestal_app/service.clj': `(ns pedestal-app.service
  (:require [io.pedestal.http :as bootstrap]
            [io.pedestal.http.route :as route]
            [io.pedestal.http.body-params :as body-params]
            [io.pedestal.http.ring-middlewares :as middlewares]
            [io.pedestal.interceptor :refer [interceptor]]
            [io.pedestal.interceptor.chain :as chain]
            [io.pedestal.log :as log]
            [ring.util.response :as ring-resp]
            [cheshire.core :as json]
            [pedestal-app.interceptors.auth :as auth]
            [pedestal-app.interceptors.cors :as cors]
            [pedestal-app.interceptors.validation :as validation]
            [pedestal-app.interceptors.error :as error]
            [pedestal-app.handlers.users :as users]
            [pedestal-app.handlers.auth :as auth-handlers]
            [pedestal-app.handlers.health :as health]
            [pedestal-app.db.core :as db]
            [clojure.core.async :as async]))

;; Common interceptors
(def common-interceptors
  [cors/cors-interceptor
   error/error-interceptor
   (body-params/body-params)
   bootstrap/html-body])

;; Content negotiation interceptor
(def content-negotiation
  (interceptor
    {:name :content-negotiation
     :enter (fn [context]
              (let [accept (get-in context [:request :headers "accept"])
                    content-type (cond
                                   (.contains accept "application/json") "application/json"
                                   (.contains accept "application/edn") "application/edn"
                                   :else "application/json")]
                (assoc-in context [:request :content-type] content-type)))}))

;; JSON response interceptor
(def json-response
  (interceptor
    {:name :json-response
     :leave (fn [context]
              (let [response (:response context)]
                (if (map? (:body response))
                  (-> context
                      (assoc-in [:response :body] (json/generate-string (:body response)))
                      (assoc-in [:response :headers "Content-Type"] "application/json"))
                  context)))}))

;; Request logging interceptor
(def request-logging
  (interceptor
    {:name :request-logging
     :enter (fn [context]
              (let [request (:request context)]
                (log/info (format "%s %s" 
                                 (name (:request-method request))
                                 (:uri request)))
                (assoc context :start-time (System/currentTimeMillis))))
     :leave (fn [context]
              (let [start-time (:start-time context)
                    duration (- (System/currentTimeMillis) start-time)
                    status (get-in context [:response :status])]
                (log/info (format "Response: %d (%dms)" status duration))
                context))}))

;; Performance monitoring interceptor
(def performance-monitoring
  (interceptor
    {:name :performance-monitoring
     :enter (fn [context]
              (assoc context :request-start (System/nanoTime)))
     :leave (fn [context]
              (let [duration-ns (- (System/nanoTime) (:request-start context))
                    duration-ms (/ duration-ns 1000000.0)]
                (when (> duration-ms 100)
                  (log/warn (format "Slow request: %s %s took %.2fms"
                                   (name (get-in context [:request :request-method]))
                                   (get-in context [:request :uri])
                                   duration-ms)))
                (assoc-in context [:response :headers "X-Response-Time"] 
                         (str duration-ms "ms"))))}))

;; Async request handling example
(def async-processing
  (interceptor
    {:name :async-processing
     :enter (fn [context]
              (if (get-in context [:request :async])
                (let [response-chan (async/chan)]
                  ;; Simulate async processing
                  (async/go
                    (async/<! (async/timeout 1000))
                    (async/>! response-chan 
                             {:status 200 
                              :body {:message "Async processing complete"}}))
                  (assoc context :response response-chan))
                context))}))

;; Routes
(def routes
  #{;; Health check
    ["/health" :get (conj common-interceptors 
                         json-response 
                         health/health-check)]
    
    ;; Authentication routes
    ["/auth/login" :post (conj common-interceptors 
                              json-response 
                              validation/login-validation
                              auth-handlers/login)]
    
    ["/auth/register" :post (conj common-interceptors 
                                 json-response 
                                 validation/register-validation
                                 auth-handlers/register)]
    
    ;; User routes (protected)
    ["/users" :get (conj common-interceptors 
                        json-response 
                        auth/auth-interceptor
                        users/get-users)]
    
    ["/users" :post (conj common-interceptors 
                         json-response 
                         auth/auth-interceptor
                         validation/create-user-validation
                         users/create-user)]
    
    ["/users/:id" :get (conj common-interceptors 
                            json-response 
                            auth/auth-interceptor
                            validation/user-id-validation
                            users/get-user)]
    
    ["/users/:id" :put (conj common-interceptors 
                            json-response 
                            auth/auth-interceptor
                            validation/user-id-validation
                            validation/update-user-validation
                            users/update-user)]
    
    ["/users/:id" :delete (conj common-interceptors 
                               json-response 
                               auth/auth-interceptor
                               validation/user-id-validation
                               users/delete-user)]
    
    ;; WebSocket route
    ["/ws" :get (conj common-interceptors 
                     users/websocket-handler)]
    
    ;; Server-sent events route
    ["/events" :get (conj common-interceptors 
                         users/sse-handler)]
    
    ;; Async processing example
    ["/async-process" :post (conj common-interceptors 
                                 json-response 
                                 async-processing)]
    
    ;; Metrics endpoint
    ["/metrics" :get (conj common-interceptors 
                          json-response 
                          users/metrics-handler)]})

;; Service configuration
(def service 
  {:env :prod
   ::bootstrap/routes routes
   ::bootstrap/resource-path "/public"
   ::bootstrap/type :jetty
   ::bootstrap/port 8080
   ::bootstrap/container-options {:h2c? true
                                  :h2? false
                                  :keystore nil
                                  :key-password nil
                                  :ssl-port 8443
                                  :ssl? false}
   ::bootstrap/join? true})`,

    'src/pedestal_app/system.clj': `(ns pedestal-app.system
  (:require [com.stuartsierra.component :as component]
            [io.pedestal.http :as server]
            [io.pedestal.log :as log]
            [pedestal-app.service :as service]
            [pedestal-app.db.core :as db]))

(defrecord Database [config]
  component/Lifecycle
  (start [this]
    (log/info "Starting database connection")
    (db/init-db)
    (assoc this :connection :connected))
  
  (stop [this]
    (log/info "Stopping database connection")
    (dissoc this :connection)))

(defrecord WebServer [config database]
  component/Lifecycle
  (start [this]
    (log/info "Starting web server on port" (:port config))
    (let [server (-> service/service
                    (merge {::server/port (:port config)
                            ::server/join? false})
                    server/create-server
                    server/start)]
      (assoc this :server server)))
  
  (stop [this]
    (log/info "Stopping web server")
    (when-let [server (:server this)]
      (server/stop server))
    (dissoc this :server)))

(defn create-system [config]
  (component/system-map
    :database (->Database config)
    :web-server (component/using
                  (->WebServer config nil)
                  [:database])))`,

    'src/pedestal_app/handlers/users.clj': `(ns pedestal-app.handlers.users
  (:require [io.pedestal.interceptor :refer [interceptor]]
            [io.pedestal.http.sse :as sse]
            [io.pedestal.log :as log]
            [ring.util.response :as ring-resp]
            [pedestal-app.db.core :as db]
            [clojure.core.async :as async]
            [cheshire.core :as json]
            [clj-time.core :as time]
            [clj-time.format :as format]))

(def get-users
  (interceptor
    {:name :get-users
     :enter (fn [context]
              (try
                (let [users (db/get-all-users)]
                  (assoc context :response
                         {:status 200
                          :body users}))
                (catch Exception e
                  (log/error e "Error getting users")
                  (assoc context :response
                         {:status 500
                          :body {:error "Failed to get users"}}))))}))

(def get-user
  (interceptor
    {:name :get-user
     :enter (fn [context]
              (try
                (let [user-id (Integer/parseInt (get-in context [:request :path-params :id]))
                      user (db/get-user-by-id user-id)]
                  (if user
                    (assoc context :response
                           {:status 200
                            :body user})
                    (assoc context :response
                           {:status 404
                            :body {:error "User not found"}})))
                (catch Exception e
                  (log/error e "Error getting user")
                  (assoc context :response
                         {:status 500
                          :body {:error "Failed to get user"}}))))}))

(def create-user
  (interceptor
    {:name :create-user
     :enter (fn [context]
              (try
                (let [user-data (get-in context [:request :json-params])
                      now (format/unparse (format/formatters :date-time) (time/now))
                      user-with-timestamp (assoc user-data :created-at now)
                      created-user (db/create-user user-with-timestamp)]
                  (assoc context :response
                         {:status 201
                          :body created-user}))
                (catch Exception e
                  (log/error e "Error creating user")
                  (assoc context :response
                         {:status 500
                          :body {:error "Failed to create user"}}))))}))

(def update-user
  (interceptor
    {:name :update-user
     :enter (fn [context]
              (try
                (let [user-id (Integer/parseInt (get-in context [:request :path-params :id]))
                      user-data (get-in context [:request :json-params])
                      existing-user (db/get-user-by-id user-id)]
                  (if existing-user
                    (let [updated-user (db/update-user user-id user-data)]
                      (assoc context :response
                             {:status 200
                              :body updated-user}))
                    (assoc context :response
                           {:status 404
                            :body {:error "User not found"}})))
                (catch Exception e
                  (log/error e "Error updating user")
                  (assoc context :response
                         {:status 500
                          :body {:error "Failed to update user"}}))))}))

(def delete-user
  (interceptor
    {:name :delete-user
     :enter (fn [context]
              (try
                (let [user-id (Integer/parseInt (get-in context [:request :path-params :id]))
                      existing-user (db/get-user-by-id user-id)]
                  (if existing-user
                    (do
                      (db/delete-user user-id)
                      (assoc context :response
                             {:status 204}))
                    (assoc context :response
                           {:status 404
                            :body {:error "User not found"}})))
                (catch Exception e
                  (log/error e "Error deleting user")
                  (assoc context :response
                         {:status 500
                          :body {:error "Failed to delete user"}}))))}))

;; WebSocket handler
(def websocket-handler
  (interceptor
    {:name :websocket-handler
     :enter (fn [context]
              (log/info "WebSocket connection established")
              (let [ws-channel (async/chan)]
                ;; Send periodic updates
                (async/go-loop []
                  (async/<! (async/timeout 5000))
                  (async/>! ws-channel
                           {:type "update"
                            :data {:timestamp (str (time/now))
                                   :users-count (count (db/get-all-users))}})
                  (recur))
                
                (assoc context :response
                       {:status 200
                        :headers {"Content-Type" "application/json"}
                        :body ws-channel})))}))

;; Server-sent events handler
(def sse-handler
  (interceptor
    {:name :sse-handler
     :enter (fn [context]
              (log/info "SSE connection established")
              (let [event-stream (sse/start-stream context)]
                ;; Send periodic events
                (async/go-loop []
                  (async/<! (async/timeout 10000))
                  (sse/send-event event-stream
                                  {:name "user-update"
                                   :data (json/generate-string
                                           {:timestamp (str (time/now))
                                            :active-users (count (db/get-all-users))})})
                  (recur))
                
                context))}))

;; Metrics handler
(def metrics-handler
  (interceptor
    {:name :metrics-handler
     :enter (fn [context]
              (let [metrics {:users-count (count (db/get-all-users))
                           :memory-usage (- (.totalMemory (Runtime/getRuntime))
                                          (.freeMemory (Runtime/getRuntime)))
                           :uptime (System/currentTimeMillis)
                           :timestamp (str (time/now))}]
                (assoc context :response
                       {:status 200
                        :body metrics})))}))`,

    'src/pedestal_app/handlers/auth.clj': `(ns pedestal-app.handlers.auth
  (:require [io.pedestal.interceptor :refer [interceptor]]
            [io.pedestal.log :as log]
            [buddy.hashers :as hashers]
            [buddy.sign.jwt :as jwt]
            [pedestal-app.db.core :as db]
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

(def login
  (interceptor
    {:name :login
     :enter (fn [context]
              (try
                (let [{:keys [email password]} (get-in context [:request :json-params])
                      user (db/get-user-by-email email)]
                  (if (and user (hashers/check password (:password user)))
                    (let [token (generate-token user)]
                      (assoc context :response
                             {:status 200
                              :body {:token token}}))
                    (assoc context :response
                           {:status 401
                            :body {:error "Invalid credentials"}})))
                (catch Exception e
                  (log/error e "Error during login")
                  (assoc context :response
                         {:status 500
                          :body {:error "Login failed"}}))))}))

(def register
  (interceptor
    {:name :register
     :enter (fn [context]
              (try
                (let [{:keys [name email password]} (get-in context [:request :json-params])
                      existing-user (db/get-user-by-email email)]
                  (if existing-user
                    (assoc context :response
                           {:status 400
                            :body {:error "User already exists"}})
                    (let [hashed-password (hashers/derive password)
                          now (format/unparse (format/formatters :date-time) (time/now))
                          user-data {:name name
                                    :email email
                                    :password hashed-password
                                    :created-at now}
                          created-user (db/create-user user-data)
                          user-response (dissoc created-user :password)]
                      (assoc context :response
                             {:status 201
                              :body user-response}))))
                (catch Exception e
                  (log/error e "Error during registration")
                  (assoc context :response
                         {:status 500
                          :body {:error "Registration failed"}}))))}))`,

    'src/pedestal_app/handlers/health.clj': `(ns pedestal-app.handlers.health
  (:require [io.pedestal.interceptor :refer [interceptor]]
            [io.pedestal.log :as log]
            [pedestal-app.db.core :as db]))

(def health-check
  (interceptor
    {:name :health-check
     :enter (fn [context]
              (try
                ;; Check database connection
                (db/health-check)
                
                (assoc context :response
                       {:status 200
                        :body {:status "ok"
                               :timestamp (str (java.time.Instant/now))
                               :service "pedestal-app"
                               :version "1.0.0"}})
                (catch Exception e
                  (log/error e "Health check failed")
                  (assoc context :response
                         {:status 503
                          :body {:status "error"
                                 :error "Service unavailable"}}))))}))`,

    'src/pedestal_app/interceptors/auth.clj': `(ns pedestal-app.interceptors.auth
  (:require [io.pedestal.interceptor :refer [interceptor]]
            [io.pedestal.log :as log]
            [buddy.sign.jwt :as jwt]
            [environ.core :refer [env]]))

(def jwt-secret (or (env :jwt-secret) "your-super-secret-key"))

(defn extract-token [request]
  (when-let [auth-header (get-in request [:headers "authorization"])]
    (when (.startsWith auth-header "Bearer ")
      (.substring auth-header 7))))

(defn verify-token [token]
  (try
    (jwt/unsign token jwt-secret)
    (catch Exception e
      (log/warn "Invalid token:" (.getMessage e))
      nil)))

(def auth-interceptor
  (interceptor
    {:name :auth-interceptor
     :enter (fn [context]
              (let [token (extract-token (:request context))]
                (if token
                  (if-let [claims (verify-token token)]
                    (assoc-in context [:request :user] claims)
                    (assoc context :response
                           {:status 401
                            :body {:error "Invalid token"}}))
                  (assoc context :response
                         {:status 401
                          :body {:error "Missing authorization token"}}))))}))

(defn get-current-user [context]
  (get-in context [:request :user]))`,

    'src/pedestal_app/interceptors/cors.clj': `(ns pedestal-app.interceptors.cors
  (:require [io.pedestal.interceptor :refer [interceptor]]
            [io.pedestal.log :as log]))

(def cors-interceptor
  (interceptor
    {:name :cors-interceptor
     :enter (fn [context]
              (let [request (:request context)
                    method (:request-method request)]
                (if (= method :options)
                  ;; Handle preflight request
                  (assoc context :response
                         {:status 200
                          :headers {"Access-Control-Allow-Origin" "*"
                                   "Access-Control-Allow-Methods" "GET, POST, PUT, DELETE, OPTIONS"
                                   "Access-Control-Allow-Headers" "Content-Type, Authorization"
                                   "Access-Control-Max-Age" "86400"}})
                  context)))
     :leave (fn [context]
              (let [response (:response context)]
                (assoc-in context [:response :headers]
                         (merge (:headers response {})
                                {"Access-Control-Allow-Origin" "*"
                                 "Access-Control-Allow-Methods" "GET, POST, PUT, DELETE, OPTIONS"
                                 "Access-Control-Allow-Headers" "Content-Type, Authorization"}))))}))`,

    'src/pedestal_app/interceptors/validation.clj': `(ns pedestal-app.interceptors.validation
  (:require [io.pedestal.interceptor :refer [interceptor]]
            [io.pedestal.log :as log]
            [schema.core :as s]))

;; Schema definitions
(def User
  {:id s/Int
   :name s/Str
   :email s/Str
   :created-at s/Str
   (s/optional-key :password) s/Str})

(def CreateUserRequest
  {:name s/Str
   :email s/Str
   :password s/Str})

(def UpdateUserRequest
  {(s/optional-key :name) s/Str
   (s/optional-key :email) s/Str})

(def LoginRequest
  {:email s/Str
   :password s/Str})

(defn validate-data [schema data]
  (try
    (s/validate schema data)
    true
    (catch Exception e
      (log/warn "Validation error:" (.getMessage e))
      false)))

(defn create-validation-interceptor [schema error-message]
  (interceptor
    {:name :validation
     :enter (fn [context]
              (let [data (get-in context [:request :json-params])]
                (if (validate-data schema data)
                  context
                  (assoc context :response
                         {:status 400
                          :body {:error error-message}}))))}))

(def login-validation
  (create-validation-interceptor LoginRequest "Invalid login request"))

(def register-validation
  (create-validation-interceptor CreateUserRequest "Invalid registration request"))

(def create-user-validation
  (create-validation-interceptor CreateUserRequest "Invalid user creation request"))

(def update-user-validation
  (create-validation-interceptor UpdateUserRequest "Invalid user update request"))

(def user-id-validation
  (interceptor
    {:name :user-id-validation
     :enter (fn [context]
              (try
                (let [user-id (get-in context [:request :path-params :id])]
                  (Integer/parseInt user-id)
                  context)
                (catch Exception e
                  (log/warn "Invalid user ID:" (.getMessage e))
                  (assoc context :response
                         {:status 400
                          :body {:error "Invalid user ID"}}))))}))`,

    'src/pedestal_app/interceptors/error.clj': `(ns pedestal-app.interceptors.error
  (:require [io.pedestal.interceptor :refer [interceptor]]
            [io.pedestal.interceptor.error :refer [error-dispatch]]
            [io.pedestal.log :as log]
            [ring.util.response :as ring-resp]))

(def error-interceptor
  (error-dispatch
    [context ex]
    
    ;; Handle validation errors
    [{:exception-type :validation-error}]
    (assoc context :response
           {:status 400
            :body {:error "Validation failed"}})
    
    ;; Handle authentication errors
    [{:exception-type :authentication-error}]
    (assoc context :response
           {:status 401
            :body {:error "Authentication required"}})
    
    ;; Handle authorization errors
    [{:exception-type :authorization-error}]
    (assoc context :response
           {:status 403
            :body {:error "Access forbidden"}})
    
    ;; Handle not found errors
    [{:exception-type :not-found-error}]
    (assoc context :response
           {:status 404
            :body {:error "Resource not found"}})
    
    ;; Handle database errors
    [{:exception-type :database-error}]
    (do
      (log/error ex "Database error")
      (assoc context :response
             {:status 500
              :body {:error "Database error"}}))
    
    ;; Handle general exceptions
    :else
    (do
      (log/error ex "Unhandled exception")
      (assoc context :response
             {:status 500
              :body {:error "Internal server error"}}))))`,

    'src/pedestal_app/db/core.clj': `(ns pedestal-app.db.core
  (:require [clojure.java.jdbc :as jdbc]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]))

;; Database configuration
(def db-spec {:classname "org.postgresql.Driver"
              :subprotocol "postgresql"
              :subname (or (env :database-url) "//localhost:5432/pedestal_app")
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
        <file>logs/pedestal-app.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/pedestal-app.%d{yyyy-MM-dd}.log</fileNamePattern>
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

    'test/pedestal_app/service_test.clj': `(ns pedestal-app.service-test
  (:require [clojure.test :refer :all]
            [io.pedestal.test :refer :all]
            [io.pedestal.http :as bootstrap]
            [pedestal-app.service :as service]
            [cheshire.core :as json]))

(def service
  (::bootstrap/service-fn (bootstrap/create-servlet service/service)))

(deftest test-health-endpoint
  (testing "health check endpoint"
    (is (= 200 (:status (response-for service :get "/health"))))))

(deftest test-auth-endpoints
  (testing "register endpoint"
    (let [user-data {:name "Test User"
                    :email "test@example.com" 
                    :password "password123"}
          response (response-for service :post "/auth/register"
                                :headers {"Content-Type" "application/json"}
                                :body (json/generate-string user-data))]
      (is (= 201 (:status response)))
      (is (contains? (json/parse-string (:body response) true) :id))))

  (testing "login endpoint"
    (let [credentials {:email "test@example.com"
                      :password "password123"}
          response (response-for service :post "/auth/login"
                                :headers {"Content-Type" "application/json"}
                                :body (json/generate-string credentials))]
      (is (or (= 200 (:status response))
              (= 401 (:status response)))))))

(deftest test-protected-endpoints
  (testing "users endpoint without auth"
    (let [response (response-for service :get "/users")]
      (is (= 401 (:status response)))))

  (testing "users endpoint with invalid auth"
    (let [response (response-for service :get "/users"
                                :headers {"Authorization" "Bearer invalid-token"})]
      (is (= 401 (:status response))))))

(deftest test-cors-headers
  (testing "CORS preflight request"
    (let [response (response-for service :options "/users")]
      (is (= 200 (:status response)))
      (is (contains? (:headers response) "Access-Control-Allow-Origin"))))

  (testing "CORS headers on regular request"
    (let [response (response-for service :get "/health")]
      (is (contains? (:headers response) "Access-Control-Allow-Origin")))))

(deftest test-validation
  (testing "invalid user creation"
    (let [invalid-user {:name ""
                       :email "invalid-email"
                       :password "123"}
          response (response-for service :post "/users"
                                :headers {"Content-Type" "application/json"
                                         "Authorization" "Bearer fake-token"}
                                :body (json/generate-string invalid-user))]
      (is (or (= 400 (:status response))
              (= 401 (:status response)))))))`,

    'test/pedestal_app/interceptors_test.clj': `(ns pedestal-app.interceptors-test
  (:require [clojure.test :refer :all]
            [io.pedestal.interceptor.chain :as chain]
            [pedestal-app.interceptors.auth :as auth]
            [pedestal-app.interceptors.cors :as cors]
            [pedestal-app.interceptors.validation :as validation]
            [buddy.sign.jwt :as jwt]))

(deftest test-auth-interceptor
  (testing "missing token"
    (let [context {:request {}}
          result (chain/execute {:interceptors [auth/auth-interceptor]} context)]
      (is (= 401 (get-in result [:response :status])))))

  (testing "invalid token"
    (let [context {:request {:headers {"authorization" "Bearer invalid-token"}}}
          result (chain/execute {:interceptors [auth/auth-interceptor]} context)]
      (is (= 401 (get-in result [:response :status])))))

  (testing "valid token"
    (let [token (jwt/sign {:user-id 1 :email "test@example.com"} "your-super-secret-key")
          context {:request {:headers {"authorization" (str "Bearer " token)}}}
          result (chain/execute {:interceptors [auth/auth-interceptor]} context)]
      (is (contains? (get-in result [:request :user]) :user-id)))))

(deftest test-cors-interceptor
  (testing "preflight request"
    (let [context {:request {:request-method :options}}
          result (chain/execute {:interceptors [cors/cors-interceptor]} context)]
      (is (= 200 (get-in result [:response :status])))
      (is (contains? (get-in result [:response :headers]) "Access-Control-Allow-Origin"))))

  (testing "regular request"
    (let [context {:request {:request-method :get}
                  :response {:status 200 :body "test"}}
          result (chain/execute {:interceptors [cors/cors-interceptor]} context)]
      (is (contains? (get-in result [:response :headers]) "Access-Control-Allow-Origin")))))

(deftest test-validation-interceptor
  (testing "valid data"
    (let [context {:request {:json-params {:name "Test" :email "test@example.com" :password "password123"}}}
          result (chain/execute {:interceptors [validation/create-user-validation]} context)]
      (is (nil? (:response result)))))

  (testing "invalid data"
    (let [context {:request {:json-params {:name "" :email "invalid" :password "123"}}}
          result (chain/execute {:interceptors [validation/create-user-validation]} context)]
      (is (= 400 (get-in result [:response :status]))))))`,

    'README.md': `# Pedestal Web Application

A high-performance Clojure web application built with Pedestal framework, featuring interceptors, async processing, and enterprise-grade features.

## Features

- **Interceptor Architecture**: Composable request/response processing
- **Async Processing**: Non-blocking request handling
- **WebSocket Support**: Real-time bidirectional communication
- **Server-Sent Events**: Real-time server-to-client messaging
- **JWT Authentication**: Token-based authentication
- **Schema Validation**: Request/response validation
- **Performance Monitoring**: Built-in performance metrics
- **Error Handling**: Comprehensive error handling system
- **CORS Support**: Cross-origin resource sharing
- **Production Ready**: Enterprise-grade features

## Quick Start

\`\`\`bash
# Install dependencies
lein deps

# Run development server
lein run-dev

# Run production server
lein run
\`\`\`

The application will be available at:
- API: http://localhost:8080
- Health Check: http://localhost:8080/health
- Metrics: http://localhost:8080/metrics

## API Endpoints

### Authentication
- \`POST /auth/register\` - User registration
- \`POST /auth/login\` - User login

### Users (Protected)
- \`GET /users\` - Get all users
- \`POST /users\` - Create user
- \`GET /users/:id\` - Get user by ID
- \`PUT /users/:id\` - Update user
- \`DELETE /users/:id\` - Delete user

### Real-time
- \`GET /ws\` - WebSocket connection
- \`GET /events\` - Server-sent events

### System
- \`GET /health\` - Health check
- \`GET /metrics\` - System metrics
- \`POST /async-process\` - Async processing example

## Interceptor Architecture

Pedestal uses interceptors for request processing:

\`\`\`clojure
(def common-interceptors
  [cors/cors-interceptor
   error/error-interceptor
   (body-params/body-params)
   bootstrap/html-body])

(def routes
  #{["/users" :get (conj common-interceptors 
                        json-response 
                        auth/auth-interceptor
                        users/get-users)]})
\`\`\`

## Authentication

The application uses JWT tokens for authentication:

\`\`\`bash
# Register a new user
curl -X POST http://localhost:8080/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"name": "John Doe", "email": "john@example.com", "password": "password123"}'

# Login
curl -X POST http://localhost:8080/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "john@example.com", "password": "password123"}'

# Use token for protected endpoints
curl -X GET http://localhost:8080/users \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
\`\`\`

## WebSocket Communication

Connect to WebSocket endpoint for real-time updates:

\`\`\`javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
\`\`\`

## Server-Sent Events

Subscribe to server-sent events:

\`\`\`javascript
const eventSource = new EventSource('http://localhost:8080/events');

eventSource.addEventListener('user-update', function(event) {
  const data = JSON.parse(event.data);
  console.log('User update:', data);
});
\`\`\`

## Development

### Running Tests

\`\`\`bash
# Run all tests
lein test

# Run specific test namespace
lein test pedestal-app.service-test

# Run with coverage
lein cloverage
\`\`\`

### REPL Development

\`\`\`bash
# Start REPL
lein repl

# In REPL
(require '[pedestal-app.server :as server])
(server/run-dev)
\`\`\`

### Custom Interceptors

Create custom interceptors for specific needs:

\`\`\`clojure
(def my-interceptor
  (interceptor
    {:name :my-interceptor
     :enter (fn [context]
              ;; Process request
              context)
     :leave (fn [context]
              ;; Process response
              context)}))
\`\`\`

## Configuration

Environment variables:
- \`PORT\` - Server port (default: 8080)
- \`JWT_SECRET\` - JWT signing secret
- \`DATABASE_URL\` - Database connection URL
- \`DATABASE_USER\` - Database username
- \`DATABASE_PASSWORD\` - Database password

## Performance Features

### Async Processing

The application supports async request processing:

\`\`\`clojure
(def async-handler
  (interceptor
    {:name :async-handler
     :enter (fn [context]
              (let [response-chan (async/chan)]
                (async/go
                  ;; Async processing
                  (async/>! response-chan response))
                (assoc context :response response-chan)))}))
\`\`\`

### Performance Monitoring

Built-in performance monitoring tracks:
- Request duration
- Memory usage
- Active connections
- Error rates

## Docker Support

\`\`\`bash
# Build image
docker build -t pedestal-app .

# Run container
docker run -p 8080:8080 pedestal-app
\`\`\`

## Production Deployment

\`\`\`bash
# Create uberjar
lein uberjar

# Run production server
java -jar target/pedestal-app-0.1.0-standalone.jar
\`\`\`

## Architecture

### Component System

The application uses Stuart Sierra's Component system:

\`\`\`clojure
(defn create-system [config]
  (component/system-map
    :database (->Database config)
    :web-server (component/using
                  (->WebServer config nil)
                  [:database])))
\`\`\`

### Interceptor Chain

Request processing flows through interceptor chains:

1. CORS handling
2. Error handling
3. Body parameter parsing
4. Authentication
5. Validation
6. Business logic
7. Response formatting

### Error Handling

Comprehensive error handling with proper status codes:

\`\`\`clojure
(def error-interceptor
  (error-dispatch
    [context ex]
    [{:exception-type :validation-error}]
    (assoc context :response {:status 400 :body {:error "Validation failed"}})))
\`\`\`

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
EXPOSE 8080

# Run the application
CMD ["java", "-jar", "target/pedestal-app-0.1.0-standalone.jar"]`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - DATABASE_URL=//postgres:5432/pedestal_app
      - DATABASE_USER=postgres
      - DATABASE_PASSWORD=postgres
      - JWT_SECRET=your-super-secret-key
    depends_on:
      - postgres
  
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=pedestal_app
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

    'examples/websocket-client.html': `<!DOCTYPE html>
<html>
<head>
    <title>Pedestal WebSocket Client</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        #messages { border: 1px solid #ccc; height: 300px; overflow-y: auto; padding: 10px; }
        #input { width: 300px; padding: 5px; }
        button { padding: 5px 10px; margin: 5px; }
    </style>
</head>
<body>
    <h1>Pedestal WebSocket Client</h1>
    
    <div id="status">Disconnected</div>
    <button onclick="connect()">Connect</button>
    <button onclick="disconnect()">Disconnect</button>
    
    <div id="messages"></div>
    
    <input type="text" id="input" placeholder="Enter message..." onkeypress="handleKeyPress(event)">
    <button onclick="sendMessage()">Send</button>
    
    <h2>Server-Sent Events</h2>
    <div id="events"></div>
    <button onclick="subscribeToEvents()">Subscribe to Events</button>

    <script>
        let ws = null;
        let eventSource = null;
        
        function connect() {
            ws = new WebSocket('ws://localhost:8080/ws');
            
            ws.onopen = function() {
                document.getElementById('status').textContent = 'Connected';
                addMessage('Connected to server');
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                addMessage('Received: ' + JSON.stringify(data));
            };
            
            ws.onclose = function() {
                document.getElementById('status').textContent = 'Disconnected';
                addMessage('Disconnected from server');
            };
            
            ws.onerror = function(error) {
                addMessage('Error: ' + error);
            };
        }
        
        function disconnect() {
            if (ws) {
                ws.close();
            }
        }
        
        function sendMessage() {
            const input = document.getElementById('input');
            const message = input.value;
            
            if (ws && ws.readyState === WebSocket.OPEN && message) {
                ws.send(JSON.stringify({message: message}));
                input.value = '';
            }
        }
        
        function handleKeyPress(event) {
            if (event.key === 'Enter') {
                sendMessage();
            }
        }
        
        function addMessage(message) {
            const messages = document.getElementById('messages');
            const div = document.createElement('div');
            div.textContent = new Date().toLocaleTimeString() + ': ' + message;
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
        }
        
        function subscribeToEvents() {
            eventSource = new EventSource('http://localhost:8080/events');
            
            eventSource.addEventListener('user-update', function(event) {
                const data = JSON.parse(event.data);
                addEvent('User Update: ' + JSON.stringify(data));
            });
            
            eventSource.onerror = function(error) {
                addEvent('SSE Error: ' + error);
            };
        }
        
        function addEvent(message) {
            const events = document.getElementById('events');
            const div = document.createElement('div');
            div.textContent = new Date().toLocaleTimeString() + ': ' + message;
            events.appendChild(div);
        }
    </script>
</body>
</html>`,

    'examples/performance-test.clj': `(ns performance-test
  (:require [clj-http.client :as client]
            [clojure.core.async :as async]
            [clojure.tools.logging :as log]
            [cheshire.core :as json]
            [io.pedestal.log :as pedestal-log]))

(def base-url "http://localhost:8080")

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
  (make-request :post (str base-url "/auth/register")
                {:body (json/generate-string user-data)}))

(defn login-user [credentials]
  (make-request :post (str base-url "/auth/login")
                {:body (json/generate-string credentials)}))

(defn get-users [token]
  (make-request :get (str base-url "/users")
                {:headers {"Authorization" (str "Bearer " token)}}))

(defn test-async-processing []
  (make-request :post (str base-url "/async-process")
                {:body (json/generate-string {:async true})}))

(defn run-load-test [concurrent-requests]
  (let [start-time (System/currentTimeMillis)
        results-chan (async/chan concurrent-requests)
        
        test-user {:name "Load Test User"
                  :email "loadtest@example.com"
                  :password "password123"}]
    
    (pedestal-log/info (str "Starting load test with " concurrent-requests " concurrent requests"))
    
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
        
        (pedestal-log/info (str "Load test completed in " duration "ms"))
        (pedestal-log/info (str "Successful requests: " successful))
        (pedestal-log/info (str "Failed requests: " failed))
        (pedestal-log/info (str "Requests per second: " (/ concurrent-requests (/ duration 1000.0))))
        
        {:duration duration
         :successful successful
         :failed failed
         :rps (/ concurrent-requests (/ duration 1000.0))}))))

(defn test-websocket-performance []
  (pedestal-log/info "Testing WebSocket performance...")
  ;; WebSocket performance testing would require a WebSocket client
  ;; This is a placeholder for actual WebSocket testing
  {:websocket-test "Not implemented"})

(defn run-all-tests []
  (pedestal-log/info "Starting comprehensive performance tests...")
  
  ;; Test different concurrency levels
  (doseq [concurrency [1 10 50 100]]
    (pedestal-log/info (str "Testing with " concurrency " concurrent requests"))
    (run-load-test concurrency)
    (Thread/sleep 2000)) ; Wait between tests
  
  ;; Test async processing
  (pedestal-log/info "Testing async processing...")
  (let [async-results (repeatedly 10 test-async-processing)]
    (pedestal-log/info (str "Async test results: " (count async-results))))
  
  ;; Test WebSocket performance
  (test-websocket-performance))

;; Run performance tests
(defn -main []
  (run-all-tests))

;; Example usage:
;; lein run -m performance-test`
  },

  dependencies: {
    'Clojure': '^1.11.1',
    'Pedestal': '^0.6.0',
    'Jetty': '^9.4.0',
    'Cheshire': '^5.11.0',
    'Buddy': '^3.0.0',
    'Component': '^1.1.0',
    'Schema': '^1.4.1',
    'Core.async': '^1.6.0'
  },

  commands: {
    dev: 'lein run-dev',
    build: 'lein uberjar',
    test: 'lein test',
    lint: 'lein eastwood',
    format: 'lein cljfmt fix',
    repl: 'lein repl',
    clean: 'lein clean',
    deps: 'lein deps',
    'test:watch': 'lein test-refresh',
    'test:coverage': 'lein cloverage',
    'perf:test': 'lein run -m performance-test',
    'docker:build': 'docker build -t pedestal-app .',
    'docker:run': 'docker run -p 8080:8080 pedestal-app',
    'docker:up': 'docker-compose up -d',
    'docker:down': 'docker-compose down'
  },

  ports: {
    dev: 8080,
    prod: 8080
  },

  examples: [
    {
      title: 'Interceptor Chain',
      description: 'Define interceptor chains for request processing',
      code: `(def routes
  #{["/users" :get (conj common-interceptors 
                        json-response 
                        auth/auth-interceptor
                        users/get-users)]})`
    },
    {
      title: 'Custom Interceptor',
      description: 'Create custom interceptors for specific functionality',
      code: `(def my-interceptor
  (interceptor
    {:name :my-interceptor
     :enter (fn [context] context)
     :leave (fn [context] context)}))`
    },
    {
      title: 'Async Processing',
      description: 'Handle async requests with core.async',
      code: `(def async-handler
  (interceptor
    {:name :async-handler
     :enter (fn [context]
              (let [response-chan (async/chan)]
                (async/go
                  (async/>! response-chan response))
                (assoc context :response response-chan)))}))`
    }
  ]
};