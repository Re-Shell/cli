import { BackendTemplate } from '../types';

export const clojureRingTemplate: BackendTemplate = {
  id: 'clojure-ring',
  name: 'clojure-ring',
  displayName: 'Clojure Ring/Compojure Web Framework',
  description: 'Composable web applications with Ring middleware and Compojure routing - the foundation of Clojure web development',
  framework: 'ring',
  language: 'clojure',
  version: '1.11',
  author: 'Re-Shell Team',


  icon: '💍',
  type: 'rest-api',
  complexity: 'intermediate',
  keywords: ['clojure', 'ring', 'compojure', 'functional', 'web', 'middleware', 'routing'],
  
  features: [
    'Ring middleware system',
    'Compojure routing',
    'Functional web development',
    'Composable architecture',
    'JSON API support',
    'Session management',
    'Authentication middleware',
    'Database integration',
    'Static file serving',
    'Request/response handling',
    'CORS support',
    'Testing utilities',
    'Hot reload development',
    'Immutable data structures'
  ],
  
  structure: {
    'project.clj': `(defproject ring-compojure-app "0.1.0-SNAPSHOT"
  :description "A Clojure web application using Ring and Compojure"
  :url "http://example.com"
  :min-lein-version "2.0.0"
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [ring/ring-core "1.9.6"]
                 [ring/ring-jetty-adapter "1.9.6"]
                 [ring/ring-devel "1.9.6"]
                 [ring/ring-json "0.5.1"]
                 [compojure "1.7.0"]
                 [hiccup "1.0.5"]
                 [cheshire "5.11.0"]
                 [com.stuartsierra/component "1.1.0"]
                 [org.clojure/java.jdbc "0.7.12"]
                 [org.postgresql/postgresql "42.5.1"]
                 [buddy/buddy-auth "3.0.323"]
                 [buddy/buddy-hashers "1.8.158"]
                 [buddy/buddy-sign "3.4.333"]
                 [clj-time "0.15.2"]
                 [environ "1.2.0"]
                 [mount "0.1.16"]
                 [org.clojure/tools.logging "1.2.4"]
                 [ch.qos.logback/logback-classic "1.4.5"]]
  :plugins [[lein-ring "0.12.6"]
            [lein-environ "1.2.0"]]
  :ring {:handler ring-compojure-app.handler/app
         :init ring-compojure-app.handler/init
         :destroy ring-compojure-app.handler/destroy}
  :profiles
  {:dev {:dependencies [[javax.servlet/servlet-api "2.5"]
                        [ring/ring-mock "0.4.0"]
                        [midje "1.10.4"]]
         :plugins [[lein-midje "3.2.1"]]}
   :uberjar {:aot :all}})`,

    'src/ring_compojure_app/core.clj': `(ns ring-compojure-app.core
  (:require [ring.adapter.jetty :as jetty]
            [ring-compojure-app.handler :as handler]
            [environ.core :refer [env]]
            [clojure.tools.logging :as log])
  (:gen-class))

(defn get-port []
  (Integer. (or (env :port) 3000)))

(defn -main [& args]
  (let [port (get-port)]
    (log/info (str "Starting server on port " port))
    (jetty/run-jetty handler/app {:port port :join? false})))`,

    'src/ring_compojure_app/handler.clj': `(ns ring-compojure-app.handler
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]
            [ring.middleware.json :refer [wrap-json-response wrap-json-body]]
            [ring.middleware.cors :refer [wrap-cors]]
            [ring.util.response :refer [response status content-type]]
            [ring-compojure-app.routes.api :as api]
            [ring-compojure-app.routes.auth :as auth]
            [ring-compojure-app.routes.users :as users]
            [ring-compojure-app.middleware.auth :as auth-middleware]
            [ring-compojure-app.db.core :as db]
            [clojure.tools.logging :as log]
            [hiccup.core :refer [html]]
            [hiccup.page :refer [html5 include-css include-js]]))

(defn init []
  (log/info "Initializing application...")
  (db/migrate!))

(defn destroy []
  (log/info "Shutting down application..."))

(defn home-page []
  (html5 [:head
          [:title "Ring/Compojure Application"]
          (include-css "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css")]
         [:body
          [:div.container
           [:div.row
            [:div.col-md-8.offset-md-2
             [:h1.mt-5 "Welcome to Ring/Compojure"]
             [:p.lead "A functional web framework for Clojure"]
             [:div.card.mt-4
              [:div.card-body
               [:h5.card-title "API Endpoints"]
               [:ul.list-group.list-group-flush
                [:li.list-group-item "GET /api/health - Health check"]
                [:li.list-group-item "POST /api/auth/login - User authentication"]
                [:li.list-group-item "GET /api/users - List users (requires auth)"]
                [:li.list-group-item "POST /api/users - Create user"]
                [:li.list-group-item "GET /api/users/:id - Get user by ID"]]]]
             [:div.mt-4
              [:a.btn.btn-primary {:href "/api/health"} "Test API"]]]]]
          (include-js "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js")]))

(defn health-check []
  (response {:status "ok" 
             :timestamp (java.time.Instant/now)
             :uptime (str (java.lang.management.ManagementFactory/getRuntimeMXBean).getUptime "ms")}))

(defroutes app-routes
  (GET "/" [] (home-page))
  (GET "/health" [] (health-check))
  (context "/api" [] api/routes)
  (context "/auth" [] auth/routes)
  (route/resources "/")
  (route/not-found "Not Found"))

(def app
  (-> app-routes
      (wrap-cors :access-control-allow-origin [#".*"]
                 :access-control-allow-methods [:get :put :post :delete :options]
                 :access-control-allow-headers ["Content-Type" "Authorization"])
      (wrap-json-body {:keywords? true})
      (wrap-json-response)
      (wrap-defaults (assoc site-defaults :security {:anti-forgery false}))))`,

    'src/ring_compojure_app/routes/api.clj': `(ns ring-compojure-app.routes.api
  (:require [compojure.core :refer :all]
            [ring.util.response :refer [response status]]
            [ring-compojure-app.routes.users :as users]
            [ring-compojure-app.routes.auth :as auth]
            [ring-compojure-app.middleware.auth :as auth-middleware]))

(defn api-health []
  (response {:status "healthy" 
             :service "ring-compojure-app"
             :version "0.1.0"
             :timestamp (java.time.Instant/now)}))

(defroutes routes
  (GET "/health" [] (api-health))
  (context "/auth" [] auth/routes)
  (context "/users" [] 
    (-> users/routes
        (auth-middleware/wrap-authenticated))))`,

    'src/ring_compojure_app/routes/users.clj': `(ns ring-compojure-app.routes.users
  (:require [compojure.core :refer :all]
            [ring.util.response :refer [response status]]
            [ring-compojure-app.db.users :as users-db]
            [ring-compojure-app.validation :as validation]
            [clojure.tools.logging :as log]
            [schema.core :as s]))

(defn get-users [request]
  (try
    (let [users (users-db/get-all-users)]
      (response {:users users}))
    (catch Exception e
      (log/error e "Error fetching users")
      (-> (response {:error "Failed to fetch users"})
          (status 500)))))

(defn get-user [request]
  (let [user-id (-> request :params :id Integer/parseInt)]
    (try
      (if-let [user (users-db/get-user-by-id user-id)]
        (response {:user user})
        (-> (response {:error "User not found"})
            (status 404)))
      (catch NumberFormatException e
        (-> (response {:error "Invalid user ID"})
            (status 400)))
      (catch Exception e
        (log/error e "Error fetching user")
        (-> (response {:error "Failed to fetch user"})
            (status 500))))))

(defn create-user [request]
  (let [user-data (:body request)]
    (try
      (if-let [validation-errors (validation/validate-user user-data)]
        (-> (response {:errors validation-errors})
            (status 400))
        (let [new-user (users-db/create-user! user-data)]
          (-> (response {:user new-user :message "User created successfully"})
              (status 201))))
      (catch Exception e
        (log/error e "Error creating user")
        (-> (response {:error "Failed to create user"})
            (status 500))))))

(defn update-user [request]
  (let [user-id (-> request :params :id Integer/parseInt)
        user-data (:body request)]
    (try
      (if-let [validation-errors (validation/validate-user-update user-data)]
        (-> (response {:errors validation-errors})
            (status 400))
        (if-let [updated-user (users-db/update-user! user-id user-data)]
          (response {:user updated-user :message "User updated successfully"})
          (-> (response {:error "User not found"})
              (status 404))))
      (catch NumberFormatException e
        (-> (response {:error "Invalid user ID"})
            (status 400)))
      (catch Exception e
        (log/error e "Error updating user")
        (-> (response {:error "Failed to update user"})
            (status 500))))))

(defn delete-user [request]
  (let [user-id (-> request :params :id Integer/parseInt)]
    (try
      (if (users-db/delete-user! user-id)
        (response {:message "User deleted successfully"})
        (-> (response {:error "User not found"})
            (status 404)))
      (catch NumberFormatException e
        (-> (response {:error "Invalid user ID"})
            (status 400)))
      (catch Exception e
        (log/error e "Error deleting user")
        (-> (response {:error "Failed to delete user"})
            (status 500))))))

(defroutes routes
  (GET "/" [] get-users)
  (GET "/:id" [] get-user)
  (POST "/" [] create-user)
  (PUT "/:id" [] update-user)
  (DELETE "/:id" [] delete-user))`,

    'src/ring_compojure_app/routes/auth.clj': `(ns ring-compojure-app.routes.auth
  (:require [compojure.core :refer :all]
            [ring.util.response :refer [response status]]
            [ring-compojure-app.db.users :as users-db]
            [ring-compojure-app.services.auth :as auth-service]
            [ring-compojure-app.validation :as validation]
            [clojure.tools.logging :as log]
            [buddy.hashers :as hashers]))

(defn login [request]
  (let [{:keys [email password]} (:body request)]
    (try
      (if-let [validation-errors (validation/validate-login {:email email :password password})]
        (-> (response {:errors validation-errors})
            (status 400))
        (if-let [user (users-db/get-user-by-email email)]
          (if (hashers/check password (:password user))
            (let [token (auth-service/generate-token user)]
              (response {:token token 
                        :user (dissoc user :password)
                        :message "Login successful"}))
            (-> (response {:error "Invalid credentials"})
                (status 401)))
          (-> (response {:error "Invalid credentials"})
              (status 401))))
      (catch Exception e
        (log/error e "Error during login")
        (-> (response {:error "Authentication failed"})
            (status 500))))))

(defn register [request]
  (let [user-data (:body request)]
    (try
      (if-let [validation-errors (validation/validate-user user-data)]
        (-> (response {:errors validation-errors})
            (status 400))
        (if (users-db/get-user-by-email (:email user-data))
          (-> (response {:error "User already exists"})
              (status 409))
          (let [hashed-password (hashers/derive (:password user-data))
                new-user (users-db/create-user! 
                          (assoc user-data :password hashed-password))
                token (auth-service/generate-token new-user)]
            (-> (response {:token token 
                          :user (dissoc new-user :password)
                          :message "Registration successful"})
                (status 201)))))
      (catch Exception e
        (log/error e "Error during registration")
        (-> (response {:error "Registration failed"})
            (status 500))))))

(defn logout [request]
  (response {:message "Logout successful"}))

(defn profile [request]
  (let [user (:user request)]
    (response {:user (dissoc user :password)})))

(defroutes routes
  (POST "/login" [] login)
  (POST "/register" [] register)
  (POST "/logout" [] logout)
  (GET "/profile" [] profile))`,

    'src/ring_compojure_app/middleware/auth.clj': `(ns ring-compojure-app.middleware.auth
  (:require [buddy.auth :refer [authenticated?]]
            [buddy.auth.backends.token :refer [token-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]
            [ring.util.response :refer [response status]]
            [ring-compojure-app.services.auth :as auth-service]
            [clojure.tools.logging :as log]))

(defn token-authfn [request token]
  (try
    (auth-service/verify-token token)
    (catch Exception e
      (log/debug e "Token verification failed")
      nil)))

(def auth-backend
  (token-backend {:authfn token-authfn
                  :token-name "Authorization"
                  :options {:header-name "Authorization"
                           :header-prefix "Bearer "}}))

(defn unauthorized-handler [request metadata]
  (-> (response {:error "Unauthorized"})
      (status 401)))

(defn wrap-authenticated [handler]
  (-> handler
      (wrap-authentication auth-backend)
      (wrap-authorization auth-backend)
      (wrap-authorization unauthorized-handler)))

(defn require-auth [handler]
  (fn [request]
    (if (authenticated? request)
      (handler request)
      (unauthorized-handler request nil))))`,

    'src/ring_compojure_app/services/auth.clj': `(ns ring-compojure-app.services.auth
  (:require [buddy.sign.jwt :as jwt]
            [buddy.core.keys :as keys]
            [clj-time.core :as time]
            [clj-time.coerce :as coerce]
            [environ.core :refer [env]]
            [ring-compojure-app.db.users :as users-db]
            [clojure.tools.logging :as log]))

(def secret (or (env :jwt-secret) "default-secret-key-change-in-production"))

(defn generate-token [user]
  (let [exp (time/plus (time/now) (time/hours 24))
        claims {:user-id (:id user)
                :email (:email user)
                :exp (coerce/to-epoch exp)}]
    (jwt/sign claims secret)))

(defn verify-token [token]
  (try
    (let [claims (jwt/unsign token secret)
          user-id (:user-id claims)]
      (when user-id
        (users-db/get-user-by-id user-id)))
    (catch Exception e
      (log/debug e "Token verification failed")
      nil)))

(defn extract-token [request]
  (when-let [auth-header (get-in request [:headers "authorization"])]
    (when (.startsWith auth-header "Bearer ")
      (.substring auth-header 7))))`,

    'src/ring_compojure_app/db/core.clj': `(ns ring-compojure-app.db.core
  (:require [clojure.java.jdbc :as jdbc]
            [environ.core :refer [env]]
            [mount.core :refer [defstate]]
            [clojure.tools.logging :as log]))

(def db-spec 
  {:subprotocol "postgresql"
   :subname (or (env :database-url) "//localhost:5432/ring_compojure_app")
   :user (or (env :database-user) "postgres")
   :password (or (env :database-password) "password")})

(defstate db
  :start (do
           (log/info "Connecting to database...")
           db-spec)
  :stop (log/info "Disconnecting from database..."))

(defn migrate! []
  (log/info "Running database migrations...")
  (try
    (jdbc/execute! db
      ["CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          first_name VARCHAR(255),
          last_name VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"])
    
    (jdbc/execute! db
      ["CREATE TABLE IF NOT EXISTS todos (
          id SERIAL PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          completed BOOLEAN DEFAULT FALSE,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"])
    
    (log/info "Database migrations completed successfully")
    (catch Exception e
      (log/error e "Database migration failed"))))

(defn query [sql-params]
  (jdbc/query db sql-params))

(defn execute! [sql-params]
  (jdbc/execute! db sql-params))

(defn insert! [table row]
  (first (jdbc/insert! db table row)))

(defn update! [table set-map where-clause]
  (jdbc/update! db table set-map where-clause))

(defn delete! [table where-clause]
  (jdbc/delete! db table where-clause))`,

    'src/ring_compojure_app/db/users.clj': `(ns ring-compojure-app.db.users
  (:require [ring-compojure-app.db.core :as db]
            [clojure.tools.logging :as log]
            [clj-time.core :as time]
            [clj-time.coerce :as coerce]))

(defn get-all-users []
  (db/query ["SELECT id, email, first_name, last_name, created_at, updated_at FROM users ORDER BY created_at DESC"]))

(defn get-user-by-id [id]
  (first (db/query ["SELECT * FROM users WHERE id = ?" id])))

(defn get-user-by-email [email]
  (first (db/query ["SELECT * FROM users WHERE email = ?" email])))

(defn create-user! [user-data]
  (let [now (coerce/to-sql-time (time/now))
        user-record (merge user-data {:created_at now :updated_at now})]
    (db/insert! :users user-record)))

(defn update-user! [id user-data]
  (let [now (coerce/to-sql-time (time/now))
        updated-data (merge user-data {:updated_at now})]
    (when (pos? (first (db/update! :users updated-data ["id = ?" id])))
      (get-user-by-id id))))

(defn delete-user! [id]
  (pos? (first (db/delete! :users ["id = ?" id]))))

(defn user-exists? [email]
  (some? (get-user-by-email email)))`,

    'src/ring_compojure_app/validation.clj': `(ns ring-compojure-app.validation
  (:require [schema.core :as s]
            [clojure.string :as str]))

(def UserSchema
  {:email s/Str
   :password s/Str
   :first_name s/Str
   :last_name s/Str})

(def UserUpdateSchema
  {:email (s/maybe s/Str)
   :first_name (s/maybe s/Str)
   :last_name (s/maybe s/Str)})

(def LoginSchema
  {:email s/Str
   :password s/Str})

(defn valid-email? [email]
  (re-matches #"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" email))

(defn validate-user [user-data]
  (let [errors []]
    (cond-> errors
      (str/blank? (:email user-data))
      (conj "Email is required")
      
      (and (:email user-data) (not (valid-email? (:email user-data))))
      (conj "Email format is invalid")
      
      (str/blank? (:password user-data))
      (conj "Password is required")
      
      (and (:password user-data) (< (count (:password user-data)) 6))
      (conj "Password must be at least 6 characters long")
      
      (str/blank? (:first_name user-data))
      (conj "First name is required")
      
      (str/blank? (:last_name user-data))
      (conj "Last name is required")
      
      :always
      (seq))))

(defn validate-user-update [user-data]
  (let [errors []]
    (cond-> errors
      (and (:email user-data) (not (valid-email? (:email user-data))))
      (conj "Email format is invalid")
      
      (and (:password user-data) (< (count (:password user-data)) 6))
      (conj "Password must be at least 6 characters long")
      
      :always
      (seq))))

(defn validate-login [login-data]
  (let [errors []]
    (cond-> errors
      (str/blank? (:email login-data))
      (conj "Email is required")
      
      (str/blank? (:password login-data))
      (conj "Password is required")
      
      :always
      (seq))))`,

    'test/ring_compojure_app/handler_test.clj': `(ns ring-compojure-app.handler-test
  (:require [clojure.test :refer :all]
            [ring.mock.request :as mock]
            [ring-compojure-app.handler :refer :all]
            [cheshire.core :as json]
            [ring-compojure-app.db.core :as db]))

(deftest test-home-page
  (testing "home page"
    (let [response (app (mock/request :get "/"))]
      (is (= (:status response) 200))
      (is (re-find #"Ring/Compojure" (:body response))))))

(deftest test-health-check
  (testing "health check endpoint"
    (let [response (app (mock/request :get "/health"))]
      (is (= (:status response) 200))
      (let [body (json/parse-string (:body response) true)]
        (is (= (:status body) "ok"))
        (is (contains? body :timestamp))
        (is (contains? body :uptime))))))

(deftest test-api-health
  (testing "API health endpoint"
    (let [response (app (mock/request :get "/api/health"))]
      (is (= (:status response) 200))
      (let [body (json/parse-string (:body response) true)]
        (is (= (:status body) "healthy"))
        (is (= (:service body) "ring-compojure-app"))
        (is (= (:version body) "0.1.0"))))))

(deftest test-not-found
  (testing "not found route"
    (let [response (app (mock/request :get "/invalid"))]
      (is (= (:status response) 404)))))

(deftest test-cors-headers
  (testing "CORS headers are present"
    (let [response (app (mock/request :options "/api/health"))]
      (is (contains? (:headers response) "Access-Control-Allow-Origin")))))`,

    'test/ring_compojure_app/routes/users_test.clj': `(ns ring-compojure-app.routes.users-test
  (:require [clojure.test :refer :all]
            [ring.mock.request :as mock]
            [ring-compojure-app.handler :refer [app]]
            [ring-compojure-app.db.core :as db]
            [ring-compojure-app.db.users :as users-db]
            [cheshire.core :as json]
            [buddy.hashers :as hashers]))

(def test-user
  {:email "test@example.com"
   :password "password123"
   :first_name "John"
   :last_name "Doe"})

(defn create-test-user []
  (users-db/create-user! 
    (assoc test-user :password (hashers/derive (:password test-user)))))

(defn get-auth-token []
  (let [user (create-test-user)
        login-request (-> (mock/request :post "/auth/login")
                         (mock/json-body (select-keys test-user [:email :password])))
        response (app login-request)]
    (when (= 200 (:status response))
      (-> response :body (json/parse-string true) :token))))

(deftest test-create-user
  (testing "Create user with valid data"
    (let [user-data {:email "newuser@example.com"
                    :password "password123"
                    :first_name "Jane"
                    :last_name "Smith"}
          request (-> (mock/request :post "/api/users")
                     (mock/json-body user-data))
          response (app request)]
      (is (= 201 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (= "User created successfully" (:message body)))
        (is (= (:email user-data) (get-in body [:user :email]))))))

  (testing "Create user with invalid email"
    (let [user-data {:email "invalid-email"
                    :password "password123"
                    :first_name "Jane"
                    :last_name "Smith"}
          request (-> (mock/request :post "/api/users")
                     (mock/json-body user-data))
          response (app request)]
      (is (= 400 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (contains? (:errors body) "Email format is invalid")))))

  (testing "Create user with missing required fields"
    (let [user-data {:email "test@example.com"}
          request (-> (mock/request :post "/api/users")
                     (mock/json-body user-data))
          response (app request)]
      (is (= 400 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (seq (:errors body)))))))

(deftest test-get-users
  (testing "Get users without authentication"
    (let [response (app (mock/request :get "/api/users"))]
      (is (= 401 (:status response)))))

  (testing "Get users with authentication"
    (when-let [token (get-auth-token)]
      (let [request (-> (mock/request :get "/api/users")
                       (mock/header "Authorization" (str "Bearer " token)))
            response (app request)]
        (is (= 200 (:status response)))
        (let [body (json/parse-string (:body response) true)]
          (is (contains? body :users))
          (is (vector? (:users body))))))))

(deftest test-get-user-by-id
  (testing "Get user by ID with authentication"
    (when-let [token (get-auth-token)]
      (let [user (create-test-user)
            request (-> (mock/request :get (str "/api/users/" (:id user)))
                       (mock/header "Authorization" (str "Bearer " token)))
            response (app request)]
        (is (= 200 (:status response)))
        (let [body (json/parse-string (:body response) true)]
          (is (= (:id user) (get-in body [:user :id])))
          (is (= (:email user) (get-in body [:user :email])))))))

  (testing "Get non-existent user"
    (when-let [token (get-auth-token)]
      (let [request (-> (mock/request :get "/api/users/99999")
                       (mock/header "Authorization" (str "Bearer " token)))
            response (app request)]
        (is (= 404 (:status response)))))))`,

    'test/ring_compojure_app/routes/auth_test.clj': `(ns ring-compojure-app.routes.auth-test
  (:require [clojure.test :refer :all]
            [ring.mock.request :as mock]
            [ring-compojure-app.handler :refer [app]]
            [ring-compojure-app.db.users :as users-db]
            [cheshire.core :as json]
            [buddy.hashers :as hashers]))

(def test-user
  {:email "auth-test@example.com"
   :password "password123"
   :first_name "Auth"
   :last_name "Test"})

(defn create-test-user []
  (users-db/create-user! 
    (assoc test-user :password (hashers/derive (:password test-user)))))

(deftest test-register
  (testing "Register new user"
    (let [user-data {:email "register@example.com"
                    :password "password123"
                    :first_name "Register"
                    :last_name "Test"}
          request (-> (mock/request :post "/auth/register")
                     (mock/json-body user-data))
          response (app request)]
      (is (= 201 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (= "Registration successful" (:message body)))
        (is (contains? body :token))
        (is (contains? body :user))
        (is (= (:email user-data) (get-in body [:user :email]))))))

  (testing "Register with existing email"
    (let [_ (create-test-user)
          request (-> (mock/request :post "/auth/register")
                     (mock/json-body test-user))
          response (app request)]
      (is (= 409 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (= "User already exists" (:error body))))))

  (testing "Register with invalid data"
    (let [user-data {:email "invalid"
                    :password "123"}
          request (-> (mock/request :post "/auth/register")
                     (mock/json-body user-data))
          response (app request)]
      (is (= 400 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (seq (:errors body)))))))

(deftest test-login
  (testing "Login with valid credentials"
    (let [_ (create-test-user)
          login-data (select-keys test-user [:email :password])
          request (-> (mock/request :post "/auth/login")
                     (mock/json-body login-data))
          response (app request)]
      (is (= 200 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (= "Login successful" (:message body)))
        (is (contains? body :token))
        (is (contains? body :user))
        (is (= (:email test-user) (get-in body [:user :email]))))))

  (testing "Login with invalid credentials"
    (let [_ (create-test-user)
          login-data {:email (:email test-user) :password "wrongpassword"}
          request (-> (mock/request :post "/auth/login")
                     (mock/json-body login-data))
          response (app request)]
      (is (= 401 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (= "Invalid credentials" (:error body))))))

  (testing "Login with non-existent user"
    (let [login-data {:email "nonexistent@example.com" :password "password123"}
          request (-> (mock/request :post "/auth/login")
                     (mock/json-body login-data))
          response (app request)]
      (is (= 401 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (= "Invalid credentials" (:error body))))))

  (testing "Login with missing data"
    (let [login-data {:email "test@example.com"}
          request (-> (mock/request :post "/auth/login")
                     (mock/json-body login-data))
          response (app request)]
      (is (= 400 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (seq (:errors body)))))))

(deftest test-logout
  (testing "Logout endpoint"
    (let [request (mock/request :post "/auth/logout")
          response (app request)]
      (is (= 200 (:status response)))
      (let [body (json/parse-string (:body response) true)]
        (is (= "Logout successful" (:message body)))))))`,

    'resources/logback.xml': `<configuration>
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
    
    <logger name="ring-compojure-app" level="DEBUG" />
    <logger name="org.eclipse.jetty" level="WARN" />
    <logger name="org.postgresql" level="WARN" />
</configuration>`,

    'resources/public/css/style.css': `/* Ring/Compojure Application Styles */
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: #f8f9fa;
}

.hero-section {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 60px 0;
    margin-bottom: 40px;
}

.hero-section h1 {
    font-size: 3rem;
    font-weight: 700;
    margin-bottom: 20px;
}

.hero-section .lead {
    font-size: 1.25rem;
    margin-bottom: 30px;
}

.api-card {
    border: none;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    transition: transform 0.2s ease-in-out;
}

.api-card:hover {
    transform: translateY(-5px);
}

.endpoint-list {
    list-style: none;
    padding: 0;
}

.endpoint-list li {
    padding: 10px 15px;
    margin: 5px 0;
    background: #f8f9fa;
    border-radius: 5px;
    border-left: 4px solid #007bff;
}

.method-get { border-left-color: #28a745; }
.method-post { border-left-color: #007bff; }
.method-put { border-left-color: #ffc107; }
.method-delete { border-left-color: #dc3545; }

.footer {
    background-color: #343a40;
    color: white;
    text-align: center;
    padding: 20px 0;
    margin-top: 60px;
}

.btn-primary {
    background: linear-gradient(45deg, #007bff, #0056b3);
    border: none;
    padding: 12px 30px;
    font-weight: 600;
    border-radius: 25px;
    transition: all 0.3s ease;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 123, 255, 0.3);
}`,

    'Dockerfile': `FROM clojure:openjdk-11-lein-2.9.8

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

# Set environment variables
ENV PORT=3000
ENV DATABASE_URL=jdbc:postgresql://localhost:5432/ring_compojure_app

# Run the application
CMD ["java", "-jar", "target/ring-compojure-app-0.1.0-SNAPSHOT-standalone.jar"]`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - PORT=3000
      - DATABASE_URL=jdbc:postgresql://postgres:5432/ring_compojure_app
      - DATABASE_USER=postgres
      - DATABASE_PASSWORD=password
      - JWT_SECRET=your-secret-key-change-in-production
    depends_on:
      - postgres
    volumes:
      - ./logs:/app/logs

  postgres:
    image: postgres:14
    environment:
      - POSTGRES_DB=ring_compojure_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:`,

    'dev/user.clj': `(ns user
  (:require [mount.core :as mount]
            [ring-compojure-app.core :refer [app]]
            [ring-compojure-app.db.core :as db]
            [clojure.tools.namespace.repl :refer [refresh]]
            [clojure.repl :refer :all]
            [clojure.pprint :refer [pprint]]))

(defn start []
  (mount/start))

(defn stop []
  (mount/stop))

(defn restart []
  (stop)
  (refresh)
  (start))

(defn reset []
  (mount/stop)
  (refresh :after 'user/start))

(comment
  ;; Start the system
  (start)
  
  ;; Stop the system
  (stop)
  
  ;; Restart the system
  (restart)
  
  ;; Reset the system
  (reset)
  
  ;; Run migrations
  (db/migrate!)
  
  ;; Test database connection
  (db/query ["SELECT 1 as test"])
  
  ;; Test routes
  (app {:request-method :get :uri "/"})
  (app {:request-method :get :uri "/health"})
  )`,

    'README.md': `# Ring/Compojure Clojure Web Application

A functional web application built with Ring and Compojure - the foundation of Clojure web development.

## Features

- **Ring Middleware System**: Composable request/response processing
- **Compojure Routing**: Elegant URL routing with pattern matching
- **Functional Architecture**: Immutable data structures and pure functions
- **JSON API**: RESTful API with automatic JSON serialization
- **JWT Authentication**: Secure token-based authentication
- **Database Integration**: PostgreSQL with connection pooling
- **Input Validation**: Schema-based validation with detailed error messages
- **Comprehensive Testing**: Unit and integration tests
- **Development Tools**: REPL-driven development with hot reload
- **Docker Support**: Production-ready containerization

## Quick Start

### Prerequisites

- Java 11 or later
- Leiningen 2.9.8 or later
- PostgreSQL (or use Docker Compose)

### Installation

\`\`\`bash
# Clone the project
git clone <repository-url>
cd ring-compojure-app

# Install dependencies
lein deps

# Start PostgreSQL (or use Docker Compose)
docker-compose up -d postgres

# Run migrations
lein repl
user=> (require '[ring-compojure-app.db.core :as db])
user=> (db/migrate!)

# Start the development server
lein ring server-headless
\`\`\`

The application will be available at \`http://localhost:3000\`

### Development

\`\`\`bash
# Start REPL for interactive development
lein repl

# Run tests
lein test

# Run specific test namespace
lein test ring-compojure-app.routes.users-test

# Build uberjar
lein uberjar

# Run with Docker Compose
docker-compose up
\`\`\`

## Project Structure

\`\`\`
├── src/ring_compojure_app/
│   ├── core.clj                 # Application entry point
│   ├── handler.clj              # Main request handler and routing
│   ├── routes/
│   │   ├── api.clj              # API route definitions
│   │   ├── auth.clj             # Authentication routes
│   │   └── users.clj            # User management routes
│   ├── middleware/
│   │   └── auth.clj             # Authentication middleware
│   ├── services/
│   │   └── auth.clj             # Authentication service
│   ├── db/
│   │   ├── core.clj             # Database connection and utilities
│   │   └── users.clj            # User database operations
│   └── validation.clj           # Input validation schemas
├── test/                        # Test files
├── resources/                   # Static resources and configuration
├── dev/                         # Development utilities
├── project.clj                  # Project configuration
└── README.md                    # This file
\`\`\`

## API Endpoints

### Authentication
- \`POST /auth/register\` - User registration
- \`POST /auth/login\` - User login
- \`POST /auth/logout\` - User logout
- \`GET /auth/profile\` - Get current user profile

### Users (requires authentication)
- \`GET /api/users\` - List all users
- \`GET /api/users/:id\` - Get user by ID
- \`POST /api/users\` - Create new user
- \`PUT /api/users/:id\` - Update user
- \`DELETE /api/users/:id\` - Delete user

### System
- \`GET /health\` - Application health check
- \`GET /api/health\` - API health check

## Configuration

### Environment Variables

\`\`\`bash
# Database
DATABASE_URL=jdbc:postgresql://localhost:5432/ring_compojure_app
DATABASE_USER=postgres
DATABASE_PASSWORD=password

# JWT
JWT_SECRET=your-secret-key-change-in-production

# Server
PORT=3000
\`\`\`

### Development Configuration

Edit \`project.clj\` for development settings:

\`\`\`clojure
:profiles
{:dev {:dependencies [[ring/ring-mock "0.4.0"]
                      [midje "1.10.4"]]
       :plugins [[lein-midje "3.2.1"]]
       :env {:database-url "jdbc:postgresql://localhost:5432/ring_compojure_app_dev"}}}
\`\`\`

## Ring Middleware

The application uses several Ring middleware components:

\`\`\`clojure
(def app
  (-> app-routes
      (wrap-cors ...)           ; CORS handling
      (wrap-json-body ...)      ; JSON request parsing
      (wrap-json-response ...)  ; JSON response formatting
      (wrap-defaults ...)))     ; Default middleware stack
\`\`\`

### Custom Middleware

\`\`\`clojure
(defn wrap-logging [handler]
  (fn [request]
    (log/info "Request:" (:request-method request) (:uri request))
    (handler request)))
\`\`\`

## Database

### Schema

\`\`\`sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Todos table
CREATE TABLE todos (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    completed BOOLEAN DEFAULT FALSE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
\`\`\`

### Database Operations

\`\`\`clojure
;; Query users
(db/query ["SELECT * FROM users WHERE email = ?" email])

;; Insert user
(db/insert! :users {:email "user@example.com" :password "hashed"})

;; Update user
(db/update! :users {:first_name "John"} ["id = ?" user-id])

;; Delete user
(db/delete! :users ["id = ?" user-id])
\`\`\`

## Authentication

### JWT Token Generation

\`\`\`clojure
(defn generate-token [user]
  (let [exp (time/plus (time/now) (time/hours 24))
        claims {:user-id (:id user)
                :email (:email user)
                :exp (coerce/to-epoch exp)}]
    (jwt/sign claims secret)))
\`\`\`

### Protected Routes

\`\`\`clojure
(defroutes protected-routes
  (GET "/profile" [] profile-handler)
  (GET "/users" [] users-handler))

(def app
  (-> protected-routes
      (wrap-authenticated)))
\`\`\`

## Validation

### Schema Validation

\`\`\`clojure
(def UserSchema
  {:email s/Str
   :password s/Str
   :first_name s/Str
   :last_name s/Str})

(defn validate-user [user-data]
  (try
    (s/validate UserSchema user-data)
    nil
    (catch Exception e
      {:errors [(str "Validation error: " (.getMessage e))]})))
\`\`\`

### Custom Validation

\`\`\`clojure
(defn valid-email? [email]
  (re-matches #"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" email))

(defn validate-email [email]
  (when-not (valid-email? email)
    "Invalid email format"))
\`\`\`

## Testing

### Unit Tests

\`\`\`clojure
(deftest test-user-creation
  (testing "Create user with valid data"
    (let [user-data {:email "test@example.com" :password "password123"}
          result (create-user! user-data)]
      (is (= (:email result) (:email user-data))))))
\`\`\`

### Integration Tests

\`\`\`clojure
(deftest test-api-endpoint
  (testing "GET /api/users"
    (let [response (app (mock/request :get "/api/users"))]
      (is (= 200 (:status response))))))
\`\`\`

### Running Tests

\`\`\`bash
# Run all tests
lein test

# Run specific test
lein test ring-compojure-app.routes.users-test

# Run tests with coverage
lein with-profile +test cloverage

# Run tests in watch mode
lein test-refresh
\`\`\`

## REPL Development

### Starting REPL

\`\`\`bash
lein repl
\`\`\`

### Common REPL Commands

\`\`\`clojure
;; Load user namespace
(load-file "dev/user.clj")

;; Start system
(start)

;; Stop system
(stop)

;; Restart system
(restart)

;; Test database
(db/query ["SELECT 1 as test"])

;; Test routes
(app {:request-method :get :uri "/"})
\`\`\`

## Deployment

### Docker

\`\`\`bash
# Build image
docker build -t ring-compojure-app .

# Run container
docker run -p 3000:3000 ring-compojure-app

# Use Docker Compose
docker-compose up
\`\`\`

### Uberjar

\`\`\`bash
# Build uberjar
lein uberjar

# Run uberjar
java -jar target/ring-compojure-app-0.1.0-SNAPSHOT-standalone.jar
\`\`\`

### Production Configuration

\`\`\`bash
# Environment variables
export DATABASE_URL="jdbc:postgresql://prod-db:5432/ring_compojure_app"
export JWT_SECRET="your-production-secret"
export PORT=8080

# Run application
java -jar app.jar
\`\`\`

## Best Practices

### Code Organization

1. **Separate Concerns**: Keep routes, handlers, and business logic separate
2. **Pure Functions**: Use pure functions where possible
3. **Immutable Data**: Leverage Clojure's immutable data structures
4. **Error Handling**: Use proper exception handling and validation

### Performance

1. **Connection Pooling**: Use connection pooling for database operations
2. **Caching**: Implement caching for frequently accessed data
3. **Lazy Evaluation**: Use lazy sequences for large datasets
4. **Profiling**: Use profiling tools to identify bottlenecks

### Security

1. **Input Validation**: Always validate user input
2. **SQL Injection**: Use parameterized queries
3. **XSS Prevention**: Sanitize output
4. **CSRF Protection**: Enable CSRF protection for forms

## Learning Resources

- [Ring Documentation](https://github.com/ring-clojure/ring)
- [Compojure Documentation](https://github.com/weavejester/compojure)
- [Clojure for the Brave and True](https://www.braveclojure.com/)
- [Clojure Web Development](https://pragprog.com/titles/dswdcloj3/web-development-with-clojure/)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License.`
  }
};