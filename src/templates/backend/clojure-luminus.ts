import { BackendTemplate } from '../types';

export const clojureLuminusTemplate: BackendTemplate = {
  id: 'clojure-luminus',
  name: 'clojure-luminus',
  displayName: 'Clojure Luminus Full-Stack Framework',
  description: 'Production-ready full-stack Clojure web framework with batteries included - database, authentication, and deployment',
  framework: 'luminus',
  language: 'clojure',
  version: '4.41',
  author: 'Re-Shell Team',

  icon: '🏛️',
  type: 'full-stack',
  complexity: 'intermediate',
  keywords: ['clojure', 'luminus', 'full-stack', 'web', 'database', 'authentication', 'production'],
  
  features: [
    'Full-stack web framework',
    'Database migrations',
    'Authentication system',
    'Hot code reloading',
    'Asset pipeline',
    'Production deployment',
    'Docker integration',
    'ClojureScript frontend',
    'RESTful API',
    'Session management',
    'Email integration',
    'Logging system',
    'Testing framework',
    'Configuration management'
  ],
  
  structure: {
    'project.clj': `(defproject luminus-app "0.1.0"
  :description "A Luminus application"
  :url "http://example.com"
  
  :dependencies [[ch.qos.logback/logback-classic "1.4.5"]
                 [cheshire "5.11.0"]
                 [clojure.java-time "1.2.0"]
                 [com.fasterxml.jackson.core/jackson-core "2.14.2"]
                 [com.fasterxml.jackson.core/jackson-databind "2.14.2"]
                 [cprop "0.1.19"]
                 [expound "0.9.0"]
                 [funcool/struct "1.4.0"]
                 [json-html "0.4.7"]
                 [luminus-jetty "0.2.1"]
                 [luminus-migrations "0.7.5"]
                 [luminus-transit "0.1.5"]
                 [luminus/ring-ttl-session "0.3.3"]
                 [markdown-clj "1.11.4"]
                 [metosin/malli "0.10.1"]
                 [metosin/muuntaja "0.6.8"]
                 [metosin/reitit "0.6.0"]
                 [metosin/ring-http-response "0.9.3"]
                 [mount "0.1.16"]
                 [nrepl "1.0.0"]
                 [org.clojure/clojure "1.11.1"]
                 [org.clojure/tools.cli "1.0.214"]
                 [org.clojure/tools.logging "1.2.4"]
                 [org.postgresql/postgresql "42.5.1"]
                 [org.webjars.npm/bulma "0.9.4"]
                 [org.webjars.npm/material-icons "1.13.1"]
                 [org.webjars/webjars-locator "0.46"]
                 [ring-webjars "0.2.0"]
                 [ring/ring-core "1.9.6"]
                 [ring/ring-defaults "0.3.4"]
                 [selmer "1.12.55"]
                 [luminus-http-kit "0.1.9"]
                 [buddy/buddy-auth "3.0.323"]
                 [buddy/buddy-core "1.10.413"]
                 [buddy/buddy-hashers "1.8.158"]
                 [buddy/buddy-sign "3.4.333"]
                 [conman "0.9.6"]
                 [org.clojure/java.jdbc "0.7.12"]
                 [migratus "1.4.9"]
                 [mount "0.1.16"]
                 [cprop "0.1.19"]]

  :min-lein-version "2.0.0"
  
  :source-paths ["src/clj"]
  :test-paths ["test/clj"]
  :resource-paths ["resources" "target/cljsbuild"]
  :target-path "target/%s/"
  :main ^:skip-aot luminus-app.core

  :plugins [[lein-cljsbuild "1.1.8"]
            [lein-uberwar "0.2.0"]
            [migratus-lein "0.7.3"]
            [lein-cprop "1.0.3"]
            [lein-cloverage "1.2.4"]]
  
  :clean-targets ^{:protect false}
  [:target-path [:cljsbuild :builds :app :compiler :output-dir] [:cljsbuild :builds :app :compiler :output-to]]
  
  :uberwar
  {:handler luminus-app.handler/app
   :init luminus-app.handler/init
   :destroy luminus-app.handler/destroy
   :name "luminus-app.war"}

  :profiles
  {:uberjar {:omit-source true
             :prep-tasks ["compile" ["cljsbuild" "once" "min"]]
             :cljsbuild{:builds
                        {:min {:source-paths ["src/cljs"]
                               :compiler
                               {:output-dir "target/cljsbuild/public/js"
                                :output-to "target/cljsbuild/public/js/app.js"
                                :source-map "target/cljsbuild/public/js/app.js.map"
                                :optimizations :advanced
                                :pretty-print false
                                :closure-warnings {:externs-validation :off
                                                   :non-standard-jsdoc :off}
                                :externs ["react/externs/react.js"]}}}}
             :aot :all
             :uberjar-name "luminus-app.jar"
             :source-paths ["env/prod/clj"]
             :resource-paths ["env/prod/resources"]}

   :dev           [:project/dev :profiles/dev]
   :test          [:project/test :profiles/test]

   :project/dev  {:jvm-opts ["-Dconf=dev-config.edn"]
                  :dependencies [[binaryage/devtools "1.0.7"]
                                 [cider/piggieback "0.5.3"]
                                 [doo "0.1.11"]
                                 [figwheel-sidecar "0.5.20"]
                                 [nrepl "1.0.0"]
                                 [pjstadig/humane-test-output "0.11.0"]
                                 [prone "2021-04-23"]
                                 [re-frisk "1.6.0"]
                                 [ring/ring-devel "1.9.6"]
                                 [ring/ring-mock "0.4.0"]
                                 [thheller/shadow-cljs "2.20.1"]]
                  :plugins      [[com.jakemccrary/lein-test-refresh "0.25.0"]
                                 [jonase/eastwood "1.3.0"]
                                 [cider/cider-nrepl "0.28.5"]]
                  :cljsbuild
                  {:builds
                   {:app
                    {:source-paths ["src/cljs"]
                     :figwheel {:on-jsload "luminus-app.core/mount-components"}
                     :compiler
                     {:output-to "target/cljsbuild/public/js/app.js"
                      :output-dir "target/cljsbuild/public/js/out"
                      :source-map true
                      :optimizations :none
                      :pretty-print true}}}}
                  :figwheel
                  {:http-server-root "public"
                   :server-port 3449
                   :nrepl-port 7002
                   :nrepl-middleware [cider.piggieback/wrap-cljs-repl]
                   :css-dirs ["resources/public/css"]
                   :ring-handler luminus-app.handler/app}
                  :source-paths ["env/dev/clj"]
                  :resource-paths ["env/dev/resources"]
                  :repl-options {:init-ns user
                                 :timeout 120000}
                  :injections [(require 'pjstadig.humane-test-output)
                               (pjstadig.humane-test-output/activate!)]}
   :project/test {:jvm-opts ["-Dconf=test-config.edn"]
                  :resource-paths ["env/test/resources"]
                  :cljsbuild
                  {:builds
                   {:test
                    {:source-paths ["src/cljs" "test/cljs"]
                     :compiler
                     {:output-to "target/test.js"
                      :main "luminus-app.doo-runner"
                      :optimizations :whitespace
                      :pretty-print true}}}}
                  :doo {:build "test"}}}

  :aliases
  {"kaocha" ["with-profile" "+kaocha" "run" "-m" "kaocha.runner"]
   "migrations" ["run" "-m" "luminus-app.migrations"]})`,

    'src/clj/luminus_app/core.clj': `(ns luminus-app.core
  (:require
   [luminus-app.handler :as handler]
   [luminus-app.nrepl :as nrepl]
   [luminus-migrations.core :as migrations]
   [luminus-app.config :refer [env]]
   [clojure.tools.cli :refer [parse-opts]]
   [clojure.tools.logging :as log]
   [mount.core :as mount])
  (:gen-class))

(def cli-options
  [["-p" "--port PORT" "Port number"
    :default 3000
    :parse-fn #(Integer/parseInt %)
    :validate [#(< 0 % 0x10000) "Must be a number between 0 and 65536"]]
   ["-h" "--help"]])

(mount/defstate ^{:on-reload :noop} http-server
  :start
  (handler/start-app (:port env))
  :stop
  (handler/stop-app http-server))

(mount/defstate ^{:on-reload :noop} repl-server
  :start
  (when (env :nrepl-port)
    (nrepl/start {:bind (env :nrepl-bind)
                  :port (env :nrepl-port)}))
  :stop
  (when repl-server
    (nrepl/stop repl-server)))

(defn stop-app []
  (doseq [component (:stopped (mount/stop))]
    (log/info component "stopped"))
  (shutdown-agents))

(defn start-app [args]
  (doseq [component (:started (mount/start))]
    (log/info component "started"))
  (.addShutdownHook (Runtime/getRuntime) (Thread. stop-app)))

(defn -main [& args]
  (mount/start #'luminus-app.config/env)
  (cond
    (nil? (:database-url env))
    (do
      (log/error "Database configuration not found, :database-url environment variable must be set before running")
      (System/exit 1))
    (some #{"migrate" "rollback"} args)
    (do
      (migrations/migrate args (select-keys env [:database-url]))
      (System/exit 0))
    :else
    (let [{:keys [options arguments errors summary]} (parse-opts args cli-options)]
      (cond
        (:help options)
        (println summary)
        (not (nil? errors))
        (do
          (doseq [error errors]
            (println error))
          (System/exit 1))
        :else
        (start-app (or (:port options) (:port env) 3000))))))`,

    'src/clj/luminus_app/handler.clj': `(ns luminus-app.handler
  (:require
   [luminus-app.middleware :as middleware]
   [luminus-app.layout :refer [error-page]]
   [luminus-app.routes.home :refer [home-routes]]
   [luminus-app.routes.services :refer [service-routes]]
   [luminus-app.routes.auth :refer [auth-routes]]
   [reitit.ring :as ring]
   [ring.middleware.content-type :refer [wrap-content-type]]
   [ring.middleware.webjars :refer [wrap-webjars]]
   [luminus-app.env :refer [defaults]]
   [mount.core :as mount]
   [luminus-app.config :refer [env]]
   [clojure.tools.logging :as log]
   [luminus.http-server :as http]))

(mount/defstate init-app
  :start
  ((or (:init defaults) (fn [])))
  :stop
  ((or (:stop defaults) (fn []))))

(mount/defstate app-routes
  :start
  (ring/ring-handler
   (ring/router
    [(home-routes)
     (service-routes)
     (auth-routes)])
   (ring/routes
    (ring/create-resource-handler
     {:path "/"})
    (wrap-content-type
     (wrap-webjars (constantly nil)))
    (ring/create-default-handler
     {:not-found
      (constantly (error-page {:status 404, :title "404 - Page not found"}))
      :method-not-allowed
      (constantly (error-page {:status 405, :title "405 - Not allowed"}))
      :not-acceptable
      (constantly (error-page {:status 406, :title "406 - Not acceptable"}))}))))

(defn app []
  (middleware/wrap-base #'app-routes))

(defn start-app [port]
  (http/start {:handler (app)
               :port port}))

(defn stop-app [server]
  (http/stop server))`,

    'src/clj/luminus_app/routes/home.clj': `(ns luminus-app.routes.home
  (:require
   [luminus-app.layout :as layout]
   [luminus-app.db.core :as db]
   [clojure.java.io :as io]
   [luminus-app.middleware :as middleware]
   [ring.util.response]
   [ring.util.http-response :as response]
   [struct.core :as st]))

(defn home-page [request]
  (layout/render request "home.html"))

(defn about-page [request]
  (layout/render request "about.html"))

(defn home-routes []
  [""
   {:middleware [middleware/wrap-csrf
                 middleware/wrap-formats]}
   ["/" {:get home-page}]
   ["/about" {:get about-page}]
   ["/docs" {:get (fn [_]
                    (-> (response/ok (-> "docs/docs.md" io/resource slurp))
                        (response/header "Content-Type" "text/plain; charset=utf-8")))}]])`,

    'src/clj/luminus_app/routes/services.clj': `(ns luminus-app.routes.services
  (:require
   [reitit.swagger :as swagger]
   [reitit.swagger-ui :as swagger-ui]
   [reitit.ring.coercion :as coercion]
   [reitit.coercion.spec :as spec-coercion]
   [reitit.ring.middleware.muuntaja :as muuntaja]
   [reitit.ring.middleware.multipart :as multipart]
   [reitit.ring.middleware.parameters :as parameters]
   [luminus-app.routes.users :as users]
   [luminus-app.routes.todos :as todos]
   [luminus-app.middleware.formats :as formats]
   [luminus-app.middleware.exception :as exception]
   [ring.util.http-response :refer :all]
   [clojure.java.io :as io]
   [struct.core :as st]))

(defn service-routes []
  ["/api"
   {:coercion spec-coercion/coercion
    :muuntaja formats/instance
    :swagger {:id ::api}
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
                 multipart/multipart-middleware]}

   ;; swagger documentation
   ["" {:no-doc true
        :swagger {:info {:title "Luminus API"
                         :description "API documentation for Luminus application"
                         :version "1.0.0"}}}

    ["/swagger.json"
     {:get (swagger/create-swagger-handler)}]

    ["/api-docs/*"
     {:get (swagger-ui/create-swagger-ui-handler
            {:url "/api/swagger.json"
             :config {:validator-url nil}})}]

    ["/ping"
     {:get (constantly (ok {:message "pong"}))}]]

   ;; API routes
   ["/health"
    {:get {:summary "Health check endpoint"
           :responses {200 {:body {:status string?
                                   :timestamp string?}}}
           :handler (fn [_]
                      (ok {:status "healthy"
                           :timestamp (str (java.time.Instant/now))}))}}]

   ;; User routes
   users/routes
   
   ;; Todo routes  
   todos/routes])`,

    'src/clj/luminus_app/routes/auth.clj': `(ns luminus-app.routes.auth
  (:require
   [luminus-app.db.core :as db]
   [luminus-app.validation :as validation]
   [ring.util.http-response :as response]
   [buddy.hashers :as hashers]
   [buddy.sign.jwt :as jwt]
   [clojure.tools.logging :as log]
   [luminus-app.config :refer [env]]
   [struct.core :as st]))

(def jwt-secret (env :jwt-secret "default-secret-change-in-production"))

(defn generate-token [user]
  (let [exp (+ (System/currentTimeMillis) (* 1000 60 60 24)) ; 24 hours
        claims {:user-id (:id user)
                :email (:email user)
                :exp exp}]
    (jwt/sign claims jwt-secret)))

(defn verify-token [token]
  (try
    (jwt/unsign token jwt-secret)
    (catch Exception e
      (log/debug "Token verification failed:" (.getMessage e))
      nil)))

(defn register-user [{{:keys [email password first-name last-name]} :body-params}]
  (try
    (if-let [errors (validation/validate-user {:email email 
                                              :password password 
                                              :first-name first-name 
                                              :last-name last-name})]
      (response/bad-request {:errors errors})
      (if (db/user-exists? {:email email})
        (response/conflict {:error "User already exists"})
        (let [hashed-password (hashers/derive password)
              user (db/create-user! {:email email
                                    :password hashed-password
                                    :first_name first-name
                                    :last_name last-name})
              token (generate-token user)]
          (response/created {:token token
                            :user (dissoc user :password)
                            :message "Registration successful"}))))
    (catch Exception e
      (log/error e "Registration error")
      (response/internal-server-error {:error "Registration failed"}))))

(defn login-user [{{:keys [email password]} :body-params}]
  (try
    (if-let [errors (validation/validate-login {:email email :password password})]
      (response/bad-request {:errors errors})
      (if-let [user (db/get-user-by-email {:email email})]
        (if (hashers/check password (:password user))
          (let [token (generate-token user)]
            (response/ok {:token token
                         :user (dissoc user :password)
                         :message "Login successful"}))
          (response/unauthorized {:error "Invalid credentials"}))
        (response/unauthorized {:error "Invalid credentials"})))
    (catch Exception e
      (log/error e "Login error")
      (response/internal-server-error {:error "Login failed"}))))

(defn logout-user [_]
  (response/ok {:message "Logout successful"}))

(defn get-profile [{{:keys [user]} :session}]
  (if user
    (response/ok {:user (dissoc user :password)})
    (response/unauthorized {:error "Not authenticated"})))

(defn auth-routes []
  ["/auth"
   ["/register" {:post {:summary "Register a new user"
                       :parameters {:body {:email string?
                                          :password string?
                                          :first-name string?
                                          :last-name string?}}
                       :responses {201 {:body {:token string?
                                              :user map?
                                              :message string?}}
                                  400 {:body {:errors vector?}}
                                  409 {:body {:error string?}}}
                       :handler register-user}}]
   
   ["/login" {:post {:summary "Login user"
                    :parameters {:body {:email string?
                                       :password string?}}
                    :responses {200 {:body {:token string?
                                           :user map?
                                           :message string?}}
                               400 {:body {:errors vector?}}
                               401 {:body {:error string?}}}
                    :handler login-user}}]
   
   ["/logout" {:post {:summary "Logout user"
                     :responses {200 {:body {:message string?}}}
                     :handler logout-user}}]
   
   ["/profile" {:get {:summary "Get user profile"
                     :responses {200 {:body {:user map?}}
                                401 {:body {:error string?}}}
                     :handler get-profile}}]])`,

    'src/clj/luminus_app/routes/users.clj': `(ns luminus-app.routes.users
  (:require
   [luminus-app.db.core :as db]
   [luminus-app.validation :as validation]
   [ring.util.http-response :as response]
   [buddy.hashers :as hashers]
   [clojure.tools.logging :as log]
   [struct.core :as st]))

(defn get-users [_]
  (try
    (let [users (db/get-users)]
      (response/ok {:users (map #(dissoc % :password) users)}))
    (catch Exception e
      (log/error e "Error fetching users")
      (response/internal-server-error {:error "Failed to fetch users"}))))

(defn get-user [{{:keys [id]} :path-params}]
  (try
    (if-let [user (db/get-user {:id (Integer/parseInt id)})]
      (response/ok {:user (dissoc user :password)})
      (response/not-found {:error "User not found"}))
    (catch NumberFormatException e
      (response/bad-request {:error "Invalid user ID"}))
    (catch Exception e
      (log/error e "Error fetching user")
      (response/internal-server-error {:error "Failed to fetch user"}))))

(defn create-user [{{:keys [email password first-name last-name]} :body-params}]
  (try
    (if-let [errors (validation/validate-user {:email email 
                                              :password password 
                                              :first-name first-name 
                                              :last-name last-name})]
      (response/bad-request {:errors errors})
      (if (db/user-exists? {:email email})
        (response/conflict {:error "User already exists"})
        (let [hashed-password (hashers/derive password)
              user (db/create-user! {:email email
                                    :password hashed-password
                                    :first_name first-name
                                    :last_name last-name})]
          (response/created {:user (dissoc user :password)
                            :message "User created successfully"}))))
    (catch Exception e
      (log/error e "Error creating user")
      (response/internal-server-error {:error "Failed to create user"}))))

(defn update-user [{{:keys [id]} :path-params
                   {:keys [email first-name last-name]} :body-params}]
  (try
    (if-let [errors (validation/validate-user-update {:email email 
                                                     :first-name first-name 
                                                     :last-name last-name})]
      (response/bad-request {:errors errors})
      (if (db/get-user {:id (Integer/parseInt id)})
        (let [updated-user (db/update-user! {:id (Integer/parseInt id)
                                            :email email
                                            :first_name first-name
                                            :last_name last-name})]
          (response/ok {:user (dissoc updated-user :password)
                       :message "User updated successfully"}))
        (response/not-found {:error "User not found"})))
    (catch NumberFormatException e
      (response/bad-request {:error "Invalid user ID"}))
    (catch Exception e
      (log/error e "Error updating user")
      (response/internal-server-error {:error "Failed to update user"}))))

(defn delete-user [{{:keys [id]} :path-params}]
  (try
    (if (db/get-user {:id (Integer/parseInt id)})
      (do
        (db/delete-user! {:id (Integer/parseInt id)})
        (response/ok {:message "User deleted successfully"}))
      (response/not-found {:error "User not found"}))
    (catch NumberFormatException e
      (response/bad-request {:error "Invalid user ID"}))
    (catch Exception e
      (log/error e "Error deleting user")
      (response/internal-server-error {:error "Failed to delete user"}))))

(def routes
  ["/users"
   ["" {:get {:summary "Get all users"
             :responses {200 {:body {:users vector?}}}
             :handler get-users}
        :post {:summary "Create a new user"
               :parameters {:body {:email string?
                                  :password string?
                                  :first-name string?
                                  :last-name string?}}
               :responses {201 {:body {:user map?
                                      :message string?}}
                          400 {:body {:errors vector?}}
                          409 {:body {:error string?}}}
               :handler create-user}}]
   
   ["/:id" {:get {:summary "Get user by ID"
                 :parameters {:path {:id int?}}
                 :responses {200 {:body {:user map?}}
                            404 {:body {:error string?}}}
                 :handler get-user}
            :put {:summary "Update user"
                  :parameters {:path {:id int?}
                              :body {:email string?
                                    :first-name string?
                                    :last-name string?}}
                  :responses {200 {:body {:user map?
                                         :message string?}}
                             404 {:body {:error string?}}}
                  :handler update-user}
            :delete {:summary "Delete user"
                    :parameters {:path {:id int?}}
                    :responses {200 {:body {:message string?}}
                               404 {:body {:error string?}}}
                    :handler delete-user}}]])`,

    'src/clj/luminus_app/routes/todos.clj': `(ns luminus-app.routes.todos
  (:require
   [luminus-app.db.core :as db]
   [luminus-app.validation :as validation]
   [ring.util.http-response :as response]
   [clojure.tools.logging :as log]
   [struct.core :as st]))

(defn get-todos [_]
  (try
    (let [todos (db/get-todos)]
      (response/ok {:todos todos}))
    (catch Exception e
      (log/error e "Error fetching todos")
      (response/internal-server-error {:error "Failed to fetch todos"}))))

(defn get-todo [{{:keys [id]} :path-params}]
  (try
    (if-let [todo (db/get-todo {:id (Integer/parseInt id)})]
      (response/ok {:todo todo})
      (response/not-found {:error "Todo not found"}))
    (catch NumberFormatException e
      (response/bad-request {:error "Invalid todo ID"}))
    (catch Exception e
      (log/error e "Error fetching todo")
      (response/internal-server-error {:error "Failed to fetch todo"}))))

(defn create-todo [{{:keys [title description user-id]} :body-params}]
  (try
    (if-let [errors (validation/validate-todo {:title title 
                                              :description description
                                              :user-id user-id})]
      (response/bad-request {:errors errors})
      (let [todo (db/create-todo! {:title title
                                  :description description
                                  :user_id user-id
                                  :completed false})]
        (response/created {:todo todo
                          :message "Todo created successfully"})))
    (catch Exception e
      (log/error e "Error creating todo")
      (response/internal-server-error {:error "Failed to create todo"}))))

(defn update-todo [{{:keys [id]} :path-params
                   {:keys [title description completed]} :body-params}]
  (try
    (if-let [errors (validation/validate-todo-update {:title title 
                                                     :description description
                                                     :completed completed})]
      (response/bad-request {:errors errors})
      (if (db/get-todo {:id (Integer/parseInt id)})
        (let [updated-todo (db/update-todo! {:id (Integer/parseInt id)
                                            :title title
                                            :description description
                                            :completed completed})]
          (response/ok {:todo updated-todo
                       :message "Todo updated successfully"}))
        (response/not-found {:error "Todo not found"})))
    (catch NumberFormatException e
      (response/bad-request {:error "Invalid todo ID"}))
    (catch Exception e
      (log/error e "Error updating todo")
      (response/internal-server-error {:error "Failed to update todo"}))))

(defn delete-todo [{{:keys [id]} :path-params}]
  (try
    (if (db/get-todo {:id (Integer/parseInt id)})
      (do
        (db/delete-todo! {:id (Integer/parseInt id)})
        (response/ok {:message "Todo deleted successfully"}))
      (response/not-found {:error "Todo not found"}))
    (catch NumberFormatException e
      (response/bad-request {:error "Invalid todo ID"}))
    (catch Exception e
      (log/error e "Error deleting todo")
      (response/internal-server-error {:error "Failed to delete todo"}))))

(def routes
  ["/todos"
   ["" {:get {:summary "Get all todos"
             :responses {200 {:body {:todos vector?}}}
             :handler get-todos}
        :post {:summary "Create a new todo"
               :parameters {:body {:title string?
                                  :description string?
                                  :user-id int?}}
               :responses {201 {:body {:todo map?
                                      :message string?}}
                          400 {:body {:errors vector?}}}
               :handler create-todo}}]
   
   ["/:id" {:get {:summary "Get todo by ID"
                 :parameters {:path {:id int?}}
                 :responses {200 {:body {:todo map?}}
                            404 {:body {:error string?}}}
                 :handler get-todo}
            :put {:summary "Update todo"
                  :parameters {:path {:id int?}
                              :body {:title string?
                                    :description string?
                                    :completed boolean?}}
                  :responses {200 {:body {:todo map?
                                         :message string?}}
                             404 {:body {:error string?}}}
                  :handler update-todo}
            :delete {:summary "Delete todo"
                    :parameters {:path {:id int?}}
                    :responses {200 {:body {:message string?}}
                               404 {:body {:error string?}}}
                    :handler delete-todo}}]])`,

    'src/clj/luminus_app/db/core.clj': `(ns luminus-app.db.core
  (:require
   [conman.core :as conman]
   [mount.core :refer [defstate]]
   [luminus-app.config :refer [env]]
   [clojure.tools.logging :as log]))

(defstate ^:dynamic *db*
  :start (if-let [jdbc-url (env :database-url)]
           (conman/connect! {:jdbc-url jdbc-url})
           (do
             (log/warn "database connection URL was not found, please set :database-url in your config, e.g: dev-config.edn")
             *db*))
  :stop (conman/disconnect! *db*))

(conman/bind-connection *db* "sql/queries.sql")

(defn migrate []
  (log/info "migrating database")
  (conman/migrate))

(defn rollback []
  (log/info "rolling back database")
  (conman/rollback))`,

    'src/clj/luminus_app/validation.clj': `(ns luminus-app.validation
  (:require
   [struct.core :as st]))

(def user-schema
  [[:email st/required st/email]
   [:password st/required st/string {:message "Password is required"}]
   [:first-name st/required st/string {:message "First name is required"}]
   [:last-name st/required st/string {:message "Last name is required"}]])

(def user-update-schema
  [[:email st/email]
   [:first-name st/string]
   [:last-name st/string]])

(def login-schema
  [[:email st/required st/email]
   [:password st/required st/string {:message "Password is required"}]])

(def todo-schema
  [[:title st/required st/string {:message "Title is required"}]
   [:description st/string]
   [:user-id st/required st/integer {:message "User ID is required"}]])

(def todo-update-schema
  [[:title st/string]
   [:description st/string]
   [:completed st/boolean]])

(defn validate-user [params]
  (first (st/validate params user-schema)))

(defn validate-user-update [params]
  (first (st/validate params user-update-schema)))

(defn validate-login [params]
  (first (st/validate params login-schema)))

(defn validate-todo [params]
  (first (st/validate params todo-schema)))

(defn validate-todo-update [params]
  (first (st/validate params todo-update-schema)))`,

    'src/clj/luminus_app/layout.clj': `(ns luminus-app.layout
  (:require
   [clojure.java.io]
   [selmer.parser :as parser]
   [selmer.filters :as filters]
   [markdown.core :refer [md-to-html-string]]
   [ring.util.anti-forgery :refer [anti-forgery-field]]
   [ring.middleware.anti-forgery :refer [*anti-forgery-token*]]
   [ring.util.response :refer [content-type response]]
   [luminus-app.config :refer [env]]
   [clojure.tools.logging :as log]))

(declare ^:dynamic *app-context*)
(parser/set-resource-path! (clojure.java.io/resource "html"))
(parser/add-tag! :csrf-field (fn [_ _] (anti-forgery-field)))
(filters/add-filter! :markdown (fn [content] [:safe (md-to-html-string content)]))

(defn render
  "renders the HTML template located relative to resources/html"
  [request template & [params]]
  (content-type
   (response
    (parser/render-file
     template
     (assoc params
            :page template
            :csrf-token *anti-forgery-token*
            :servlet-context *app-context*)))
   "text/html; charset=utf-8"))

(defn error-page
  "error-details should be a map containing the following keys:
   :status - error status
   :title - error title (optional)
   :message - detailed error message (optional)
   returns a response map with the error page as the body
   and the status specified by the status key"
  [error-details]
  {:status  (:status error-details)
   :headers {"Content-Type" "text/html; charset=utf-8"}
   :body    (parser/render-file "error.html" error-details)})`,

    'src/clj/luminus_app/middleware.clj': `(ns luminus-app.middleware
  (:require
   [luminus-app.env :refer [defaults]]
   [luminus-app.config :refer [env]]
   [ring.middleware.anti-forgery :refer [wrap-anti-forgery]]
   [luminus-app.layout :refer [error-page]]
   [ring.middleware.format :refer [wrap-restful-format]]
   [luminus.middleware.trailing-slash :refer [wrap-trailing-slash]]
   [luminus.middleware.defaults :refer [wrap-base]]
   [luminus-app.middleware.formats :as formats]
   [ring.middleware.flash :refer [wrap-flash]]
   [ring.adapter.undertow.middleware.session :refer [wrap-session]]
   [ring.middleware.defaults :refer [site-defaults wrap-defaults]]
   [ring.middleware.webjars :refer [wrap-webjars]]
   [ring.middleware.format :refer [wrap-restful-format]]
   [mount.core :as mount]
   [clojure.tools.logging :as log]))

(defn wrap-context [handler]
  (fn [request]
    (binding [luminus-app.layout/*app-context*
              (if-let [context (:servlet-context request)]
                ;; If we're not inside a servlet environment
                ;; (for example when using mock requests), then
                ;; .getContextPath might not exist
                (try (.getContextPath context)
                     (catch IllegalArgumentException _ context))
                ;; if the context is not specified in the request
                ;; we check if one has been specified in the environment
                ;; instead
                (:app-context env))]
      (handler request))))

(defn wrap-internal-error [handler]
  (fn [request]
    (try
      (handler request)
      (catch Throwable t
        (log/error t (.getMessage t))
        (error-page {:status 500
                     :title "Something very bad has happened!"
                     :message "We've dispatched a team of highly trained gnomes to take care of the problem."})))))

(defn wrap-csrf [handler]
  (wrap-anti-forgery
   handler
   {:error-response
    (error-page
     {:status 403
      :title "Invalid anti-forgery token"})}))

(defn wrap-formats [handler]
  (let [wrapped (-> handler wrap-restful-format)]
    (fn [request]
      ;; disable wrap-formats for websockets
      ;; since they're not compatible with this middleware
      ((if (:websocket? request) handler wrapped) request))))

(defn wrap-base [handler]
  (-> ((:middleware defaults) handler)
      wrap-webjars
      (wrap-defaults
       (-> site-defaults
           (assoc-in [:security :anti-forgery] false)
           (assoc-in [:session :store] (ttl-memory-store (* 60 30)))))
      wrap-context
      wrap-internal-error))`,

    'resources/sql/queries.sql': `-- :name create-user! :! :n
-- :doc creates a new user record
INSERT INTO users
(email, password, first_name, last_name)
VALUES (:email, :password, :first_name, :last_name)

-- :name update-user! :! :n
-- :doc updates an existing user record
UPDATE users
SET email = :email,
    first_name = :first_name,
    last_name = :last_name,
    updated_at = NOW()
WHERE id = :id

-- :name get-user :? :1
-- :doc retrieves a user record given the id
SELECT * FROM users
WHERE id = :id

-- :name get-user-by-email :? :1
-- :doc retrieves a user record given the email
SELECT * FROM users
WHERE email = :email

-- :name user-exists? :? :1
-- :doc checks if a user exists with the given email
SELECT id FROM users
WHERE email = :email

-- :name get-users :? :*
-- :doc retrieves all user records
SELECT id, email, first_name, last_name, created_at, updated_at FROM users
ORDER BY created_at DESC

-- :name delete-user! :! :n
-- :doc deletes a user record given the id
DELETE FROM users
WHERE id = :id

-- :name create-todo! :! :n
-- :doc creates a new todo record
INSERT INTO todos
(title, description, completed, user_id)
VALUES (:title, :description, :completed, :user_id)

-- :name update-todo! :! :n
-- :doc updates an existing todo record
UPDATE todos
SET title = :title,
    description = :description,
    completed = :completed,
    updated_at = NOW()
WHERE id = :id

-- :name get-todo :? :1
-- :doc retrieves a todo record given the id
SELECT * FROM todos
WHERE id = :id

-- :name get-todos :? :*
-- :doc retrieves all todo records
SELECT * FROM todos
ORDER BY created_at DESC

-- :name get-todos-by-user :? :*
-- :doc retrieves all todo records for a specific user
SELECT * FROM todos
WHERE user_id = :user_id
ORDER BY created_at DESC

-- :name delete-todo! :! :n
-- :doc deletes a todo record given the id
DELETE FROM todos
WHERE id = :id`,

    'resources/migrations/20231201120000-add-users-table.up.sql': `CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  first_name VARCHAR(255),
  last_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

--;;

CREATE INDEX idx_users_email ON users(email);`,

    'resources/migrations/20231201120000-add-users-table.down.sql': `DROP TABLE users;`,

    'resources/migrations/20231201120001-add-todos-table.up.sql': `CREATE TABLE todos (
  id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  completed BOOLEAN DEFAULT FALSE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

--;;

CREATE INDEX idx_todos_user_id ON todos(user_id);
CREATE INDEX idx_todos_completed ON todos(completed);`,

    'resources/migrations/20231201120001-add-todos-table.down.sql': `DROP TABLE todos;`,

    'resources/html/home.html': `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Luminus Application</title>
    <link rel="stylesheet" href="/webjars/bulma/0.9.4/css/bulma.min.css">
    <link rel="stylesheet" href="/webjars/material-icons/1.13.1/material-icons.css">
    <style>
        .hero-gradient {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .feature-card {
            transition: transform 0.3s ease;
        }
        .feature-card:hover {
            transform: translateY(-5px);
        }
    </style>
</head>
<body>
    <section class="hero is-primary hero-gradient">
        <div class="hero-body">
            <div class="container">
                <h1 class="title">
                    <i class="material-icons">web</i>
                    Welcome to Luminus
                </h1>
                <h2 class="subtitle">
                    A powerful full-stack Clojure web framework
                </h2>
            </div>
        </div>
    </section>

    <section class="section">
        <div class="container">
            <div class="columns">
                <div class="column is-8">
                    <div class="content">
                        <h2 class="title is-3">Features</h2>
                        <div class="columns is-multiline">
                            <div class="column is-6">
                                <div class="card feature-card">
                                    <div class="card-content">
                                        <div class="media">
                                            <div class="media-left">
                                                <i class="material-icons is-size-2 has-text-primary">api</i>
                                            </div>
                                            <div class="media-content">
                                                <p class="title is-4">RESTful API</p>
                                                <p class="subtitle is-6">Complete REST API with Swagger documentation</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="column is-6">
                                <div class="card feature-card">
                                    <div class="card-content">
                                        <div class="media">
                                            <div class="media-left">
                                                <i class="material-icons is-size-2 has-text-primary">storage</i>
                                            </div>
                                            <div class="media-content">
                                                <p class="title is-4">Database</p>
                                                <p class="subtitle is-6">PostgreSQL with migrations and connection pooling</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="column is-6">
                                <div class="card feature-card">
                                    <div class="card-content">
                                        <div class="media">
                                            <div class="media-left">
                                                <i class="material-icons is-size-2 has-text-primary">security</i>
                                            </div>
                                            <div class="media-content">
                                                <p class="title is-4">Authentication</p>
                                                <p class="subtitle is-6">JWT-based authentication with user management</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="column is-6">
                                <div class="card feature-card">
                                    <div class="card-content">
                                        <div class="media">
                                            <div class="media-left">
                                                <i class="material-icons is-size-2 has-text-primary">code</i>
                                            </div>
                                            <div class="media-content">
                                                <p class="title is-4">Hot Reload</p>
                                                <p class="subtitle is-6">REPL-driven development with hot code reloading</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="column is-4">
                    <div class="card">
                        <div class="card-header">
                            <p class="card-header-title">
                                <i class="material-icons">link</i>
                                &nbsp;API Endpoints
                            </p>
                        </div>
                        <div class="card-content">
                            <div class="content">
                                <div class="field">
                                    <label class="label">Health Check</label>
                                    <div class="control">
                                        <a href="/api/health" class="button is-small is-success">
                                            <span class="icon">
                                                <i class="material-icons">health_and_safety</i>
                                            </span>
                                            <span>GET /api/health</span>
                                        </a>
                                    </div>
                                </div>
                                
                                <div class="field">
                                    <label class="label">API Documentation</label>
                                    <div class="control">
                                        <a href="/api/api-docs/" class="button is-small is-info">
                                            <span class="icon">
                                                <i class="material-icons">description</i>
                                            </span>
                                            <span>Swagger UI</span>
                                        </a>
                                    </div>
                                </div>
                                
                                <div class="field">
                                    <label class="label">Authentication</label>
                                    <div class="buttons">
                                        <button class="button is-small is-primary">
                                            <span class="icon">
                                                <i class="material-icons">login</i>
                                            </span>
                                            <span>Login</span>
                                        </button>
                                        <button class="button is-small is-primary">
                                            <span class="icon">
                                                <i class="material-icons">person_add</i>
                                            </span>
                                            <span>Register</span>
                                        </button>
                                    </div>
                                </div>
                                
                                <div class="field">
                                    <label class="label">Resources</label>
                                    <div class="buttons">
                                        <button class="button is-small is-warning">
                                            <span class="icon">
                                                <i class="material-icons">people</i>
                                            </span>
                                            <span>Users</span>
                                        </button>
                                        <button class="button is-small is-warning">
                                            <span class="icon">
                                                <i class="material-icons">checklist</i>
                                            </span>
                                            <span>Todos</span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="content has-text-centered">
            <p>
                <strong>Luminus Application</strong> built with
                <a href="https://luminusweb.com/">Luminus</a> and
                <a href="https://clojure.org/">Clojure</a>.
            </p>
        </div>
    </footer>
</body>
</html>`,

    'env/dev/resources/dev-config.edn': `{:dev true
 :port 3000
 :database-url "postgresql://localhost:5432/luminus_app_dev?user=postgres&password=password"
 :jwt-secret "dev-secret-key"
 :nrepl-port 7000
 :nrepl-bind "127.0.0.1"}`,

    'env/prod/resources/prod-config.edn': `{:prod true
 :port 3000}`,

    'env/test/resources/test-config.edn': `{:test true
 :port 3001
 :database-url "postgresql://localhost:5432/luminus_app_test?user=postgres&password=password"
 :jwt-secret "test-secret-key"}`,

    'Dockerfile': `FROM openjdk:11-jre-slim

WORKDIR /app

# Copy the built JAR file
COPY target/luminus-app.jar app.jar

# Expose port
EXPOSE 3000

# Set environment variables
ENV PORT=3000
ENV DATABASE_URL=jdbc:postgresql://postgres:5432/luminus_app
ENV JWT_SECRET=change-this-in-production

# Run the application
CMD ["java", "-jar", "app.jar"]`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - PORT=3000
      - DATABASE_URL=postgresql://postgres:5432/luminus_app?user=postgres&password=password
      - JWT_SECRET=change-this-in-production
    depends_on:
      - postgres
    volumes:
      - ./logs:/app/logs

  postgres:
    image: postgres:14
    environment:
      - POSTGRES_DB=luminus_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:`,

    'README.md': `# Luminus Full-Stack Clojure Application

A production-ready full-stack Clojure web application built with the Luminus framework, featuring complete database integration, authentication, and modern development tools.

## Features

- **Full-Stack Framework**: Complete web application framework with frontend and backend
- **Database Integration**: PostgreSQL with migrations and connection pooling
- **Authentication System**: JWT-based authentication with user management
- **RESTful API**: Complete REST API with Swagger documentation
- **Hot Code Reloading**: REPL-driven development with instant feedback
- **Asset Pipeline**: Optimized asset management and building
- **Production Ready**: Docker support and deployment configuration
- **Testing Framework**: Comprehensive testing with Clojure.test
- **Configuration Management**: Environment-specific configuration

## Quick Start

### Prerequisites

- Java 11 or later
- Leiningen 2.9.8 or later
- PostgreSQL (or use Docker Compose)

### Installation

\`\`\`bash
# Clone the project
git clone <repository-url>
cd luminus-app

# Install dependencies
lein deps

# Set up database
docker-compose up -d postgres

# Run migrations
lein migrations migrate

# Start the development server
lein run
\`\`\`

The application will be available at \`http://localhost:3000\`

### Development

\`\`\`bash
# Start development server with hot reload
lein figwheel

# Start REPL
lein repl

# Run tests
lein test

# Build for production
lein uberjar

# Run with Docker Compose
docker-compose up
\`\`\`

## Project Structure

\`\`\`
├── src/clj/luminus_app/
│   ├── core.clj                 # Application entry point
│   ├── handler.clj              # Main request handler
│   ├── routes/
│   │   ├── home.clj             # Home page routes
│   │   ├── services.clj         # API service routes
│   │   ├── auth.clj             # Authentication routes
│   │   ├── users.clj            # User management routes
│   │   └── todos.clj            # Todo management routes
│   ├── db/
│   │   └── core.clj             # Database connection and queries
│   ├── middleware.clj           # Ring middleware
│   ├── layout.clj               # Template rendering
│   └── validation.clj           # Input validation
├── resources/
│   ├── sql/queries.sql          # SQL queries
│   ├── migrations/              # Database migrations
│   └── html/                    # HTML templates
├── env/                         # Environment-specific configurations
├── test/                        # Test files
└── project.clj                  # Project configuration
\`\`\`

## API Endpoints

### Authentication
- \`POST /auth/register\` - User registration
- \`POST /auth/login\` - User login
- \`POST /auth/logout\` - User logout
- \`GET /auth/profile\` - Get current user profile

### Users
- \`GET /api/users\` - List all users
- \`GET /api/users/:id\` - Get user by ID
- \`POST /api/users\` - Create new user
- \`PUT /api/users/:id\` - Update user
- \`DELETE /api/users/:id\` - Delete user

### Todos
- \`GET /api/todos\` - List all todos
- \`GET /api/todos/:id\` - Get todo by ID
- \`POST /api/todos\` - Create new todo
- \`PUT /api/todos/:id\` - Update todo
- \`DELETE /api/todos/:id\` - Delete todo

### Documentation
- \`GET /api/api-docs/\` - Swagger UI documentation
- \`GET /api/swagger.json\` - OpenAPI specification

## Database

### Migrations

\`\`\`bash
# Create migration
lein migrations create add-new-table

# Run migrations
lein migrations migrate

# Rollback migration
lein migrations rollback
\`\`\`

### Schema

The application includes two main tables:

#### Users Table
\`\`\`sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  first_name VARCHAR(255),
  last_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
\`\`\`

#### Todos Table
\`\`\`sql
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

## Configuration

### Environment Variables

Create configuration files in \`env/\` directory:

**dev-config.edn**
\`\`\`clojure
{:dev true
 :port 3000
 :database-url "postgresql://localhost:5432/luminus_app_dev?user=postgres&password=password"
 :jwt-secret "dev-secret-key"
 :nrepl-port 7000}
\`\`\`

**prod-config.edn**
\`\`\`clojure
{:prod true
 :port 3000
 :database-url "postgresql://prod-db:5432/luminus_app?user=prod_user&password=prod_password"
 :jwt-secret "production-secret-key"}
\`\`\`

## Authentication

### JWT Token Structure

\`\`\`clojure
{:user-id 1
 :email "user@example.com"
 :exp 1640995200000}
\`\`\`

### Protected Routes

Routes are protected using Ring middleware:

\`\`\`clojure
(defn wrap-auth [handler]
  (fn [request]
    (if-let [token (extract-token request)]
      (if-let [user (verify-token token)]
        (handler (assoc request :user user))
        (unauthorized-response))
      (unauthorized-response))))
\`\`\`

## Testing

### Unit Tests

\`\`\`clojure
(deftest test-user-creation
  (testing "User creation with valid data"
    (let [user-data {:email "test@example.com"
                    :password "password123"
                    :first-name "John"
                    :last-name "Doe"}
          response (create-user user-data)]
      (is (= 201 (:status response))))))
\`\`\`

### Integration Tests

\`\`\`clojure
(deftest test-api-endpoints
  (testing "GET /api/health"
    (let [response (app (request :get "/api/health"))]
      (is (= 200 (:status response))))))
\`\`\`

### Running Tests

\`\`\`bash
# Run all tests
lein test

# Run specific test namespace
lein test luminus-app.routes.users-test

# Run tests with coverage
lein cloverage

# Run tests in watch mode
lein test-refresh
\`\`\`

## Development Workflow

### REPL Development

\`\`\`bash
# Start REPL
lein repl

# In REPL
user=> (start)     ; Start the system
user=> (stop)      ; Stop the system
user=> (restart)   ; Restart the system
user=> (reset)     ; Reset the system
\`\`\`

### Hot Reload

The application supports hot reloading for:
- Clojure code changes
- HTML template changes
- CSS changes
- ClojureScript changes (with Figwheel)

### Database Development

\`\`\`clojure
;; Test database queries in REPL
(require '[luminus-app.db.core :as db])

;; Create a user
(db/create-user! {:email "test@example.com"
                  :password "hashed-password"
                  :first_name "John"
                  :last_name "Doe"})

;; Query users
(db/get-users)
\`\`\`

## Deployment

### Docker

\`\`\`bash
# Build production JAR
lein uberjar

# Build Docker image
docker build -t luminus-app .

# Run with Docker Compose
docker-compose up
\`\`\`

### Production Deployment

\`\`\`bash
# Set environment variables
export DATABASE_URL="postgresql://prod-db:5432/luminus_app"
export JWT_SECRET="your-production-secret"
export PORT=8080

# Run application
java -jar target/luminus-app.jar
\`\`\`

### Environment Configuration

Create environment-specific configuration files:

- \`env/dev/resources/dev-config.edn\` - Development
- \`env/prod/resources/prod-config.edn\` - Production
- \`env/test/resources/test-config.edn\` - Testing

## Architecture

### Middleware Stack

\`\`\`clojure
(defn wrap-base [handler]
  (-> handler
      wrap-webjars
      wrap-defaults
      wrap-context
      wrap-internal-error))
\`\`\`

### Database Layer

Uses ConMan for database operations:

\`\`\`clojure
(conman/bind-connection *db* "sql/queries.sql")
\`\`\`

### Routing

Uses Reitit for routing with data-driven configuration:

\`\`\`clojure
(ring/router
  [(home-routes)
   (service-routes)
   (auth-routes)])
\`\`\`

## Best Practices

### Code Organization

1. **Separate Concerns**: Keep routes, business logic, and data access separate
2. **Use Namespaces**: Organize code into logical namespaces
3. **Pure Functions**: Prefer pure functions for business logic
4. **Database Queries**: Keep SQL queries in separate files

### Error Handling

\`\`\`clojure
(defn handle-error [e]
  (log/error e)
  (response/internal-server-error {:error "Internal server error"}))
\`\`\`

### Security

1. **Input Validation**: Always validate user input
2. **SQL Injection**: Use parameterized queries
3. **Authentication**: Implement proper JWT handling
4. **CORS**: Configure CORS appropriately

## Learning Resources

- [Luminus Documentation](https://luminusweb.com/)
- [Clojure Documentation](https://clojure.org/)
- [Ring Documentation](https://github.com/ring-clojure/ring)
- [Reitit Documentation](https://metosin.github.io/reitit/)

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