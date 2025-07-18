import { BackendTemplate } from '../types';

export const perlDancer2Template: BackendTemplate = {
  id: 'perl-dancer2',
  name: 'perl-dancer2',
  displayName: 'Perl Dancer2 Web Framework',
  description: 'Lightweight and flexible web framework for Perl with modern routing, middleware support, and plugin ecosystem',
  framework: 'dancer2',
  language: 'perl',
  version: '1.0.0',
  author: 'Re-Shell Team',
  featured: true,
  recommended: true,
  icon: '💃',
  type: 'web-framework',
  complexity: 'beginner',
  keywords: ['perl', 'dancer2', 'lightweight', 'routing', 'middleware', 'plugins'],
  
  features: [
    'Lightweight web framework',
    'Modern routing system',
    'Middleware support',
    'Plugin ecosystem',
    'Template engines',
    'Session management',
    'Authentication helpers',
    'Database integration',
    'JSON API support',
    'Static file serving',
    'Error handling',
    'Configuration management',
    'Testing framework',
    'Deployment ready'
  ],
  
  structure: {
    'cpanfile': `# Dancer2 application dependencies
requires "Dancer2", "1.0.0";
requires "Dancer2::Plugin::Database", "2.17";
requires "Dancer2::Plugin::Auth::Extensible", "0.709";
requires "Dancer2::Plugin::REST", "1.02";
requires "Dancer2::Plugin::CORS", "0.11";
requires "Dancer2::Session::Cookie", "0.30";
requires "Dancer2::Template::TemplateToolkit", "1.0.0";
requires "DBI", "1.643";
requires "DBD::Pg", "3.16.0";
requires "JSON", "4.10";
requires "Crypt::Bcrypt", "0.011";
requires "Email::Valid", "1.202";
requires "DateTime", "1.59";
requires "UUID::Tiny", "1.04";
requires "Try::Tiny", "0.31";
requires "Data::Validate::Email", "0.04";
requires "HTTP::Status", "6.36";

# Development dependencies
on 'develop' => sub {
  requires "Dancer2::Test", "1.0.0";
  requires "Test::More", "1.302190";
  requires "Test::Deep", "1.130";
  requires "Test::JSON", "0.11";
  requires "Plack::Test", "1.0047";
  requires "HTTP::Request::Common", "6.36";
  requires "Perl::Critic", "1.148";
  requires "Perl::Tidy", "20230309";
  requires "Devel::Cover", "1.38";
};`,

    'lib/Dancer2App.pm': `package Dancer2App;
use Dancer2;
use Dancer2::Plugin::Database;
use Dancer2::Plugin::Auth::Extensible;
use Dancer2::Plugin::REST;
use Dancer2::Plugin::CORS;

use JSON;
use Crypt::Bcrypt qw(bcrypt bcrypt_check);
use Email::Valid;
use DateTime;
use UUID::Tiny ':std';
use Try::Tiny;
use HTTP::Status qw(:constants);

our $VERSION = '0.1';

# Configure CORS
cors_allow_origin '*';
cors_allow_methods 'GET, POST, PUT, DELETE, OPTIONS';
cors_allow_headers 'Content-Type, Authorization, X-Requested-With';
cors_max_age 86400;

# Configure authentication
set auth_extensible => {
    disable_roles => 0,
    no_default_pages => 1,
    no_login_handler => 1,
    realms => {
        users => {
            provider => 'Database',
            db_connection_name => 'default',
            users_table => 'users',
            username_column => 'email',
            password_column => 'password_hash',
            role_column => 'role',
            name_column => 'name',
            password_check => \\&check_password,
        },
    },
};

# Password verification helper
sub check_password {
    my ($password, $hash) = @_;
    return bcrypt_check($password, $hash);
}

# JSON response helper
sub json_response {
    my ($data, $status) = @_;
    $status //= HTTP_OK;
    
    status $status;
    content_type 'application/json';
    return encode_json($data);
}

# Error response helper
sub error_response {
    my ($message, $status, $details) = @_;
    $status //= HTTP_BAD_REQUEST;
    
    my $error = { error => $message };
    $error->{details} = $details if $details;
    
    return json_response($error, $status);
}

# Validation helper
sub validate_email {
    my ($email) = @_;
    return Email::Valid->address($email);
}

# Initialize database schema
hook before_request => sub {
    return if request->path eq '/setup';
    _ensure_database_schema();
};

# Set up database tables
sub _ensure_database_schema {
    my $db = database;
    
    # Create users table
    try {
        $db->do(q{
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        });
        
        # Insert sample data if table is empty
        my $count = $db->selectrow_array('SELECT COUNT(*) FROM users');
        if ($count == 0) {
            $db->do(q{
                INSERT INTO users (name, email, password_hash, role) VALUES 
                (?, ?, ?, ?),
                (?, ?, ?, ?)
            }, undef,
                'Admin User', 'admin@example.com', bcrypt('admin123', '$2a$10$' . generate_salt()), 'admin',
                'Regular User', 'user@example.com', bcrypt('user123', '$2a$10$' . generate_salt()), 'user'
            );
        }
    } catch {
        warning "Database setup failed: $_";
    };
}

sub generate_salt {
    return join('', map { chr(int(rand(94)) + 33) } 1..22);
}

# Authentication routes
post '/api/auth/register' => sub {
    my $data = decode_json(request->body);
    
    # Validate input
    my @errors;
    push @errors, "Name is required" unless $data->{name} && length($data->{name}) > 0;
    push @errors, "Email is required" unless $data->{email};
    push @errors, "Invalid email format" unless validate_email($data->{email});
    push @errors, "Password is required" unless $data->{password};
    push @errors, "Password must be at least 6 characters" unless length($data->{password} // '') >= 6;
    
    return error_response("Validation failed", HTTP_BAD_REQUEST, \\@errors) if @errors;
    
    # Check if user already exists
    my $existing = database->selectrow_hashref(
        'SELECT id FROM users WHERE email = ?',
        undef, $data->{email}
    );
    
    return error_response("User already exists", HTTP_CONFLICT) if $existing;
    
    # Create user
    my $password_hash = bcrypt($data->{password}, '$2a$10$' . generate_salt());
    my $user_id = database->last_insert_id(
        undef, undef, 'users', 'id',
        {}, 
        database->do(q{
            INSERT INTO users (name, email, password_hash, role, created_at, updated_at) 
            VALUES (?, ?, ?, ?, NOW(), NOW())
        }, undef, $data->{name}, $data->{email}, $password_hash, 'user')
    );
    
    my $user = database->selectrow_hashref(
        'SELECT id, name, email, role, created_at FROM users WHERE id = ?',
        undef, $user_id
    );
    
    return json_response($user, HTTP_CREATED);
};

post '/api/auth/login' => sub {
    my $data = decode_json(request->body);
    
    # Validate input
    return error_response("Email is required") unless $data->{email};
    return error_response("Password is required") unless $data->{password};
    
    # Find user
    my $user = database->selectrow_hashref(
        'SELECT id, name, email, password_hash, role FROM users WHERE email = ?',
        undef, $data->{email}
    );
    
    return error_response("Invalid credentials", HTTP_UNAUTHORIZED) unless $user;
    
    # Check password
    unless (bcrypt_check($data->{password}, $user->{password_hash})) {
        return error_response("Invalid credentials", HTTP_UNAUTHORIZED);
    }
    
    # Create session
    session user_id => $user->{id};
    session user_email => $user->{email};
    session user_role => $user->{role};
    
    # Generate token (simple implementation)
    my $token = encode_json({
        user_id => $user->{id},
        email => $user->{email},
        role => $user->{role},
        expires => time + 3600,
        uuid => create_uuid_as_string()
    });
    
    return json_response({
        token => $token,
        user => {
            id => $user->{id},
            name => $user->{name},
            email => $user->{email},
            role => $user->{role}
        }
    });
};

post '/api/auth/logout' => sub {
    session->destroy;
    return json_response({ message => 'Logged out successfully' });
};

# Protected routes helper
sub require_auth {
    my ($role) = @_;
    
    # Check session
    my $user_id = session('user_id');
    return error_response("Authentication required", HTTP_UNAUTHORIZED) unless $user_id;
    
    # Check role if specified
    if ($role) {
        my $user_role = session('user_role');
        return error_response("Insufficient permissions", HTTP_FORBIDDEN) 
            unless $user_role eq $role || $user_role eq 'admin';
    }
    
    return;
}

# User management routes
get '/api/users' => sub {
    my $auth_error = require_auth();
    return $auth_error if $auth_error;
    
    my $users = database->selectall_arrayref(
        'SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC',
        { Slice => {} }
    );
    
    return json_response($users);
};

get '/api/users/:id' => sub {
    my $auth_error = require_auth();
    return $auth_error if $auth_error;
    
    my $id = route_parameters->get('id');
    return error_response("Invalid user ID") unless $id =~ /^\\d+$/;
    
    my $user = database->selectrow_hashref(
        'SELECT id, name, email, role, created_at FROM users WHERE id = ?',
        undef, $id
    );
    
    return error_response("User not found", HTTP_NOT_FOUND) unless $user;
    
    return json_response($user);
};

post '/api/users' => sub {
    my $auth_error = require_auth('admin');
    return $auth_error if $auth_error;
    
    my $data = decode_json(request->body);
    
    # Validate input
    my @errors;
    push @errors, "Name is required" unless $data->{name} && length($data->{name}) > 0;
    push @errors, "Email is required" unless $data->{email};
    push @errors, "Invalid email format" unless validate_email($data->{email});
    push @errors, "Password is required" unless $data->{password};
    push @errors, "Password must be at least 6 characters" unless length($data->{password} // '') >= 6;
    
    return error_response("Validation failed", HTTP_BAD_REQUEST, \\@errors) if @errors;
    
    # Check if user already exists
    my $existing = database->selectrow_hashref(
        'SELECT id FROM users WHERE email = ?',
        undef, $data->{email}
    );
    
    return error_response("User already exists", HTTP_CONFLICT) if $existing;
    
    # Create user
    my $password_hash = bcrypt($data->{password}, '$2a$10$' . generate_salt());
    my $role = $data->{role} || 'user';
    
    database->do(q{
        INSERT INTO users (name, email, password_hash, role, created_at, updated_at) 
        VALUES (?, ?, ?, ?, NOW(), NOW())
    }, undef, $data->{name}, $data->{email}, $password_hash, $role);
    
    my $user = database->selectrow_hashref(
        'SELECT id, name, email, role, created_at FROM users WHERE email = ?',
        undef, $data->{email}
    );
    
    return json_response($user, HTTP_CREATED);
};

put '/api/users/:id' => sub {
    my $auth_error = require_auth();
    return $auth_error if $auth_error;
    
    my $id = route_parameters->get('id');
    return error_response("Invalid user ID") unless $id =~ /^\\d+$/;
    
    # Check if user exists
    my $existing = database->selectrow_hashref(
        'SELECT id, email FROM users WHERE id = ?',
        undef, $id
    );
    
    return error_response("User not found", HTTP_NOT_FOUND) unless $existing;
    
    # Check permissions (users can only update themselves unless admin)
    my $user_id = session('user_id');
    my $user_role = session('user_role');
    unless ($user_role eq 'admin' || $user_id == $id) {
        return error_response("Insufficient permissions", HTTP_FORBIDDEN);
    }
    
    my $data = decode_json(request->body);
    
    # Validate input
    my @errors;
    push @errors, "Name cannot be empty" if exists $data->{name} && length($data->{name}) == 0;
    push @errors, "Invalid email format" if $data->{email} && !validate_email($data->{email});
    
    return error_response("Validation failed", HTTP_BAD_REQUEST, \\@errors) if @errors;
    
    # Check email uniqueness
    if ($data->{email} && $data->{email} ne $existing->{email}) {
        my $email_exists = database->selectrow_hashref(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            undef, $data->{email}, $id
        );
        return error_response("Email already exists", HTTP_CONFLICT) if $email_exists;
    }
    
    # Build update query
    my @fields = ();
    my @values = ();
    
    for my $field (qw(name email)) {
        if (exists $data->{$field}) {
            push @fields, "$field = ?";
            push @values, $data->{$field};
        }
    }
    
    # Only admins can change roles
    if ($data->{role} && $user_role eq 'admin') {
        push @fields, "role = ?";
        push @values, $data->{role};
    }
    
    return error_response("No fields to update") unless @fields;
    
    push @fields, "updated_at = NOW()";
    push @values, $id;
    
    database->do(
        "UPDATE users SET " . join(', ', @fields) . " WHERE id = ?",
        undef, @values
    );
    
    my $user = database->selectrow_hashref(
        'SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = ?',
        undef, $id
    );
    
    return json_response($user);
};

del '/api/users/:id' => sub {
    my $auth_error = require_auth('admin');
    return $auth_error if $auth_error;
    
    my $id = route_parameters->get('id');
    return error_response("Invalid user ID") unless $id =~ /^\\d+$/;
    
    # Check if user exists
    my $existing = database->selectrow_hashref(
        'SELECT id FROM users WHERE id = ?',
        undef, $id
    );
    
    return error_response("User not found", HTTP_NOT_FOUND) unless $existing;
    
    # Don't allow deleting yourself
    my $user_id = session('user_id');
    return error_response("Cannot delete yourself", HTTP_BAD_REQUEST) if $user_id == $id;
    
    database->do('DELETE FROM users WHERE id = ?', undef, $id);
    
    status HTTP_NO_CONTENT;
    return '';
};

# Health check endpoint
get '/health' => sub {
    my $health = {
        status => 'ok',
        timestamp => DateTime->now->iso8601,
        version => $VERSION,
        service => 'dancer2-app'
    };
    
    # Check database connection
    try {
        database->selectrow_array('SELECT 1');
        $health->{database} = 'connected';
    } catch {
        $health->{status} = 'error';
        $health->{database} = 'disconnected';
        $health->{error} = $_;
        return json_response($health, HTTP_SERVICE_UNAVAILABLE);
    };
    
    return json_response($health);
};

# Static routes
get '/' => sub {
    template 'index';
};

get '/docs' => sub {
    template 'docs';
};

# Handle preflight requests
options qr{.*} => sub {
    status HTTP_OK;
    return '';
};

# 404 handler
any qr{.*} => sub {
    status HTTP_NOT_FOUND;
    return json_response({ error => 'Not Found' }, HTTP_NOT_FOUND);
};

true;`,

    'config.yml': `# Dancer2 configuration file

# Application settings
appname: "Dancer2App"
charset: "UTF-8"
logger: "console"
log: "debug"

# Template settings
template: "template_toolkit"
engines:
  template:
    template_toolkit:
      start_tag: '[%'
      end_tag: '%]'
      encoding: 'utf8'

# Session settings
session: "Cookie"
engines:
  session:
    Cookie:
      cookie_name: "dancer2_session"
      cookie_duration: 3600
      is_secure: 0
      is_http_only: 1
      secret_key: "your-secret-key-here"

# Database settings
plugins:
  Database:
    driver: 'Pg'
    database: 'dancer2_app'
    host: 'localhost'
    port: 5432
    username: 'postgres'
    password: 'postgres'
    connection_check_threshold: 10
    dbi_params:
      RaiseError: 1
      AutoCommit: 1
      PrintError: 1
      pg_enable_utf8: 1

# CORS settings
cors:
  origin: "*"
  methods: "GET, POST, PUT, DELETE, OPTIONS"
  headers: "Content-Type, Authorization, X-Requested-With"
  max_age: 86400

# Development settings
show_errors: 1
warnings: 1
traces: 1

# Static file serving
static_handler: 1
public_dir: "public"

# Auto page rendering
auto_page: 1`,

    'environments/development.yml': `# Development environment
logger: "console"
log: "debug"
show_errors: 1
warnings: 1
traces: 1

# Database for development
plugins:
  Database:
    driver: 'Pg'
    database: 'dancer2_app_dev'
    host: 'localhost'
    port: 5432
    username: 'postgres'
    password: 'postgres'
    connection_check_threshold: 10
    dbi_params:
      RaiseError: 1
      AutoCommit: 1
      PrintError: 1
      pg_enable_utf8: 1

# Session settings for development
engines:
  session:
    Cookie:
      cookie_name: "dancer2_dev_session"
      cookie_duration: 3600
      is_secure: 0
      is_http_only: 1
      secret_key: "dev-secret-key"`,

    'environments/production.yml': `# Production environment
logger: "file"
log: "error"
show_errors: 0
warnings: 0
traces: 0

# Database for production
plugins:
  Database:
    driver: 'Pg'
    database: 'dancer2_app_prod'
    host: 'localhost'
    port: 5432
    username: 'postgres'
    password: 'postgres'
    connection_check_threshold: 10
    dbi_params:
      RaiseError: 1
      AutoCommit: 1
      PrintError: 0
      pg_enable_utf8: 1

# Session settings for production
engines:
  session:
    Cookie:
      cookie_name: "dancer2_prod_session"
      cookie_duration: 3600
      is_secure: 1
      is_http_only: 1
      secret_key: "production-secret-key"

# Logging for production
engines:
  logger:
    file:
      log_dir: "logs"
      file_name: "dancer2_app.log"`,

    'bin/app.psgi': `#!/usr/bin/env perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Dancer2App;
use Dancer2;

# Return the PSGI app
Dancer2App->to_app;`,

    'bin/server.pl': `#!/usr/bin/env perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Dancer2App;
use Dancer2;

# Start the Dancer2 application
Dancer2App->dance;`,

    'views/index.tt': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dancer2 Web Application</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
        }
        .feature {
            margin: 20px 0;
            padding: 15px;
            background: #f9f9f9;
            border-left: 4px solid #007bff;
        }
        .api-endpoint {
            background: #e9ecef;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-family: monospace;
        }
        .auth-demo {
            margin: 20px 0;
            padding: 15px;
            background: #f0f8ff;
            border-radius: 5px;
        }
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover {
            background: #0056b3;
        }
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%;
            padding: 8px;
            margin: 5px 0;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        .response {
            border: 1px solid #ddd;
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
            font-family: monospace;
            background: #f8f9fa;
            min-height: 100px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>💃 Dancer2 Web Application</h1>
        
        <div class="feature">
            <h3>Lightweight Web Framework</h3>
            <p>Built with Dancer2, featuring modern routing, middleware support, and a rich plugin ecosystem.</p>
        </div>
        
        <div class="feature">
            <h3>API Endpoints</h3>
            <div class="api-endpoint">POST /api/auth/register - User registration</div>
            <div class="api-endpoint">POST /api/auth/login - User authentication</div>
            <div class="api-endpoint">GET /api/users - Get all users (admin only)</div>
            <div class="api-endpoint">POST /api/users - Create user (admin only)</div>
            <div class="api-endpoint">GET /health - Health check</div>
        </div>
        
        <div class="feature">
            <h3>Authentication Demo</h3>
            <div class="auth-demo">
                <h4>User Registration</h4>
                <input type="text" id="regName" placeholder="Full Name">
                <input type="email" id="regEmail" placeholder="Email">
                <input type="password" id="regPassword" placeholder="Password">
                <button onclick="registerUser()">Register</button>
                
                <h4>User Login</h4>
                <input type="email" id="loginEmail" placeholder="Email">
                <input type="password" id="loginPassword" placeholder="Password">
                <button onclick="loginUser()">Login</button>
                
                <h4>Protected Actions</h4>
                <button onclick="getUsers()">Get Users</button>
                <button onclick="logout()">Logout</button>
                
                <h4>Response</h4>
                <div id="response" class="response"></div>
            </div>
        </div>
        
        <div class="feature">
            <h3>Features</h3>
            <ul>
                <li>Lightweight and flexible routing</li>
                <li>Middleware support</li>
                <li>Plugin ecosystem</li>
                <li>Template engine integration</li>
                <li>Session management</li>
                <li>Database integration</li>
                <li>JSON API support</li>
                <li>Authentication and authorization</li>
            </ul>
        </div>
    </div>

    <script>
        let authToken = null;
        
        function showResponse(data) {
            const response = document.getElementById('response');
            response.textContent = JSON.stringify(data, null, 2);
        }
        
        function makeRequest(method, url, data = null) {
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            };
            
            if (authToken) {
                options.headers['Authorization'] = 'Bearer ' + authToken;
            }
            
            if (data) {
                options.body = JSON.stringify(data);
            }
            
            return fetch(url, options)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(\`HTTP \${response.status}: \${response.statusText}\`);
                    }
                    return response.json();
                })
                .catch(error => {
                    throw new Error(\`Request failed: \${error.message}\`);
                });
        }
        
        function registerUser() {
            const name = document.getElementById('regName').value;
            const email = document.getElementById('regEmail').value;
            const password = document.getElementById('regPassword').value;
            
            if (!name || !email || !password) {
                showResponse({ error: 'All fields are required' });
                return;
            }
            
            makeRequest('POST', '/api/auth/register', {
                name: name,
                email: email,
                password: password
            })
            .then(data => {
                showResponse(data);
                // Clear form
                document.getElementById('regName').value = '';
                document.getElementById('regEmail').value = '';
                document.getElementById('regPassword').value = '';
            })
            .catch(error => {
                showResponse({ error: error.message });
            });
        }
        
        function loginUser() {
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            
            if (!email || !password) {
                showResponse({ error: 'Email and password are required' });
                return;
            }
            
            makeRequest('POST', '/api/auth/login', {
                email: email,
                password: password
            })
            .then(data => {
                authToken = data.token;
                showResponse(data);
                // Clear form
                document.getElementById('loginEmail').value = '';
                document.getElementById('loginPassword').value = '';
            })
            .catch(error => {
                showResponse({ error: error.message });
            });
        }
        
        function getUsers() {
            if (!authToken) {
                showResponse({ error: 'Please login first' });
                return;
            }
            
            makeRequest('GET', '/api/users')
            .then(data => {
                showResponse(data);
            })
            .catch(error => {
                showResponse({ error: error.message });
            });
        }
        
        function logout() {
            makeRequest('POST', '/api/auth/logout')
            .then(data => {
                authToken = null;
                showResponse(data);
            })
            .catch(error => {
                showResponse({ error: error.message });
            });
        }
        
        // Test health endpoint on load
        window.addEventListener('load', function() {
            makeRequest('GET', '/health')
            .then(data => {
                console.log('Health check:', data);
            })
            .catch(error => {
                console.error('Health check failed:', error);
            });
        });
    </script>
</body>
</html>`,

    'views/docs.tt': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Documentation - Dancer2 App</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .endpoint {
            margin: 20px 0;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
        .method {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            margin-right: 10px;
        }
        .get { background: #28a745; }
        .post { background: #007bff; }
        .put { background: #ffc107; color: #333; }
        .delete { background: #dc3545; }
        .code {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            overflow-x: auto;
        }
        .response {
            margin: 10px 0;
            padding: 10px;
            background: #e9ecef;
            border-radius: 3px;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        .table th, .table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .table th {
            background: #f8f9fa;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📚 API Documentation</h1>
        
        <h2>Base URL</h2>
        <div class="code">http://localhost:5000</div>
        
        <h2>Authentication</h2>
        <p>This API uses session-based authentication. After successful login, the session cookie is automatically included in subsequent requests.</p>
        
        <h2>Endpoints</h2>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span>/api/auth/register</h3>
            <p>Register a new user account.</p>
            <div class="code">
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
            </div>
            <div class="response">
                <strong>Response (201):</strong>
                <div class="code">
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "role": "user",
  "created_at": "2024-01-01T12:00:00Z"
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span>/api/auth/login</h3>
            <p>Authenticate user and create session.</p>
            <div class="code">
{
  "email": "john@example.com",
  "password": "password123"
}
            </div>
            <div class="response">
                <strong>Response (200):</strong>
                <div class="code">
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "user"
  }
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span>/api/auth/logout</h3>
            <p>Destroy user session.</p>
            <div class="response">
                <strong>Response (200):</strong>
                <div class="code">
{
  "message": "Logged out successfully"
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method get">GET</span>/api/users</h3>
            <p>Get all users (requires authentication).</p>
            <div class="response">
                <strong>Response (200):</strong>
                <div class="code">
[
  {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "user",
    "created_at": "2024-01-01T12:00:00Z"
  }
]
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span>/api/users</h3>
            <p>Create a new user (requires admin role).</p>
            <div class="code">
{
  "name": "Jane Smith",
  "email": "jane@example.com",
  "password": "password456",
  "role": "user"
}
            </div>
            <div class="response">
                <strong>Response (201):</strong>
                <div class="code">
{
  "id": 2,
  "name": "Jane Smith",
  "email": "jane@example.com",
  "role": "user",
  "created_at": "2024-01-01T12:00:00Z"
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method get">GET</span>/api/users/:id</h3>
            <p>Get a specific user by ID (requires authentication).</p>
            <div class="response">
                <strong>Response (200):</strong>
                <div class="code">
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "role": "user",
  "created_at": "2024-01-01T12:00:00Z"
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method put">PUT</span>/api/users/:id</h3>
            <p>Update a user (requires authentication, users can only update themselves unless admin).</p>
            <div class="code">
{
  "name": "John Updated",
  "email": "john.updated@example.com"
}
            </div>
            <div class="response">
                <strong>Response (200):</strong>
                <div class="code">
{
  "id": 1,
  "name": "John Updated",
  "email": "john.updated@example.com",
  "role": "user",
  "updated_at": "2024-01-01T13:00:00Z"
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method delete">DELETE</span>/api/users/:id</h3>
            <p>Delete a user (requires admin role).</p>
            <div class="response">
                <strong>Response (204):</strong>
                <div class="code">
No content
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method get">GET</span>/health</h3>
            <p>Health check endpoint.</p>
            <div class="response">
                <strong>Response (200):</strong>
                <div class="code">
{
  "status": "ok",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "0.1",
  "service": "dancer2-app",
  "database": "connected"
}
                </div>
            </div>
        </div>
        
        <h2>User Roles</h2>
        <table class="table">
            <thead>
                <tr>
                    <th>Role</th>
                    <th>Permissions</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>user</td>
                    <td>Read own profile, update own profile</td>
                    <td>Regular user with limited permissions</td>
                </tr>
                <tr>
                    <td>admin</td>
                    <td>Full access to all endpoints</td>
                    <td>Administrator with full system access</td>
                </tr>
            </tbody>
        </table>
        
        <h2>Error Responses</h2>
        <div class="response">
            <strong>400 Bad Request:</strong>
            <div class="code">
{
  "error": "Validation failed",
  "details": ["Name is required", "Invalid email format"]
}
            </div>
        </div>
        
        <div class="response">
            <strong>401 Unauthorized:</strong>
            <div class="code">
{
  "error": "Authentication required"
}
            </div>
        </div>
        
        <div class="response">
            <strong>403 Forbidden:</strong>
            <div class="code">
{
  "error": "Insufficient permissions"
}
            </div>
        </div>
        
        <div class="response">
            <strong>404 Not Found:</strong>
            <div class="code">
{
  "error": "User not found"
}
            </div>
        </div>
        
        <div class="response">
            <strong>409 Conflict:</strong>
            <div class="code">
{
  "error": "User already exists"
}
            </div>
        </div>
        
        <h2>Request Headers</h2>
        <table class="table">
            <thead>
                <tr>
                    <th>Header</th>
                    <th>Value</th>
                    <th>Required</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Content-Type</td>
                    <td>application/json</td>
                    <td>For POST/PUT requests</td>
                </tr>
                <tr>
                    <td>Accept</td>
                    <td>application/json</td>
                    <td>Recommended</td>
                </tr>
                <tr>
                    <td>Authorization</td>
                    <td>Bearer {token}</td>
                    <td>For protected endpoints</td>
                </tr>
            </tbody>
        </table>
    </div>
</body>
</html>`,

    'views/layouts/main.tt': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>[% title %] - Dancer2 App</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        .navbar {
            background: #007bff;
            color: white;
            padding: 1rem 0;
            margin-bottom: 2rem;
        }
        .navbar .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .navbar a {
            color: white;
            text-decoration: none;
            margin: 0 10px;
        }
        .navbar a:hover {
            text-decoration: underline;
        }
        .content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        .footer {
            background: #333;
            color: white;
            text-align: center;
            padding: 2rem 0;
            margin-top: 3rem;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div>
                <a href="/">💃 Dancer2 App</a>
            </div>
            <div>
                <a href="/">Home</a>
                <a href="/docs">API Docs</a>
                <a href="/health">Health</a>
            </div>
        </div>
    </nav>
    
    <div class="content">
        [% content %]
    </div>
    
    <footer class="footer">
        <div class="container">
            <p>&copy; 2024 Dancer2 Web Application. Built with Dancer2 framework.</p>
        </div>
    </footer>
</body>
</html>`,

    't/001_base.t': `use strict;
use warnings;
use Test::More;
use Plack::Test;
use HTTP::Request::Common;
use JSON;

use Dancer2App;

my $app = Dancer2App->to_app;
my $test = Plack::Test->create($app);

# Test health endpoint
subtest 'Health endpoint' => sub {
    my $res = $test->request(GET '/health');
    is $res->code, 200, 'Health check returns 200';
    
    my $data = decode_json($res->content);
    is $data->{status}, 'ok', 'Health status is ok';
    ok $data->{timestamp}, 'Health response has timestamp';
    ok $data->{version}, 'Health response has version';
};

# Test home page
subtest 'Home page' => sub {
    my $res = $test->request(GET '/');
    is $res->code, 200, 'Home page returns 200';
    like $res->content, qr/Dancer2 Web Application/, 'Home page has correct title';
};

# Test API documentation
subtest 'API documentation' => sub {
    my $res = $test->request(GET '/docs');
    is $res->code, 200, 'Docs page returns 200';
    like $res->content, qr/API Documentation/, 'Docs page has correct title';
};

# Test 404 handling
subtest '404 handling' => sub {
    my $res = $test->request(GET '/nonexistent');
    is $res->code, 404, 'Non-existent route returns 404';
    
    my $data = decode_json($res->content);
    is $data->{error}, 'Not Found', '404 response has error message';
};

# Test CORS preflight
subtest 'CORS preflight' => sub {
    my $res = $test->request(OPTIONS '/api/users');
    is $res->code, 200, 'CORS preflight returns 200';
    
    my $headers = $res->headers;
    like $headers->header('Access-Control-Allow-Origin'), qr/\\*/, 'CORS origin header present';
    like $headers->header('Access-Control-Allow-Methods'), qr/GET.*POST.*PUT.*DELETE/, 'CORS methods header present';
};

done_testing;`,

    't/002_auth.t': `use strict;
use warnings;
use Test::More;
use Plack::Test;
use HTTP::Request::Common;
use JSON;

use Dancer2App;

my $app = Dancer2App->to_app;
my $test = Plack::Test->create($app);

# Test user registration
subtest 'User registration' => sub {
    my $user_data = {
        name => 'Test User',
        email => 'test@example.com',
        password => 'password123'
    };
    
    my $res = $test->request(POST '/api/auth/register',
        'Content-Type' => 'application/json',
        Content => encode_json($user_data)
    );
    
    is $res->code, 201, 'User registration returns 201';
    
    my $data = decode_json($res->content);
    ok $data->{id}, 'Registration response has user ID';
    is $data->{name}, 'Test User', 'Registration response has correct name';
    is $data->{email}, 'test@example.com', 'Registration response has correct email';
    is $data->{role}, 'user', 'Registration response has correct role';
};

# Test duplicate registration
subtest 'Duplicate registration' => sub {
    my $user_data = {
        name => 'Test User',
        email => 'test@example.com',
        password => 'password123'
    };
    
    my $res = $test->request(POST '/api/auth/register',
        'Content-Type' => 'application/json',
        Content => encode_json($user_data)
    );
    
    is $res->code, 409, 'Duplicate registration returns 409';
    
    my $data = decode_json($res->content);
    is $data->{error}, 'User already exists', 'Duplicate registration has error message';
};

# Test validation errors
subtest 'Registration validation' => sub {
    my $invalid_data = {
        name => '',
        email => 'invalid-email',
        password => '123'
    };
    
    my $res = $test->request(POST '/api/auth/register',
        'Content-Type' => 'application/json',
        Content => encode_json($invalid_data)
    );
    
    is $res->code, 400, 'Invalid registration returns 400';
    
    my $data = decode_json($res->content);
    is $data->{error}, 'Validation failed', 'Invalid registration has error message';
    ok ref($data->{details}) eq 'ARRAY', 'Invalid registration has details array';
};

# Test user login
subtest 'User login' => sub {
    my $login_data = {
        email => 'test@example.com',
        password => 'password123'
    };
    
    my $res = $test->request(POST '/api/auth/login',
        'Content-Type' => 'application/json',
        Content => encode_json($login_data)
    );
    
    is $res->code, 200, 'User login returns 200';
    
    my $data = decode_json($res->content);
    ok $data->{token}, 'Login response has token';
    ok $data->{user}, 'Login response has user data';
    is $data->{user}->{email}, 'test@example.com', 'Login response has correct email';
};

# Test invalid login
subtest 'Invalid login' => sub {
    my $login_data = {
        email => 'test@example.com',
        password => 'wrongpassword'
    };
    
    my $res = $test->request(POST '/api/auth/login',
        'Content-Type' => 'application/json',
        Content => encode_json($login_data)
    );
    
    is $res->code, 401, 'Invalid login returns 401';
    
    my $data = decode_json($res->content);
    is $data->{error}, 'Invalid credentials', 'Invalid login has error message';
};

# Test protected endpoint without auth
subtest 'Protected endpoint without auth' => sub {
    my $res = $test->request(GET '/api/users');
    is $res->code, 401, 'Protected endpoint without auth returns 401';
    
    my $data = decode_json($res->content);
    is $data->{error}, 'Authentication required', 'Protected endpoint has error message';
};

done_testing;`,

    't/003_users.t': `use strict;
use warnings;
use Test::More;
use Plack::Test;
use HTTP::Request::Common;
use JSON;

use Dancer2App;

my $app = Dancer2App->to_app;
my $test = Plack::Test->create($app);

# Helper to login and get session
sub login_user {
    my ($email, $password) = @_;
    
    my $login_data = {
        email => $email,
        password => $password
    };
    
    my $res = $test->request(POST '/api/auth/login',
        'Content-Type' => 'application/json',
        Content => encode_json($login_data)
    );
    
    return decode_json($res->content);
}

# Test user management with admin user
subtest 'User management' => sub {
    # Login as admin
    my $admin_login = login_user('admin@example.com', 'admin123');
    ok $admin_login->{token}, 'Admin login successful';
    
    # Get users
    my $res = $test->request(GET '/api/users');
    is $res->code, 200, 'Get users returns 200';
    
    my $users = decode_json($res->content);
    ok ref($users) eq 'ARRAY', 'Get users returns array';
    ok @$users >= 2, 'Users array has at least 2 users';
    
    # Get specific user
    my $user_id = $users->[0]->{id};
    $res = $test->request(GET "/api/users/$user_id");
    is $res->code, 200, 'Get specific user returns 200';
    
    my $user = decode_json($res->content);
    is $user->{id}, $user_id, 'Get specific user returns correct user';
    
    # Create new user
    my $new_user_data = {
        name => 'New User',
        email => 'new@example.com',
        password => 'password123',
        role => 'user'
    };
    
    $res = $test->request(POST '/api/users',
        'Content-Type' => 'application/json',
        Content => encode_json($new_user_data)
    );
    
    is $res->code, 201, 'Create user returns 201';
    
    my $new_user = decode_json($res->content);
    ok $new_user->{id}, 'New user has ID';
    is $new_user->{name}, 'New User', 'New user has correct name';
    is $new_user->{email}, 'new@example.com', 'New user has correct email';
    
    # Update user
    my $update_data = {
        name => 'Updated User'
    };
    
    $res = $test->request(PUT "/api/users/" . $new_user->{id},
        'Content-Type' => 'application/json',
        Content => encode_json($update_data)
    );
    
    is $res->code, 200, 'Update user returns 200';
    
    my $updated_user = decode_json($res->content);
    is $updated_user->{name}, 'Updated User', 'User name updated correctly';
    
    # Delete user
    $res = $test->request(DELETE "/api/users/" . $new_user->{id});
    is $res->code, 204, 'Delete user returns 204';
    
    # Verify user is deleted
    $res = $test->request(GET "/api/users/" . $new_user->{id});
    is $res->code, 404, 'Deleted user returns 404';
};

# Test user permissions
subtest 'User permissions' => sub {
    # Login as regular user
    my $user_login = login_user('user@example.com', 'user123');
    ok $user_login->{token}, 'User login successful';
    
    # Try to create user (should fail)
    my $new_user_data = {
        name => 'Unauthorized User',
        email => 'unauthorized@example.com',
        password => 'password123'
    };
    
    my $res = $test->request(POST '/api/users',
        'Content-Type' => 'application/json',
        Content => encode_json($new_user_data)
    );
    
    is $res->code, 403, 'Regular user cannot create users';
    
    # Try to delete user (should fail)
    $res = $test->request(DELETE '/api/users/1');
    is $res->code, 403, 'Regular user cannot delete users';
};

done_testing;`,

    'README.md': `# Dancer2 Web Application

A lightweight and flexible web application built with Dancer2 framework, featuring modern routing, middleware support, and a comprehensive plugin ecosystem.

## Features

- **Lightweight Framework**: Built with Dancer2 for rapid development
- **Modern Routing**: Flexible and intuitive routing system
- **Middleware Support**: Extensible middleware architecture
- **Plugin Ecosystem**: Rich collection of plugins for common tasks
- **Template Engine**: Template Toolkit integration
- **Session Management**: Cookie-based session handling
- **Authentication**: Role-based authentication system
- **Database Integration**: PostgreSQL with DBI
- **JSON API**: RESTful JSON API endpoints
- **CORS Support**: Cross-origin resource sharing
- **Error Handling**: Comprehensive error handling
- **Testing Framework**: Built-in testing capabilities

## Quick Start

\`\`\`bash
# Install dependencies
cpanm --installdeps .

# Set up database
createdb dancer2_app

# Run the application
plackup bin/app.psgi

# Or use the development server
perl bin/server.pl
\`\`\`

The application will be available at:
- Web Interface: http://localhost:5000
- API Documentation: http://localhost:5000/docs
- Health Check: http://localhost:5000/health

## API Endpoints

### Authentication
- \`POST /api/auth/register\` - User registration
- \`POST /api/auth/login\` - User login
- \`POST /api/auth/logout\` - User logout

### Users
- \`GET /api/users\` - Get all users (authenticated)
- \`POST /api/users\` - Create user (admin only)
- \`GET /api/users/:id\` - Get user by ID (authenticated)
- \`PUT /api/users/:id\` - Update user (authenticated)
- \`DELETE /api/users/:id\` - Delete user (admin only)

### System
- \`GET /health\` - Health check endpoint
- \`GET /\` - Home page
- \`GET /docs\` - API documentation

## Usage Examples

### User Registration

\`\`\`bash
curl -X POST http://localhost:5000/api/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123"
  }'
\`\`\`

### User Login

\`\`\`bash
curl -X POST http://localhost:5000/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
\`\`\`

### Access Protected Endpoint

\`\`\`bash
curl -X GET http://localhost:5000/api/users \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  -b "dancer2_session=YOUR_SESSION_COOKIE"
\`\`\`

## Configuration

### Database Configuration

Edit \`config.yml\` to configure the database:

\`\`\`yaml
plugins:
  Database:
    driver: 'Pg'
    database: 'dancer2_app'
    host: 'localhost'
    port: 5432
    username: 'postgres'
    password: 'postgres'
\`\`\`

### Session Configuration

\`\`\`yaml
session: "Cookie"
engines:
  session:
    Cookie:
      cookie_name: "dancer2_session"
      cookie_duration: 3600
      secret_key: "your-secret-key-here"
\`\`\`

### Environment-Specific Configuration

- \`environments/development.yml\` - Development settings
- \`environments/production.yml\` - Production settings

## Development

### Running Tests

\`\`\`bash
# Run all tests
prove -l t/

# Run specific test file
prove -l t/001_base.t

# Run with verbose output
prove -lv t/
\`\`\`

### Development Server

\`\`\`bash
# Start development server
plackup -R lib bin/app.psgi

# Start with specific port
plackup -R lib -p 8080 bin/app.psgi

# Start with debugging
DANCER_ENVIRONMENT=development plackup -R lib bin/app.psgi
\`\`\`

### Production Deployment

\`\`\`bash
# Using Starman
starman --port 5000 --workers 4 bin/app.psgi

# Using Hypnotoad (if available)
hypnotoad bin/app.psgi

# Using nginx + FastCGI
plackup -s FCGI --listen /tmp/dancer2_app.sock bin/app.psgi
\`\`\`

## Architecture

### MVC Structure

- **Models**: Database interaction and business logic
- **Views**: Template Toolkit templates
- **Controllers**: Route handlers and request processing

### Plugin Architecture

The application uses several Dancer2 plugins:

- **Database**: Database connectivity and query execution
- **Auth::Extensible**: Authentication and authorization
- **REST**: RESTful API helpers
- **CORS**: Cross-origin resource sharing
- **Session::Cookie**: Session management

### Middleware Stack

- CORS handling
- Session management
- Authentication
- Database connectivity
- Error handling
- JSON serialization

## User Roles

### User
- Read own profile
- Update own profile
- Access basic endpoints

### Admin
- Full access to all endpoints
- User management capabilities
- System administration

## Security Features

- **Password Hashing**: bcrypt for secure password storage
- **Session Security**: Secure cookie configuration
- **Input Validation**: Comprehensive request validation
- **CORS Protection**: Configurable CORS policies
- **SQL Injection Prevention**: Parameterized queries
- **Role-based Access Control**: Granular permissions

## Performance

- **Lightweight**: Minimal overhead and fast startup
- **Efficient Routing**: Optimized route matching
- **Connection Pooling**: Database connection management
- **Template Caching**: Compiled template caching
- **Static File Serving**: Efficient static content delivery

## Testing

The application includes comprehensive tests:

- **Unit Tests**: Individual component testing
- **Integration Tests**: API endpoint testing
- **Authentication Tests**: Login/logout/registration testing
- **Permission Tests**: Role-based access testing

## Docker Support

\`\`\`bash
# Build image
docker build -t dancer2-app .

# Run container
docker run -p 5000:5000 dancer2-app

# Using docker-compose
docker-compose up -d
\`\`\`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

Copyright © 2024 Re-Shell Team

This project is licensed under the MIT License.
`,

    'Dockerfile': `FROM perl:5.38-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    libpq-dev \\
    postgresql-client \\
    && rm -rf /var/lib/apt/lists/*

# Install cpanm
RUN curl -L https://cpanmin.us | perl - App::cpanminus

# Copy dependencies file
COPY cpanfile .

# Install Perl dependencies
RUN cpanm --installdeps .

# Copy application code
COPY . .

# Make scripts executable
RUN chmod +x bin/server.pl bin/app.psgi

# Expose port
EXPOSE 5000

# Run the application
CMD ["plackup", "-p", "5000", "-s", "Starman", "bin/app.psgi"]`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DANCER_ENVIRONMENT=production
      - POSTGRES_HOST=postgres
      - POSTGRES_DB=dancer2_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    depends_on:
      - postgres
    volumes:
      - ./logs:/app/logs
  
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=dancer2_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:`,

    '.gitignore': `# Perl
*.bak
*.tmp
*~
MYMETA.*
Makefile
Makefile.old
blib/
pm_to_blib
META.yml
META.json
MANIFEST.bak
inc/
.build/
_build/
Build
Build.bat
.last_cover_stats
cover_db/
nytprof.out
nytprof/

# Dancer2 specific
logs/
*.log
*.pid
session_data/
environments/*.local.yml

# Application specific
.env
config.local.yml

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db`,

    'examples/client.pl': `#!/usr/bin/env perl
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request::Common;
use JSON;
use Data::Dumper;

# Create user agent
my $ua = LWP::UserAgent->new;
$ua->cookie_jar({}); # Enable cookies for session management

my $base_url = 'http://localhost:5000';

# Helper function to make JSON requests
sub json_request {
    my ($method, $url, $data) = @_;
    
    my $req;
    if ($method eq 'GET') {
        $req = GET $url;
    } elsif ($method eq 'POST') {
        $req = POST $url, 'Content-Type' => 'application/json', Content => encode_json($data);
    } elsif ($method eq 'PUT') {
        $req = PUT $url, 'Content-Type' => 'application/json', Content => encode_json($data);
    } elsif ($method eq 'DELETE') {
        $req = DELETE $url;
    }
    
    my $response = $ua->request($req);
    
    if ($response->is_success) {
        return decode_json($response->content);
    } else {
        die "Request failed: " . $response->status_line . "\\n" . $response->content;
    }
}

print "=== Dancer2 API Client Example ===\\n\\n";

# Test health endpoint
print "1. Testing health endpoint...\\n";
my $health = json_request('GET', "$base_url/health");
print "Health status: " . $health->{status} . "\\n";
print "Service version: " . $health->{version} . "\\n\\n";

# Register a user
print "2. Registering new user...\\n";
my $user_data = {
    name => 'Test User',
    email => 'test@example.com',
    password => 'password123'
};

eval {
    my $registered_user = json_request('POST', "$base_url/api/auth/register", $user_data);
    print "User registered successfully: " . $registered_user->{name} . "\\n";
    print "User ID: " . $registered_user->{id} . "\\n";
};
if ($@) {
    print "Registration failed (user may already exist): $@\\n";
}

# Login user
print "\\n3. Logging in user...\\n";
my $login_data = {
    email => 'test@example.com',
    password => 'password123'
};

my $login_result = json_request('POST', "$base_url/api/auth/login", $login_data);
print "Login successful!\\n";
print "User: " . $login_result->{user}->{name} . "\\n";
print "Token: " . substr($login_result->{token}, 0, 50) . "...\\n";

# Get users (this should work now that we're logged in)
print "\\n4. Getting users list...\\n";
my $users = json_request('GET', "$base_url/api/users");
print "Found " . scalar(@$users) . " users:\\n";
for my $user (@$users) {
    print "  - " . $user->{name} . " (" . $user->{email} . ") [" . $user->{role} . "]\\n";
}

# Get specific user
print "\\n5. Getting specific user...\\n";
my $first_user = $users->[0];
my $specific_user = json_request('GET', "$base_url/api/users/" . $first_user->{id});
print "User details: " . $specific_user->{name} . " (" . $specific_user->{email} . ")\\n";

# Update user (only works if we're updating ourselves or we're admin)
print "\\n6. Updating user profile...\\n";
my $update_data = {
    name => 'Updated Test User'
};

eval {
    my $updated_user = json_request('PUT', "$base_url/api/users/" . $first_user->{id}, $update_data);
    print "User updated successfully: " . $updated_user->{name} . "\\n";
};
if ($@) {
    print "Update failed (insufficient permissions): $@\\n";
}

# Try to create a user (admin only)
print "\\n7. Attempting to create user (admin only)...\\n";
my $new_user_data = {
    name => 'Admin Created User',
    email => 'admin_created@example.com',
    password => 'password456',
    role => 'user'
};

eval {
    my $new_user = json_request('POST', "$base_url/api/users", $new_user_data);
    print "User created successfully: " . $new_user->{name} . "\\n";
};
if ($@) {
    print "User creation failed (admin role required): $@\\n";
}

# Logout
print "\\n8. Logging out...\\n";
my $logout_result = json_request('POST', "$base_url/api/auth/logout");
print "Logout message: " . $logout_result->{message} . "\\n";

print "\\n=== API testing complete! ===\\n";`,

    'examples/benchmark.pl': `#!/usr/bin/env perl
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request::Common;
use JSON;
use Time::HiRes qw(time);
use List::Util qw(sum);

my $ua = LWP::UserAgent->new;
my $base_url = 'http://localhost:5000';

sub benchmark_endpoint {
    my ($method, $url, $data, $iterations) = @_;
    $iterations ||= 100;
    
    print "Benchmarking $method $url ($iterations iterations)...\\n";
    
    my @times;
    my $success_count = 0;
    
    for my $i (1..$iterations) {
        my $start = time;
        
        my $req;
        if ($method eq 'GET') {
            $req = GET $url;
        } elsif ($method eq 'POST') {
            $req = POST $url, 'Content-Type' => 'application/json', Content => encode_json($data);
        }
        
        my $response = $ua->request($req);
        my $elapsed = time - $start;
        
        push @times, $elapsed;
        $success_count++ if $response->is_success;
        
        print "." if $i % 10 == 0;
    }
    
    print "\\n";
    
    my $total_time = sum(@times);
    my $avg_time = $total_time / @times;
    my $min_time = min(@times);
    my $max_time = max(@times);
    my $success_rate = ($success_count / $iterations) * 100;
    
    printf "Results:\\n";
    printf "  Total time: %.3f seconds\\n", $total_time;
    printf "  Average time: %.3f seconds\\n", $avg_time;
    printf "  Min time: %.3f seconds\\n", $min_time;
    printf "  Max time: %.3f seconds\\n", $max_time;
    printf "  Success rate: %.1f%%\\n", $success_rate;
    printf "  Requests per second: %.1f\\n", $iterations / $total_time;
    print "\\n";
}

sub min {
    my @values = @_;
    my $min = $values[0];
    for my $value (@values) {
        $min = $value if $value < $min;
    }
    return $min;
}

sub max {
    my @values = @_;
    my $max = $values[0];
    for my $value (@values) {
        $max = $value if $value > $max;
    }
    return $max;
}

print "=== Dancer2 Performance Benchmark ===\\n\\n";

# Benchmark health endpoint
benchmark_endpoint('GET', "$base_url/health");

# Benchmark home page
benchmark_endpoint('GET', "$base_url/");

# Benchmark API documentation
benchmark_endpoint('GET', "$base_url/docs");

# Benchmark user registration
benchmark_endpoint('POST', "$base_url/api/auth/register", {
    name => 'Benchmark User',
    email => 'benchmark@example.com',
    password => 'password123'
}, 10); # Fewer iterations for write operations

print "=== Benchmark complete! ===\\n";`
  },

  dependencies: {
    'Dancer2': '^1.0.0',
    'DBI': '^1.643',
    'DBD::Pg': '^3.16.0',
    'Crypt::Bcrypt': '^0.011',
    'JSON': '^4.10',
    'Email::Valid': '^1.202',
    'DateTime': '^1.59',
    'UUID::Tiny': '^1.04',
    'Template::Toolkit': '^3.101'
  },

  commands: {
    dev: 'plackup -R lib bin/app.psgi',
    build: 'perl -c lib/Dancer2App.pm',
    test: 'prove -l t/',
    lint: 'perlcritic lib/',
    format: 'perltidy -b lib/**/*.pm',
    repl: 'perl -Ilib -MDancer2App -E "say \\"Ready\\""',
    clean: 'rm -rf cover_db/ nytprof*',
    'test:verbose': 'prove -lv t/',
    'test:coverage': 'cover -test -report html',
    'dev:reload': 'plackup -R lib -p 5000 bin/app.psgi',
    'prod:start': 'starman --port 5000 --workers 4 bin/app.psgi',
    'docker:build': 'docker build -t dancer2-app .',
    'docker:run': 'docker run -p 5000:5000 dancer2-app',
    'docker:up': 'docker-compose up -d',
    'docker:down': 'docker-compose down'
  },

  ports: {
    dev: 5000,
    prod: 5000
  },

  examples: [
    {
      title: 'Route Definition',
      description: 'Define routes with HTTP methods and handlers',
      code: `get '/api/users' => sub {
  my $users = database->selectall_arrayref('SELECT * FROM users');
  return json_response($users);
};`
    },
    {
      title: 'Authentication Check',
      description: 'Protect routes with authentication middleware',
      code: `sub require_auth {
  my $user_id = session('user_id');
  return error_response("Authentication required", 401) unless $user_id;
  return;
}`
    },
    {
      title: 'Database Integration',
      description: 'Use database plugin for data operations',
      code: `my $user = database->selectrow_hashref(
  'SELECT * FROM users WHERE id = ?',
  undef, $user_id
);`
    }
  ]
};