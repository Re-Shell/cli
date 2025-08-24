import { BackendTemplate } from '../types';

export const perlMojoliciousTemplate: BackendTemplate = {
  id: 'perl-mojolicious',
  name: 'perl-mojolicious',
  displayName: 'Perl Mojolicious Web Framework',
  description: 'Real-time web framework for Perl with built-in WebSocket support, async I/O, and modern web development features',
  framework: 'mojolicious',
  language: 'perl',
  version: '9.34',
  author: 'Re-Shell Team',


  icon: '🔥',
  type: 'web-framework',
  complexity: 'intermediate',
  keywords: ['perl', 'mojolicious', 'realtime', 'websocket', 'async', 'modern'],
  
  features: [
    'Real-time web framework',
    'Built-in WebSocket support',
    'Async I/O operations',
    'Modern web development',
    'RESTful routing',
    'Template engine',
    'JSON API support',
    'Session management',
    'Authentication helpers',
    'Database integration',
    'Plugin system',
    'Hot code reloading',
    'Development tools',
    'Production deployment'
  ],
  
  structure: {
    'cpanfile': `# Mojolicious application dependencies
requires "Mojolicious", "9.34";
requires "Mojolicious::Plugin::Authentication", "1.40";
requires "Mojolicious::Plugin::Database", "1.22";
requires "Mojolicious::Plugin::OpenAPI", "5.00";
requires "Mojolicious::Plugin::Webpack", "0.12";
requires "DBI", "1.643";
requires "DBD::Pg", "3.16.0";
requires "Mojo::JWT", "0.09";
requires "Crypt::Bcrypt", "0.011";
requires "Data::Validate::Email", "0.04";
requires "DateTime", "1.59";
requires "JSON::Validator", "5.14";
requires "Mojo::Redis", "3.29";
requires "Test::Mojo", "0";
requires "Test::MockModule", "0";
requires "Devel::Cover", "1.38";

# Development dependencies
on 'develop' => sub {
  requires "Perl::Critic", "1.148";
  requires "Perl::Tidy", "20230309";
  requires "Devel::NYTProf", "6.12";
};`,

    'lib/MojoliciousApp.pm': `package MojoliciousApp;
use Mojo::Base 'Mojolicious', -signatures;

use MojoliciousApp::Model::Users;
use MojoliciousApp::Model::Auth;

# This method will run once at server start
sub startup ($self) {
    # Load configuration from config file
    my $config = $self->plugin('NotYAMLConfig');
    
    # Configure the application
    $self->secrets($config->{secrets});
    $self->sessions->cookie_name('mojolicious_app');
    $self->sessions->default_expiration(3600); # 1 hour
    
    # Load plugins
    $self->plugin('Authentication' => {
        load_user => sub ($app, $uid) {
            return MojoliciousApp::Model::Users->new->find($uid);
        },
        validate_user => sub ($app, $username, $password, $extradata) {
            return MojoliciousApp::Model::Auth->new->authenticate($username, $password);
        }
    });
    
    $self->plugin('Database' => {
        dsn => $config->{database}->{dsn},
        username => $config->{database}->{username},
        password => $config->{database}->{password},
        options => { RaiseError => 1, AutoCommit => 1 }
    });
    
    $self->plugin('OpenAPI' => {
        url => $self->home->rel_file('public/api.json')
    });
    
    # Enable CORS
    $self->hook(before_dispatch => sub ($c) {
        $c->res->headers->header('Access-Control-Allow-Origin' => '*');
        $c->res->headers->header('Access-Control-Allow-Methods' => 'GET, POST, PUT, DELETE, OPTIONS');
        $c->res->headers->header('Access-Control-Allow-Headers' => 'Content-Type, Authorization');
        
        # Handle preflight requests
        if ($c->req->method eq 'OPTIONS') {
            $c->render(text => '', status => 200);
            return;
        }
    });
    
    # Add helper methods
    $self->helper(users => sub { MojoliciousApp::Model::Users->new });
    $self->helper(auth => sub { MojoliciousApp::Model::Auth->new });
    
    # JWT helper
    $self->helper(jwt => sub ($c, $payload = undef) {
        state $jwt = Mojo::JWT->new(secret => $self->secrets->[0]);
        return $payload ? $jwt->encode($payload) : $jwt;
    });
    
    # Authentication helper
    $self->helper(authenticate => sub ($c) {
        my $auth_header = $c->req->headers->authorization;
        return unless $auth_header && $auth_header =~ /^Bearer\\s+(.+)$/;
        
        my $token = $1;
        my $claims = eval { $c->jwt->decode($token) };
        return unless $claims;
        
        $c->stash(user => $claims);
        return 1;
    });
    
    # Router
    my $r = $self->routes;
    
    # API routes
    my $api = $r->under('/api');
    
    # Authentication routes
    $api->post('/auth/register')->to('auth#register');
    $api->post('/auth/login')->to('auth#login');
    $api->post('/auth/logout')->to('auth#logout');
    
    # Protected routes
    my $protected = $api->under('/')->to('auth#check_auth');
    
    # User routes
    $protected->get('/users')->to('users#index');
    $protected->post('/users')->to('users#create');
    $protected->get('/users/:id')->to('users#show');
    $protected->put('/users/:id')->to('users#update');
    $protected->delete('/users/:id')->to('users#delete');
    
    # WebSocket route
    $r->websocket('/ws')->to('websocket#connect');
    
    # Real-time events
    $r->get('/events')->to('events#stream');
    
    # Health check
    $r->get('/health')->to('health#check');
    
    # Static files
    $r->get('/')->to('static#index');
    $r->get('/docs')->to('static#docs');
    
    # Set up database tables
    $self->_setup_database;
}

sub _setup_database ($self) {
    my $db = $self->app->database;
    
    # Create users table
    $db->query(q{
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    });
    
    # Insert sample data
    my $existing = $db->query('SELECT COUNT(*) FROM users')->array->[0];
    if ($existing == 0) {
        $db->query(q{
            INSERT INTO users (name, email, password_hash) VALUES 
            ('John Doe', 'john@example.com', ?),
            ('Jane Smith', 'jane@example.com', ?)
        }, '$2b$12$example.hash1', '$2b$12$example.hash2');
    }
}

1;`,

    'lib/MojoliciousApp/Controller/Auth.pm': `package MojoliciousApp::Controller::Auth;
use Mojo::Base 'Mojolicious::Controller', -signatures;

use Crypt::Bcrypt qw(bcrypt bcrypt_check);
use Data::Validate::Email qw(is_email);
use DateTime;

sub register ($self) {
    my $json = $self->req->json;
    
    # Validate input
    my $validation = $self->validation;
    $validation->required('name')->size(1, 100);
    $validation->required('email')->like(qr/^[^@]+@[^@]+\\.[^@]+$/);
    $validation->required('password')->size(6, 100);
    
    if ($validation->has_error) {
        return $self->render(json => {
            error => 'Validation failed',
            details => $validation->failed
        }, status => 400);
    }
    
    my $name = $json->{name};
    my $email = $json->{email};
    my $password = $json->{password};
    
    # Check if user already exists
    my $existing = $self->users->find_by_email($email);
    if ($existing) {
        return $self->render(json => {
            error => 'User already exists'
        }, status => 409);
    }
    
    # Hash password
    my $password_hash = bcrypt($password, '$2b$12$' . join('', map { chr(int(rand(94)) + 33) } 1..22));
    
    # Create user
    my $user = $self->users->create({
        name => $name,
        email => $email,
        password_hash => $password_hash
    });
    
    if ($user) {
        delete $user->{password_hash};
        $self->render(json => $user, status => 201);
    } else {
        $self->render(json => {
            error => 'Failed to create user'
        }, status => 500);
    }
}

sub login ($self) {
    my $json = $self->req->json;
    
    # Validate input
    my $validation = $self->validation;
    $validation->required('email')->like(qr/^[^@]+@[^@]+\\.[^@]+$/);
    $validation->required('password')->size(1, 100);
    
    if ($validation->has_error) {
        return $self->render(json => {
            error => 'Validation failed',
            details => $validation->failed
        }, status => 400);
    }
    
    my $email = $json->{email};
    my $password = $json->{password};
    
    # Find user
    my $user = $self->users->find_by_email($email);
    unless ($user) {
        return $self->render(json => {
            error => 'Invalid credentials'
        }, status => 401);
    }
    
    # Check password
    unless (bcrypt_check($password, $user->{password_hash})) {
        return $self->render(json => {
            error => 'Invalid credentials'
        }, status => 401);
    }
    
    # Generate JWT token
    my $payload = {
        user_id => $user->{id},
        email => $user->{email},
        exp => time + 3600, # 1 hour
        iat => time
    };
    
    my $token = $self->jwt($payload);
    
    $self->render(json => {
        token => $token,
        user => {
            id => $user->{id},
            name => $user->{name},
            email => $user->{email}
        }
    });
}

sub logout ($self) {
    $self->session(expires => 1);
    $self->render(json => { message => 'Logged out successfully' });
}

sub check_auth ($self) {
    return $self->continue if $self->authenticate;
    
    $self->render(json => {
        error => 'Authentication required'
    }, status => 401);
    return 0;
}

1;`,

    'lib/MojoliciousApp/Controller/Users.pm': `package MojoliciousApp::Controller::Users;
use Mojo::Base 'Mojolicious::Controller', -signatures;

use DateTime;

sub index ($self) {
    my $users = $self->users->all;
    
    # Remove password hashes
    for my $user (@$users) {
        delete $user->{password_hash};
    }
    
    $self->render(json => $users);
}

sub show ($self) {
    my $id = $self->param('id');
    
    unless ($id =~ /^\\d+$/) {
        return $self->render(json => {
            error => 'Invalid user ID'
        }, status => 400);
    }
    
    my $user = $self->users->find($id);
    unless ($user) {
        return $self->render(json => {
            error => 'User not found'
        }, status => 404);
    }
    
    delete $user->{password_hash};
    $self->render(json => $user);
}

sub create ($self) {
    my $json = $self->req->json;
    
    # Validate input
    my $validation = $self->validation;
    $validation->required('name')->size(1, 100);
    $validation->required('email')->like(qr/^[^@]+@[^@]+\\.[^@]+$/);
    $validation->required('password')->size(6, 100);
    
    if ($validation->has_error) {
        return $self->render(json => {
            error => 'Validation failed',
            details => $validation->failed
        }, status => 400);
    }
    
    my $name = $json->{name};
    my $email = $json->{email};
    my $password = $json->{password};
    
    # Check if user already exists
    my $existing = $self->users->find_by_email($email);
    if ($existing) {
        return $self->render(json => {
            error => 'User already exists'
        }, status => 409);
    }
    
    # Hash password
    use Crypt::Bcrypt qw(bcrypt);
    my $password_hash = bcrypt($password, '$2b$12$' . join('', map { chr(int(rand(94)) + 33) } 1..22));
    
    # Create user
    my $user = $self->users->create({
        name => $name,
        email => $email,
        password_hash => $password_hash
    });
    
    if ($user) {
        delete $user->{password_hash};
        $self->render(json => $user, status => 201);
    } else {
        $self->render(json => {
            error => 'Failed to create user'
        }, status => 500);
    }
}

sub update ($self) {
    my $id = $self->param('id');
    my $json = $self->req->json;
    
    unless ($id =~ /^\\d+$/) {
        return $self->render(json => {
            error => 'Invalid user ID'
        }, status => 400);
    }
    
    # Find existing user
    my $user = $self->users->find($id);
    unless ($user) {
        return $self->render(json => {
            error => 'User not found'
        }, status => 404);
    }
    
    # Validate input
    my $validation = $self->validation;
    $validation->optional('name')->size(1, 100);
    $validation->optional('email')->like(qr/^[^@]+@[^@]+\\.[^@]+$/);
    
    if ($validation->has_error) {
        return $self->render(json => {
            error => 'Validation failed',
            details => $validation->failed
        }, status => 400);
    }
    
    # Check for email conflicts
    if ($json->{email} && $json->{email} ne $user->{email}) {
        my $existing = $self->users->find_by_email($json->{email});
        if ($existing) {
            return $self->render(json => {
                error => 'Email already exists'
            }, status => 409);
        }
    }
    
    # Update user
    my $updated_user = $self->users->update($id, $json);
    
    if ($updated_user) {
        delete $updated_user->{password_hash};
        $self->render(json => $updated_user);
    } else {
        $self->render(json => {
            error => 'Failed to update user'
        }, status => 500);
    }
}

sub delete ($self) {
    my $id = $self->param('id');
    
    unless ($id =~ /^\\d+$/) {
        return $self->render(json => {
            error => 'Invalid user ID'
        }, status => 400);
    }
    
    # Find existing user
    my $user = $self->users->find($id);
    unless ($user) {
        return $self->render(json => {
            error => 'User not found'
        }, status => 404);
    }
    
    # Delete user
    if ($self->users->delete($id)) {
        $self->render(json => { message => 'User deleted successfully' }, status => 204);
    } else {
        $self->render(json => {
            error => 'Failed to delete user'
        }, status => 500);
    }
}

1;`,

    'lib/MojoliciousApp/Controller/WebSocket.pm': `package MojoliciousApp::Controller::WebSocket;
use Mojo::Base 'Mojolicious::Controller', -signatures;

use Mojo::JSON qw(encode_json decode_json);
use DateTime;

# Store active connections
my $connections = {};

sub connect ($self) {
    my $id = $self->tx->connection;
    
    # Store connection
    $connections->{$id} = {
        tx => $self->tx,
        connected_at => DateTime->now,
        user => $self->stash('user') // { id => 'anonymous' }
    };
    
    $self->app->log->info("WebSocket connection established: $id");
    
    # Send welcome message
    $self->send({
        json => {
            type => 'welcome',
            message => 'Connected to Mojolicious WebSocket',
            connection_id => $id,
            timestamp => DateTime->now->iso8601
        }
    });
    
    # Handle incoming messages
    $self->on(message => sub ($tx, $msg) {
        my $data = eval { decode_json($msg) };
        
        if ($@) {
            $self->send({
                json => {
                    type => 'error',
                    message => 'Invalid JSON',
                    timestamp => DateTime->now->iso8601
                }
            });
            return;
        }
        
        # Handle different message types
        my $type = $data->{type} // 'message';
        
        if ($type eq 'ping') {
            $self->send({
                json => {
                    type => 'pong',
                    timestamp => DateTime->now->iso8601
                }
            });
        }
        elsif ($type eq 'broadcast') {
            # Broadcast to all connected clients
            _broadcast_to_all({
                type => 'broadcast',
                user => $connections->{$id}->{user},
                message => $data->{message},
                timestamp => DateTime->now->iso8601
            });
        }
        elsif ($type eq 'private') {
            # Send private message to specific user
            my $target_user = $data->{target_user};
            _send_to_user($target_user, {
                type => 'private',
                from => $connections->{$id}->{user},
                message => $data->{message},
                timestamp => DateTime->now->iso8601
            });
        }
        else {
            # Echo message back
            $self->send({
                json => {
                    type => 'echo',
                    original => $data,
                    timestamp => DateTime->now->iso8601
                }
            });
        }
    });
    
    # Handle connection close
    $self->on(finish => sub ($tx, $code, $reason) {
        $self->app->log->info("WebSocket connection closed: $id ($code: $reason)");
        delete $connections->{$id};
        
        # Notify other clients
        _broadcast_to_all({
            type => 'user_disconnected',
            user => $connections->{$id}->{user} // { id => 'anonymous' },
            timestamp => DateTime->now->iso8601
        });
    });
    
    # Notify other clients about new connection
    _broadcast_to_all({
        type => 'user_connected',
        user => $connections->{$id}->{user},
        timestamp => DateTime->now->iso8601
    });
    
    # Send periodic updates
    Mojo::IOLoop->recurring(30 => sub {
        return unless $connections->{$id};
        
        $self->send({
            json => {
                type => 'heartbeat',
                active_connections => scalar keys %$connections,
                timestamp => DateTime->now->iso8601
            }
        });
    });
}

sub _broadcast_to_all ($message) {
    my $json = encode_json($message);
    
    for my $conn_id (keys %$connections) {
        my $conn = $connections->{$conn_id};
        next unless $conn && $conn->{tx};
        
        eval {
            $conn->{tx}->send($json);
        };
        
        if ($@) {
            # Connection is dead, remove it
            delete $connections->{$conn_id};
        }
    }
}

sub _send_to_user ($target_user_id, $message) {
    my $json = encode_json($message);
    
    for my $conn_id (keys %$connections) {
        my $conn = $connections->{$conn_id};
        next unless $conn && $conn->{tx};
        next unless $conn->{user}->{id} eq $target_user_id;
        
        eval {
            $conn->{tx}->send($json);
        };
        
        if ($@) {
            # Connection is dead, remove it
            delete $connections->{$conn_id};
        }
    }
}

1;`,

    'lib/MojoliciousApp/Controller/Events.pm': `package MojoliciousApp::Controller::Events;
use Mojo::Base 'Mojolicious::Controller', -signatures;

use DateTime;
use Mojo::JSON qw(encode_json);

sub stream ($self) {
    # Set up Server-Sent Events
    $self->res->headers->content_type('text/event-stream');
    $self->res->headers->cache_control('no-cache');
    $self->res->headers->connection('keep-alive');
    
    # Send initial event
    $self->write_chunk(sprintf(
        "event: connected\\ndata: %s\\n\\n",
        encode_json({
            message => 'Connected to event stream',
            timestamp => DateTime->now->iso8601
        })
    ));
    
    # Set up periodic events
    my $id = Mojo::IOLoop->recurring(10 => sub {
        return unless $self->tx;
        
        # Send server status update
        $self->write_chunk(sprintf(
            "event: server-status\\ndata: %s\\n\\n",
            encode_json({
                uptime => time - $^T,
                memory_usage => _get_memory_usage(),
                active_connections => scalar keys %{$self->app->connections // {}},
                timestamp => DateTime->now->iso8601
            })
        ));
    });
    
    # Send user activity updates
    my $user_id = Mojo::IOLoop->recurring(30 => sub {
        return unless $self->tx;
        
        # Get user activity data
        my $users = $self->users->all;
        my $user_count = scalar @$users;
        
        $self->write_chunk(sprintf(
            "event: user-activity\\ndata: %s\\n\\n",
            encode_json({
                total_users => $user_count,
                recent_activity => _get_recent_activity($self),
                timestamp => DateTime->now->iso8601
            })
        ));
    });
    
    # Clean up when connection closes
    $self->on(finish => sub {
        Mojo::IOLoop->remove($id);
        Mojo::IOLoop->remove($user_id);
    });
}

sub _get_memory_usage {
    if (open my $fh, '<', '/proc/self/status') {
        while (my $line = <$fh>) {
            if ($line =~ /^VmRSS:\\s+(\\d+)\\s+kB/) {
                return $1 * 1024; # Convert to bytes
            }
        }
        close $fh;
    }
    return 0;
}

sub _get_recent_activity ($self) {
    # This would typically query a database for recent activity
    # For now, return dummy data
    return {
        recent_logins => int(rand(10)),
        active_sessions => int(rand(50)),
        api_requests => int(rand(100))
    };
}

1;`,

    'lib/MojoliciousApp/Controller/Health.pm': `package MojoliciousApp::Controller::Health;
use Mojo::Base 'Mojolicious::Controller', -signatures;

use DateTime;

sub check ($self) {
    my $health = {
        status => 'ok',
        timestamp => DateTime->now->iso8601,
        version => '1.0.0',
        service => 'mojolicious-app'
    };
    
    # Check database connection
    eval {
        my $result = $self->app->database->query('SELECT 1');
        $health->{database} = 'connected';
    };
    
    if ($@) {
        $health->{status} = 'error';
        $health->{database} = 'disconnected';
        $health->{error} = $@;
        return $self->render(json => $health, status => 503);
    }
    
    # Check memory usage
    $health->{memory} = {
        usage => _get_memory_usage(),
        limit => 1024 * 1024 * 512 # 512MB limit
    };
    
    # Check uptime
    $health->{uptime} = time - $^T;
    
    # Check active connections
    $health->{connections} = scalar keys %{$self->app->connections // {}};
    
    $self->render(json => $health);
}

sub _get_memory_usage {
    if (open my $fh, '<', '/proc/self/status') {
        while (my $line = <$fh>) {
            if ($line =~ /^VmRSS:\\s+(\\d+)\\s+kB/) {
                return $1 * 1024; # Convert to bytes
            }
        }
        close $fh;
    }
    return 0;
}

1;`,

    'lib/MojoliciousApp/Controller/Static.pm': `package MojoliciousApp::Controller::Static;
use Mojo::Base 'Mojolicious::Controller', -signatures;

sub index ($self) {
    $self->render(template => 'index');
}

sub docs ($self) {
    $self->render(template => 'docs');
}

1;`,

    'lib/MojoliciousApp/Model/Users.pm': `package MojoliciousApp::Model::Users;
use Mojo::Base -base, -signatures;

use DateTime;

has 'db';

sub new ($class) {
    my $self = $class->SUPER::new;
    # In a real app, you'd inject the database connection
    return $self;
}

sub all ($self) {
    my $db = $self->_get_db();
    my $results = $db->query('SELECT * FROM users ORDER BY created_at DESC');
    return $results->hashes->to_array;
}

sub find ($self, $id) {
    my $db = $self->_get_db();
    my $result = $db->query('SELECT * FROM users WHERE id = ?', $id);
    return $result->hash;
}

sub find_by_email ($self, $email) {
    my $db = $self->_get_db();
    my $result = $db->query('SELECT * FROM users WHERE email = ?', $email);
    return $result->hash;
}

sub create ($self, $data) {
    my $db = $self->_get_db();
    
    my $now = DateTime->now->iso8601;
    my $result = $db->query(
        'INSERT INTO users (name, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?) RETURNING *',
        $data->{name},
        $data->{email},
        $data->{password_hash},
        $now,
        $now
    );
    
    return $result->hash;
}

sub update ($self, $id, $data) {
    my $db = $self->_get_db();
    
    my @fields = ();
    my @values = ();
    
    for my $field (qw(name email)) {
        if (exists $data->{$field}) {
            push @fields, "$field = ?";
            push @values, $data->{$field};
        }
    }
    
    return unless @fields;
    
    push @fields, 'updated_at = ?';
    push @values, DateTime->now->iso8601;
    push @values, $id;
    
    my $sql = 'UPDATE users SET ' . join(', ', @fields) . ' WHERE id = ? RETURNING *';
    my $result = $db->query($sql, @values);
    
    return $result->hash;
}

sub delete ($self, $id) {
    my $db = $self->_get_db();
    my $result = $db->query('DELETE FROM users WHERE id = ?', $id);
    return $result->rows > 0;
}

sub _get_db ($self) {
    # This is a hack for the example - in a real app, you'd inject the database
    use Mojo::Pg;
    state $pg = Mojo::Pg->new('postgresql://postgres:postgres@localhost/mojolicious_app');
    return $pg->db;
}

1;`,

    'lib/MojoliciousApp/Model/Auth.pm': `package MojoliciousApp::Model::Auth;
use Mojo::Base -base, -signatures;

use Crypt::Bcrypt qw(bcrypt_check);
use MojoliciousApp::Model::Users;

has 'users' => sub { MojoliciousApp::Model::Users->new };

sub authenticate ($self, $email, $password) {
    my $user = $self->users->find_by_email($email);
    return unless $user;
    
    return bcrypt_check($password, $user->{password_hash}) ? $user : undef;
}

sub generate_token ($self, $user) {
    # This would typically use a proper JWT library
    # For now, return a simple token
    return sprintf("%d:%s:%d", $user->{id}, $user->{email}, time);
}

sub verify_token ($self, $token) {
    # This would typically verify a JWT token
    # For now, parse the simple token
    my ($id, $email, $timestamp) = split ':', $token;
    
    return unless $id && $email && $timestamp;
    return unless time - $timestamp < 3600; # 1 hour expiry
    
    return $self->users->find($id);
}

1;`,

    'mojolicious_app.conf': `{
  secrets => ['your-secret-key-here'],
  database => {
    dsn => 'dbi:Pg:dbname=mojolicious_app;host=localhost',
    username => 'postgres',
    password => 'postgres'
  },
  jwt => {
    secret => 'your-jwt-secret-key',
    expiration => 3600
  },
  cors => {
    allow_origin => '*',
    allow_methods => 'GET, POST, PUT, DELETE, OPTIONS',
    allow_headers => 'Content-Type, Authorization'
  }
}`,

    'script/mojolicious_app': `#!/usr/bin/env perl

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";

# Start command line interface for application
require Mojolicious::Commands;
Mojolicious::Commands->start_app('MojoliciousApp');`,

    'templates/index.html.ep': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mojolicious App</title>
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
        .ws-demo {
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
        }
        button:hover {
            background: #0056b3;
        }
        #messages {
            border: 1px solid #ddd;
            height: 200px;
            overflow-y: auto;
            padding: 10px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔥 Mojolicious Web Application</h1>
        
        <div class="feature">
            <h3>Real-time Web Framework</h3>
            <p>Built with Mojolicious, featuring WebSocket support, async I/O, and modern web development capabilities.</p>
        </div>
        
        <div class="feature">
            <h3>API Endpoints</h3>
            <div class="api-endpoint">POST /api/auth/register - User registration</div>
            <div class="api-endpoint">POST /api/auth/login - User authentication</div>
            <div class="api-endpoint">GET /api/users - Get all users (protected)</div>
            <div class="api-endpoint">POST /api/users - Create user (protected)</div>
            <div class="api-endpoint">GET /health - Health check</div>
        </div>
        
        <div class="feature">
            <h3>WebSocket Demo</h3>
            <div class="ws-demo">
                <button onclick="connectWebSocket()">Connect WebSocket</button>
                <button onclick="disconnectWebSocket()">Disconnect</button>
                <button onclick="sendMessage()">Send Message</button>
                <div id="messages"></div>
                <input type="text" id="messageInput" placeholder="Enter message..." style="width: 100%; padding: 5px;">
            </div>
        </div>
        
        <div class="feature">
            <h3>Server-Sent Events</h3>
            <button onclick="subscribeToEvents()">Subscribe to Events</button>
            <div id="events" style="border: 1px solid #ddd; height: 100px; overflow-y: auto; padding: 10px; margin: 10px 0;"></div>
        </div>
    </div>

    <script>
        let ws = null;
        let eventSource = null;
        
        function connectWebSocket() {
            ws = new WebSocket('ws://localhost:3000/ws');
            
            ws.onopen = function() {
                addMessage('Connected to WebSocket');
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                addMessage('Received: ' + JSON.stringify(data));
            };
            
            ws.onclose = function() {
                addMessage('WebSocket connection closed');
            };
            
            ws.onerror = function(error) {
                addMessage('WebSocket error: ' + error);
            };
        }
        
        function disconnectWebSocket() {
            if (ws) {
                ws.close();
            }
        }
        
        function sendMessage() {
            const input = document.getElementById('messageInput');
            const message = input.value;
            
            if (ws && ws.readyState === WebSocket.OPEN && message) {
                ws.send(JSON.stringify({
                    type: 'broadcast',
                    message: message
                }));
                input.value = '';
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
            eventSource = new EventSource('/events');
            
            eventSource.addEventListener('server-status', function(event) {
                const data = JSON.parse(event.data);
                addEvent('Server Status: ' + JSON.stringify(data));
            });
            
            eventSource.addEventListener('user-activity', function(event) {
                const data = JSON.parse(event.data);
                addEvent('User Activity: ' + JSON.stringify(data));
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
            events.scrollTop = events.scrollHeight;
        }
        
        // Enable Enter key for message input
        document.getElementById('messageInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>`,

    'templates/docs.html.ep': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Documentation - Mojolicious App</title>
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
    </style>
</head>
<body>
    <div class="container">
        <h1>📚 API Documentation</h1>
        
        <h2>Base URL</h2>
        <div class="code">http://localhost:3000</div>
        
        <h2>Authentication</h2>
        <p>This API uses JWT tokens for authentication. Include the token in the Authorization header:</p>
        <div class="code">Authorization: Bearer YOUR_JWT_TOKEN</div>
        
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
  "created_at": "2024-01-01T12:00:00Z"
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span>/api/auth/login</h3>
            <p>Authenticate user and receive JWT token.</p>
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
    "email": "john@example.com"
  }
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
    "created_at": "2024-01-01T12:00:00Z"
  }
]
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span>/api/users</h3>
            <p>Create a new user (requires authentication).</p>
            <div class="code">
{
  "name": "Jane Smith",
  "email": "jane@example.com",
  "password": "password456"
}
            </div>
            <div class="response">
                <strong>Response (201):</strong>
                <div class="code">
{
  "id": 2,
  "name": "Jane Smith",
  "email": "jane@example.com",
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
  "created_at": "2024-01-01T12:00:00Z"
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method put">PUT</span>/api/users/:id</h3>
            <p>Update a user (requires authentication).</p>
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
  "updated_at": "2024-01-01T13:00:00Z"
}
                </div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method delete">DELETE</span>/api/users/:id</h3>
            <p>Delete a user (requires authentication).</p>
            <div class="response">
                <strong>Response (204):</strong>
                <div class="code">
{
  "message": "User deleted successfully"
}
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
  "version": "1.0.0",
  "service": "mojolicious-app",
  "database": "connected",
  "uptime": 3600
}
                </div>
            </div>
        </div>
        
        <h2>WebSocket</h2>
        <p>Connect to the WebSocket endpoint for real-time communication:</p>
        <div class="code">ws://localhost:3000/ws</div>
        
        <h3>WebSocket Message Types</h3>
        <div class="endpoint">
            <h4>Ping/Pong</h4>
            <div class="code">
// Send
{"type": "ping"}

// Receive
{"type": "pong", "timestamp": "2024-01-01T12:00:00Z"}
            </div>
        </div>
        
        <div class="endpoint">
            <h4>Broadcast</h4>
            <div class="code">
// Send
{"type": "broadcast", "message": "Hello everyone!"}

// All clients receive
{
  "type": "broadcast",
  "user": {"id": 1, "name": "John Doe"},
  "message": "Hello everyone!",
  "timestamp": "2024-01-01T12:00:00Z"
}
            </div>
        </div>
        
        <h2>Server-Sent Events</h2>
        <p>Subscribe to server-sent events:</p>
        <div class="code">GET /events</div>
        
        <h3>Event Types</h3>
        <ul>
            <li><strong>server-status</strong>: Server health and performance metrics</li>
            <li><strong>user-activity</strong>: User activity and statistics</li>
        </ul>
        
        <h2>Error Responses</h2>
        <div class="response">
            <strong>400 Bad Request:</strong>
            <div class="code">
{
  "error": "Validation failed",
  "details": ["name is required", "email is invalid"]
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
            <strong>404 Not Found:</strong>
            <div class="code">
{
  "error": "User not found"
}
            </div>
        </div>
    </div>
</body>
</html>`,

    'public/api.json': `{
  "openapi": "3.0.0",
  "info": {
    "title": "Mojolicious API",
    "version": "1.0.0",
    "description": "REST API built with Mojolicious framework"
  },
  "servers": [
    {
      "url": "http://localhost:3000",
      "description": "Development server"
    }
  ],
  "paths": {
    "/api/auth/register": {
      "post": {
        "summary": "Register a new user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/RegisterRequest"
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "User created successfully",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/User"
                }
              }
            }
          }
        }
      }
    },
    "/api/auth/login": {
      "post": {
        "summary": "Authenticate user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/LoginRequest"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Login successful",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/LoginResponse"
                }
              }
            }
          }
        }
      }
    },
    "/api/users": {
      "get": {
        "summary": "Get all users",
        "security": [
          {
            "bearerAuth": []
          }
        ],
        "responses": {
          "200": {
            "description": "List of users",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/User"
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "User": {
        "type": "object",
        "properties": {
          "id": {
            "type": "integer"
          },
          "name": {
            "type": "string"
          },
          "email": {
            "type": "string"
          },
          "created_at": {
            "type": "string",
            "format": "date-time"
          }
        }
      },
      "RegisterRequest": {
        "type": "object",
        "required": ["name", "email", "password"],
        "properties": {
          "name": {
            "type": "string"
          },
          "email": {
            "type": "string"
          },
          "password": {
            "type": "string"
          }
        }
      },
      "LoginRequest": {
        "type": "object",
        "required": ["email", "password"],
        "properties": {
          "email": {
            "type": "string"
          },
          "password": {
            "type": "string"
          }
        }
      },
      "LoginResponse": {
        "type": "object",
        "properties": {
          "token": {
            "type": "string"
          },
          "user": {
            "$ref": "#/components/schemas/User"
          }
        }
      }
    },
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      }
    }
  }
}`,

    't/basic.t': `#!/usr/bin/env perl
use Mojo::Base -strict;

use Test::More;
use Test::Mojo;

my $t = Test::Mojo->new('MojoliciousApp');

# Test health endpoint
$t->get_ok('/health')
  ->status_is(200)
  ->json_is('/status' => 'ok')
  ->json_has('/timestamp')
  ->json_has('/version');

# Test index page
$t->get_ok('/')
  ->status_is(200)
  ->content_like(qr/Mojolicious Web Application/);

# Test API endpoints without authentication
$t->get_ok('/api/users')
  ->status_is(401)
  ->json_has('/error');

# Test user registration
$t->post_ok('/api/auth/register' => json => {
    name => 'Test User',
    email => 'test@example.com',
    password => 'password123'
  })
  ->status_is(201)
  ->json_has('/id')
  ->json_is('/name' => 'Test User')
  ->json_is('/email' => 'test@example.com');

# Test user login
$t->post_ok('/api/auth/login' => json => {
    email => 'test@example.com',
    password => 'password123'
  })
  ->status_is(200)
  ->json_has('/token')
  ->json_has('/user');

# Test invalid login
$t->post_ok('/api/auth/login' => json => {
    email => 'test@example.com',
    password => 'wrongpassword'
  })
  ->status_is(401)
  ->json_has('/error');

# Test validation errors
$t->post_ok('/api/auth/register' => json => {
    name => '',
    email => 'invalid-email',
    password => '123'
  })
  ->status_is(400)
  ->json_has('/error');

done_testing();`,

    't/websocket.t': `#!/usr/bin/env perl
use Mojo::Base -strict;

use Test::More;
use Test::Mojo;
use Mojo::JSON qw(decode_json);

my $t = Test::Mojo->new('MojoliciousApp');

# Test WebSocket connection
$t->websocket_ok('/ws')
  ->send_ok({json => {type => 'ping'}})
  ->message_ok
  ->json_message_is('/type' => 'pong')
  ->json_message_has('/timestamp');

# Test broadcast message
$t->websocket_ok('/ws')
  ->send_ok({json => {type => 'broadcast', message => 'Hello World'}})
  ->message_ok
  ->json_message_is('/type' => 'broadcast')
  ->json_message_is('/message' => 'Hello World')
  ->json_message_has('/timestamp');

# Test echo message
$t->websocket_ok('/ws')
  ->send_ok({json => {type => 'echo', data => 'test'}})
  ->message_ok
  ->json_message_is('/type' => 'echo')
  ->json_message_has('/original');

# Test invalid JSON
$t->websocket_ok('/ws')
  ->send_ok('invalid json')
  ->message_ok
  ->json_message_is('/type' => 'error')
  ->json_message_is('/message' => 'Invalid JSON');

done_testing();`,

    'README.md': `# Mojolicious Web Application

A real-time web application built with Mojolicious framework, featuring WebSocket support, async I/O, and modern web development capabilities.

## Features

- **Real-time Web Framework**: Built with Mojolicious for high-performance web applications
- **WebSocket Support**: Built-in WebSocket support for real-time communication
- **Async I/O**: Non-blocking I/O operations for better performance
- **RESTful API**: Clean REST API with JSON responses
- **JWT Authentication**: Token-based authentication system
- **Database Integration**: PostgreSQL database with proper ORM
- **Server-Sent Events**: Real-time server-to-client messaging
- **Plugin System**: Extensible plugin architecture
- **Hot Reload**: Development server with hot code reloading
- **Modern Templates**: Embedded Perl templates with modern syntax

## Quick Start

\`\`\`bash
# Install dependencies
cpanm --installdeps .

# Set up database
createdb mojolicious_app

# Run the application
morbo script/mojolicious_app

# Or in production mode
hypnotoad script/mojolicious_app
\`\`\`

The application will be available at:
- Web Interface: http://localhost:3000
- API Documentation: http://localhost:3000/docs
- Health Check: http://localhost:3000/health

## API Endpoints

### Authentication
- \`POST /api/auth/register\` - User registration
- \`POST /api/auth/login\` - User login
- \`POST /api/auth/logout\` - User logout

### Users (Protected)
- \`GET /api/users\` - Get all users
- \`POST /api/users\` - Create user
- \`GET /api/users/:id\` - Get user by ID
- \`PUT /api/users/:id\` - Update user
- \`DELETE /api/users/:id\` - Delete user

### Real-time
- \`WebSocket /ws\` - WebSocket connection
- \`GET /events\` - Server-sent events

### System
- \`GET /health\` - Health check endpoint

## Usage Examples

### User Registration

\`\`\`bash
curl -X POST http://localhost:3000/api/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123"
  }'
\`\`\`

### User Login

\`\`\`bash
curl -X POST http://localhost:3000/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
\`\`\`

### Access Protected Endpoint

\`\`\`bash
curl -X GET http://localhost:3000/api/users \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
\`\`\`

## WebSocket Communication

Connect to the WebSocket endpoint for real-time features:

\`\`\`javascript
const ws = new WebSocket('ws://localhost:3000/ws');

// Send ping
ws.send(JSON.stringify({type: 'ping'}));

// Broadcast message
ws.send(JSON.stringify({
  type: 'broadcast',
  message: 'Hello everyone!'
}));

// Listen for messages
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
\`\`\`

## Server-Sent Events

Subscribe to server-sent events for real-time updates:

\`\`\`javascript
const eventSource = new EventSource('http://localhost:3000/events');

eventSource.addEventListener('server-status', function(event) {
  const data = JSON.parse(event.data);
  console.log('Server status:', data);
});

eventSource.addEventListener('user-activity', function(event) {
  const data = JSON.parse(event.data);
  console.log('User activity:', data);
});
\`\`\`

## Development

### Running Tests

\`\`\`bash
# Run all tests
prove -l t/

# Run specific test
prove -l t/basic.t

# Run with verbose output
prove -lv t/
\`\`\`

### Development Server

\`\`\`bash
# Start development server with hot reload
morbo script/mojolicious_app

# Start with specific port
morbo script/mojolicious_app -l http://*:8080

# Start with debugging
morbo script/mojolicious_app -v
\`\`\`

### Production Deployment

\`\`\`bash
# Start production server
hypnotoad script/mojolicious_app

# Stop production server
hypnotoad script/mojolicious_app -s

# Restart production server
hypnotoad script/mojolicious_app
\`\`\`

## Configuration

Edit \`mojolicious_app.conf\` to configure the application:

\`\`\`perl
{
  secrets => ['your-secret-key-here'],
  database => {
    dsn => 'dbi:Pg:dbname=mojolicious_app;host=localhost',
    username => 'postgres',
    password => 'postgres'
  },
  jwt => {
    secret => 'your-jwt-secret-key',
    expiration => 3600
  }
}
\`\`\`

## Database Setup

The application uses PostgreSQL. Set up the database:

\`\`\`bash
# Create database
createdb mojolicious_app

# The application will automatically create tables on startup
\`\`\`

## Docker Support

\`\`\`bash
# Build image
docker build -t mojolicious-app .

# Run container
docker run -p 3000:3000 mojolicious-app

# Using docker-compose
docker-compose up -d
\`\`\`

## Architecture

### MVC Structure

- **Models**: Database interaction and business logic
- **Controllers**: Request handling and response formatting
- **Templates**: HTML templates with embedded Perl

### Plugin System

The application uses Mojolicious plugins for:
- Authentication
- Database connectivity
- OpenAPI documentation
- WebSocket handling

### Real-time Features

- **WebSocket**: Bidirectional real-time communication
- **Server-Sent Events**: Server-to-client real-time updates
- **Async I/O**: Non-blocking operations for better performance

## Performance

Mojolicious provides excellent performance with:
- Non-blocking I/O
- Event-driven architecture
- Efficient routing
- Built-in caching
- Production-ready server (Hypnotoad)

## Security

- JWT token authentication
- Password hashing with bcrypt
- CORS support
- Input validation
- SQL injection prevention

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
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

# Make script executable
RUN chmod +x script/mojolicious_app

# Expose port
EXPOSE 3000

# Run the application
CMD ["perl", "script/mojolicious_app", "daemon", "-l", "http://*:3000"]`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - POSTGRES_HOST=postgres
      - POSTGRES_DB=mojolicious_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    depends_on:
      - postgres
    volumes:
      - .:/app
    command: ["perl", "script/mojolicious_app", "daemon", "-l", "http://*:3000"]
  
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=mojolicious_app
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

# Application specific
log/
*.log
*.pid
*.conf.local
.env

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db`,

    'examples/client.pl': `#!/usr/bin/env perl
use Mojo::Base -strict;

use Mojo::UserAgent;
use Mojo::JSON qw(decode_json encode_json);
use Data::Dumper;

# Create user agent
my $ua = Mojo::UserAgent->new;
my $base_url = 'http://localhost:3000';

# Test health endpoint
print "Testing health endpoint...\\n";
my $health = $ua->get("$base_url/health")->result;
print "Health: " . $health->json->{status} . "\\n\\n";

# Register a user
print "Registering user...\\n";
my $register = $ua->post("$base_url/api/auth/register" => json => {
    name => 'Test User',
    email => 'test@example.com',
    password => 'password123'
})->result;

if ($register->is_success) {
    print "User registered: " . $register->json->{name} . "\\n";
} else {
    print "Registration failed: " . $register->json->{error} . "\\n";
}

# Login user
print "\\nLogging in user...\\n";
my $login = $ua->post("$base_url/api/auth/login" => json => {
    email => 'test@example.com',
    password => 'password123'
})->result;

my $token;
if ($login->is_success) {
    $token = $login->json->{token};
    print "Login successful, token: " . substr($token, 0, 20) . "...\\n";
} else {
    print "Login failed: " . $login->json->{error} . "\\n";
    exit 1;
}

# Get users (protected endpoint)
print "\\nGetting users...\\n";
my $users = $ua->get("$base_url/api/users" => {
    Authorization => "Bearer $token"
})->result;

if ($users->is_success) {
    my $user_list = $users->json;
    print "Found " . scalar(@$user_list) . " users\\n";
    for my $user (@$user_list) {
        print "  - $user->{name} ($user->{email})\\n";
    }
} else {
    print "Failed to get users: " . $users->json->{error} . "\\n";
}

# Create a new user
print "\\nCreating new user...\\n";
my $create = $ua->post("$base_url/api/users" => {
    Authorization => "Bearer $token"
} => json => {
    name => 'Jane Doe',
    email => 'jane@example.com',
    password => 'password456'
})->result;

if ($create->is_success) {
    print "User created: " . $create->json->{name} . "\\n";
} else {
    print "Failed to create user: " . $create->json->{error} . "\\n";
}

print "\\nAPI testing complete!\\n";`,

    'examples/websocket_client.pl': `#!/usr/bin/env perl
use Mojo::Base -strict;

use Mojo::UserAgent;
use Mojo::JSON qw(decode_json encode_json);
use Data::Dumper;

# Create user agent
my $ua = Mojo::UserAgent->new;

print "Connecting to WebSocket...\\n";

# Connect to WebSocket
$ua->websocket('ws://localhost:3000/ws' => sub {
    my ($ua, $tx) = @_;
    
    unless ($tx->is_websocket) {
        print "WebSocket handshake failed!\\n";
        return;
    }
    
    print "WebSocket connected!\\n";
    
    # Send ping message
    $tx->send({json => {type => 'ping'}});
    
    # Send broadcast message
    $tx->send({json => {
        type => 'broadcast',
        message => 'Hello from Perl client!'
    }});
    
    # Handle incoming messages
    $tx->on(message => sub {
        my ($tx, $msg) = @_;
        my $data = decode_json($msg);
        
        print "Received message: \\n";
        print Dumper($data);
        
        # Respond to welcome message
        if ($data->{type} eq 'welcome') {
            $tx->send({json => {
                type => 'broadcast',
                message => 'Thanks for the welcome!'
            }});
        }
    });
    
    # Handle connection close
    $tx->on(finish => sub {
        my ($tx, $code, $reason) = @_;
        print "WebSocket closed: $code - $reason\\n";
    });
    
    # Keep connection alive for 30 seconds
    Mojo::IOLoop->timer(30 => sub {
        $tx->finish;
    });
});

# Start the event loop
Mojo::IOLoop->start unless Mojo::IOLoop->is_running;

print "WebSocket client finished.\\n";`,

    'examples/performance_test.pl': `#!/usr/bin/env perl
use Mojo::Base -strict;

use Mojo::UserAgent;
use Mojo::IOLoop;
use Time::HiRes qw(time);
use List::Util qw(sum);

my $ua = Mojo::UserAgent->new;
my $base_url = 'http://localhost:3000';

sub run_performance_test {
    my ($concurrent_requests, $endpoint) = @_;
    
    print "Running performance test with $concurrent_requests concurrent requests to $endpoint\\n";
    
    my $start_time = time;
    my @response_times;
    my $completed = 0;
    my $errors = 0;
    
    for my $i (1..$concurrent_requests) {
        my $request_start = time;
        
        $ua->get("$base_url$endpoint" => sub {
            my ($ua, $tx) = @_;
            
            my $response_time = time - $request_start;
            push @response_times, $response_time;
            
            if ($tx->result->is_success) {
                $completed++;
            } else {
                $errors++;
            }
            
            # Stop event loop when all requests are done
            if ($completed + $errors == $concurrent_requests) {
                Mojo::IOLoop->stop;
            }
        });
    }
    
    # Start event loop
    Mojo::IOLoop->start;
    
    my $total_time = time - $start_time;
    my $avg_response_time = sum(@response_times) / @response_times;
    my $rps = $concurrent_requests / $total_time;
    
    print "Results:\\n";
    print "  Total time: " . sprintf("%.2f", $total_time) . " seconds\\n";
    print "  Completed requests: $completed\\n";
    print "  Failed requests: $errors\\n";
    print "  Average response time: " . sprintf("%.3f", $avg_response_time) . " seconds\\n";
    print "  Requests per second: " . sprintf("%.2f", $rps) . "\\n\\n";
    
    return {
        total_time => $total_time,
        completed => $completed,
        errors => $errors,
        avg_response_time => $avg_response_time,
        rps => $rps
    };
}

# Test different endpoints
print "=== Performance Testing ===\\n\\n";

run_performance_test(10, '/health');
run_performance_test(50, '/health');
run_performance_test(100, '/health');

print "Performance testing complete!\\n";`
  },

  dependencies: {
    'Mojolicious': '^9.34',
    'DBI': '^1.643',
    'DBD::Pg': '^3.16.0',
    'Mojo::JWT': '^0.09',
    'Crypt::Bcrypt': '^0.011',
    'DateTime': '^1.59',
    'Data::Validate::Email': '^0.04',
    'Test::Mojo': 'latest'
  },

  commands: {
    dev: 'morbo script/mojolicious_app',
    build: 'perl script/mojolicious_app build',
    test: 'prove -l t/',
    lint: 'perlcritic lib/',
    format: 'perltidy -b lib/**/*.pm',
    repl: 'perl -Ilib -E "use MojoliciousApp; say \\"Ready\\""',
    clean: 'rm -rf blib/ cover_db/ nytprof*',
    'test:verbose': 'prove -lv t/',
    'test:coverage': 'cover -test',
    'dev:verbose': 'morbo script/mojolicious_app -v',
    'prod:start': 'hypnotoad script/mojolicious_app',
    'prod:stop': 'hypnotoad script/mojolicious_app -s',
    'prod:restart': 'hypnotoad script/mojolicious_app',
    'docker:build': 'docker build -t mojolicious-app .',
    'docker:run': 'docker run -p 3000:3000 mojolicious-app',
    'docker:up': 'docker-compose up -d',
    'docker:down': 'docker-compose down'
  },

  ports: {
    dev: 3000,
    prod: 3000
  },

  examples: [
    {
      title: 'Route Definition',
      description: 'Define routes with controllers and actions',
      code: `$api->post('/users')->to('users#create');
$api->get('/users/:id')->to('users#show');
$protected->get('/users')->to('users#index');`
    },
    {
      title: 'WebSocket Handler',
      description: 'Handle WebSocket connections and messages',
      code: `$self->on(message => sub ($tx, $msg) {
  my $data = decode_json($msg);
  $self->send({json => {type => 'pong'}});
});`
    },
    {
      title: 'JWT Authentication',
      description: 'Authenticate users with JWT tokens',
      code: `my $token = $self->jwt({
  user_id => $user->{id},
  email => $user->{email},
  exp => time + 3600
});`
    }
  ]
};