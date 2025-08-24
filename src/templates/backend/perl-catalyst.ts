import { BackendTemplate } from '../types';

export const perlCatalystTemplate: BackendTemplate = {
  id: 'perl-catalyst',
  name: 'perl-catalyst',
  displayName: 'Perl Catalyst Web Framework',
  description: 'Enterprise-grade MVC web framework for Perl with comprehensive features, scalability, and extensive plugin ecosystem',
  framework: 'catalyst',
  language: 'perl',
  version: '5.90130',
  author: 'Re-Shell Team',


  icon: '🏭',
  type: 'mvc-framework',
  complexity: 'advanced',
  keywords: ['perl', 'catalyst', 'mvc', 'enterprise', 'scalable', 'plugins'],
  
  features: [
    'Enterprise MVC framework',
    'Comprehensive plugin system',
    'Scalable architecture',
    'Template engine support',
    'Authentication framework',
    'Database abstraction layer',
    'Session management',
    'Form handling',
    'REST API support',
    'Testing framework',
    'Deployment tools',
    'Performance optimization',
    'Security features',
    'Configuration management'
  ],
  
  structure: {
    'cpanfile': `# Catalyst application dependencies
requires "Catalyst::Runtime", "5.90130";
requires "Catalyst::Plugin::ConfigLoader", "0.34";
requires "Catalyst::Plugin::Static::Simple", "0.36";
requires "Catalyst::Plugin::Session", "0.43";
requires "Catalyst::Plugin::Session::State::Cookie", "0.18";
requires "Catalyst::Plugin::Session::Store::FastMmap", "0.16";
requires "Catalyst::Plugin::Authentication", "0.10023";
requires "Catalyst::Plugin::Authorization::Roles", "0.09";
requires "Catalyst::Authentication::Store::DBIx::Class", "0.1506";
requires "Catalyst::View::TT", "0.45";
requires "Catalyst::Model::DBIC::Schema", "0.65";
requires "Catalyst::Controller::REST", "1.21";
requires "Catalyst::Action::RenderView", "0.16";
requires "Catalyst::Plugin::StatusMessage", "1.002000";
requires "Catalyst::Plugin::StackTrace", "0.12";
requires "Catalyst::Plugin::SmartURI", "0.041";
requires "Catalyst::Plugin::Unicode::Encoding", "2.1";
requires "Catalyst::Plugin::Static::Simple", "0.36";
requires "DBIx::Class::Core", "0.082843";
requires "DBIx::Class::Schema::Loader", "0.07051";
requires "DBIx::Class::TimeStamp", "0.14";
requires "DBIx::Class::PassphraseColumn", "0.02";
requires "DBD::Pg", "3.16.0";
requires "Template", "3.101";
requires "JSON", "4.10";
requires "DateTime", "1.59";
requires "DateTime::Format::Pg", "0.16014";
requires "Crypt::Bcrypt", "0.011";
requires "Email::Valid", "1.202";
requires "HTML::FormHandler", "0.40068";
requires "HTML::FormHandler::Model::DBIC", "0.29";
requires "Config::General", "2.65";
requires "Try::Tiny", "0.31";
requires "Moose", "2.2015";
requires "namespace::autoclean", "0.29";

# Development dependencies
on 'develop' => sub {
  requires "Catalyst::Devel", "1.42";
  requires "Test::More", "1.302190";
  requires "Test::WWW::Mechanize::Catalyst", "0.62";
  requires "Test::Deep", "1.130";
  requires "Test::JSON", "0.11";
  requires "Catalyst::Test", "5.90130";
  requires "Perl::Critic", "1.148";
  requires "Perl::Tidy", "20230309";
  requires "Devel::Cover", "1.38";
  requires "Test::Pod", "1.52";
  requires "Test::Pod::Coverage", "1.10";
};`,

    'lib/CatalystApp.pm': `package CatalystApp;
use Moose;
use namespace::autoclean;

use Catalyst::Runtime 5.80;

# Set flags and add plugins for the application.
#
# Note that ORDERING IS IMPORTANT here as plugins are initialized in order,
# therefore you almost certainly want to keep ConfigLoader at the head of the
# list if you're using it.
#
#         -Debug: activates the debug mode for very useful log messages
#   ConfigLoader: will load the configuration from a Config::General file in the
#                 application's home directory
# Static::Simple: will serve static files from the application's root
#                 directory

use Catalyst qw/
    -Debug
    ConfigLoader
    Static::Simple
    
    Session
    Session::State::Cookie
    Session::Store::FastMmap
    
    Authentication
    Authorization::Roles
    
    StatusMessage
    StackTrace
    SmartURI
    Unicode::Encoding
/;

extends 'Catalyst';

our $VERSION = '0.01';

# Configure the application.
#
# Note that settings in catalyst_app.conf (or other external
# configuration file that you set up manually) take precedence
# over this when using ConfigLoader. Thus configuration in this file
# is used as a default configuration, with an external configuration
# file acting as an override for local deployment.

__PACKAGE__->config(
    name => 'CatalystApp',
    # Disable deprecated behavior needed by old applications
    disable_component_resolution_regex_fallback => 1,
    enable_catalyst_header => 1, # Send X-Catalyst header
    encoding => 'UTF-8',
    default_view => 'TT',
    
    # Session configuration
    'Plugin::Session' => {
        flash_to_stash => 1,
        expires => 3600,
    },
    
    # Authentication configuration
    'Plugin::Authentication' => {
        default_realm => 'users',
        realms => {
            users => {
                credential => {
                    class => 'Password',
                    password_field => 'password',
                    password_type => 'self_check',
                },
                store => {
                    class => 'DBIx::Class',
                    user_model => 'DB::User',
                    role_relation => 'roles',
                    role_field => 'role',
                }
            },
        },
    },
    
    # Static file configuration
    'Plugin::Static::Simple' => {
        mime_types => {
            woff => 'font/woff',
            woff2 => 'font/woff2',
        },
    },
    
    # Status message configuration
    'Plugin::StatusMessage' => {
        token_name => 'mid',
        stash_name => 'status_msg',
    },
);

# Start the application
__PACKAGE__->setup();

=encoding utf8

=head1 NAME

CatalystApp - Catalyst based application

=head1 SYNOPSIS

    script/catalyst_app_server.pl

=head1 DESCRIPTION

Enterprise-grade Catalyst web application with MVC architecture,
comprehensive authentication, and extensive plugin ecosystem.

=head1 SEE ALSO

L<CatalystApp::Controller::Root>, L<Catalyst>

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;`,

    'lib/CatalystApp/Controller/Root.pm': `package CatalystApp::Controller::Root;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller' }

#
# Sets the actions in this controller to be registered with no prefix
# so they function identically to actions created in MyApp.pm
#
__PACKAGE__->config(namespace => '');

=encoding utf8

=head1 NAME

CatalystApp::Controller::Root - Root Controller for CatalystApp

=head1 DESCRIPTION

Root controller for the Catalyst application.

=head1 METHODS

=cut

=head2 index

The root page (/)

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;
    
    # Set template
    $c->stash(
        template => 'index.tt',
        title => 'Welcome to CatalystApp',
        message => 'Welcome to the Catalyst framework!'
    );
}

=head2 default

Standard 404 error page

=cut

sub default :Path {
    my ( $self, $c ) = @_;
    
    $c->response->body( 'Page not found' );
    $c->response->status(404);
}

=head2 end

Attempt to render a view, if needed.

=cut

sub end : ActionClass('RenderView') {}

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;`,

    'lib/CatalystApp/Controller/API.pm': `package CatalystApp::Controller::API;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller::REST' }

use JSON;
use Try::Tiny;
use DateTime;

=encoding utf8

=head1 NAME

CatalystApp::Controller::API - REST API Controller

=head1 DESCRIPTION

REST API controller providing JSON endpoints for the application.

=head1 METHODS

=cut

# Set the default serializer for REST responses
__PACKAGE__->config(
    default => 'application/json',
    map => {
        'application/json' => 'JSON',
        'text/html' => 'JSON',
    }
);

=head2 health

GET /api/health - Health check endpoint

=cut

sub health : Local : GET {
    my ( $self, $c ) = @_;
    
    my $health = {
        status => 'ok',
        timestamp => DateTime->now->iso8601,
        version => $CatalystApp::VERSION,
        service => 'catalyst-app'
    };
    
    # Check database connection
    try {
        my $db = $c->model('DB');
        my $result = $db->storage->dbh->selectrow_array('SELECT 1');
        $health->{database} = 'connected';
    } catch {
        $health->{status} = 'error';
        $health->{database} = 'disconnected';
        $health->{error} = $_;
        $c->response->status(503);
    };
    
    $self->status_ok($c, entity => $health);
}

=head2 info

GET /api/info - Application information

=cut

sub info : Local : GET {
    my ( $self, $c ) = @_;
    
    my $info = {
        name => $c->config->{name},
        version => $CatalystApp::VERSION,
        environment => $c->debug ? 'development' : 'production',
        features => [
            'Enterprise MVC framework',
            'Plugin ecosystem',
            'Authentication system',
            'Database abstraction',
            'Template engine',
            'Session management',
            'REST API support'
        ],
        endpoints => {
            health => '/api/health',
            info => '/api/info',
            users => '/api/users',
            auth => '/api/auth',
        }
    };
    
    $self->status_ok($c, entity => $info);
}

=head2 not_found

Handle 404 errors for API endpoints

=cut

sub not_found : Private {
    my ( $self, $c ) = @_;
    
    $self->status_not_found($c, 
        message => 'API endpoint not found',
        entity => {
            error => 'Not Found',
            message => 'The requested API endpoint was not found',
            path => $c->request->path
        }
    );
}

=head2 access_denied

Handle 403 errors for API endpoints

=cut

sub access_denied : Private {
    my ( $self, $c ) = @_;
    
    $self->status_forbidden($c,
        message => 'Access denied',
        entity => {
            error => 'Forbidden',
            message => 'You do not have permission to access this resource'
        }
    );
}

=head2 server_error

Handle 500 errors for API endpoints

=cut

sub server_error : Private {
    my ( $self, $c, $error ) = @_;
    
    $c->log->error("API Server Error: $error");
    
    $self->status_internal_server_error($c,
        message => 'Internal server error',
        entity => {
            error => 'Internal Server Error',
            message => 'An unexpected error occurred'
        }
    );
}

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;`,

    'lib/CatalystApp/Controller/API/Auth.pm': `package CatalystApp::Controller::API::Auth;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller::REST' }

use JSON;
use Try::Tiny;
use DateTime;
use Email::Valid;

=encoding utf8

=head1 NAME

CatalystApp::Controller::API::Auth - Authentication API Controller

=head1 DESCRIPTION

REST API controller for authentication operations.

=head1 METHODS

=cut

__PACKAGE__->config(
    default => 'application/json',
    map => {
        'application/json' => 'JSON',
        'text/html' => 'JSON',
    }
);

=head2 login

POST /api/auth/login - User authentication

=cut

sub login : Local : POST {
    my ( $self, $c ) = @_;
    
    my $data = $c->request->data;
    
    # Validate input
    unless ($data && $data->{email} && $data->{password}) {
        return $self->status_bad_request($c, 
            message => 'Email and password are required',
            entity => {
                error => 'Validation failed',
                details => ['Email and password are required']
            }
        );
    }
    
    # Validate email format
    unless (Email::Valid->address($data->{email})) {
        return $self->status_bad_request($c,
            message => 'Invalid email format',
            entity => {
                error => 'Validation failed',
                details => ['Invalid email format']
            }
        );
    }
    
    # Attempt authentication
    if ($c->authenticate({ 
        email => $data->{email}, 
        password => $data->{password} 
    })) {
        my $user = $c->user;
        
        # Create session
        $c->session->{user_id} = $user->id;
        $c->session->{user_email} = $user->email;
        $c->session->{login_time} = DateTime->now->iso8601;
        
        # Generate token (simple implementation)
        my $token = $self->_generate_token($user);
        
        $self->status_ok($c, entity => {
            token => $token,
            user => {
                id => $user->id,
                name => $user->name,
                email => $user->email,
                role => $user->role
            },
            session => {
                expires => DateTime->now->add(hours => 1)->iso8601
            }
        });
    } else {
        $self->status_unauthorized($c,
            message => 'Invalid credentials',
            entity => {
                error => 'Authentication failed',
                message => 'Invalid email or password'
            }
        );
    }
}

=head2 register

POST /api/auth/register - User registration

=cut

sub register : Local : POST {
    my ( $self, $c ) = @_;
    
    my $data = $c->request->data;
    
    # Validate input
    my @errors;
    push @errors, 'Name is required' unless $data->{name} && length($data->{name}) > 0;
    push @errors, 'Email is required' unless $data->{email};
    push @errors, 'Invalid email format' unless Email::Valid->address($data->{email});
    push @errors, 'Password is required' unless $data->{password};
    push @errors, 'Password must be at least 6 characters' 
        unless length($data->{password} // '') >= 6;
    
    if (@errors) {
        return $self->status_bad_request($c,
            message => 'Validation failed',
            entity => {
                error => 'Validation failed',
                details => \\@errors
            }
        );
    }
    
    # Check if user already exists
    my $existing = $c->model('DB::User')->find({ email => $data->{email} });
    if ($existing) {
        return $self->status_conflict($c,
            message => 'User already exists',
            entity => {
                error => 'Conflict',
                message => 'A user with this email already exists'
            }
        );
    }
    
    # Create user
    try {
        my $user = $c->model('DB::User')->create({
            name => $data->{name},
            email => $data->{email},
            password => $data->{password}, # Will be hashed by PassphraseColumn
            role => 'user',
            created_at => DateTime->now,
            updated_at => DateTime->now
        });
        
        $self->status_created($c, entity => {
            id => $user->id,
            name => $user->name,
            email => $user->email,
            role => $user->role,
            created_at => $user->created_at->iso8601
        });
    } catch {
        $c->log->error("User creation error: $_");
        $self->status_internal_server_error($c,
            message => 'Failed to create user',
            entity => {
                error => 'Internal Server Error',
                message => 'Failed to create user account'
            }
        );
    };
}

=head2 logout

POST /api/auth/logout - User logout

=cut

sub logout : Local : POST {
    my ( $self, $c ) = @_;
    
    # Clear session
    $c->logout;
    $c->delete_session;
    
    $self->status_ok($c, entity => {
        message => 'Logged out successfully',
        timestamp => DateTime->now->iso8601
    });
}

=head2 profile

GET /api/auth/profile - Get current user profile

=cut

sub profile : Local : GET {
    my ( $self, $c ) = @_;
    
    # Check authentication
    unless ($c->user_exists) {
        return $self->status_unauthorized($c,
            message => 'Authentication required',
            entity => {
                error => 'Unauthorized',
                message => 'Authentication required to access this resource'
            }
        );
    }
    
    my $user = $c->user;
    
    $self->status_ok($c, entity => {
        id => $user->id,
        name => $user->name,
        email => $user->email,
        role => $user->role,
        created_at => $user->created_at->iso8601,
        updated_at => $user->updated_at->iso8601,
        session => {
            login_time => $c->session->{login_time},
            user_id => $c->session->{user_id}
        }
    });
}

=head2 _generate_token

Generate authentication token (simple implementation)

=cut

sub _generate_token {
    my ($self, $user) = @_;
    
    # Simple token generation - in production, use proper JWT
    return encode_json({
        user_id => $user->id,
        email => $user->email,
        role => $user->role,
        expires => DateTime->now->add(hours => 1)->epoch,
        uuid => $self->_generate_uuid()
    });
}

=head2 _generate_uuid

Generate simple UUID

=cut

sub _generate_uuid {
    my $self = shift;
    return sprintf("%08x-%04x-%04x-%04x-%012x", 
        rand(0xffffffff), rand(0xffff), rand(0xffff), 
        rand(0xffff), rand(0xffffffffffff));
}

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;`,

    'lib/CatalystApp/Controller/API/Users.pm': `package CatalystApp::Controller::API::Users;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller::REST' }

use JSON;
use Try::Tiny;
use DateTime;
use Email::Valid;

=encoding utf8

=head1 NAME

CatalystApp::Controller::API::Users - User Management API Controller

=head1 DESCRIPTION

REST API controller for user management operations.

=head1 METHODS

=cut

__PACKAGE__->config(
    default => 'application/json',
    map => {
        'application/json' => 'JSON',
        'text/html' => 'JSON',
    }
);

=head2 index

GET /api/users - Get all users

=cut

sub index : GET {
    my ( $self, $c ) = @_;
    
    # Check authentication
    unless ($c->user_exists) {
        return $self->status_unauthorized($c,
            message => 'Authentication required',
            entity => {
                error => 'Unauthorized',
                message => 'Authentication required to access this resource'
            }
        );
    }
    
    # Get users
    my $users = $c->model('DB::User')->search({}, {
        order_by => { -desc => 'created_at' },
        columns => [qw/id name email role created_at updated_at/]
    });
    
    my @user_list;
    while (my $user = $users->next) {
        push @user_list, {
            id => $user->id,
            name => $user->name,
            email => $user->email,
            role => $user->role,
            created_at => $user->created_at->iso8601,
            updated_at => $user->updated_at->iso8601
        };
    }
    
    $self->status_ok($c, entity => \\@user_list);
}

=head2 show

GET /api/users/:id - Get user by ID

=cut

sub show : GET Args(1) {
    my ( $self, $c, $id ) = @_;
    
    # Check authentication
    unless ($c->user_exists) {
        return $self->status_unauthorized($c,
            message => 'Authentication required',
            entity => {
                error => 'Unauthorized',
                message => 'Authentication required to access this resource'
            }
        );
    }
    
    # Validate ID
    unless ($id && $id =~ /^\\d+$/) {
        return $self->status_bad_request($c,
            message => 'Invalid user ID',
            entity => {
                error => 'Bad Request',
                message => 'Invalid user ID format'
            }
        );
    }
    
    # Find user
    my $user = $c->model('DB::User')->find($id);
    unless ($user) {
        return $self->status_not_found($c,
            message => 'User not found',
            entity => {
                error => 'Not Found',
                message => 'User not found'
            }
        );
    }
    
    $self->status_ok($c, entity => {
        id => $user->id,
        name => $user->name,
        email => $user->email,
        role => $user->role,
        created_at => $user->created_at->iso8601,
        updated_at => $user->updated_at->iso8601
    });
}

=head2 create

POST /api/users - Create new user

=cut

sub create : POST {
    my ( $self, $c ) = @_;
    
    # Check authentication and authorization
    unless ($c->user_exists) {
        return $self->status_unauthorized($c,
            message => 'Authentication required',
            entity => {
                error => 'Unauthorized',
                message => 'Authentication required to access this resource'
            }
        );
    }
    
    # Check if user is admin
    unless ($c->check_user_roles('admin')) {
        return $self->status_forbidden($c,
            message => 'Admin role required',
            entity => {
                error => 'Forbidden',
                message => 'Admin role required to create users'
            }
        );
    }
    
    my $data = $c->request->data;
    
    # Validate input
    my @errors;
    push @errors, 'Name is required' unless $data->{name} && length($data->{name}) > 0;
    push @errors, 'Email is required' unless $data->{email};
    push @errors, 'Invalid email format' unless Email::Valid->address($data->{email});
    push @errors, 'Password is required' unless $data->{password};
    push @errors, 'Password must be at least 6 characters' 
        unless length($data->{password} // '') >= 6;
    
    if (@errors) {
        return $self->status_bad_request($c,
            message => 'Validation failed',
            entity => {
                error => 'Validation failed',
                details => \\@errors
            }
        );
    }
    
    # Check if user already exists
    my $existing = $c->model('DB::User')->find({ email => $data->{email} });
    if ($existing) {
        return $self->status_conflict($c,
            message => 'User already exists',
            entity => {
                error => 'Conflict',
                message => 'A user with this email already exists'
            }
        );
    }
    
    # Create user
    try {
        my $user = $c->model('DB::User')->create({
            name => $data->{name},
            email => $data->{email},
            password => $data->{password}, # Will be hashed by PassphraseColumn
            role => $data->{role} || 'user',
            created_at => DateTime->now,
            updated_at => DateTime->now
        });
        
        $self->status_created($c, entity => {
            id => $user->id,
            name => $user->name,
            email => $user->email,
            role => $user->role,
            created_at => $user->created_at->iso8601
        });
    } catch {
        $c->log->error("User creation error: $_");
        $self->status_internal_server_error($c,
            message => 'Failed to create user',
            entity => {
                error => 'Internal Server Error',
                message => 'Failed to create user account'
            }
        );
    };
}

=head2 update

PUT /api/users/:id - Update user

=cut

sub update : PUT Args(1) {
    my ( $self, $c, $id ) = @_;
    
    # Check authentication
    unless ($c->user_exists) {
        return $self->status_unauthorized($c,
            message => 'Authentication required',
            entity => {
                error => 'Unauthorized',
                message => 'Authentication required to access this resource'
            }
        );
    }
    
    # Validate ID
    unless ($id && $id =~ /^\\d+$/) {
        return $self->status_bad_request($c,
            message => 'Invalid user ID',
            entity => {
                error => 'Bad Request',
                message => 'Invalid user ID format'
            }
        );
    }
    
    # Find user
    my $user = $c->model('DB::User')->find($id);
    unless ($user) {
        return $self->status_not_found($c,
            message => 'User not found',
            entity => {
                error => 'Not Found',
                message => 'User not found'
            }
        );
    }
    
    # Check permissions (users can only update themselves unless admin)
    my $current_user = $c->user;
    unless ($current_user->id == $id || $c->check_user_roles('admin')) {
        return $self->status_forbidden($c,
            message => 'Insufficient permissions',
            entity => {
                error => 'Forbidden',
                message => 'You can only update your own profile unless you are an admin'
            }
        );
    }
    
    my $data = $c->request->data;
    
    # Validate input
    my @errors;
    push @errors, 'Name cannot be empty' if exists $data->{name} && length($data->{name}) == 0;
    push @errors, 'Invalid email format' if $data->{email} && !Email::Valid->address($data->{email});
    
    if (@errors) {
        return $self->status_bad_request($c,
            message => 'Validation failed',
            entity => {
                error => 'Validation failed',
                details => \\@errors
            }
        );
    }
    
    # Check email uniqueness
    if ($data->{email} && $data->{email} ne $user->email) {
        my $existing = $c->model('DB::User')->find({ email => $data->{email} });
        if ($existing) {
            return $self->status_conflict($c,
                message => 'Email already exists',
                entity => {
                    error => 'Conflict',
                    message => 'A user with this email already exists'
                }
            );
        }
    }
    
    # Update user
    try {
        my %update_data;
        $update_data{name} = $data->{name} if exists $data->{name};
        $update_data{email} = $data->{email} if exists $data->{email};
        $update_data{password} = $data->{password} if exists $data->{password};
        
        # Only admins can change roles
        if ($data->{role} && $c->check_user_roles('admin')) {
            $update_data{role} = $data->{role};
        }
        
        return $self->status_bad_request($c,
            message => 'No fields to update',
            entity => {
                error => 'Bad Request',
                message => 'No valid fields provided for update'
            }
        ) unless %update_data;
        
        $update_data{updated_at} = DateTime->now;
        
        $user->update(\\%update_data);
        
        $self->status_ok($c, entity => {
            id => $user->id,
            name => $user->name,
            email => $user->email,
            role => $user->role,
            created_at => $user->created_at->iso8601,
            updated_at => $user->updated_at->iso8601
        });
    } catch {
        $c->log->error("User update error: $_");
        $self->status_internal_server_error($c,
            message => 'Failed to update user',
            entity => {
                error => 'Internal Server Error',
                message => 'Failed to update user account'
            }
        );
    };
}

=head2 delete

DELETE /api/users/:id - Delete user

=cut

sub delete : DELETE Args(1) {
    my ( $self, $c, $id ) = @_;
    
    # Check authentication and authorization
    unless ($c->user_exists) {
        return $self->status_unauthorized($c,
            message => 'Authentication required',
            entity => {
                error => 'Unauthorized',
                message => 'Authentication required to access this resource'
            }
        );
    }
    
    # Check if user is admin
    unless ($c->check_user_roles('admin')) {
        return $self->status_forbidden($c,
            message => 'Admin role required',
            entity => {
                error => 'Forbidden',
                message => 'Admin role required to delete users'
            }
        );
    }
    
    # Validate ID
    unless ($id && $id =~ /^\\d+$/) {
        return $self->status_bad_request($c,
            message => 'Invalid user ID',
            entity => {
                error => 'Bad Request',
                message => 'Invalid user ID format'
            }
        );
    }
    
    # Find user
    my $user = $c->model('DB::User')->find($id);
    unless ($user) {
        return $self->status_not_found($c,
            message => 'User not found',
            entity => {
                error => 'Not Found',
                message => 'User not found'
            }
        );
    }
    
    # Don't allow deleting yourself
    my $current_user = $c->user;
    if ($current_user->id == $id) {
        return $self->status_bad_request($c,
            message => 'Cannot delete yourself',
            entity => {
                error => 'Bad Request',
                message => 'You cannot delete your own account'
            }
        );
    }
    
    # Delete user
    try {
        $user->delete;
        $c->response->status(204);
        $c->response->body('');
    } catch {
        $c->log->error("User deletion error: $_");
        $self->status_internal_server_error($c,
            message => 'Failed to delete user',
            entity => {
                error => 'Internal Server Error',
                message => 'Failed to delete user account'
            }
        );
    };
}

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;`,

    'lib/CatalystApp/Model/DB.pm': `package CatalystApp::Model::DB;

use strict;
use base 'Catalyst::Model::DBIC::Schema';

__PACKAGE__->config(
    schema_class => 'CatalystApp::Schema',
    
    connect_info => {
        dsn => 'dbi:Pg:dbname=catalyst_app;host=localhost',
        user => 'postgres',
        password => 'postgres',
        pg_enable_utf8 => 1,
        on_connect_do => ['SET search_path TO public'],
        quote_names => 1,
    }
);

=head1 NAME

CatalystApp::Model::DB - Catalyst DBIC Schema Model

=head1 SYNOPSIS

See L<CatalystApp>

=head1 DESCRIPTION

L<Catalyst::Model::DBIC::Schema> Model using schema L<CatalystApp::Schema>

=head1 GENERATED BY

Catalyst::Helper::Model::DBIC::Schema - 0.65

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;`,

    'lib/CatalystApp/Schema.pm': `use utf8;
package CatalystApp::Schema;

# Created by DBIx::Class::Schema::Loader
# DO NOT MODIFY THE FIRST PART OF THIS FILE

use strict;
use warnings;

use Moose;
use MooseX::MarkAsMethods autoclean => 1;
extends 'DBIx::Class::Schema';

__PACKAGE__->load_namespaces;

# Created by DBIx::Class::Schema::Loader v0.07051 @ 2024-01-01 12:00:00
# DO NOT MODIFY THIS OR ANYTHING ABOVE! md5sum:EXAMPLE

# You can replace this text with custom code or comments, and it will be preserved on regeneration

=head1 NAME

CatalystApp::Schema - Database Schema for Catalyst Application

=head1 SYNOPSIS

  use CatalystApp::Schema;
  
  my $schema = CatalystApp::Schema->connect($dsn, $user, $pass, $opts);

=head1 DESCRIPTION

Database schema for the Catalyst application using DBIx::Class.

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable(inline_constructor => 0);
1;`,

    'lib/CatalystApp/Schema/Result/User.pm': `use utf8;
package CatalystApp::Schema::Result::User;

# Created by DBIx::Class::Schema::Loader
# DO NOT MODIFY THE FIRST PART OF THIS FILE

use strict;
use warnings;

use Moose;
use MooseX::NonMoose;
use MooseX::MarkAsMethods autoclean => 1;
extends 'DBIx::Class::Core';

=head1 NAME

CatalystApp::Schema::Result::User

=cut

__PACKAGE__->load_components("TimeStamp", "PassphraseColumn");

=head1 TABLE: C<users>

=cut

__PACKAGE__->table("users");

=head1 ACCESSORS

=head2 id

  data_type: 'integer'
  is_auto_increment: 1
  is_nullable: 0
  sequence: 'users_id_seq'

=head2 name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 email

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 password

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 role

  data_type: 'varchar'
  default_value: 'user'
  is_nullable: 0
  size: 50

=head2 created_at

  data_type: 'timestamp'
  default_value: current_timestamp
  is_nullable: 0

=head2 updated_at

  data_type: 'timestamp'
  default_value: current_timestamp
  is_nullable: 0

=cut

__PACKAGE__->add_columns(
  "id",
  {
    data_type         => "integer",
    is_auto_increment => 1,
    is_nullable       => 0,
    sequence          => "users_id_seq",
  },
  "name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "email",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "password",
  { 
    data_type => "varchar", 
    is_nullable => 0, 
    size => 255,
    passphrase => 'bcrypt',
    passphrase_class => 'Crypt::Bcrypt',
    passphrase_args => {
      cost => 12,
    },
    passphrase_check_method => 'check_password',
  },
  "role",
  {
    data_type => "varchar",
    default_value => "user",
    is_nullable => 0,
    size => 50,
  },
  "created_at",
  {
    data_type => "timestamp",
    default_value => \\"current_timestamp",
    is_nullable => 0,
  },
  "updated_at",
  {
    data_type => "timestamp",
    default_value => \\"current_timestamp",
    is_nullable => 0,
  },
);

=head1 PRIMARY KEY

=cut

__PACKAGE__->set_primary_key("id");

=head1 UNIQUE CONSTRAINTS

=head2 C<users_email_key>

=cut

__PACKAGE__->add_unique_constraint("users_email_key", ["email"]);

# Created by DBIx::Class::Schema::Loader v0.07051 @ 2024-01-01 12:00:00
# DO NOT MODIFY THIS OR ANYTHING ABOVE! md5sum:EXAMPLE

# Enable automatic timestamp handling
__PACKAGE__->add_columns(
    "created_at",
    { data_type => 'timestamp', set_on_create => 1 },
    "updated_at", 
    { data_type => 'timestamp', set_on_create => 1, set_on_update => 1 },
);

=head1 METHODS

=head2 check_password

Check if provided password matches the stored hash

=cut

# This method is automatically created by PassphraseColumn

=head2 roles

Get user roles for authorization

=cut

sub roles {
    my $self = shift;
    return ($self->role);
}

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;
1;`,

    'lib/CatalystApp/View/TT.pm': `package CatalystApp::View::TT;
use Moose;
use namespace::autoclean;

extends 'Catalyst::View::TT';

__PACKAGE__->config(
    TEMPLATE_EXTENSION => '.tt',
    INCLUDE_PATH => [
        CatalystApp->path_to( 'root', 'src' ),
    ],
    PRE_PROCESS  => 'config/main',
    WRAPPER      => 'site/wrapper',
    ERROR        => 'error.tt',
    TIMER        => 0,
    ENCODING     => 'utf-8',
    render_die   => 1,
    expose_methods => [qw/uri_for_action/],
);

=head1 NAME

CatalystApp::View::TT - TT View for CatalystApp

=head1 DESCRIPTION

TT View for CatalystApp.

=head1 SEE ALSO

L<CatalystApp>

=head1 AUTHOR

Re-Shell Team

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;`,

    'catalyst_app.conf': `# CatalystApp configuration file
name CatalystApp
default_view TT
encoding UTF-8

# Session configuration
<Plugin::Session>
    flash_to_stash 1
    expires 3600
</Plugin::Session>

# Authentication configuration
<Plugin::Authentication>
    default_realm users
    <realms>
        <users>
            <credential>
                class Password
                password_field password
                password_type self_check
            </credential>
            <store>
                class DBIx::Class
                user_model DB::User
                role_relation roles
                role_field role
            </store>
        </users>
    </realms>
</Plugin::Authentication>

# Database configuration
<Model::DB>
    <connect_info>
        dsn dbi:Pg:dbname=catalyst_app;host=localhost
        user postgres
        password postgres
        pg_enable_utf8 1
        quote_names 1
        <on_connect_do>SET search_path TO public</on_connect_do>
    </connect_info>
</Model::DB>

# Static file configuration
<Plugin::Static::Simple>
    <mime_types>
        woff font/woff
        woff2 font/woff2
    </mime_types>
</Plugin::Static::Simple>

# Status message configuration
<Plugin::StatusMessage>
    token_name mid
    stash_name status_msg
</Plugin::StatusMessage>`,

    'script/catalyst_app_create.pl': `#!/usr/bin/env perl

use strict;
use warnings;

use Catalyst::ScriptRunner;
Catalyst::ScriptRunner->run('CatalystApp', 'Create');

1;

=head1 NAME

catalyst_app_create.pl - Create a new Catalyst component

=head1 SYNOPSIS

catalyst_app_create.pl [options] model|view|controller name [helper] [options]

 Options:
   --force        don't create a .new file where a file to be created exists
   --mechanize    use Test::WWW::Mechanize::Catalyst for tests if available
   --help         display this help and exits

 Examples:
   catalyst_app_create.pl controller My::Controller
   catalyst_app_create.pl -mechanize controller My::Controller
   catalyst_app_create.pl view My::View
   catalyst_app_create.pl view HTML TT
   catalyst_app_create.pl model My::Model
   catalyst_app_create.pl model SomeDB DBIC::Schema MyApp::Schema create=dynamic\\
   dbi:SQLite:/tmp/my.db
   catalyst_app_create.pl model AnotherDB DBIC::Schema MyApp::Schema create=static\\
   [Loader opts like db_schema, naming] dbi:Pg:dbname=foo root 4321
   [connect_info opts like quote_char, name_sep]

 See also:
   perldoc Catalyst::Manual
   perldoc Catalyst::Manual::Intro
   perldoc Catalyst::Helper::Model::DBIC::Schema
   perldoc Catalyst::Model::DBIC::Schema
   perldoc Catalyst::View::TT

=head1 DESCRIPTION

Create a new Catalyst Component.

Existing component files are not overwritten.  If any of the component files
to be created already exist the file will be written with a '.new' suffix.
This behavior can be suppressed with the C<-force> option.

=head1 AUTHORS

Catalyst Contributors, see Catalyst.pm

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut`,

    'script/catalyst_app_server.pl': `#!/usr/bin/env perl

use strict;
use warnings;

use Catalyst::ScriptRunner;
Catalyst::ScriptRunner->run('CatalystApp', 'Server');

1;

=head1 NAME

catalyst_app_server.pl - Catalyst Test Server

=head1 SYNOPSIS

catalyst_app_server.pl [options]

   -d --debug           force debug mode
   -f --fork            handle each request in a new process
                        (defaults to false)
   -? --help            display this help and exits
   -h --host            host (defaults to all)
   -p --port            port (defaults to 3000)
   -k --keepalive       enable keep-alive connections
   -r --restart         restart when files get modified
                        (defaults to false)
   -rd --restart_delay  delay between file checks
                        (ignored if you have Linux::Inotify2 installed)
   -rr --restart_regex  regex match files that trigger
                        a restart when modified
                        (defaults to '\\.(yml|yaml|conf|pm|pl)$')
   --restart_directory  the directory to search for
                        modified files, can be set multiple times
                        (defaults to '[SCRIPT_DIR]/..')
   --follow_symlinks    follow symlinks in search directories
                        (defaults to false. this is a no-op on Win32)
   --background         run the process in the background
   --pidfile            specify filename for pid file

 See also:
   perldoc Catalyst::Manual
   perldoc Catalyst::Manual::Intro

=head1 DESCRIPTION

Run a Catalyst Testserver for this application.

=head1 AUTHORS

Catalyst Contributors, see Catalyst.pm

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut`,

    'script/catalyst_app_test.pl': `#!/usr/bin/env perl

use strict;
use warnings;

use Catalyst::ScriptRunner;
Catalyst::ScriptRunner->run('CatalystApp', 'Test');

1;

=head1 NAME

catalyst_app_test.pl - Catalyst Test

=head1 SYNOPSIS

catalyst_app_test.pl [options] uri

 Options:
   --help    display this help and exits

 Examples:
   catalyst_app_test.pl http://localhost/some_action
   catalyst_app_test.pl /some_action

 See also:
   perldoc Catalyst::Manual
   perldoc Catalyst::Manual::Intro

=head1 DESCRIPTION

Run a Catalyst action from the command line.

=head1 AUTHORS

Catalyst Contributors, see Catalyst.pm

=head1 COPYRIGHT

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut`,

    'root/src/index.tt': `[% META title = 'Welcome to CatalystApp' %]

<div class="hero">
    <h1>🏭 Welcome to CatalystApp</h1>
    <p>Enterprise-grade MVC web framework for Perl</p>
</div>

<div class="features">
    <div class="feature">
        <h3>Enterprise MVC Framework</h3>
        <p>Built with Catalyst, featuring comprehensive MVC architecture, extensive plugin ecosystem, and enterprise-grade scalability.</p>
    </div>
    
    <div class="feature">
        <h3>API Endpoints</h3>
        <div class="endpoint">POST /api/auth/register - User registration</div>
        <div class="endpoint">POST /api/auth/login - User authentication</div>
        <div class="endpoint">GET /api/users - Get all users (authenticated)</div>
        <div class="endpoint">POST /api/users - Create user (admin only)</div>
        <div class="endpoint">GET /api/health - Health check</div>
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
            <button onclick="getProfile()">Get Profile</button>
            <button onclick="logout()">Logout</button>
            
            <h4>Response</h4>
            <div id="response" class="response"></div>
        </div>
    </div>
    
    <div class="feature">
        <h3>Framework Features</h3>
        <ul>
            <li>MVC Architecture</li>
            <li>Plugin System</li>
            <li>Authentication & Authorization</li>
            <li>Database Abstraction (DBIx::Class)</li>
            <li>Template Engine (Template Toolkit)</li>
            <li>Session Management</li>
            <li>REST API Support</li>
            <li>Form Handling</li>
            <li>Testing Framework</li>
            <li>Deployment Tools</li>
        </ul>
    </div>
</div>

<script>
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
            },
            credentials: 'include' // Include cookies for session
        };
        
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
        makeRequest('GET', '/api/users')
        .then(data => {
            showResponse(data);
        })
        .catch(error => {
            showResponse({ error: error.message });
        });
    }
    
    function getProfile() {
        makeRequest('GET', '/api/auth/profile')
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
            showResponse(data);
        })
        .catch(error => {
            showResponse({ error: error.message });
        });
    }
    
    // Test health endpoint on load
    window.addEventListener('load', function() {
        makeRequest('GET', '/api/health')
        .then(data => {
            console.log('Health check:', data);
        })
        .catch(error => {
            console.error('Health check failed:', error);
        });
    });
</script>`,

    'root/src/config/main': `[% # Config template
   # 
   # This is the main configuration template which is processed before
   # any other page, by virtue of it being defined as a PRE_PROCESS 
   # template.  This is the place to define any extra template variables,
   # macros, load plugins, etc.

   # define a data structure to hold sitewide data
   site = {
     title     => 'CatalystApp',
     copyright => '2024 Re-Shell Team',
   }

   # define a macro to generate URLs
   MACRO link(text, action, captures, args, anchor) BLOCK;
     IF c.controller.action_for(action);
       c.uri_for_action(action, captures, args, anchor);
     ELSE;
       c.uri_for(action, args, anchor);
     END;
   END;

   # load up other configuration items 
   PROCESS config/col
   PROCESS config/url
%]`,

    'root/src/config/col': `[% # 
   # define column classes for CSS grid framework
   #
   
   MACRO col(size) BLOCK;
     SWITCH size;
       CASE 1; 'col-1';
       CASE 2; 'col-2';
       CASE 3; 'col-3';
       CASE 4; 'col-4';
       CASE 5; 'col-5';
       CASE 6; 'col-6';
       CASE 7; 'col-7';
       CASE 8; 'col-8';
       CASE 9; 'col-9';
       CASE 10; 'col-10';
       CASE 11; 'col-11';
       CASE 12; 'col-12';
       CASE DEFAULT; 'col-12';
     END;
   END;
%]`,

    'root/src/config/url': `[% # 
   # define site URLs
   #
   
   base_url = base || c.req.base;
   site_url = c.uri_for('/');
   
   # define common URLs
   home_url = c.uri_for('/');
   api_url = c.uri_for('/api');
   health_url = c.uri_for('/api/health');
   
   # define asset URLs
   css_url = c.uri_for('/static/css');
   js_url = c.uri_for('/static/js');
   img_url = c.uri_for('/static/images');
%]`,

    'root/src/site/wrapper': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>[% title %] - [% site.title %]</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            background: #f8f9fa;
        }
        
        .navbar {
            background: #007bff;
            color: white;
            padding: 1rem 0;
            margin: 0 -20px 2rem -20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
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
            padding: 8px 16px;
            border-radius: 4px;
            transition: background 0.2s;
        }
        
        .navbar a:hover {
            background: rgba(255,255,255,0.1);
        }
        
        .navbar .brand {
            font-size: 1.5rem;
            font-weight: bold;
        }
        
        .hero {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 4rem 2rem;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .hero h1 {
            font-size: 3rem;
            margin-bottom: 1rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .hero p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }
        
        .feature {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .feature:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        
        .feature h3 {
            color: #007bff;
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }
        
        .endpoint {
            background: #f8f9fa;
            padding: 8px 12px;
            margin: 8px 0;
            border-radius: 5px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            border-left: 4px solid #007bff;
        }
        
        .auth-demo {
            background: #f0f8ff;
            padding: 1.5rem;
            border-radius: 8px;
            margin: 1rem 0;
        }
        
        .auth-demo h4 {
            color: #0056b3;
            margin: 1rem 0 0.5rem 0;
        }
        
        .auth-demo h4:first-child {
            margin-top: 0;
        }
        
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            border: 2px solid #e9ecef;
            border-radius: 5px;
            font-size: 1rem;
            transition: border-color 0.2s;
        }
        
        input[type="text"]:focus, input[type="email"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #007bff;
        }
        
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1rem;
            margin: 5px;
            transition: background 0.2s;
        }
        
        button:hover {
            background: #0056b3;
        }
        
        .response {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .footer {
            background: #343a40;
            color: white;
            text-align: center;
            padding: 2rem;
            margin: 3rem -20px 0 -20px;
        }
        
        ul {
            list-style-type: none;
            padding: 0;
        }
        
        li {
            padding: 5px 0;
        }
        
        li:before {
            content: "✓ ";
            color: #28a745;
            font-weight: bold;
        }
        
        @media (max-width: 768px) {
            .hero h1 {
                font-size: 2rem;
            }
            
            .features {
                grid-template-columns: 1fr;
            }
            
            .navbar .container {
                flex-direction: column;
                gap: 1rem;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div>
                <a href="[% home_url %]" class="brand">🏭 CatalystApp</a>
            </div>
            <div>
                <a href="[% home_url %]">Home</a>
                <a href="[% api_url %]/info">API Info</a>
                <a href="[% health_url %]">Health</a>
            </div>
        </div>
    </nav>
    
    <main>
        [% content %]
    </main>
    
    <footer class="footer">
        <div class="container">
            <p>&copy; [% site.copyright %]. Built with Catalyst framework.</p>
        </div>
    </footer>
</body>
</html>`,

    'root/src/error.tt': `[% META title = 'Error' %]

<div class="error">
    <h1>Error</h1>
    <p>An error occurred while processing your request.</p>
    
    [% IF error %]
    <div class="error-message">
        <h3>Error Details:</h3>
        <pre>[% error %]</pre>
    </div>
    [% END %]
    
    <p><a href="[% c.uri_for('/') %]">Return to Home</a></p>
</div>`,

    'sql/catalyst_app.sql': `-- PostgreSQL schema for Catalyst application

-- Create database (run as superuser)
-- CREATE DATABASE catalyst_app;

-- Connect to the database
\\c catalyst_app;

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user' NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Create trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert sample data
INSERT INTO users (name, email, password, role) VALUES 
('Admin User', 'admin@example.com', '$2b$12$example.admin.hash', 'admin'),
('Regular User', 'user@example.com', '$2b$12$example.user.hash', 'user');

-- Grant permissions (adjust as needed)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO catalyst_app_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO catalyst_app_user;`,

    't/01app.t': `#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use Catalyst::Test 'CatalystApp';

ok( request('/')->is_success, 'Request should succeed' );
ok( request('/api/health')->is_success, 'Health check should succeed' );

done_testing();`,

    't/02controller_API.t': `#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Test::Deep;

use Catalyst::Test 'CatalystApp';
use JSON;

# Test health endpoint
{
    my $response = request('/api/health');
    ok($response->is_success, 'Health endpoint returns success');
    
    my $data = decode_json($response->content);
    is($data->{status}, 'ok', 'Health status is ok');
    ok($data->{timestamp}, 'Health response has timestamp');
    ok($data->{version}, 'Health response has version');
}

# Test info endpoint
{
    my $response = request('/api/info');
    ok($response->is_success, 'Info endpoint returns success');
    
    my $data = decode_json($response->content);
    is($data->{name}, 'CatalystApp', 'Info has correct app name');
    ok($data->{version}, 'Info has version');
    ok($data->{features}, 'Info has features');
    ok($data->{endpoints}, 'Info has endpoints');
}

# Test 404 handling
{
    my $response = request('/api/nonexistent');
    is($response->code, 404, 'Non-existent API endpoint returns 404');
}

done_testing();`,

    't/03controller_API_Auth.t': `#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Test::Deep;

use Catalyst::Test 'CatalystApp';
use HTTP::Request::Common;
use JSON;

# Test user registration
{
    my $user_data = {
        name => 'Test User',
        email => 'test@example.com',
        password => 'password123'
    };
    
    my $response = request(POST '/api/auth/register',
        'Content-Type' => 'application/json',
        Content => encode_json($user_data)
    );
    
    is($response->code, 201, 'User registration returns 201');
    
    my $data = decode_json($response->content);
    ok($data->{id}, 'Registration response has user ID');
    is($data->{name}, 'Test User', 'Registration response has correct name');
    is($data->{email}, 'test@example.com', 'Registration response has correct email');
}

# Test duplicate registration
{
    my $user_data = {
        name => 'Test User',
        email => 'test@example.com',
        password => 'password123'
    };
    
    my $response = request(POST '/api/auth/register',
        'Content-Type' => 'application/json',
        Content => encode_json($user_data)
    );
    
    is($response->code, 409, 'Duplicate registration returns 409');
}

# Test validation errors
{
    my $invalid_data = {
        name => '',
        email => 'invalid-email',
        password => '123'
    };
    
    my $response = request(POST '/api/auth/register',
        'Content-Type' => 'application/json',
        Content => encode_json($invalid_data)
    );
    
    is($response->code, 400, 'Invalid registration returns 400');
}

# Test user login
{
    my $login_data = {
        email => 'test@example.com',
        password => 'password123'
    };
    
    my $response = request(POST '/api/auth/login',
        'Content-Type' => 'application/json',
        Content => encode_json($login_data)
    );
    
    is($response->code, 200, 'User login returns 200');
    
    my $data = decode_json($response->content);
    ok($data->{token}, 'Login response has token');
    ok($data->{user}, 'Login response has user data');
}

# Test invalid login
{
    my $login_data = {
        email => 'test@example.com',
        password => 'wrongpassword'
    };
    
    my $response = request(POST '/api/auth/login',
        'Content-Type' => 'application/json',
        Content => encode_json($login_data)
    );
    
    is($response->code, 401, 'Invalid login returns 401');
}

done_testing();`,

    'README.md': `# Catalyst Web Application

An enterprise-grade MVC web application built with Catalyst framework, featuring comprehensive authentication, database abstraction, and extensive plugin ecosystem.

## Features

- **Enterprise MVC Framework**: Built with Catalyst for scalable web applications
- **Comprehensive Plugin System**: Extensive plugin ecosystem for all common tasks
- **Authentication & Authorization**: Role-based access control with session management
- **Database Abstraction**: DBIx::Class ORM with PostgreSQL support
- **Template Engine**: Template Toolkit for flexible view rendering
- **REST API**: Full REST API with JSON responses
- **Session Management**: Secure cookie-based session handling
- **Form Handling**: HTML::FormHandler integration
- **Testing Framework**: Comprehensive test suite with Test::WWW::Mechanize
- **Development Tools**: Built-in development server and debugging tools

## Quick Start

\`\`\`bash
# Install dependencies
cpanm --installdeps .

# Set up database
createdb catalyst_app
psql catalyst_app < sql/catalyst_app.sql

# Run the application
perl script/catalyst_app_server.pl

# Or in development mode with auto-restart
perl script/catalyst_app_server.pl -r
\`\`\`

The application will be available at:
- Web Interface: http://localhost:3000
- API Health: http://localhost:3000/api/health
- API Info: http://localhost:3000/api/info

## API Endpoints

### Authentication
- \`POST /api/auth/register\` - User registration
- \`POST /api/auth/login\` - User login
- \`POST /api/auth/logout\` - User logout
- \`GET /api/auth/profile\` - Get current user profile

### Users
- \`GET /api/users\` - Get all users (authenticated)
- \`POST /api/users\` - Create user (admin only)
- \`GET /api/users/:id\` - Get user by ID (authenticated)
- \`PUT /api/users/:id\` - Update user (authenticated)
- \`DELETE /api/users/:id\` - Delete user (admin only)

### System
- \`GET /api/health\` - Health check endpoint
- \`GET /api/info\` - Application information

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
  -H "Content-Type: application/json" \\
  -b "catalyst_app_session=YOUR_SESSION_COOKIE"
\`\`\`

## Architecture

### MVC Structure

- **Models**: Database interaction using DBIx::Class ORM
- **Views**: Template Toolkit templates with flexible layouts
- **Controllers**: Request handling and business logic

### Plugin System

The application uses several Catalyst plugins:

- **ConfigLoader**: Configuration management
- **Session**: Session handling with cookie storage
- **Authentication**: User authentication and authorization
- **Static::Simple**: Static file serving
- **StatusMessage**: Flash message handling
- **StackTrace**: Error debugging
- **Unicode::Encoding**: UTF-8 encoding support

### Database Schema

- **Users**: User accounts with roles and authentication
- **Sessions**: Session storage and management
- **Roles**: Role-based permissions (user, admin)

## Development

### Creating Components

\`\`\`bash
# Create a new controller
perl script/catalyst_app_create.pl controller MyController

# Create a new model
perl script/catalyst_app_create.pl model MyModel

# Create a new view
perl script/catalyst_app_create.pl view MyView TT
\`\`\`

### Running Tests

\`\`\`bash
# Run all tests
prove -l t/

# Run specific test file
prove -l t/01app.t

# Run with verbose output
prove -lv t/
\`\`\`

### Development Server

\`\`\`bash
# Start development server
perl script/catalyst_app_server.pl

# Start with auto-restart
perl script/catalyst_app_server.pl -r

# Start with specific port
perl script/catalyst_app_server.pl -p 8080

# Start with debugging
perl script/catalyst_app_server.pl -d
\`\`\`

## Configuration

### Database Configuration

Edit \`catalyst_app.conf\`:

\`\`\`
<Model::DB>
    <connect_info>
        dsn dbi:Pg:dbname=catalyst_app;host=localhost
        user postgres
        password postgres
        pg_enable_utf8 1
    </connect_info>
</Model::DB>
\`\`\`

### Session Configuration

\`\`\`
<Plugin::Session>
    flash_to_stash 1
    expires 3600
</Plugin::Session>
\`\`\`

### Authentication Configuration

\`\`\`
<Plugin::Authentication>
    default_realm users
    <realms>
        <users>
            <credential>
                class Password
                password_field password
                password_type self_check
            </credential>
            <store>
                class DBIx::Class
                user_model DB::User
            </store>
        </users>
    </realms>
</Plugin::Authentication>
\`\`\`

## Database Setup

### PostgreSQL Setup

\`\`\`bash
# Create database
createdb catalyst_app

# Run schema
psql catalyst_app < sql/catalyst_app.sql

# Or create schema manually
psql catalyst_app -c "CREATE TABLE users (...);"
\`\`\`

### Schema Management

The application uses DBIx::Class for database operations:

\`\`\`perl
# Generate schema from database
perl script/catalyst_app_create.pl model DB DBIC::Schema CatalystApp::Schema \\
  create=static dbi:Pg:dbname=catalyst_app postgres password
\`\`\`

## User Roles

### User
- Access own profile
- Update own information
- Basic API access

### Admin
- Full user management
- Create/update/delete users
- System administration

## Security Features

- **Password Hashing**: bcrypt with configurable cost
- **Session Security**: Secure cookie configuration
- **SQL Injection Prevention**: Parameterized queries via DBIx::Class
- **XSS Protection**: Template escaping by default
- **CSRF Protection**: Available via plugins
- **Role-based Access Control**: Granular permissions

## Production Deployment

### Using Starman

\`\`\`bash
# Install Starman
cpanm Starman

# Run with Starman
starman --port 3000 --workers 4 catalyst_app.psgi
\`\`\`

### Using nginx

\`\`\`nginx
upstream catalyst_app {
    server 127.0.0.1:3000;
}

server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://catalyst_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
\`\`\`

## Performance

- **Preloading**: Preload modules for better performance
- **Caching**: Template caching and session caching
- **Connection Pooling**: Database connection pooling
- **Static Assets**: Efficient static file serving
- **Compression**: gzip compression support

## Docker Support

\`\`\`bash
# Build image
docker build -t catalyst-app .

# Run container
docker run -p 3000:3000 catalyst-app

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
RUN chmod +x script/catalyst_app_server.pl

# Expose port
EXPOSE 3000

# Run the application
CMD ["perl", "script/catalyst_app_server.pl", "-h", "0.0.0.0", "-p", "3000"]`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - CATALYST_DEBUG=0
      - POSTGRES_HOST=postgres
      - POSTGRES_DB=catalyst_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    depends_on:
      - postgres
    volumes:
      - ./logs:/app/logs
  
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=catalyst_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./sql:/docker-entrypoint-initdb.d
    
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

# Catalyst specific
catalyst_app.conf.local
catalyst_app_local.conf
*.pid
*.log
logs/
session_data/
tmp/

# Application specific
.env
*_local.conf

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db`
  },

  dependencies: {
    'Catalyst::Runtime': '^5.90130',
    'DBIx::Class': '^0.082843',
    'DBD::Pg': '^3.16.0',
    'Template': '^3.101',
    'JSON': '^4.10',
    'Moose': '^2.2015',
    'DateTime': '^1.59',
    'Crypt::Bcrypt': '^0.011',
    'Email::Valid': '^1.202'
  },

  commands: {
    dev: 'perl script/catalyst_app_server.pl -r',
    build: 'perl -c lib/CatalystApp.pm',
    test: 'prove -l t/',
    lint: 'perlcritic lib/',
    format: 'perltidy -b lib/**/*.pm',
    clean: 'rm -rf cover_db/ nytprof*',
    'test:verbose': 'prove -lv t/',
    'test:coverage': 'cover -test -report html',
    'dev:debug': 'perl script/catalyst_app_server.pl -d -r',
    'dev:port': 'perl script/catalyst_app_server.pl -r -p 8080',
    'prod:start': 'starman --port 3000 --workers 4 catalyst_app.psgi',
    'schema:create': 'perl script/catalyst_app_create.pl model DB DBIC::Schema',
    'component:create': 'perl script/catalyst_app_create.pl',
    'docker:build': 'docker build -t catalyst-app .',
    'docker:run': 'docker run -p 3000:3000 catalyst-app',
    'docker:up': 'docker-compose up -d',
    'docker:down': 'docker-compose down'
  },

  ports: {
    dev: 3000,
    prod: 3000
  },

  examples: [
    {
      title: 'Controller Action',
      description: 'Define controller actions with REST support',
      code: `sub show : GET Args(1) {
  my ($self, $c, $id) = @_;
  my $user = $c->model('DB::User')->find($id);
  $self->status_ok($c, entity => $user);
}`
    },
    {
      title: 'Authentication Check',
      description: 'Protect routes with authentication',
      code: `unless ($c->user_exists) {
  return $self->status_unauthorized($c,
    message => 'Authentication required'
  );
}`
    },
    {
      title: 'Database Operations',
      description: 'Use DBIx::Class for database operations',
      code: `my $user = $c->model('DB::User')->create({
  name => $data->{name},
  email => $data->{email},
  password => $data->{password}
});`
    }
  ]
};