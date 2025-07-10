import { BackendTemplate } from '../types';

export const totaljsTemplate: BackendTemplate = {
  id: 'backend-totaljs',
  name: 'Total.js',
  displayName: 'Total.js',
  description: 'Full-featured framework with built-in CMS and real-time capabilities',
  language: 'javascript',
  framework: 'totaljs',
  version: '4.0.0',
  tags: ['cms', 'real-time', 'full-featured', 'nosql'],
  port: 8000,
  dependencies: {
    'total4': '^4.0.0'
  },
  features: ['cms', 'real-time', 'routing', 'nosql', 'websockets'],
  files: {
    'index.js': `require('total4');

// Main application configuration
MAIN('default', function() {
    // Application settings
    CONF.name = 'Total.js Application';
    CONF.version = '1.0.0';
    CONF.author = 'Your Name';
    CONF.secret = 'your-secret-key-' + GUID(10);
    
    // Server configuration
    CONF['allow-gzip'] = true;
    CONF['allow-websocket'] = true;
    CONF['allow-debug'] = true;
    CONF['allow-compile'] = true;
    
    // Database configuration
    CONF.database = '/databases/';
    CONF.directory_temp = '/tmp/';
    
    // Mail configuration
    CONF.mail_smtp = 'smtp.gmail.com';
    CONF.mail_smtp_options = {
        port: 465,
        secure: true,
        user: process.env.SMTP_USER,
        password: process.env.SMTP_PASSWORD
    };
    
    // Start HTTP server
    HTTP('release', { port: process.env.PORT || 8000 });
});
`,
    'controllers/default.js': `exports.install = function() {
    // Route definitions
    ROUTE('GET /', view_homepage);
    ROUTE('GET /api/', json_api_info);
    ROUTE('GET /api/users/', json_users_list);
    ROUTE('GET /api/users/{id}/', json_user_detail);
    ROUTE('POST /api/users/ *User --> @save', json_user_create);
    ROUTE('PUT /api/users/{id}/ *User --> @save', json_user_update);
    ROUTE('DELETE /api/users/{id}/', json_user_delete);
    
    // WebSocket routes
    ROUTE('SOCKET /live/', socket_homepage);
    ROUTE('SOCKET /chat/', socket_chat);
    
    // File routes
    FILE('/download/*.pdf', file_download);
    FILE('/images/*.jpg', image_resize);
    
    // CMS routes
    ROUTE('GET /cms/', view_cms);
    ROUTE('GET /cms/pages/', view_cms_pages);
    ROUTE('GET /cms/widgets/', view_cms_widgets);
};

// Homepage controller
function view_homepage() {
    var self = this;
    self.view('index', { 
        title: 'Total.js Application',
        user: self.user 
    });
}

// API endpoints
function json_api_info() {
    this.json({
        name: CONF.name,
        version: CONF.version,
        uptime: Math.floor(process.uptime() / 60) + ' minutes',
        memory: (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2) + ' MB'
    });
}

function json_users_list() {
    var self = this;
    
    // Query builder with pagination
    var builder = NOSQL('users').find();
    
    // Apply filters
    if (self.query.search)
        builder.search('name', self.query.search);
    
    if (self.query.role)
        builder.where('role', self.query.role);
    
    // Pagination
    builder.page(self.query.page || 1, 20);
    
    builder.callback(function(err, users, count) {
        self.json({
            items: users,
            count: count,
            page: self.query.page || 1,
            pages: Math.ceil(count / 20)
        });
    });
}

function json_user_detail(id) {
    var self = this;
    
    NOSQL('users').one().where('id', id).callback(function(err, user) {
        if (err || !user) {
            self.throw404();
            return;
        }
        
        self.json(user);
    });
}

function json_user_create() {
    var self = this;
    self.json({ success: true, id: UID() });
}

function json_user_update(id) {
    var self = this;
    self.json({ success: true, id: id });
}

function json_user_delete(id) {
    var self = this;
    
    NOSQL('users').remove().where('id', id).callback(function(err, count) {
        self.json({ 
            success: !err && count > 0,
            count: count 
        });
    });
}

// WebSocket controllers
function socket_homepage() {
    var self = this;
    
    self.on('open', function(client) {
        console.log('WebSocket connected:', client.id);
        client.send({ type: 'welcome', message: 'Connected to Total.js WebSocket' });
    });
    
    self.on('close', function(client) {
        console.log('WebSocket disconnected:', client.id);
    });
    
    self.on('message', function(client, message) {
        // Broadcast to all clients
        self.send({ type: 'broadcast', data: message, from: client.id });
    });
}

function socket_chat() {
    var self = this;
    var online = {};
    
    self.on('open', function(client) {
        online[client.id] = { id: client.id, name: 'Guest' + client.id.substring(0, 4) };
        self.send({ type: 'users', users: Object.values(online) });
    });
    
    self.on('close', function(client) {
        delete online[client.id];
        self.send({ type: 'users', users: Object.values(online) });
    });
    
    self.on('message', function(client, message) {
        if (message.type === 'name') {
            online[client.id].name = message.name;
            self.send({ type: 'users', users: Object.values(online) });
        } else if (message.type === 'chat') {
            self.send({ 
                type: 'message', 
                text: message.text,
                user: online[client.id],
                timestamp: new Date()
            });
        }
    });
}

// File controllers
function file_download(req, res) {
    var filename = req.split[1];
    var filepath = PATH.public('downloads/' + filename);
    
    PATH.exists(filepath, function(exists) {
        if (!exists) {
            res.throw404();
            return;
        }
        
        res.file(filepath);
    });
}

function image_resize(req, res) {
    var filename = req.split[1];
    var image = PATH.public('images/' + filename);
    
    // Automatic image resizing
    res.image(image, function(image) {
        image.resize('200x200');
        image.quality(85);
    });
}

// CMS controllers
function view_cms() {
    this.view('@cms/index');
}

function view_cms_pages() {
    var self = this;
    
    NOSQL('pages').find().callback(function(err, pages) {
        self.view('@cms/pages', { pages: pages });
    });
}

function view_cms_widgets() {
    var self = this;
    
    NOSQL('widgets').find().callback(function(err, widgets) {
        self.view('@cms/widgets', { widgets: widgets });
    });
}
`,
    'schemas/user.js': `NEWSCHEMA('User', function(schema) {
    
    // Schema definition
    schema.define('id', 'UID');
    schema.define('name', 'String(50)', true);
    schema.define('email', 'Email', true);
    schema.define('password', 'String(100)', true);
    schema.define('role', ['admin', 'user', 'guest'], true);
    schema.define('active', Boolean, true);
    schema.define('created', Date);
    schema.define('updated', Date);
    schema.define('profile', Object);
    
    // Validations
    schema.required('name', i => i.name && i.name.length > 2);
    schema.required('email', i => i.email && i.email.isEmail());
    
    // Setters
    schema.setSave(function($, model) {
        var user = $.clean();
        
        // New user
        if (!user.id) {
            user.id = UID();
            user.created = NOW;
            user.password = user.password.sha256(CONF.secret);
            
            // Check if email exists
            NOSQL('users').one().where('email', user.email).callback(function(err, exists) {
                if (exists) {
                    $.invalid('email', 'Email already exists');
                    return;
                }
                
                NOSQL('users').insert(user).callback(function() {
                    $.success(user.id);
                });
            });
        } else {
            // Update user
            user.updated = NOW;
            
            if (user.password)
                user.password = user.password.sha256(CONF.secret);
            else
                delete user.password;
            
            NOSQL('users').modify(user).where('id', user.id).callback(function(err, count) {
                if (count)
                    $.success(user.id);
                else
                    $.invalid('error', 'User not found');
            });
        }
    });
    
    // Getters
    schema.setGet(function($) {
        var opt = $.options;
        var filter = $.query || $.options;
        
        NOSQL('users').one().where('id', filter.id).callback(function(err, user) {
            if (user) {
                delete user.password;
                $.callback(user);
            } else {
                $.invalid('error', 'User not found');
            }
        });
    });
    
    // Actions
    schema.addWorkflow('login', function($, model) {
        var user = model.$clean();
        
        NOSQL('users').one()
            .where('email', user.email)
            .where('password', user.password.sha256(CONF.secret))
            .where('active', true)
            .callback(function(err, found) {
                if (found) {
                    delete found.password;
                    $.success(found);
                } else {
                    $.invalid('error', 'Invalid credentials');
                }
            });
    });
    
    schema.addWorkflow('register', function($, model) {
        model.active = true;
        model.role = 'user';
        schema.setSave($, model);
    });
    
    schema.addWorkflow('forgot', function($, model) {
        var email = model.email;
        
        NOSQL('users').one().where('email', email).callback(function(err, user) {
            if (!user) {
                $.invalid('email', 'Email not found');
                return;
            }
            
            var token = GUID(30);
            
            // Save reset token
            NOSQL('tokens').insert({
                id: token,
                user: user.id,
                type: 'reset',
                created: NOW,
                expires: NOW.add('1 hour')
            });
            
            // Send email
            MAIL(email, 'Password Reset', '@password-reset', {
                name: user.name,
                token: token,
                url: 'http://localhost:8000/reset/' + token
            }, $.done());
        });
    });
});
`,
    'models/cms.js': `// CMS Page model
NEWSCHEMA('Page', function(schema) {
    
    schema.define('id', 'UID');
    schema.define('title', 'String(100)', true);
    schema.define('slug', 'String(100)', true);
    schema.define('content', 'String');
    schema.define('meta_title', 'String(100)');
    schema.define('meta_description', 'String(200)');
    schema.define('template', 'String(50)');
    schema.define('parent', 'UID');
    schema.define('order', Number);
    schema.define('published', Boolean);
    schema.define('created', Date);
    schema.define('updated', Date);
    schema.define('author', 'UID');
    
    schema.setSave(function($, model) {
        var page = $.clean();
        
        if (!page.id) {
            page.id = UID();
            page.created = NOW;
            page.slug = page.title.slug();
        } else {
            page.updated = NOW;
        }
        
        // Generate slug if empty
        if (!page.slug)
            page.slug = page.title.slug();
        
        NOSQL('pages').save(page).where('id', page.id).callback($.done());
    });
    
    schema.setRemove(function($) {
        NOSQL('pages').remove().where('id', $.id).callback($.done());
    });
    
    schema.setQuery(function($) {
        var builder = NOSQL('pages').find();
        
        if ($.options.published)
            builder.where('published', true);
        
        if ($.options.parent)
            builder.where('parent', $.options.parent);
        
        builder.sort('order', true);
        builder.callback($.callback);
    });
});

// CMS Widget model
NEWSCHEMA('Widget', function(schema) {
    
    schema.define('id', 'UID');
    schema.define('name', 'String(50)', true);
    schema.define('type', ['html', 'menu', 'form', 'gallery'], true);
    schema.define('content', 'String');
    schema.define('config', Object);
    schema.define('active', Boolean);
    schema.define('created', Date);
    schema.define('updated', Date);
    
    schema.setSave(function($, model) {
        var widget = $.clean();
        
        if (!widget.id) {
            widget.id = UID();
            widget.created = NOW;
        } else {
            widget.updated = NOW;
        }
        
        NOSQL('widgets').save(widget).where('id', widget.id).callback($.done());
    });
    
    schema.setRemove(function($) {
        NOSQL('widgets').remove().where('id', $.id).callback($.done());
    });
    
    schema.setQuery(function($) {
        var builder = NOSQL('widgets').find();
        
        if ($.options.active)
            builder.where('active', true);
        
        if ($.options.type)
            builder.where('type', $.options.type);
        
        builder.callback($.callback);
    });
});

// CMS Media model
NEWSCHEMA('Media', function(schema) {
    
    schema.define('id', 'UID');
    schema.define('name', 'String(100)', true);
    schema.define('filename', 'String(200)', true);
    schema.define('type', 'String(50)');
    schema.define('size', Number);
    schema.define('width', Number);
    schema.define('height', Number);
    schema.define('folder', 'String(100)');
    schema.define('tags', '[String]');
    schema.define('created', Date);
    schema.define('author', 'UID');
    
    schema.setSave(function($, model) {
        var media = $.clean();
        
        if (!media.id) {
            media.id = UID();
            media.created = NOW;
        }
        
        NOSQL('media').save(media).where('id', media.id).callback($.done());
    });
    
    schema.setRemove(function($) {
        var id = $.id;
        
        NOSQL('media').one().where('id', id).callback(function(err, media) {
            if (!media) {
                $.invalid('error', 'Media not found');
                return;
            }
            
            // Delete physical file
            var filepath = PATH.public('uploads/' + media.filename);
            Fs.unlink(filepath, NOOP);
            
            // Delete from database
            NOSQL('media').remove().where('id', id).callback($.done());
        });
    });
});
`,
    'definitions/auth.js': `// Authentication and authorization definitions

// Middleware for authentication
MIDDLEWARE('auth', function(req, res, next, options) {
    var token = req.headers['x-token'] || req.query.token;
    
    if (!token) {
        res.throw401();
        return;
    }
    
    // Verify token
    NOSQL('sessions').one()
        .where('token', token)
        .where('expires', '>', NOW)
        .callback(function(err, session) {
            if (!session) {
                res.throw401();
                return;
            }
            
            // Load user
            NOSQL('users').one().where('id', session.user).callback(function(err, user) {
                if (!user || !user.active) {
                    res.throw401();
                    return;
                }
                
                req.user = user;
                
                // Check role if specified
                if (options && options.role && user.role !== options.role) {
                    res.throw403();
                    return;
                }
                
                next();
            });
        });
});

// Authorize decorator
F.decorator('authorize', function(role) {
    var self = this;
    return function(req, res, next) {
        if (!req.user) {
            res.throw401();
            return;
        }
        
        if (role && req.user.role !== role) {
            res.throw403();
            return;
        }
        
        self.call(req, res, next);
    };
});

// Login operation
OPERATION('auth.login', function($, model) {
    EXEC('+User --> login', model, function(err, user) {
        if (err) {
            $.invalid(err);
            return;
        }
        
        // Create session
        var session = {
            id: UID(),
            token: GUID(40),
            user: user.id,
            created: NOW,
            expires: NOW.add('7 days')
        };
        
        NOSQL('sessions').insert(session);
        
        $.success({
            token: session.token,
            user: user
        });
    });
});

// Logout operation
OPERATION('auth.logout', function($) {
    var token = $.headers['x-token'] || $.query.token;
    
    if (token) {
        NOSQL('sessions').remove().where('token', token).callback(NOOP);
    }
    
    $.success();
});

// Password reset operation
OPERATION('auth.reset', function($, model) {
    var token = model.token;
    var password = model.password;
    
    NOSQL('tokens').one()
        .where('id', token)
        .where('type', 'reset')
        .where('expires', '>', NOW)
        .callback(function(err, reset) {
            if (!reset) {
                $.invalid('token', 'Invalid or expired token');
                return;
            }
            
            // Update password
            NOSQL('users').modify({
                password: password.sha256(CONF.secret),
                updated: NOW
            }).where('id', reset.user).callback(function(err, count) {
                if (count) {
                    // Delete used token
                    NOSQL('tokens').remove().where('id', token).callback(NOOP);
                    $.success();
                } else {
                    $.invalid('error', 'User not found');
                }
            });
        });
});
`,
    'definitions/helpers.js': `// Global helper functions

// Localization helper
F.helpers.translate = function(key, lang) {
    return TRANSLATE(lang || this.language, key);
};

// Date formatting helper
F.helpers.dateformat = function(date, format) {
    return date ? date.format(format || 'yyyy-MM-dd') : '';
};

// Number formatting helper
F.helpers.number = function(num, decimals) {
    return num ? num.format(decimals || 0) : '0';
};

// Currency helper
F.helpers.currency = function(amount, currency) {
    currency = currency || CONF.currency || 'USD';
    return currency + ' ' + (amount || 0).format(2);
};

// Truncate text helper
F.helpers.truncate = function(text, length, suffix) {
    if (!text) return '';
    length = length || 100;
    suffix = suffix || '...';
    return text.length > length ? text.substring(0, length) + suffix : text;
};

// URL slug helper
F.helpers.slug = function(text) {
    return text ? text.slug() : '';
};

// Gravatar helper
F.helpers.gravatar = function(email, size) {
    size = size || 80;
    var hash = email ? email.md5() : '';
    return 'https://www.gravatar.com/avatar/' + hash + '?s=' + size + '&d=mm';
};

// Active menu helper
F.helpers.active = function(path, className) {
    className = className || 'active';
    return this.url === path ? className : '';
};

// CSRF token helper
F.helpers.csrf = function() {
    return '<input type="hidden" name="csrf" value="' + this.csrf + '" />';
};

// JSON helper for templates
F.helpers.json = function(obj, spaces) {
    return JSON.stringify(obj, null, spaces || 0);
};

// Pagination helper
F.helpers.pagination = function(count, page, limit, max) {
    page = page || 1;
    limit = limit || 20;
    max = max || 5;
    
    var pages = Math.ceil(count / limit);
    var half = Math.floor(max / 2);
    var first = Math.max(1, page - half);
    var last = Math.min(pages, first + max - 1);
    
    if (last - first < max)
        first = Math.max(1, last - max + 1);
    
    var builder = [];
    
    if (page > 1)
        builder.push({ page: page - 1, text: 'Previous', active: false });
    
    for (var i = first; i <= last; i++)
        builder.push({ page: i, text: i, active: i === page });
    
    if (page < pages)
        builder.push({ page: page + 1, text: 'Next', active: false });
    
    return builder;
};

// File size helper
F.helpers.filesize = function(bytes) {
    if (!bytes) return '0 B';
    
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    
    while (bytes >= 1024 && i < units.length - 1) {
        bytes /= 1024;
        i++;
    }
    
    return bytes.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
};

// Time ago helper
F.helpers.timeago = function(date) {
    if (!date) return '';
    
    var diff = Date.now() - date.getTime();
    var seconds = Math.floor(diff / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' minutes ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
    if (seconds < 604800) return Math.floor(seconds / 86400) + ' days ago';
    
    return date.format('yyyy-MM-dd');
};
`,
    'views/index.html': `@{layout('layout')}

<div class="hero">
    <h1>Welcome to @{config.name}</h1>
    <p>Full-featured Node.js framework with built-in CMS and real-time capabilities</p>
    
    <div class="features">
        <div class="feature">
            <h3>🚀 MVC Architecture</h3>
            <p>Clean and organized code structure with automatic routing</p>
        </div>
        
        <div class="feature">
            <h3>📦 NoSQL Database</h3>
            <p>Built-in database with powerful query builder</p>
        </div>
        
        <div class="feature">
            <h3>🔌 Real-time WebSockets</h3>
            <p>Built-in support for real-time communication</p>
        </div>
        
        <div class="feature">
            <h3>📝 Content Management</h3>
            <p>Integrated CMS with pages, widgets, and media</p>
        </div>
    </div>
</div>

<div class="demo">
    <h2>Live Demo</h2>
    
    <div class="websocket-demo">
        <h3>WebSocket Connection</h3>
        <div id="status">Disconnected</div>
        <button onclick="connect()">Connect</button>
        <button onclick="disconnect()">Disconnect</button>
        
        <div class="messages" id="messages"></div>
        
        <form onsubmit="sendMessage(event)">
            <input type="text" id="message" placeholder="Type a message..." />
            <button type="submit">Send</button>
        </form>
    </div>
</div>

<script>
var ws = null;

function connect() {
    ws = new WebSocket('ws://' + window.location.host + '/live/');
    
    ws.onopen = function() {
        document.getElementById('status').textContent = 'Connected';
        addMessage('System', 'Connected to server');
    };
    
    ws.onclose = function() {
        document.getElementById('status').textContent = 'Disconnected';
        addMessage('System', 'Disconnected from server');
    };
    
    ws.onmessage = function(event) {
        var data = JSON.parse(event.data);
        
        if (data.type === 'welcome') {
            addMessage('Server', data.message);
        } else if (data.type === 'broadcast') {
            addMessage('User ' + data.from.substring(0, 8), data.data);
        }
    };
}

function disconnect() {
    if (ws) {
        ws.close();
        ws = null;
    }
}

function sendMessage(event) {
    event.preventDefault();
    
    var input = document.getElementById('message');
    var message = input.value.trim();
    
    if (message && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(message);
        addMessage('You', message);
        input.value = '';
    }
}

function addMessage(from, text) {
    var messages = document.getElementById('messages');
    var message = document.createElement('div');
    message.innerHTML = '<strong>' + from + ':</strong> ' + text;
    messages.appendChild(message);
    messages.scrollTop = messages.scrollHeight;
}
</script>

<style>
.hero {
    text-align: center;
    padding: 4rem 0;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 2rem;
    margin-top: 3rem;
    padding: 0 2rem;
}

.feature {
    background: rgba(255, 255, 255, 0.1);
    padding: 2rem;
    border-radius: 8px;
}

.demo {
    padding: 4rem 2rem;
    max-width: 800px;
    margin: 0 auto;
}

.websocket-demo {
    background: #f5f5f5;
    padding: 2rem;
    border-radius: 8px;
}

#status {
    display: inline-block;
    padding: 0.5rem 1rem;
    margin: 1rem 0;
    background: #e0e0e0;
    border-radius: 4px;
}

.messages {
    height: 300px;
    overflow-y: auto;
    background: white;
    border: 1px solid #ddd;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 4px;
}

.messages div {
    margin-bottom: 0.5rem;
}

form {
    display: flex;
    gap: 0.5rem;
}

input[type="text"] {
    flex: 1;
    padding: 0.5rem;
    border: 1px solid #ddd;
    border-radius: 4px;
}

button {
    padding: 0.5rem 1rem;
    background: #667eea;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

button:hover {
    background: #5a67d8;
}
</style>
`,
    'views/layout.html': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>@{title || config.name}</title>
    <meta name="description" content="@{description || 'Total.js Application'}" />
    
    @{import('meta', 'head', 'favicon.ico', 'css')}
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
        }
        
        header {
            background: #333;
            color: white;
            padding: 1rem 2rem;
        }
        
        nav {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        nav a {
            color: white;
            text-decoration: none;
            margin-left: 2rem;
        }
        
        nav a:hover {
            text-decoration: underline;
        }
        
        main {
            min-height: calc(100vh - 140px);
        }
        
        footer {
            background: #f5f5f5;
            padding: 2rem;
            text-align: center;
            color: #666;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
        }
    </style>
</head>
<body>
    <header>
        <nav>
            <div>
                <strong>@{config.name}</strong>
            </div>
            <div>
                <a href="/">Home</a>
                <a href="/api/">API</a>
                <a href="/cms/">CMS</a>
                @{if user}
                    <a href="/profile/">@{user.name}</a>
                    <a href="/logout/">Logout</a>
                @{else}
                    <a href="/login/">Login</a>
                @{fi}
            </div>
        </nav>
    </header>
    
    <main>
        @{body}
    </main>
    
    <footer>
        <p>&copy; @{NOW.getFullYear()} @{config.name} - Powered by Total.js v@{F.version}</p>
    </footer>
    
    @{import('script')}
</body>
</html>
`,
    'views/cms/index.html': `@{layout('layout')}

<div class="container cms">
    <h1>Content Management System</h1>
    
    <div class="cms-menu">
        <a href="/cms/pages/" class="cms-item">
            <h3>📄 Pages</h3>
            <p>Manage website pages and content</p>
        </a>
        
        <a href="/cms/widgets/" class="cms-item">
            <h3>🧩 Widgets</h3>
            <p>Create and manage content widgets</p>
        </a>
        
        <a href="/cms/media/" class="cms-item">
            <h3>🖼️ Media</h3>
            <p>Upload and organize media files</p>
        </a>
        
        <a href="/cms/users/" class="cms-item">
            <h3>👥 Users</h3>
            <p>Manage users and permissions</p>
        </a>
        
        <a href="/cms/settings/" class="cms-item">
            <h3>⚙️ Settings</h3>
            <p>Configure system settings</p>
        </a>
        
        <a href="/cms/analytics/" class="cms-item">
            <h3>📊 Analytics</h3>
            <p>View site statistics and reports</p>
        </a>
    </div>
</div>

<style>
.cms {
    padding: 3rem 0;
}

.cms h1 {
    margin-bottom: 2rem;
}

.cms-menu {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 2rem;
}

.cms-item {
    background: #f8f9fa;
    padding: 2rem;
    border-radius: 8px;
    text-decoration: none;
    color: inherit;
    transition: transform 0.2s, box-shadow 0.2s;
    border: 1px solid #e9ecef;
}

.cms-item:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.cms-item h3 {
    margin-bottom: 0.5rem;
    color: #333;
}

.cms-item p {
    color: #666;
    font-size: 0.95rem;
}
</style>
`,
    'tests/test.js': `// Total.js testing framework

// Load testing module
require('total4/test');

// Test user registration
TEST('user.register', function() {
    var self = this;
    
    RESTBuilder.POST('/api/users/', {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123'
    }).exec(function(err, response) {
        self.ok(response.success === true, 'User should be created');
        self.ok(response.id, 'Should return user ID');
        self.done();
    });
});

// Test user login
TEST('user.login', function() {
    var self = this;
    
    RESTBuilder.POST('/api/auth/login/', {
        email: 'test@example.com',
        password: 'password123'
    }).exec(function(err, response) {
        self.ok(!err, 'Should not have error');
        self.ok(response.token, 'Should return auth token');
        self.ok(response.user, 'Should return user data');
        self.done();
    });
});

// Test API endpoints
TEST('api.info', function() {
    var self = this;
    
    RESTBuilder.GET('/api/').exec(function(err, response) {
        self.ok(!err, 'Should not have error');
        self.ok(response.name, 'Should have app name');
        self.ok(response.version, 'Should have version');
        self.done();
    });
});

// Test WebSocket connection
TEST('websocket.connect', function() {
    var self = this;
    
    WEBSOCKET('ws://localhost:8000/live/', function(client) {
        
        client.on('open', function() {
            self.ok(true, 'WebSocket should connect');
        });
        
        client.on('message', function(message) {
            self.ok(message.type === 'welcome', 'Should receive welcome message');
            client.close();
            self.done();
        });
        
        client.on('error', function(err) {
            self.ok(false, 'WebSocket error: ' + err);
            self.done();
        });
    });
});

// Test schema validation
TEST('schema.validation', function() {
    var self = this;
    
    EXEC('+User --> validate', {
        name: 'A', // Too short
        email: 'invalid-email',
        password: '123'
    }, function(err) {
        self.ok(err !== null, 'Should have validation errors');
        self.ok(err.items.length > 0, 'Should have error items');
        self.done();
    });
});

// Test NOSQL operations
TEST('nosql.operations', function() {
    var self = this;
    var id = UID();
    
    // Insert
    NOSQL('test').insert({ id: id, name: 'Test' }).callback(function(err) {
        self.ok(!err, 'Should insert without error');
        
        // Find
        NOSQL('test').find().callback(function(err, items) {
            self.ok(!err, 'Should find without error');
            self.ok(items.length > 0, 'Should have items');
            
            // Update
            NOSQL('test').modify({ name: 'Updated' }).where('id', id).callback(function(err, count) {
                self.ok(!err, 'Should update without error');
                self.ok(count > 0, 'Should update at least one item');
                
                // Remove
                NOSQL('test').remove().where('id', id).callback(function(err, count) {
                    self.ok(!err, 'Should remove without error');
                    self.ok(count > 0, 'Should remove at least one item');
                    self.done();
                });
            });
        });
    });
});

// Test localization
TEST('localization', function() {
    var self = this;
    
    self.ok(TRANSLATE('en', 'welcome'), 'Should have English translation');
    self.ok(TRANSLATE('es', 'welcome'), 'Should have Spanish translation');
    self.done();
});

// Test file operations
TEST('file.operations', function() {
    var self = this;
    var filename = 'test-' + UID() + '.txt';
    var filepath = PATH.temp(filename);
    
    // Write file
    Fs.writeFile(filepath, 'Test content', function(err) {
        self.ok(!err, 'Should write file');
        
        // Read file
        Fs.readFile(filepath, 'utf8', function(err, content) {
            self.ok(!err, 'Should read file');
            self.ok(content === 'Test content', 'Content should match');
            
            // Delete file
            Fs.unlink(filepath, function(err) {
                self.ok(!err, 'Should delete file');
                self.done();
            });
        });
    });
});

// Run all tests
setTimeout(function() {
    // Give server time to start
    RUN();
}, 2000);
`,
    'package.json': `{
  "name": "totaljs-app",
  "version": "1.0.0",
  "description": "Total.js application with CMS and real-time features",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "node debug.js",
    "test": "node tests/test.js",
    "build": "total4 --minify --compile"
  },
  "dependencies": {
    "total4": "^4.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.0"
  },
  "engines": {
    "node": ">=14.0.0"
  }
}
`,
    'debug.js': `// Debug mode with auto-restart
require('total4/debug')({ 
    port: 8000,
    watch: true,
    cluster: false
});
`,
    'config': `# Total.js configuration file

name                : Total.js Application
version             : 1.0.0
author              : Your Name

# Server
default-ip          : 127.0.0.1
default-port        : 8000

# Security
secret              : your-secret-key-change-this
cookie-secret       : another-secret-key

# Database
database            : ./databases/

# Directories
directory-temp      : /tmp/
directory-public    : /public/
directory-logs      : /logs/
directory-resources : /resources/

# Localization
default-language    : en
languages           : en,es,fr,de

# Mail
mail-smtp           : smtp.gmail.com
mail-smtp-port      : 465
mail-smtp-secure    : true
mail-from           : noreply@yourdomain.com

# Performance
default-request-timeout  : 5000
default-interval-clear   : 60000
default-maximum-file     : 10485760

# Features
allow-gzip          : true
allow-websocket     : true
allow-performance   : false
allow-compile       : true
allow-compress-html : true
allow-compress-js   : true
allow-compress-css  : true

# CORS
cors                : *
cors-credentials    : true

# Custom settings
currency            : USD
items-per-page      : 20
`,
    'resources/en.resource': `// English translations

welcome             : Welcome
login               : Login
logout              : Logout
register            : Register
profile             : Profile
settings            : Settings
save                : Save
cancel              : Cancel
delete              : Delete
edit                : Edit
create              : Create
search              : Search
loading             : Loading...
error               : Error
success             : Success
confirm             : Are you sure?

// Forms
email               : Email
password            : Password
name                : Name
username            : Username
remember_me         : Remember me
forgot_password     : Forgot password?

// Messages
login_success       : Successfully logged in
logout_success      : Successfully logged out
save_success        : Successfully saved
delete_success      : Successfully deleted
error_generic       : An error occurred
error_not_found     : Not found
error_unauthorized  : Unauthorized
error_forbidden     : Forbidden

// CMS
pages               : Pages
widgets             : Widgets
media               : Media
users               : Users
analytics           : Analytics
dashboard           : Dashboard
content             : Content
`,
    'Dockerfile': `FROM node:18-alpine

# Install dependencies for Total.js
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    cairo-dev \
    jpeg-dev \
    pango-dev \
    giflib-dev

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Create required directories
RUN mkdir -p /app/tmp /app/logs /app/databases /app/public/uploads

# Set permissions
RUN chmod -R 755 /app

# Expose port
EXPOSE 8000

# Set environment
ENV NODE_ENV=production

# Start application
CMD ["node", "index.js"]
`,
    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    container_name: totaljs-app
    ports:
      - "8000:8000"
    environment:
      - NODE_ENV=production
      - PORT=8000
      - DATABASE_PATH=/data/databases
      - TEMP_PATH=/data/tmp
      - SMTP_USER=\${SMTP_USER}
      - SMTP_PASSWORD=\${SMTP_PASSWORD}
    volumes:
      - ./data:/data
      - ./public/uploads:/app/public/uploads
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Optional: Add Redis for caching
  redis:
    image: redis:7-alpine
    container_name: totaljs-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  # Optional: Add PostgreSQL for relational data
  postgres:
    image: postgres:15-alpine
    container_name: totaljs-postgres
    environment:
      - POSTGRES_DB=totaljs
      - POSTGRES_USER=totaljs
      - POSTGRES_PASSWORD=\${DB_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  redis_data:
  postgres_data:
`,
    '.env.example': `# Environment Variables

# Application
NODE_ENV=development
PORT=8000
SECRET_KEY=your-secret-key-here

# Database
DB_PASSWORD=your-db-password

# SMTP
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-email-password

# External Services
GOOGLE_ANALYTICS_ID=
SENTRY_DSN=
STRIPE_API_KEY=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
`,
    'README.md': `# Total.js Application

A full-featured web application built with Total.js framework, including CMS and real-time capabilities.

## Features

- 🚀 **MVC Architecture** - Clean and organized code structure
- 📦 **Built-in NoSQL Database** - No external database required
- 🔌 **Real-time WebSockets** - Built-in support for real-time features
- 📝 **Content Management System** - Integrated CMS with pages and widgets
- 🔐 **Authentication & Authorization** - Complete auth system
- 📧 **Email System** - Built-in mail sending with templates
- 🌍 **Internationalization** - Multi-language support
- 🧪 **Testing Framework** - Built-in testing tools
- 🐳 **Docker Ready** - Containerized deployment

## Quick Start

### Development

\`\`\`bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test
\`\`\`

### Production

\`\`\`bash
# Build and minify
npm run build

# Start production server
npm start
\`\`\`

### Docker

\`\`\`bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f app
\`\`\`

## Project Structure

\`\`\`
├── controllers/     # Route controllers
├── definitions/     # Global definitions and middleware
├── models/         # Data models and schemas
├── schemas/        # Business logic schemas
├── views/          # HTML templates
├── public/         # Static files
├── resources/      # Translations and resources
├── databases/      # NoSQL database files
├── tests/          # Test files
└── tmp/           # Temporary files
\`\`\`

## Configuration

Edit the \`config\` file to customize your application:

- Server settings (port, IP, timeouts)
- Security (secret keys, CORS)
- Features (gzip, websocket, minification)
- Mail settings (SMTP configuration)
- Localization (languages, translations)

## API Documentation

### Authentication
- \`POST /api/auth/login\` - User login
- \`POST /api/auth/logout\` - User logout
- \`POST /api/auth/register\` - User registration
- \`POST /api/auth/forgot\` - Password reset

### Users
- \`GET /api/users\` - List users
- \`GET /api/users/{id}\` - Get user details
- \`POST /api/users\` - Create user
- \`PUT /api/users/{id}\` - Update user
- \`DELETE /api/users/{id}\` - Delete user

### WebSocket
- \`ws://localhost:8000/live/\` - General WebSocket connection
- \`ws://localhost:8000/chat/\` - Chat room WebSocket

## CMS Usage

Access the CMS at \`/cms/\` with admin credentials.

### Features:
- **Pages** - Create and manage website pages
- **Widgets** - Reusable content blocks
- **Media** - Upload and manage files
- **Users** - User management
- **Settings** - System configuration
- **Analytics** - Site statistics

## Testing

Total.js includes a built-in testing framework:

\`\`\`javascript
TEST('test.name', function() {
    var self = this;
    // Your test code
    self.ok(condition, 'Test description');
    self.done();
});
\`\`\`

## Deployment

### Environment Variables
- \`NODE_ENV\` - Environment (development/production)
- \`PORT\` - Server port
- \`SECRET_KEY\` - Application secret
- \`SMTP_USER\` - Email username
- \`SMTP_PASSWORD\` - Email password

### Production Tips
1. Use process manager (PM2, systemd)
2. Enable SSL/TLS with reverse proxy
3. Set up regular backups
4. Monitor application health
5. Use environment variables for secrets

## Resources

- [Total.js Documentation](https://docs.totaljs.com)
- [Total.js Examples](https://github.com/totaljs/examples)
- [Total.js Community](https://community.totaljs.com)

## License

MIT
`
  }
};