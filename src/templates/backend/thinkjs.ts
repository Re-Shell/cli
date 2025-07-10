import { BackendTemplate } from '../types';

export const thinkjsTemplate: BackendTemplate = {
  id: 'thinkjs',
  name: 'ThinkJS',
  description: 'Modern Node.js MVC framework with ES6/ES7 support and auto-loading',
  icon: '🚀',
  framework: 'thinkjs',
  displayName: 'ThinkJS MVC Framework',
  language: 'javascript',
  version: '3.2.14',
  tags: ['mvc', 'es6', 'es7', 'auto-loading', 'orm', 'websocket', 'cron', 'typescript'],
  dependencies: {
    'think-cache': '^1.1.0',
    'think-cache-file': '^1.1.0',
    'think-cache-redis': '^1.1.0',
    'think-cache-memcache': '^1.0.2',
    'think-session': '^1.1.0',
    'think-session-file': '^1.0.1',
    'think-session-redis': '^1.0.0',
    'think-view': '^1.1.0',
    'think-view-nunjucks': '^1.0.7',
    'think-view-ejs': '^1.0.0',
    'think-model': '^1.5.0',
    'think-model-mysql': '^1.1.0',
    'think-model-postgresql': '^1.0.1',
    'think-model-sqlite': '^1.0.0',
    'think-websocket': '^1.0.3',
    'think-websocket-socket.io': '^1.0.1',
    'think-i18n': '^1.2.3',
    'think-validator': '^1.5.0',
    'thinkjs': '^3.2.14',
    'think-typescript': '^1.1.0',
    'ioredis': '^5.3.2',
    'jsonwebtoken': '^9.0.0',
    'bcryptjs': '^2.4.3',
    'moment': '^2.29.4',
    'axios': '^1.5.0',
    'winston': '^3.10.0',
    'winston-daily-rotate-file': '^4.7.1'
  },
  
  files: {
    'package.json': `{
  "name": "thinkjs-microservice",
  "description": "ThinkJS microservice with modern JavaScript features",
  "version": "1.0.0",
  "author": "",
  "scripts": {
    "start": "node development.js",
    "dev": "node development.js",
    "build": "npm run compile",
    "compile": "babel src/ --out-dir app/",
    "lint": "eslint src/",
    "lint-fix": "eslint --fix src/",
    "test": "THINK_UNIT_TEST=1 nyc mocha test/unit",
    "test-integration": "mocha test/integration",
    "coverage": "nyc report --reporter=html",
    "production": "node production.js",
    "docker": "docker-compose up -d"
  },
  "dependencies": {
    "think-cache": "^1.1.0",
    "think-cache-file": "^1.1.0",
    "think-cache-redis": "^1.1.0",
    "think-cache-memcache": "^1.0.2",
    "think-session": "^1.1.0",
    "think-session-file": "^1.0.1",
    "think-session-redis": "^1.0.0",
    "think-view": "^1.1.0",
    "think-view-nunjucks": "^1.0.7",
    "think-view-ejs": "^1.0.0",
    "think-model": "^1.5.0",
    "think-model-mysql": "^1.1.0",
    "think-model-postgresql": "^1.0.1",
    "think-model-sqlite": "^1.0.0",
    "think-websocket": "^1.0.3",
    "think-websocket-socket.io": "^1.0.1",
    "think-i18n": "^1.2.3",
    "think-validator": "^1.5.0",
    "thinkjs": "^3.2.14",
    "think-typescript": "^1.1.0",
    "ioredis": "^5.3.2",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3",
    "moment": "^2.29.4",
    "axios": "^1.5.0",
    "winston": "^3.10.0",
    "winston-daily-rotate-file": "^4.7.1"
  },
  "devDependencies": {
    "@babel/cli": "^7.22.10",
    "@babel/core": "^7.22.10",
    "@babel/preset-env": "^7.22.10",
    "@types/node": "^20.5.0",
    "eslint": "^8.47.0",
    "eslint-config-think": "^1.0.2",
    "mocha": "^10.2.0",
    "nyc": "^15.1.0",
    "supertest": "^6.3.3",
    "think-watcher": "^3.0.3",
    "typescript": "^5.1.6"
  },
  "engines": {
    "node": ">=14.0.0"
  },
  "readmeFilename": "README.md",
  "thinkjs": {
    "metadata": {
      "name": "thinkjs-microservice",
      "description": "ThinkJS microservice with modern JavaScript features",
      "author": "",
      "babel": true
    }
  }
}`,
    
    'development.js': `const Application = require('thinkjs');
const watcher = require('think-watcher');
const babel = require('@babel/core');
const path = require('path');

const instance = new Application({
  ROOT_PATH: __dirname,
  watcher: watcher,
  transpiler: [babel, {
    presets: [['@babel/preset-env', { modules: false }]]
  }],
  notifier: true,
  env: 'development'
});

instance.run();`,
    
    'production.js': `const Application = require('thinkjs');

const instance = new Application({
  ROOT_PATH: __dirname,
  proxy: true,
  env: 'production'
});

instance.run();`,
    
    'src/config/config.js': `module.exports = {
  // Service identification
  serviceName: 'thinkjs-microservice',
  serviceVersion: '1.0.0',
  
  // Server configuration
  port: parseInt(process.env.PORT) || 8360,
  host: '0.0.0.0',
  workers: 0, // 0 = number of CPUs
  
  // Security
  stickyCluster: true,
  enableCORS: true,
  
  // Logging
  logLevel: process.env.LOG_LEVEL || 'info',
  
  // API configuration
  apiPrefix: '/api/v1',
  apiVersion: 'v1',
  
  // Health check
  healthCheckPath: '/health',
  readinessPath: '/ready'
};`,
    
    'src/config/adapter.js': `const fileCache = require('think-cache-file');
const redisCache = require('think-cache-redis');
const memcacheCache = require('think-cache-memcache');
const nunjucks = require('think-view-nunjucks');
const ejs = require('think-view-ejs');
const fileSession = require('think-session-file');
const redisSession = require('think-session-redis');
const mysql = require('think-model-mysql');
const postgresql = require('think-model-postgresql');
const sqlite = require('think-model-sqlite');
const socketio = require('think-websocket-socket.io');
const path = require('path');

// Cache adapter configuration
exports.cache = {
  type: 'file',
  common: {
    timeout: 24 * 60 * 60 * 1000 // 24 hours
  },
  file: {
    handle: fileCache,
    cachePath: path.join(think.ROOT_PATH, 'runtime/cache')
  },
  redis: {
    handle: redisCache,
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD || '',
    db: process.env.REDIS_DB || 0
  },
  memcache: {
    handle: memcacheCache,
    hosts: process.env.MEMCACHE_HOSTS || '127.0.0.1:11211',
    maxKeySize: 1000000,
    poolSize: 10
  }
};

// Session adapter configuration
exports.session = {
  type: 'file',
  common: {
    cookie: {
      name: 'thinkjs',
      keys: ['werwer', 'werwrr'],
      signed: true,
      httponly: true,
      sameSite: 'strict'
    }
  },
  file: {
    handle: fileSession,
    sessionPath: path.join(think.ROOT_PATH, 'runtime/session')
  },
  redis: {
    handle: redisSession,
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD || '',
    db: process.env.REDIS_DB || 1
  }
};

// View adapter configuration
exports.view = {
  type: 'nunjucks',
  common: {
    viewPath: path.join(think.ROOT_PATH, 'view'),
    sep: '_',
    extname: '.html'
  },
  nunjucks: {
    handle: nunjucks,
    options: {
      autoescape: true,
      noCache: think.env === 'development',
      throwOnUndefined: false
    }
  },
  ejs: {
    handle: ejs,
    options: {
      cache: think.env !== 'development'
    }
  }
};

// Model adapter configuration
exports.model = {
  type: 'mysql',
  common: {
    logConnect: think.env === 'development',
    logSql: think.env === 'development',
    logger: msg => think.logger.info(msg)
  },
  mysql: {
    handle: mysql,
    database: process.env.DB_NAME || 'thinkjs',
    prefix: process.env.DB_PREFIX || 'tk_',
    encoding: 'utf8mb4',
    host: process.env.DB_HOST || '127.0.0.1',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    dateStrings: true,
    connectionLimit: 10,
    acquireTimeout: 60000
  },
  postgresql: {
    handle: postgresql,
    database: process.env.PG_DATABASE || 'thinkjs',
    user: process.env.PG_USER || 'postgres',
    password: process.env.PG_PASSWORD || '',
    host: process.env.PG_HOST || '127.0.0.1',
    port: process.env.PG_PORT || 5432,
    connectionLimit: 10
  },
  sqlite: {
    handle: sqlite,
    path: path.join(think.ROOT_PATH, 'runtime/sqlite'),
    database: 'thinkjs'
  }
};

// WebSocket adapter configuration
exports.websocket = {
  type: 'socketio',
  common: {
    // common config
  },
  socketio: {
    handle: socketio,
    allowOrigin: process.env.WEBSOCKET_ORIGINS || 'http://localhost:*',
    path: '/socket.io',
    adapter: null,
    messages: {
      open: 'home/websocket/open',
      addUser: 'home/websocket/addUser',
      typing: 'home/websocket/typing',
      chat: 'home/websocket/chat'
    }
  }
};`,
    
    'src/config/middleware.js': `const path = require('path');

module.exports = [
  {
    handle: 'meta',
    options: {
      logRequest: think.env === 'development',
      sendResponseTime: true,
      sendPoweredBy: false,
      requestTimeout: 30 * 1000 // 30 seconds
    }
  },
  {
    handle: 'resource',
    enable: true,
    options: {
      root: path.join(think.ROOT_PATH, 'www'),
      publicPath: /^\\/static/
    }
  },
  {
    handle: 'trace',
    enable: think.env === 'development',
    options: {
      debug: true,
      error(err) {
        think.logger.error(err);
      }
    }
  },
  {
    handle: 'payload',
    options: {
      keepExtensions: true,
      limit: '5mb',
      encoding: 'utf-8',
      multiples: true
    }
  },
  {
    handle: 'router',
    options: {
      suffix: ['.html'],
      enableDefaultRouter: true,
      optimizeHomepageRouter: true
    }
  },
  'logic',
  'controller'
];`,
    
    'src/config/router.js': `module.exports = [
  // RESTful API routes
  ['/api/v1/users', 'api/user', 'rest'],
  ['/api/v1/products', 'api/product', 'rest'],
  ['/api/v1/orders', 'api/order', 'rest'],
  
  // Custom routes
  ['/api/v1/auth/login', 'api/auth/login', 'post'],
  ['/api/v1/auth/logout', 'api/auth/logout', 'post'],
  ['/api/v1/auth/refresh', 'api/auth/refresh', 'post'],
  ['/api/v1/auth/verify', 'api/auth/verify', 'get'],
  
  // WebSocket routes
  ['/ws', 'websocket/index', 'websocket'],
  
  // Health check routes
  ['/health', 'common/health/check', 'get'],
  ['/ready', 'common/health/ready', 'get'],
  ['/metrics', 'common/metrics/index', 'get'],
  
  // File upload
  ['/api/v1/upload', 'api/upload/file', 'post'],
  ['/api/v1/upload/image', 'api/upload/image', 'post'],
  
  // Batch operations
  ['/api/v1/batch', 'api/batch/process', 'post'],
  
  // Search and filter
  ['/api/v1/search', 'api/search/query', 'get'],
  ['/api/v1/filter/:resource', 'api/filter/apply', 'post']
];`,
    
    'src/config/crontab.js': `module.exports = [
  {
    cron: '0 0 * * *', // Daily at midnight
    handle: 'cron/daily/cleanup',
    type: 'one' // Run on one worker only
  },
  {
    cron: '*/5 * * * *', // Every 5 minutes
    handle: 'cron/monitor/health',
    type: 'one'
  },
  {
    cron: '0 */1 * * *', // Every hour
    handle: 'cron/sync/data',
    type: 'one'
  },
  {
    cron: '0 2 * * 0', // Weekly on Sunday at 2 AM
    handle: 'cron/backup/database',
    type: 'one'
  },
  {
    cron: '*/30 * * * *', // Every 30 minutes
    handle: 'cron/cache/refresh',
    type: 'all' // Run on all workers
  },
  {
    interval: '10m', // Every 10 minutes using interval syntax
    handle: 'cron/analytics/aggregate',
    immediate: false,
    type: 'one'
  }
];`,
    
    'src/config/locale/en.js': `module.exports = {
  // Common messages
  WELCOME_MESSAGE: 'Welcome to ThinkJS Microservice',
  SUCCESS: 'Operation successful',
  ERROR: 'An error occurred',
  NOT_FOUND: 'Resource not found',
  UNAUTHORIZED: 'Unauthorized access',
  FORBIDDEN: 'Access forbidden',
  
  // Validation messages
  REQUIRED_FIELD: '{field} is required',
  INVALID_EMAIL: 'Invalid email address',
  INVALID_FORMAT: 'Invalid {field} format',
  MIN_LENGTH: '{field} must be at least {min} characters',
  MAX_LENGTH: '{field} must not exceed {max} characters',
  
  // Authentication
  LOGIN_SUCCESS: 'Login successful',
  LOGIN_FAILED: 'Invalid credentials',
  LOGOUT_SUCCESS: 'Logout successful',
  TOKEN_EXPIRED: 'Authentication token expired',
  TOKEN_INVALID: 'Invalid authentication token',
  
  // User messages
  USER_CREATED: 'User created successfully',
  USER_UPDATED: 'User updated successfully',
  USER_DELETED: 'User deleted successfully',
  USER_NOT_FOUND: 'User not found',
  EMAIL_EXISTS: 'Email already exists',
  
  // API messages
  RATE_LIMIT_EXCEEDED: 'Rate limit exceeded',
  INVALID_REQUEST: 'Invalid request parameters',
  SERVER_ERROR: 'Internal server error',
  SERVICE_UNAVAILABLE: 'Service temporarily unavailable'
};`,
    
    'src/controller/base.js': `module.exports = class extends think.Controller {
  async __before() {
    // Global before hook for all controllers
    this.startTime = Date.now();
    
    // Set common headers
    this.header('X-Service-Name', think.config('serviceName'));
    this.header('X-Service-Version', think.config('serviceVersion'));
    
    // Log request
    think.logger.info(\`\${this.method} \${this.ctx.url} - \${this.ip}\`);
  }
  
  async __after() {
    // Global after hook
    const duration = Date.now() - this.startTime;
    this.header('X-Response-Time', \`\${duration}ms\`);
    
    // Log response
    think.logger.info(\`Response sent in \${duration}ms - Status: \${this.ctx.status}\`);
  }
  
  /**
   * Success response helper
   */
  success(data = null, message = '') {
    return this.json({
      success: true,
      data,
      message: message || this.locale('SUCCESS'),
      timestamp: new Date().toISOString()
    });
  }
  
  /**
   * Error response helper
   */
  error(message = '', code = 400, data = null) {
    this.ctx.status = code;
    return this.json({
      success: false,
      error: {
        message: message || this.locale('ERROR'),
        code,
        data
      },
      timestamp: new Date().toISOString()
    });
  }
  
  /**
   * Paginated response helper
   */
  paginate(data, currentPage, pageSize, totalCount) {
    const totalPages = Math.ceil(totalCount / pageSize);
    
    return this.json({
      success: true,
      data,
      pagination: {
        currentPage,
        pageSize,
        totalCount,
        totalPages,
        hasNext: currentPage < totalPages,
        hasPrev: currentPage > 1
      },
      timestamp: new Date().toISOString()
    });
  }
  
  /**
   * Get validated pagination parameters
   */
  getPagination() {
    const page = Math.max(1, parseInt(this.get('page')) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(this.get('pageSize')) || 20));
    const offset = (page - 1) * pageSize;
    
    return { page, pageSize, offset };
  }
  
  /**
   * Check if request wants JSON response
   */
  isJsonRequest() {
    const accept = this.header('accept') || '';
    return accept.includes('application/json') || this.isAjax || this.isPost;
  }
};`,
    
    'src/controller/api/user.js': `const Base = require('../base.js');

module.exports = class extends Base {
  /**
   * RESTful GET - Get all users or single user
   */
  async getAction() {
    const id = this.id;
    
    if (id) {
      // Get single user
      const user = await this.model('user').where({ id }).find();
      
      if (think.isEmpty(user)) {
        return this.error(this.locale('USER_NOT_FOUND'), 404);
      }
      
      delete user.password; // Remove sensitive data
      return this.success(user);
    }
    
    // Get all users with pagination
    const { page, pageSize, offset } = this.getPagination();
    const where = this.buildWhereConditions();
    
    const [users, totalCount] = await Promise.all([
      this.model('user')
        .where(where)
        .field('id,username,email,role,status,created_at,updated_at')
        .limit(pageSize)
        .offset(offset)
        .order('created_at DESC')
        .select(),
      this.model('user').where(where).count()
    ]);
    
    return this.paginate(users, page, pageSize, totalCount);
  }
  
  /**
   * RESTful POST - Create new user
   */
  async postAction() {
    const data = this.post();
    
    // Validate input
    const validation = await this.validateUser(data);
    if (!validation.valid) {
      return this.error(validation.message, 400, validation.errors);
    }
    
    // Check if email exists
    const exists = await this.model('user').where({ email: data.email }).find();
    if (!think.isEmpty(exists)) {
      return this.error(this.locale('EMAIL_EXISTS'), 409);
    }
    
    // Hash password
    const bcrypt = require('bcryptjs');
    data.password = await bcrypt.hash(data.password, 10);
    
    // Create user
    data.created_at = new Date();
    data.updated_at = new Date();
    
    const userId = await this.model('user').add(data);
    const user = await this.model('user')
      .field('id,username,email,role,status,created_at')
      .where({ id: userId })
      .find();
    
    // Emit user created event
    think.messenger.broadcast('user:created', user);
    
    return this.success(user, this.locale('USER_CREATED'));
  }
  
  /**
   * RESTful PUT - Update user
   */
  async putAction() {
    const id = this.id;
    if (!id) {
      return this.error(this.locale('INVALID_REQUEST'), 400);
    }
    
    const data = this.post();
    delete data.id; // Prevent ID update
    
    // Check if user exists
    const user = await this.model('user').where({ id }).find();
    if (think.isEmpty(user)) {
      return this.error(this.locale('USER_NOT_FOUND'), 404);
    }
    
    // Validate update data
    const validation = await this.validateUser(data, true);
    if (!validation.valid) {
      return this.error(validation.message, 400, validation.errors);
    }
    
    // Update password if provided
    if (data.password) {
      const bcrypt = require('bcryptjs');
      data.password = await bcrypt.hash(data.password, 10);
    }
    
    // Update user
    data.updated_at = new Date();
    await this.model('user').where({ id }).update(data);
    
    const updatedUser = await this.model('user')
      .field('id,username,email,role,status,updated_at')
      .where({ id })
      .find();
    
    return this.success(updatedUser, this.locale('USER_UPDATED'));
  }
  
  /**
   * RESTful DELETE - Delete user
   */
  async deleteAction() {
    const id = this.id;
    if (!id) {
      return this.error(this.locale('INVALID_REQUEST'), 400);
    }
    
    // Check if user exists
    const user = await this.model('user').where({ id }).find();
    if (think.isEmpty(user)) {
      return this.error(this.locale('USER_NOT_FOUND'), 404);
    }
    
    // Soft delete
    await this.model('user').where({ id }).update({
      status: 'deleted',
      deleted_at: new Date(),
      updated_at: new Date()
    });
    
    return this.success(null, this.locale('USER_DELETED'));
  }
  
  /**
   * Build where conditions from query parameters
   */
  buildWhereConditions() {
    const where = { status: ['!=', 'deleted'] };
    
    // Search by username or email
    const search = this.get('search');
    if (search) {
      where._complex = {
        username: ['like', \`%\${search}%\`],
        email: ['like', \`%\${search}%\`],
        _logic: 'or'
      };
    }
    
    // Filter by role
    const role = this.get('role');
    if (role) {
      where.role = role;
    }
    
    // Filter by status
    const status = this.get('status');
    if (status && status !== 'deleted') {
      where.status = status;
    }
    
    return where;
  }
  
  /**
   * Validate user data
   */
  async validateUser(data, isUpdate = false) {
    const rules = {
      username: {
        required: !isUpdate,
        string: true,
        min: 3,
        max: 50,
        regexp: /^[a-zA-Z0-9_-]+$/
      },
      email: {
        required: !isUpdate,
        email: true
      },
      password: {
        required: !isUpdate,
        string: true,
        min: 8,
        max: 100
      },
      role: {
        in: ['admin', 'user', 'guest']
      },
      status: {
        in: ['active', 'inactive', 'suspended']
      }
    };
    
    const flag = await this.validate(rules, data);
    if (!flag) {
      return {
        valid: false,
        message: this.locale('INVALID_REQUEST'),
        errors: this.validateErrors
      };
    }
    
    return { valid: true };
  }
};`,
    
    'src/model/user.js': `module.exports = class extends think.Model {
  // Define table schema
  get schema() {
    return {
      id: {
        type: 'int',
        primary: true,
        autoIncrement: true
      },
      username: {
        type: 'string',
        size: 50,
        unique: true,
        index: true
      },
      email: {
        type: 'string',
        size: 100,
        unique: true,
        index: true
      },
      password: {
        type: 'string',
        size: 255
      },
      role: {
        type: 'string',
        default: 'user',
        index: true
      },
      status: {
        type: 'string',
        default: 'active',
        index: true
      },
      profile: {
        type: 'json',
        default: {}
      },
      last_login_at: {
        type: 'datetime'
      },
      created_at: {
        type: 'datetime',
        default: () => new Date()
      },
      updated_at: {
        type: 'datetime',
        default: () => new Date()
      },
      deleted_at: {
        type: 'datetime'
      }
    };
  }
  
  // Define relations
  get relation() {
    return {
      orders: {
        type: think.Model.HAS_MANY,
        model: 'order',
        fKey: 'user_id'
      },
      profile: {
        type: think.Model.HAS_ONE,
        model: 'user_profile',
        fKey: 'user_id'
      },
      roles: {
        type: think.Model.MANY_TO_MANY,
        model: 'role',
        rModel: 'user_role',
        fKey: 'user_id',
        rfKey: 'role_id'
      }
    };
  }
  
  // Model hooks
  beforeAdd(data) {
    data.created_at = new Date();
    data.updated_at = new Date();
    return data;
  }
  
  beforeUpdate(data) {
    data.updated_at = new Date();
    return data;
  }
  
  afterFind(data, options) {
    // Hide password field by default
    if (data && !options.includePassword) {
      delete data.password;
    }
    return data;
  }
  
  afterSelect(data, options) {
    // Hide password field for all results
    if (!options.includePassword) {
      data.forEach(item => delete item.password);
    }
    return data;
  }
  
  // Custom methods
  async findByEmail(email) {
    return this.where({ email, status: ['!=', 'deleted'] }).find();
  }
  
  async findByUsername(username) {
    return this.where({ username, status: ['!=', 'deleted'] }).find();
  }
  
  async updateLastLogin(userId) {
    return this.where({ id: userId }).update({
      last_login_at: new Date(),
      updated_at: new Date()
    });
  }
  
  async getActiveUsers(page = 1, pageSize = 20) {
    const offset = (page - 1) * pageSize;
    
    return this.where({ status: 'active' })
      .field('id,username,email,role,created_at')
      .limit(pageSize)
      .offset(offset)
      .order('created_at DESC')
      .select();
  }
  
  async searchUsers(keyword, options = {}) {
    const where = {
      status: ['!=', 'deleted'],
      _complex: {
        username: ['like', \`%\${keyword}%\`],
        email: ['like', \`%\${keyword}%\`],
        _logic: 'or'
      }
    };
    
    let query = this.where(where);
    
    if (options.fields) {
      query = query.field(options.fields);
    }
    
    if (options.limit) {
      query = query.limit(options.limit);
    }
    
    return query.select();
  }
  
  // Transaction example
  async createUserWithProfile(userData, profileData) {
    const transaction = await this.startTrans();
    
    try {
      // Create user
      const userId = await this.add(userData);
      
      // Create profile
      profileData.user_id = userId;
      await this.model('user_profile').add(profileData);
      
      await this.commit();
      return userId;
    } catch (error) {
      await this.rollback();
      throw error;
    }
  }
};`,
    
    'src/controller/websocket/index.js': `const Base = require('../base.js');

module.exports = class extends Base {
  constructor(...args) {
    super(...args);
    this.room = 'default';
    this.users = new Map();
  }
  
  /**
   * WebSocket connection opened
   */
  async openAction() {
    const socketId = this.wsData.socketId;
    const userId = this.wsData.userId || \`guest_\${socketId}\`;
    
    // Store user connection
    this.users.set(socketId, {
      id: userId,
      socketId,
      joinedAt: new Date(),
      room: this.room
    });
    
    // Join default room
    await this.broadcast('join', {
      user: userId,
      message: \`\${userId} joined the room\`,
      timestamp: new Date()
    });
    
    // Send welcome message
    this.emit('welcome', {
      message: 'Welcome to ThinkJS WebSocket',
      socketId,
      userId,
      room: this.room
    });
    
    // Send active users list
    this.emit('users', Array.from(this.users.values()));
    
    think.logger.info(\`WebSocket connected: \${socketId}\`);
  }
  
  /**
   * Handle chat messages
   */
  async chatAction() {
    const { message, room = this.room } = this.wsData;
    const socketId = this.wsData.socketId;
    const user = this.users.get(socketId);
    
    if (!user || !message) {
      return this.emit('error', { message: 'Invalid chat request' });
    }
    
    const chatMessage = {
      id: think.uuid('v4'),
      userId: user.id,
      message,
      room,
      timestamp: new Date()
    };
    
    // Store message in database
    await this.model('chat_message').add(chatMessage);
    
    // Broadcast to room
    await this.broadcast('message', chatMessage, room);
    
    // Log chat activity
    think.logger.info(\`Chat message from \${user.id}: \${message}\`);
  }
  
  /**
   * Handle typing indicator
   */
  async typingAction() {
    const { isTyping } = this.wsData;
    const socketId = this.wsData.socketId;
    const user = this.users.get(socketId);
    
    if (!user) return;
    
    // Broadcast typing status
    await this.broadcast('typing', {
      userId: user.id,
      isTyping,
      timestamp: new Date()
    }, user.room, socketId);
  }
  
  /**
   * Join a specific room
   */
  async joinRoomAction() {
    const { room } = this.wsData;
    const socketId = this.wsData.socketId;
    const user = this.users.get(socketId);
    
    if (!user || !room) {
      return this.emit('error', { message: 'Invalid room request' });
    }
    
    // Leave current room
    await this.broadcast('leave', {
      user: user.id,
      message: \`\${user.id} left the room\`
    }, user.room);
    
    // Update user room
    user.room = room;
    this.users.set(socketId, user);
    
    // Join new room
    await this.broadcast('join', {
      user: user.id,
      message: \`\${user.id} joined the room\`
    }, room);
    
    // Confirm room change
    this.emit('roomChanged', {
      room,
      message: \`You joined room: \${room}\`
    });
  }
  
  /**
   * Send private message
   */
  async privateMessageAction() {
    const { targetUserId, message } = this.wsData;
    const socketId = this.wsData.socketId;
    const sender = this.users.get(socketId);
    
    if (!sender || !targetUserId || !message) {
      return this.emit('error', { message: 'Invalid private message' });
    }
    
    // Find target user
    const targetSocket = Array.from(this.users.entries())
      .find(([_, user]) => user.id === targetUserId);
    
    if (!targetSocket) {
      return this.emit('error', { message: 'User not found' });
    }
    
    const privateMessage = {
      id: think.uuid('v4'),
      from: sender.id,
      to: targetUserId,
      message,
      timestamp: new Date()
    };
    
    // Send to target user
    this.emit('privateMessage', privateMessage, targetSocket[0]);
    
    // Confirm to sender
    this.emit('privateMessageSent', privateMessage);
  }
  
  /**
   * Get chat history
   */
  async historyAction() {
    const { room = this.room, limit = 50 } = this.wsData;
    
    const messages = await this.model('chat_message')
      .where({ room })
      .limit(limit)
      .order('timestamp DESC')
      .select();
    
    this.emit('history', {
      room,
      messages: messages.reverse()
    });
  }
  
  /**
   * Handle disconnection
   */
  async closeAction() {
    const socketId = this.wsData.socketId;
    const user = this.users.get(socketId);
    
    if (user) {
      // Remove from users map
      this.users.delete(socketId);
      
      // Notify others
      await this.broadcast('leave', {
        user: user.id,
        message: \`\${user.id} disconnected\`,
        timestamp: new Date()
      }, user.room);
      
      think.logger.info(\`WebSocket disconnected: \${socketId}\`);
    }
  }
  
  /**
   * Broadcast message to room
   */
  async broadcast(event, data, room = this.room, excludeSocketId = null) {
    const sockets = await this.getWebsocketSockets();
    
    sockets.forEach(socket => {
      if (socket.id !== excludeSocketId) {
        const socketUser = this.users.get(socket.id);
        if (socketUser && socketUser.room === room) {
          this.emit(event, data, socket.id);
        }
      }
    });
  }
};`,
    
    'src/controller/cron/daily/cleanup.js': `module.exports = class extends think.Controller {
  async __call() {
    const startTime = Date.now();
    think.logger.info('Starting daily cleanup job...');
    
    try {
      // Clean up expired sessions
      const sessionsCleaned = await this.cleanExpiredSessions();
      
      // Clean up old logs
      const logsCleaned = await this.cleanOldLogs();
      
      // Clean up temporary files
      const filesCleaned = await this.cleanTempFiles();
      
      // Clean up soft-deleted records
      const recordsCleaned = await this.cleanSoftDeletedRecords();
      
      // Generate cleanup report
      const report = {
        sessionsCleaned,
        logsCleaned,
        filesCleaned,
        recordsCleaned,
        duration: Date.now() - startTime
      };
      
      // Store cleanup report
      await this.model('cron_log').add({
        job_name: 'daily_cleanup',
        status: 'success',
        report: JSON.stringify(report),
        executed_at: new Date()
      });
      
      think.logger.info(\`Daily cleanup completed in \${report.duration}ms\`, report);
      
    } catch (error) {
      think.logger.error('Daily cleanup failed:', error);
      
      await this.model('cron_log').add({
        job_name: 'daily_cleanup',
        status: 'failed',
        error: error.message,
        executed_at: new Date()
      });
    }
  }
  
  async cleanExpiredSessions() {
    const expiredDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
    
    const count = await this.model('session')
      .where({ updated_at: ['<', expiredDate] })
      .delete();
    
    return count;
  }
  
  async cleanOldLogs() {
    const fs = require('fs').promises;
    const path = require('path');
    const logsDir = path.join(think.ROOT_PATH, 'runtime/logs');
    
    let cleaned = 0;
    const files = await fs.readdir(logsDir);
    
    for (const file of files) {
      const filePath = path.join(logsDir, file);
      const stats = await fs.stat(filePath);
      
      // Delete logs older than 7 days
      if (Date.now() - stats.mtime.getTime() > 7 * 24 * 60 * 60 * 1000) {
        await fs.unlink(filePath);
        cleaned++;
      }
    }
    
    return cleaned;
  }
  
  async cleanTempFiles() {
    const fs = require('fs').promises;
    const path = require('path');
    const tempDir = path.join(think.ROOT_PATH, 'runtime/temp');
    
    let cleaned = 0;
    
    try {
      const files = await fs.readdir(tempDir);
      
      for (const file of files) {
        const filePath = path.join(tempDir, file);
        const stats = await fs.stat(filePath);
        
        // Delete temp files older than 1 day
        if (Date.now() - stats.mtime.getTime() > 24 * 60 * 60 * 1000) {
          await fs.unlink(filePath);
          cleaned++;
        }
      }
    } catch (error) {
      // Temp directory might not exist
    }
    
    return cleaned;
  }
  
  async cleanSoftDeletedRecords() {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    let totalCleaned = 0;
    
    // Clean soft-deleted users
    const usersDeleted = await this.model('user')
      .where({
        status: 'deleted',
        deleted_at: ['<', thirtyDaysAgo]
      })
      .delete();
    
    totalCleaned += usersDeleted;
    
    // Clean other soft-deleted records
    // Add more models as needed
    
    return totalCleaned;
  }
};`,
    
    'src/service/auth.js': `const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

module.exports = class extends think.Service {
  constructor() {
    super();
    this.jwtSecret = think.config('jwt.secret') || 'your-secret-key';
    this.jwtExpiry = think.config('jwt.expiry') || '1h';
    this.refreshExpiry = think.config('jwt.refreshExpiry') || '7d';
  }
  
  /**
   * Authenticate user with credentials
   */
  async authenticate(email, password) {
    // Find user by email
    const user = await this.model('user').findByEmail(email);
    
    if (think.isEmpty(user)) {
      return { success: false, message: 'Invalid credentials' };
    }
    
    // Verify password
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return { success: false, message: 'Invalid credentials' };
    }
    
    // Check if user is active
    if (user.status !== 'active') {
      return { success: false, message: 'Account is not active' };
    }
    
    // Generate tokens
    const tokens = this.generateTokens(user);
    
    // Update last login
    await this.model('user').updateLastLogin(user.id);
    
    // Remove sensitive data
    delete user.password;
    
    return {
      success: true,
      user,
      tokens
    };
  }
  
  /**
   * Generate JWT tokens
   */
  generateTokens(user) {
    const payload = {
      id: user.id,
      email: user.email,
      role: user.role
    };
    
    const accessToken = jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.jwtExpiry,
      issuer: 'thinkjs-microservice'
    });
    
    const refreshToken = jwt.sign(
      { ...payload, type: 'refresh' },
      this.jwtSecret,
      {
        expiresIn: this.refreshExpiry,
        issuer: 'thinkjs-microservice'
      }
    );
    
    return {
      accessToken,
      refreshToken,
      expiresIn: this.getExpirySeconds(this.jwtExpiry)
    };
  }
  
  /**
   * Verify JWT token
   */
  async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, this.jwtSecret, {
        issuer: 'thinkjs-microservice'
      });
      
      // Check if user still exists and is active
      const user = await this.model('user')
        .where({ id: decoded.id, status: 'active' })
        .find();
      
      if (think.isEmpty(user)) {
        return { valid: false, message: 'User not found or inactive' };
      }
      
      delete user.password;
      
      return {
        valid: true,
        user,
        decoded
      };
    } catch (error) {
      return {
        valid: false,
        message: error.message
      };
    }
  }
  
  /**
   * Refresh access token
   */
  async refreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, this.jwtSecret, {
        issuer: 'thinkjs-microservice'
      });
      
      if (decoded.type !== 'refresh') {
        return { success: false, message: 'Invalid refresh token' };
      }
      
      // Get fresh user data
      const user = await this.model('user')
        .where({ id: decoded.id, status: 'active' })
        .find();
      
      if (think.isEmpty(user)) {
        return { success: false, message: 'User not found or inactive' };
      }
      
      // Generate new tokens
      const tokens = this.generateTokens(user);
      
      return {
        success: true,
        tokens
      };
    } catch (error) {
      return {
        success: false,
        message: error.message
      };
    }
  }
  
  /**
   * Create API key for service authentication
   */
  async createApiKey(userId, name, permissions = []) {
    const apiKey = this.generateApiKey();
    const hashedKey = await bcrypt.hash(apiKey, 10);
    
    await this.model('api_key').add({
      user_id: userId,
      name,
      key_hash: hashedKey,
      permissions: JSON.stringify(permissions),
      last_used_at: null,
      created_at: new Date()
    });
    
    return apiKey;
  }
  
  /**
   * Verify API key
   */
  async verifyApiKey(apiKey) {
    const keys = await this.model('api_key')
      .where({ status: 'active' })
      .select();
    
    for (const key of keys) {
      const isValid = await bcrypt.compare(apiKey, key.key_hash);
      
      if (isValid) {
        // Update last used
        await this.model('api_key')
          .where({ id: key.id })
          .update({ last_used_at: new Date() });
        
        return {
          valid: true,
          userId: key.user_id,
          permissions: JSON.parse(key.permissions || '[]')
        };
      }
    }
    
    return { valid: false };
  }
  
  /**
   * Generate random API key
   */
  generateApiKey() {
    const crypto = require('crypto');
    return \`tk_\${crypto.randomBytes(32).toString('hex')}\`;
  }
  
  /**
   * Convert expiry string to seconds
   */
  getExpirySeconds(expiry) {
    const units = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400
    };
    
    const match = expiry.match(/^(\\d+)([smhd])$/);
    if (match) {
      return parseInt(match[1]) * units[match[2]];
    }
    
    return 3600; // Default 1 hour
  }
};`,
    
    'src/config/extend.ts': `import { think } from 'thinkjs';

// Extend think with custom methods
export default {
  // Add custom application methods
  application: {
    async getServiceHealth(): Promise<object> {
      const checks = {
        database: await this.checkDatabase(),
        redis: await this.checkRedis(),
        disk: await this.checkDiskSpace()
      };
      
      const healthy = Object.values(checks).every(check => check.status === 'healthy');
      
      return {
        status: healthy ? 'healthy' : 'unhealthy',
        checks,
        timestamp: new Date().toISOString()
      };
    },
    
    async checkDatabase(): Promise<object> {
      try {
        await think.model('user').count();
        return { status: 'healthy' };
      } catch (error) {
        return { status: 'unhealthy', error: error.message };
      }
    },
    
    async checkRedis(): Promise<object> {
      try {
        const redis = think.cache('redis');
        await redis.set('health_check', Date.now());
        return { status: 'healthy' };
      } catch (error) {
        return { status: 'unhealthy', error: error.message };
      }
    },
    
    async checkDiskSpace(): Promise<object> {
      const os = require('os');
      const disk = os.freemem() / os.totalmem();
      
      return {
        status: disk > 0.1 ? 'healthy' : 'unhealthy',
        freePercent: Math.round(disk * 100)
      };
    }
  },
  
  // Add custom context methods
  context: {
    getUserFromToken(): object | null {
      const token = this.header('authorization')?.replace('Bearer ', '');
      
      if (!token) {
        return null;
      }
      
      try {
        const authService = think.service('auth');
        const result = authService.verifyToken(token);
        return result.valid ? result.user : null;
      } catch (error) {
        return null;
      }
    },
    
    getRequestId(): string {
      return this.header('x-request-id') || think.uuid('v4');
    },
    
    logRequest(level: string, message: string, data?: any): void {
      const requestId = this.getRequestId();
      const log = {
        requestId,
        method: this.method,
        url: this.url,
        ip: this.ip,
        userAgent: this.header('user-agent'),
        message,
        data,
        timestamp: new Date().toISOString()
      };
      
      think.logger[level](log);
    }
  },
  
  // Add custom controller methods
  controller: {
    async cache(key: string, fn: Function, expire: number = 3600): Promise<any> {
      const cache = await think.cache(key);
      
      if (cache !== undefined) {
        return cache;
      }
      
      const data = await fn();
      await think.cache(key, data, expire);
      
      return data;
    },
    
    async validateRequest(rules: object): Promise<boolean> {
      const data = this.isGet ? this.get() : this.post();
      const flag = await this.validate(rules, data);
      
      if (!flag) {
        this.fail(this.validateErrors);
        return false;
      }
      
      return true;
    }
  }
};`,
    
    'Dockerfile': `FROM node:18-alpine

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Build the application
RUN npm run build

# Create runtime directories
RUN mkdir -p runtime/cache runtime/session runtime/logs runtime/temp

# Set permissions
RUN chown -R node:node /usr/src/app

# Switch to non-root user
USER node

# Expose port
EXPOSE 8360

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8360/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

# Start the application
CMD ["node", "production.js"]`,
    
    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    container_name: thinkjs-app
    restart: unless-stopped
    ports:
      - "8360:8360"
    environment:
      - NODE_ENV=production
      - PORT=8360
      - DB_HOST=mysql
      - DB_PORT=3306
      - DB_NAME=thinkjs
      - DB_USER=thinkjs
      - DB_PASSWORD=thinkjs_password
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    depends_on:
      - mysql
      - redis
    volumes:
      - ./runtime:/usr/src/app/runtime
      - ./logs:/usr/src/app/logs
    networks:
      - thinkjs-network

  mysql:
    image: mysql:8.0
    container_name: thinkjs-mysql
    restart: unless-stopped
    environment:
      - MYSQL_ROOT_PASSWORD=root_password
      - MYSQL_DATABASE=thinkjs
      - MYSQL_USER=thinkjs
      - MYSQL_PASSWORD=thinkjs_password
    ports:
      - "3306:3306"
    volumes:
      - mysql-data:/var/lib/mysql
    networks:
      - thinkjs-network

  redis:
    image: redis:7-alpine
    container_name: thinkjs-redis
    restart: unless-stopped
    command: redis-server --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - thinkjs-network

  nginx:
    image: nginx:alpine
    container_name: thinkjs-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - thinkjs-network

volumes:
  mysql-data:
  redis-data:

networks:
  thinkjs-network:
    driver: bridge`,
    
    'README.md': `# ThinkJS Microservice

A modern Node.js microservice built with ThinkJS framework, featuring ES6/ES7 syntax, auto-loading, and comprehensive tooling.

## Features

- **ES6/ES7 Syntax**: Modern JavaScript with async/await throughout
- **MVC Architecture**: Auto-loading controllers, models, and services
- **ORM Support**: Built-in think-model with MySQL, PostgreSQL, SQLite adapters
- **RESTful APIs**: Automatic REST routing with validation
- **WebSocket**: Real-time communication with Socket.io
- **Caching**: Multiple cache adapters (File, Redis, Memcache)
- **I18n**: Built-in internationalization support
- **Cron Jobs**: Scheduled tasks with flexible configuration
- **TypeScript**: Optional TypeScript support
- **Docker**: Production-ready containerization

## Quick Start

\`\`\`bash
# Install dependencies
npm install

# Development mode with hot reload
npm run dev

# Build for production
npm run build

# Start production server
npm run production

# Run with Docker
docker-compose up -d
\`\`\`

## Project Structure

\`\`\`
├── src/
│   ├── config/         # Configuration files
│   │   ├── config.js   # Base configuration
│   │   ├── adapter.js  # Adapter configurations
│   │   ├── middleware.js
│   │   ├── router.js   # Route definitions
│   │   └── crontab.js  # Cron job schedules
│   ├── controller/     # Controllers (auto-loaded)
│   │   ├── api/        # API controllers
│   │   ├── websocket/  # WebSocket handlers
│   │   └── cron/       # Cron job controllers
│   ├── model/          # Models (auto-loaded)
│   ├── service/        # Business logic services
│   └── logic/          # Request validation logic
├── runtime/            # Runtime files (cache, logs, etc.)
├── view/               # View templates
└── www/                # Static assets
\`\`\`

## API Examples

### RESTful User API

\`\`\`bash
# Get all users
GET /api/v1/users?page=1&pageSize=20

# Get single user
GET /api/v1/users/123

# Create user
POST /api/v1/users
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "secure_password"
}

# Update user
PUT /api/v1/users/123
{
  "email": "newemail@example.com"
}

# Delete user
DELETE /api/v1/users/123
\`\`\`

### WebSocket

\`\`\`javascript
const socket = io('http://localhost:8360');

// Join chat
socket.emit('chat', {
  message: 'Hello, ThinkJS!'
});

// Listen for messages
socket.on('message', (data) => {
  console.log('New message:', data);
});
\`\`\`

## Configuration

### Database

Configure database in \`src/config/adapter.js\`:

\`\`\`javascript
exports.model = {
  type: 'mysql',
  mysql: {
    database: 'thinkjs',
    host: '127.0.0.1',
    port: 3306,
    user: 'root',
    password: ''
  }
};
\`\`\`

### Cache

Configure cache adapters:

\`\`\`javascript
exports.cache = {
  type: 'redis',
  redis: {
    host: '127.0.0.1',
    port: 6379
  }
};
\`\`\`

## Testing

\`\`\`bash
# Run unit tests
npm test

# Run integration tests
npm run test-integration

# Generate coverage report
npm run coverage
\`\`\`

## Production Deployment

1. Build the application:
   \`\`\`bash
   npm run build
   \`\`\`

2. Set environment variables:
   \`\`\`bash
   export NODE_ENV=production
   export PORT=8360
   export DB_HOST=your-db-host
   \`\`\`

3. Start with PM2:
   \`\`\`bash
   pm2 start production.js -i max
   \`\`\`

## Docker Deployment

\`\`\`bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f app

# Scale application
docker-compose up -d --scale app=3
\`\`\`

## License

MIT`
  }
};