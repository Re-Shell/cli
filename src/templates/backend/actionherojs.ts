import { BackendTemplate } from '../../types/template';

export const actionheroTemplate: BackendTemplate = {
  name: 'actionherojs',
  description: 'Multi-transport API server with clustering, real-time capabilities, and background jobs',
  packageJson: {
    name: 'actionhero-backend',
    version: '1.0.0',
    description: 'ActionHero multi-transport API server',
    scripts: {
      start: 'actionhero start',
      'start:cluster': 'actionhero start cluster --workers=4',
      dev: 'actionhero start --watch',
      test: 'jest',
      'test:watch': 'jest --watch',
      'test:coverage': 'jest --coverage',
      actionhero: 'actionhero',
      build: 'tsc',
      'docker:build': 'docker build -t actionhero-backend .',
      'docker:run': 'docker run -p 8080:8080 -p 5000:5000 actionhero-backend',
      'generate:action': 'actionhero generate action',
      'generate:task': 'actionhero generate task',
      'generate:initializer': 'actionhero generate initializer',
      'generate:server': 'actionhero generate server'
    },
    dependencies: {
      actionhero: '^29.0.0',
      redis: '^4.6.0',
      ioredis: '^5.3.0',
      winston: '^3.11.0',
      'winston-daily-rotate-file': '^4.7.1',
      bcrypt: '^5.1.0',
      jsonwebtoken: '^9.0.0',
      uuid: '^9.0.0',
      axios: '^1.6.0',
      'node-schedule': '^2.1.0',
      pg: '^8.11.0',
      sequelize: '^6.35.0',
      'sequelize-typescript': '^2.1.6'
    },
    devDependencies: {
      '@types/node': '^20.10.0',
      '@types/jest': '^29.5.0',
      '@types/bcrypt': '^5.0.0',
      '@types/jsonwebtoken': '^9.0.0',
      '@types/uuid': '^9.0.0',
      '@types/node-schedule': '^2.1.0',
      typescript: '^5.3.0',
      jest: '^29.7.0',
      'ts-jest': '^29.1.0',
      'ts-node': '^10.9.0',
      nodemon: '^3.0.0',
      supertest: '^6.3.0'
    },
    engines: {
      node: '>=18.0.0'
    }
  },
  files: [
    {
      path: 'config/servers/web.ts',
      content: `export const DEFAULT = {
  servers: {
    web: (config: any) => {
      return {
        enabled: true,
        secure: false,
        serverOptions: {},
        allowedRequestHosts: process.env.ALLOWED_HOSTS?.split(',') || [],
        port: process.env.WEB_PORT || 8080,
        bindIP: '0.0.0.0',
        httpHeaders: {
          'X-Powered-By': config.general.serverName,
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'HEAD, GET, POST, PUT, PATCH, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        },
        urlPathForActions: 'api',
        urlPathForFiles: 'public',
        rootEndpointType: 'file',
        directoryFileType: 'index.html',
        fingerprintOptions: {
          fingerprintOnlyStaticFiles: false
        },
        formOptions: {
          uploadDir: '/tmp',
          keepExtensions: false,
          maxFieldsSize: 1024 * 1024 * 20,
          maxFileSize: 1024 * 1024 * 200
        },
        metadataOptions: {
          serverInformation: true,
          requesterInformation: true
        },
        returnErrorCodes: true,
        compress: true,
        padding: 2,
        metadataOptions: {
          serverInformation: true,
          requesterInformation: true
        }
      };
    }
  }
};

export const test = {
  servers: {
    web: (config: any) => {
      return {
        enabled: true,
        secure: false,
        port: 18080 + parseInt(process.env.JEST_WORKER_ID || '0'),
        matchExtensionMime: true,
        metadataOptions: {
          serverInformation: true,
          requesterInformation: true
        }
      };
    }
  }
};
`
    },
    {
      path: 'config/servers/websocket.ts',
      content: `export const DEFAULT = {
  servers: {
    websocket: (config: any) => {
      return {
        enabled: true,
        clientUrl: 'http://localhost:8080',
        clientJsPath: 'public/javascript/',
        clientJsName: 'ActionheroWebsocketClient.min.js',
        clientApiPath: 'public/api/',
        headers: {},
        logLevel: 'info',
        verbs: [
          'quit',
          'exit',
          'roomAdd',
          'roomLeave',
          'roomView',
          'detailsView',
          'say',
          'file',
          'event',
          'documentation',
          'status',
          'time'
        ]
      };
    }
  }
};

export const test = {
  servers: {
    websocket: (config: any) => {
      return {
        enabled: true,
        port: 19000 + parseInt(process.env.JEST_WORKER_ID || '0'),
        clientUrl: 'http://localhost:8080'
      };
    }
  }
};
`
    },
    {
      path: 'config/servers/socket.ts',
      content: `export const DEFAULT = {
  servers: {
    socket: (config: any) => {
      return {
        enabled: true,
        secure: false,
        serverOptions: {},
        port: process.env.SOCKET_PORT || 5000,
        bindIP: '0.0.0.0',
        setKeepAlive: false,
        maxConnections: 0,
        logLevel: 'info'
      };
    }
  }
};

export const test = {
  servers: {
    socket: (config: any) => {
      return {
        enabled: true,
        port: 15000 + parseInt(process.env.JEST_WORKER_ID || '0')
      };
    }
  }
};
`
    },
    {
      path: 'config/redis.ts',
      content: `import { URL } from 'url';

let host = process.env.REDIS_HOST || '127.0.0.1';
let port = process.env.REDIS_PORT || 6379;
let db = process.env.REDIS_DB || 0;
let password = process.env.REDIS_PASSWORD || null;

if (process.env.REDIS_URL) {
  const parsed = new URL(process.env.REDIS_URL);
  host = parsed.hostname;
  port = parsed.port || 6379;
  password = parsed.password;
  if (parsed.pathname) {
    db = parseInt(parsed.pathname.substring(1));
  }
}

export const DEFAULT = {
  redis: (config: any) => {
    const redisConfig: any = {
      enabled: true,
      _toExpand: false,
      client: {
        host,
        port,
        password,
        db,
        buildNew: true
      },
      subscriber: {
        host,
        port,
        password,
        db,
        buildNew: true
      },
      tasks: {
        host,
        port,
        password,
        db,
        buildNew: true
      }
    };

    return redisConfig;
  }
};

export const test = {
  redis: (config: any) => {
    const testDb = 10 + parseInt(process.env.JEST_WORKER_ID || '0');
    
    return {
      enabled: true,
      _toExpand: false,
      client: {
        host: '127.0.0.1',
        port: 6379,
        password: null,
        db: testDb,
        buildNew: true
      },
      subscriber: {
        host: '127.0.0.1',
        port: 6379,
        password: null,
        db: testDb,
        buildNew: true
      },
      tasks: {
        host: '127.0.0.1',
        port: 6379,
        password: null,
        db: testDb,
        buildNew: true
      }
    };
  }
};
`
    },
    {
      path: 'config/tasks.ts',
      content: `export const DEFAULT = {
  tasks: (config: any) => {
    return {
      scheduler: true,
      queues: ['*'],
      verbose: true,
      workerLogging: {
        failure: 'error',
        success: 'info',
        start: 'info',
        end: 'info',
        cleaning_worker: 'info',
        poll: 'debug',
        job: 'debug',
        pause: 'debug',
        internalError: 'error',
        multiWorkerAction: 'debug'
      },
      stuckWorkerTimeout: 1000 * 60 * 60,
      checkTimeout: 500,
      maxEventLoopDelay: 5,
      toDisconnectProcessors: true,
      redis: config.redis
    };
  }
};

export const test = {
  tasks: (config: any) => {
    return {
      scheduler: false,
      queues: ['*'],
      checkTimeout: 100,
      maxEventLoopDelay: 5
    };
  }
};
`
    },
    {
      path: 'config/routes.ts',
      content: `export const DEFAULT = {
  routes: (config: any) => {
    return {
      // Basic REST routes
      get: [
        { path: '/status', action: 'status' },
        { path: '/swagger', action: 'swagger' },
        { path: '/users', action: 'users:list' },
        { path: '/users/:id', action: 'users:show' },
        { path: '/products', action: 'products:list' },
        { path: '/products/:id', action: 'products:show' },
        { path: '/health', action: 'health' }
      ],
      
      post: [
        { path: '/auth/login', action: 'auth:login' },
        { path: '/auth/register', action: 'auth:register' },
        { path: '/auth/refresh', action: 'auth:refresh' },
        { path: '/users', action: 'users:create' },
        { path: '/products', action: 'products:create' },
        { path: '/jobs/:name', action: 'jobs:enqueue' },
        { path: '/chat/send', action: 'chat:send' }
      ],
      
      put: [
        { path: '/users/:id', action: 'users:update' },
        { path: '/products/:id', action: 'products:update' }
      ],
      
      patch: [
        { path: '/users/:id', action: 'users:patch' },
        { path: '/products/:id', action: 'products:patch' }
      ],
      
      delete: [
        { path: '/users/:id', action: 'users:delete' },
        { path: '/products/:id', action: 'products:delete' },
        { path: '/cache/:key', action: 'cache:delete' }
      ],
      
      // Versioned routes
      all: [
        { path: '/v1/:action', action: 'v1:%action' },
        { path: '/v2/:action', action: 'v2:%action' }
      ]
    };
  }
};
`
    },
    {
      path: 'actions/status.ts',
      content: `import { Action, api } from 'actionhero';

export class StatusAction extends Action {
  constructor() {
    super();
    this.name = 'status';
    this.description = 'Get server status and statistics';
    this.outputExample = {
      id: '192.168.2.11',
      actionheroVersion: '29.0.0',
      uptime: 10469,
      stats: {
        connections: 0,
        actions: 5,
        tasks: 0
      }
    };
  }

  async run({ response }: { response: any }) {
    const stats = await api.resque.queue.stats();
    
    response.id = api.id;
    response.actionheroVersion = api.actionheroVersion;
    response.uptime = process.uptime();
    response.nodeVersion = process.version;
    response.pid = process.pid;
    response.stats = {
      connections: Object.keys(api.connections.connections).length,
      actions: Object.keys(api.actions.actions).length,
      tasks: Object.keys(api.tasks.tasks).length,
      queue: stats
    };
    response.serverInformation = {
      serverName: api.config.general.serverName,
      apiVersion: api.config.general.apiVersion,
      requestDuration: new Date().getTime() - response.messageId,
      currentTime: new Date().getTime()
    };
    response.health = 'OK';
  }
}
`
    },
    {
      path: 'actions/users.ts',
      content: `import { Action, api, ParamsFrom } from 'actionhero';
import { User } from '../models/User';
import bcrypt from 'bcrypt';
import { Op } from 'sequelize';

// List users action
export class UsersList extends Action {
  constructor() {
    super();
    this.name = 'users:list';
    this.description = 'List all users with pagination';
    this.inputs = {
      page: { required: false, default: 1 },
      limit: { required: false, default: 20 },
      search: { required: false }
    };
    this.middleware = ['auth'];
    this.outputExample = {
      users: [],
      pagination: {
        page: 1,
        limit: 20,
        total: 100
      }
    };
  }

  async run(data: ParamsFrom<UsersList>) {
    const { page = 1, limit = 20, search } = data.params;
    const offset = (page - 1) * limit;
    
    const where: any = {};
    if (search) {
      where[Op.or] = [
        { name: { [Op.iLike]: \`%\${search}%\` } },
        { email: { [Op.iLike]: \`%\${search}%\` } }
      ];
    }
    
    const { rows: users, count } = await User.findAndCountAll({
      where,
      limit,
      offset,
      attributes: { exclude: ['password'] },
      order: [['createdAt', 'DESC']]
    });
    
    data.response.users = users;
    data.response.pagination = {
      page,
      limit,
      total: count,
      totalPages: Math.ceil(count / limit)
    };
  }
}

// Get single user action
export class UsersShow extends Action {
  constructor() {
    super();
    this.name = 'users:show';
    this.description = 'Get a single user by ID';
    this.inputs = {
      id: { required: true }
    };
    this.middleware = ['auth'];
  }

  async run(data: ParamsFrom<UsersShow>) {
    const user = await User.findByPk(data.params.id, {
      attributes: { exclude: ['password'] }
    });
    
    if (!user) {
      throw new Error('User not found');
    }
    
    data.response.user = user;
  }
}

// Create user action
export class UsersCreate extends Action {
  constructor() {
    super();
    this.name = 'users:create';
    this.description = 'Create a new user';
    this.inputs = {
      name: { required: true },
      email: { required: true, validator: 'email' },
      password: { required: true, validator: 'min:6' },
      role: { required: false, default: 'user' }
    };
    this.middleware = ['auth', 'adminOnly'];
  }

  async run(data: ParamsFrom<UsersCreate>) {
    const { name, email, password, role } = data.params;
    
    // Check if user exists
    const existing = await User.findOne({ where: { email } });
    if (existing) {
      throw new Error('User already exists with this email');
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role
    });
    
    // Remove password from response
    const userData = user.toJSON();
    delete userData.password;
    
    data.response.user = userData;
  }
}

// Update user action
export class UsersUpdate extends Action {
  constructor() {
    super();
    this.name = 'users:update';
    this.description = 'Update a user';
    this.inputs = {
      id: { required: true },
      name: { required: false },
      email: { required: false, validator: 'email' },
      password: { required: false, validator: 'min:6' },
      role: { required: false }
    };
    this.middleware = ['auth', 'ownerOrAdmin'];
  }

  async run(data: ParamsFrom<UsersUpdate>) {
    const { id, ...updates } = data.params;
    
    const user = await User.findByPk(id);
    if (!user) {
      throw new Error('User not found');
    }
    
    // Hash password if provided
    if (updates.password) {
      updates.password = await bcrypt.hash(updates.password, 10);
    }
    
    // Update user
    await user.update(updates);
    
    // Remove password from response
    const userData = user.toJSON();
    delete userData.password;
    
    data.response.user = userData;
  }
}

// Delete user action
export class UsersDelete extends Action {
  constructor() {
    super();
    this.name = 'users:delete';
    this.description = 'Delete a user';
    this.inputs = {
      id: { required: true }
    };
    this.middleware = ['auth', 'adminOnly'];
  }

  async run(data: ParamsFrom<UsersDelete>) {
    const user = await User.findByPk(data.params.id);
    if (!user) {
      throw new Error('User not found');
    }
    
    await user.destroy();
    data.response.success = true;
  }
}
`
    },
    {
      path: 'actions/auth.ts',
      content: `import { Action, api, ParamsFrom } from 'actionhero';
import { User } from '../models/User';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

export class AuthLogin extends Action {
  constructor() {
    super();
    this.name = 'auth:login';
    this.description = 'Authenticate user and return JWT token';
    this.inputs = {
      email: { required: true, validator: 'email' },
      password: { required: true }
    };
    this.outputExample = {
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      user: {
        id: 1,
        name: 'John Doe',
        email: 'john@example.com'
      }
    };
  }

  async run(data: ParamsFrom<AuthLogin>) {
    const { email, password } = data.params;
    
    // Find user
    const user = await User.findOne({ where: { email } });
    if (!user) {
      throw new Error('Invalid credentials');
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      throw new Error('Invalid credentials');
    }
    
    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    // Cache token for validation
    await api.cache.save(\`auth:token:\${user.id}\`, token, 1000 * 60 * 60 * 24 * 7);
    
    // Return token and user info
    const userData = user.toJSON();
    delete userData.password;
    
    data.response.token = token;
    data.response.user = userData;
  }
}

export class AuthRegister extends Action {
  constructor() {
    super();
    this.name = 'auth:register';
    this.description = 'Register a new user';
    this.inputs = {
      name: { required: true },
      email: { required: true, validator: 'email' },
      password: { required: true, validator: 'min:6' }
    };
  }

  async run(data: ParamsFrom<AuthRegister>) {
    const { name, email, password } = data.params;
    
    // Check if user exists
    const existing = await User.findOne({ where: { email } });
    if (existing) {
      throw new Error('User already exists with this email');
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: 'user'
    });
    
    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    // Cache token
    await api.cache.save(\`auth:token:\${user.id}\`, token, 1000 * 60 * 60 * 24 * 7);
    
    // Return token and user info
    const userData = user.toJSON();
    delete userData.password;
    
    data.response.token = token;
    data.response.user = userData;
  }
}

export class AuthRefresh extends Action {
  constructor() {
    super();
    this.name = 'auth:refresh';
    this.description = 'Refresh JWT token';
    this.middleware = ['auth'];
  }

  async run(data: ParamsFrom<AuthRefresh>) {
    const { user } = data.session;
    
    // Generate new token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    // Update cached token
    await api.cache.save(\`auth:token:\${user.id}\`, token, 1000 * 60 * 60 * 24 * 7);
    
    data.response.token = token;
  }
}
`
    },
    {
      path: 'actions/chat.ts',
      content: `import { Action, api, ParamsFrom, chatRoom } from 'actionhero';

export class ChatSend extends Action {
  constructor() {
    super();
    this.name = 'chat:send';
    this.description = 'Send a message to a chat room';
    this.inputs = {
      room: { required: true },
      message: { required: true }
    };
    this.middleware = ['auth'];
  }

  async run(data: ParamsFrom<ChatSend>) {
    const { room, message } = data.params;
    const { user } = data.session;
    
    // Check if user is in the room
    const rooms = await api.chatRoom.roomStatus(room);
    const userInRoom = rooms.members.includes(data.connection.id);
    
    if (!userInRoom) {
      throw new Error('You must join the room first');
    }
    
    // Broadcast message to room
    await api.chatRoom.broadcast(
      {},
      room,
      {
        type: 'message',
        from: user.name,
        userId: user.id,
        message,
        timestamp: new Date().toISOString()
      }
    );
    
    // Save message to database (optional)
    await api.tasks.enqueue('saveMessage', {
      room,
      userId: user.id,
      message,
      timestamp: new Date()
    }, 'chat');
    
    data.response.success = true;
  }
}

export class ChatJoin extends Action {
  constructor() {
    super();
    this.name = 'chat:join';
    this.description = 'Join a chat room';
    this.inputs = {
      room: { required: true }
    };
    this.middleware = ['auth'];
  }

  async run(data: ParamsFrom<ChatJoin>) {
    const { room } = data.params;
    const { user } = data.session;
    
    // Add connection to room
    await api.chatRoom.addMember(data.connection.id, room);
    
    // Broadcast join message
    await api.chatRoom.broadcast(
      { id: data.connection.id },
      room,
      {
        type: 'userJoined',
        user: user.name,
        userId: user.id,
        timestamp: new Date().toISOString()
      }
    );
    
    data.response.success = true;
    data.response.room = room;
  }
}

export class ChatLeave extends Action {
  constructor() {
    super();
    this.name = 'chat:leave';
    this.description = 'Leave a chat room';
    this.inputs = {
      room: { required: true }
    };
    this.middleware = ['auth'];
  }

  async run(data: ParamsFrom<ChatLeave>) {
    const { room } = data.params;
    const { user } = data.session;
    
    // Remove connection from room
    await api.chatRoom.removeMember(data.connection.id, room);
    
    // Broadcast leave message
    await api.chatRoom.broadcast(
      {},
      room,
      {
        type: 'userLeft',
        user: user.name,
        userId: user.id,
        timestamp: new Date().toISOString()
      }
    );
    
    data.response.success = true;
  }
}

export class ChatRooms extends Action {
  constructor() {
    super();
    this.name = 'chat:rooms';
    this.description = 'List available chat rooms';
    this.middleware = ['auth'];
  }

  async run(data: ParamsFrom<ChatRooms>) {
    const rooms = await api.chatRoom.availableRooms();
    const roomsWithInfo = [];
    
    for (const room of rooms) {
      const status = await api.chatRoom.roomStatus(room);
      roomsWithInfo.push({
        name: room,
        memberCount: status.members.length,
        members: status.members
      });
    }
    
    data.response.rooms = roomsWithInfo;
  }
}
`
    },
    {
      path: 'actions/jobs.ts',
      content: `import { Action, api, ParamsFrom } from 'actionhero';

export class JobsEnqueue extends Action {
  constructor() {
    super();
    this.name = 'jobs:enqueue';
    this.description = 'Enqueue a background job';
    this.inputs = {
      name: { required: true },
      args: { required: false, default: {} },
      queue: { required: false, default: 'default' },
      delay: { required: false, default: 0 }
    };
    this.middleware = ['auth'];
  }

  async run(data: ParamsFrom<JobsEnqueue>) {
    const { name, args, queue, delay } = data.params;
    
    // Check if task exists
    if (!api.tasks.tasks[name]) {
      throw new Error(\`Task '\${name}' does not exist\`);
    }
    
    // Enqueue the job
    if (delay > 0) {
      await api.tasks.enqueueIn(delay, name, args, queue);
    } else {
      await api.tasks.enqueue(name, args, queue);
    }
    
    data.response.success = true;
    data.response.job = {
      name,
      args,
      queue,
      delay,
      enqueuedAt: new Date().toISOString()
    };
  }
}

export class JobsStatus extends Action {
  constructor() {
    super();
    this.name = 'jobs:status';
    this.description = 'Get job queue status';
    this.middleware = ['auth', 'adminOnly'];
  }

  async run(data: ParamsFrom<JobsStatus>) {
    const stats = await api.resque.queue.stats();
    const workers = await api.resque.queue.workers();
    const failed = await api.resque.queue.failed();
    const queues = await api.resque.queue.queues();
    
    const queueLengths: any = {};
    for (const queue of queues) {
      queueLengths[queue] = await api.resque.queue.length(queue);
    }
    
    data.response.stats = {
      ...stats,
      workers: workers.length,
      failed: failed,
      queues: queueLengths
    };
  }
}

export class JobsRetry extends Action {
  constructor() {
    super();
    this.name = 'jobs:retry';
    this.description = 'Retry failed jobs';
    this.inputs = {
      start: { required: false, default: 0 },
      stop: { required: false, default: -1 }
    };
    this.middleware = ['auth', 'adminOnly'];
  }

  async run(data: ParamsFrom<JobsRetry>) {
    const { start, stop } = data.params;
    
    const failed = await api.resque.queue.failed();
    const endIndex = stop === -1 ? failed : Math.min(stop, failed);
    
    let retried = 0;
    for (let i = start; i < endIndex; i++) {
      try {
        await api.resque.queue.retryAndRemoveFailed(i);
        retried++;
      } catch (error) {
        api.log(\`Failed to retry job at index \${i}: \${error.message}\`, 'error');
      }
    }
    
    data.response.retried = retried;
    data.response.success = true;
  }
}
`
    },
    {
      path: 'tasks/email.ts',
      content: `import { Task, api, log, config } from 'actionhero';

export class SendEmail extends Task {
  constructor() {
    super();
    this.name = 'sendEmail';
    this.description = 'Send email notifications';
    this.frequency = 0; // No automatic runs
    this.queue = 'email';
    this.middleware = [];
  }

  async run(params: {
    to: string;
    subject: string;
    body: string;
    template?: string;
    data?: any;
  }) {
    const { to, subject, body, template, data } = params;
    
    api.log(\`Sending email to \${to}: \${subject}\`, 'info');
    
    try {
      // Here you would integrate with your email service
      // Example: SendGrid, AWS SES, Mailgun, etc.
      
      // For demo purposes, we'll just log it
      api.log(\`Email sent successfully to \${to}\`, 'info');
      
      // Track email sent
      await api.cache.increment('stats:emails:sent');
      
      return { success: true, to, subject };
    } catch (error) {
      api.log(\`Failed to send email to \${to}: \${error.message}\`, 'error');
      
      // Track failed email
      await api.cache.increment('stats:emails:failed');
      
      // Re-throw to mark task as failed
      throw error;
    }
  }
}

export class SendBulkEmail extends Task {
  constructor() {
    super();
    this.name = 'sendBulkEmail';
    this.description = 'Send bulk email to multiple recipients';
    this.frequency = 0;
    this.queue = 'email';
  }

  async run(params: {
    recipients: string[];
    subject: string;
    body: string;
    template?: string;
    batchSize?: number;
  }) {
    const { recipients, subject, body, template, batchSize = 50 } = params;
    
    api.log(\`Sending bulk email to \${recipients.length} recipients\`, 'info');
    
    // Process in batches
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
      // Queue individual emails
      for (const recipient of batch) {
        await api.tasks.enqueue('sendEmail', {
          to: recipient,
          subject,
          body,
          template
        }, 'email');
      }
      
      // Small delay between batches
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    return {
      success: true,
      totalRecipients: recipients.length,
      batches: Math.ceil(recipients.length / batchSize)
    };
  }
}
`
    },
    {
      path: 'tasks/cleanup.ts',
      content: `import { Task, api } from 'actionhero';
import { Op } from 'sequelize';
import { Session } from '../models/Session';
import { AuditLog } from '../models/AuditLog';

export class CleanupSessions extends Task {
  constructor() {
    super();
    this.name = 'cleanupSessions';
    this.description = 'Clean up expired sessions';
    this.frequency = 1000 * 60 * 60; // Every hour
    this.queue = 'maintenance';
  }

  async run() {
    const cutoff = new Date(Date.now() - 1000 * 60 * 60 * 24 * 7); // 7 days
    
    const deleted = await Session.destroy({
      where: {
        lastAccessedAt: {
          [Op.lt]: cutoff
        }
      }
    });
    
    api.log(\`Cleaned up \${deleted} expired sessions\`, 'info');
    
    return { deleted };
  }
}

export class CleanupLogs extends Task {
  constructor() {
    super();
    this.name = 'cleanupLogs';
    this.description = 'Clean up old audit logs';
    this.frequency = 1000 * 60 * 60 * 24; // Daily
    this.queue = 'maintenance';
  }

  async run() {
    const cutoff = new Date(Date.now() - 1000 * 60 * 60 * 24 * 90); // 90 days
    
    const deleted = await AuditLog.destroy({
      where: {
        createdAt: {
          [Op.lt]: cutoff
        }
      }
    });
    
    api.log(\`Cleaned up \${deleted} old audit logs\`, 'info');
    
    return { deleted };
  }
}

export class CacheMaintenance extends Task {
  constructor() {
    super();
    this.name = 'cacheMaintenance';
    this.description = 'Perform cache maintenance';
    this.frequency = 1000 * 60 * 30; // Every 30 minutes
    this.queue = 'maintenance';
  }

  async run() {
    // Get cache statistics
    const keys = await api.cache.keys();
    const stats = {
      totalKeys: keys.length,
      expired: 0,
      cleaned: 0
    };
    
    // Clean expired entries
    for (const key of keys) {
      const ttl = await api.cache.ttl(key);
      if (ttl && ttl < 0) {
        await api.cache.destroy(key);
        stats.expired++;
      }
    }
    
    api.log(\`Cache maintenance: \${stats.expired} expired keys removed\`, 'info');
    
    return stats;
  }
}
`
    },
    {
      path: 'tasks/reports.ts',
      content: `import { Task, api } from 'actionhero';
import { User } from '../models/User';
import { Order } from '../models/Order';
import { Op } from 'sequelize';

export class DailyReport extends Task {
  constructor() {
    super();
    this.name = 'dailyReport';
    this.description = 'Generate daily usage report';
    this.frequency = 1000 * 60 * 60 * 24; // Daily
    this.queue = 'reports';
  }

  async run() {
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    yesterday.setHours(0, 0, 0, 0);
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    // Gather statistics
    const newUsers = await User.count({
      where: {
        createdAt: {
          [Op.gte]: yesterday,
          [Op.lt]: today
        }
      }
    });
    
    const activeUsers = await User.count({
      where: {
        lastLoginAt: {
          [Op.gte]: yesterday,
          [Op.lt]: today
        }
      }
    });
    
    const orders = await Order.findAll({
      where: {
        createdAt: {
          [Op.gte]: yesterday,
          [Op.lt]: today
        }
      },
      attributes: [
        [api.sequelize.fn('COUNT', api.sequelize.col('id')), 'count'],
        [api.sequelize.fn('SUM', api.sequelize.col('total')), 'revenue']
      ]
    });
    
    const report = {
      date: yesterday.toISOString().split('T')[0],
      metrics: {
        newUsers,
        activeUsers,
        orders: orders[0]?.get('count') || 0,
        revenue: orders[0]?.get('revenue') || 0
      }
    };
    
    // Send report email
    await api.tasks.enqueue('sendEmail', {
      to: process.env.ADMIN_EMAIL || 'admin@example.com',
      subject: \`Daily Report - \${report.date}\`,
      template: 'daily-report',
      data: report
    }, 'email');
    
    api.log(\`Daily report generated for \${report.date}\`, 'info');
    
    return report;
  }
}

export class WeeklyAnalytics extends Task {
  constructor() {
    super();
    this.name = 'weeklyAnalytics';
    this.description = 'Generate weekly analytics report';
    this.frequency = 1000 * 60 * 60 * 24 * 7; // Weekly
    this.queue = 'reports';
  }

  async run() {
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    
    // Complex analytics logic here
    const analytics = {
      userGrowth: await this.calculateUserGrowth(weekAgo),
      engagement: await this.calculateEngagement(weekAgo),
      revenue: await this.calculateRevenue(weekAgo),
      performance: await this.getPerformanceMetrics()
    };
    
    // Store analytics
    await api.cache.save('analytics:weekly:latest', analytics, 1000 * 60 * 60 * 24 * 8);
    
    // Send to analytics service
    await api.tasks.enqueue('sendAnalytics', {
      type: 'weekly',
      data: analytics
    }, 'analytics');
    
    return analytics;
  }

  private async calculateUserGrowth(since: Date) {
    // Implementation
    return { new: 0, active: 0, churn: 0 };
  }

  private async calculateEngagement(since: Date) {
    // Implementation
    return { sessions: 0, avgDuration: 0, bounceRate: 0 };
  }

  private async calculateRevenue(since: Date) {
    // Implementation
    return { total: 0, average: 0, growth: 0 };
  }

  private async getPerformanceMetrics() {
    // Implementation
    return { responseTime: 0, errorRate: 0, uptime: 0 };
  }
}
`
    },
    {
      path: 'middleware/auth.ts',
      content: `import { api, Action } from 'actionhero';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export class AuthMiddleware {
  name = 'auth';
  global = false;
  priority = 1000;

  async preProcessor(data: any) {
    const { connection } = data;
    const token = this.extractToken(connection);

    if (!token) {
      throw new Error('No authentication token provided');
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      
      // Check if token is cached (not revoked)
      const cachedToken = await api.cache.load(\`auth:token:\${decoded.id}\`);
      if (cachedToken !== token) {
        throw new Error('Token has been revoked');
      }
      
      // Attach user to session
      data.session = { user: decoded };
      
      // Log access
      await api.tasks.enqueue('logAccess', {
        userId: decoded.id,
        action: data.actionTemplate.name,
        ip: connection.remoteIP,
        timestamp: new Date()
      }, 'audit');
      
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Token has expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token');
      }
      throw error;
    }
  }

  private extractToken(connection: any): string | null {
    // Check Authorization header
    if (connection.rawConnection.req?.headers?.authorization) {
      const parts = connection.rawConnection.req.headers.authorization.split(' ');
      if (parts.length === 2 && parts[0] === 'Bearer') {
        return parts[1];
      }
    }
    
    // Check query parameter
    if (connection.params?.token) {
      return connection.params.token;
    }
    
    // Check cookie
    if (connection.rawConnection.req?.cookies?.token) {
      return connection.rawConnection.req.cookies.token;
    }
    
    return null;
  }
}

export class AdminOnlyMiddleware {
  name = 'adminOnly';
  global = false;
  priority = 1001;

  async preProcessor(data: any) {
    const { user } = data.session || {};
    
    if (!user) {
      throw new Error('Authentication required');
    }
    
    if (user.role !== 'admin') {
      throw new Error('Admin access required');
    }
  }
}

export class OwnerOrAdminMiddleware {
  name = 'ownerOrAdmin';
  global = false;
  priority = 1001;

  async preProcessor(data: any) {
    const { user } = data.session || {};
    const { id } = data.params;
    
    if (!user) {
      throw new Error('Authentication required');
    }
    
    if (user.role !== 'admin' && user.id !== parseInt(id)) {
      throw new Error('Access denied');
    }
  }
}
`
    },
    {
      path: 'middleware/rate-limit.ts',
      content: `import { api } from 'actionhero';

export class RateLimitMiddleware {
  name = 'rateLimit';
  global = true;
  priority = 500;
  
  // Rate limit configuration
  limits = {
    default: { window: 60000, max: 100 }, // 100 requests per minute
    auth: { window: 300000, max: 5 }, // 5 auth attempts per 5 minutes
    api: { window: 60000, max: 1000 }, // 1000 API calls per minute
    heavy: { window: 300000, max: 10 } // 10 heavy operations per 5 minutes
  };

  async preProcessor(data: any) {
    const { connection, actionTemplate } = data;
    const key = \`rateLimit:\${connection.remoteIP}:\${actionTemplate.name}\`;
    
    // Get rate limit for this action
    const limitType = actionTemplate.rateLimit || 'default';
    const limit = this.limits[limitType] || this.limits.default;
    
    // Get current count
    const count = await api.cache.load(key) || 0;
    
    if (count >= limit.max) {
      const error = new Error('Rate limit exceeded');
      error['code'] = 'RATE_LIMIT_EXCEEDED';
      error['statusCode'] = 429;
      error['limit'] = limit.max;
      error['window'] = limit.window;
      throw error;
    }
    
    // Increment counter
    await api.cache.save(
      key,
      count + 1,
      limit.window,
      { increment: true }
    );
    
    // Add rate limit headers
    connection.rawConnection.responseHeaders = {
      ...connection.rawConnection.responseHeaders,
      'X-RateLimit-Limit': limit.max,
      'X-RateLimit-Remaining': limit.max - count - 1,
      'X-RateLimit-Reset': new Date(Date.now() + limit.window).toISOString()
    };
  }
}
`
    },
    {
      path: 'middleware/validation.ts',
      content: `import { api } from 'actionhero';

export class ValidationMiddleware {
  name = 'validation';
  global = true;
  priority = 700;

  validators = {
    email: (value: string) => {
      const regex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
      if (!regex.test(value)) {
        throw new Error('Invalid email format');
      }
    },
    
    'min:6': (value: string) => {
      if (value.length < 6) {
        throw new Error('Value must be at least 6 characters');
      }
    },
    
    uuid: (value: string) => {
      const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!regex.test(value)) {
        throw new Error('Invalid UUID format');
      }
    },
    
    numeric: (value: any) => {
      if (isNaN(value)) {
        throw new Error('Value must be numeric');
      }
    },
    
    boolean: (value: any) => {
      if (typeof value !== 'boolean' && value !== 'true' && value !== 'false') {
        throw new Error('Value must be boolean');
      }
    },
    
    date: (value: string) => {
      const date = new Date(value);
      if (isNaN(date.getTime())) {
        throw new Error('Invalid date format');
      }
    },
    
    json: (value: string) => {
      try {
        JSON.parse(value);
      } catch {
        throw new Error('Invalid JSON format');
      }
    }
  };

  async preProcessor(data: any) {
    const { params, actionTemplate } = data;
    
    if (!actionTemplate.inputs) return;
    
    for (const [param, config] of Object.entries(actionTemplate.inputs)) {
      const value = params[param];
      
      // Check required
      if (config.required && (value === undefined || value === null || value === '')) {
        throw new Error(\`Parameter '\${param}' is required\`);
      }
      
      // Skip validation if not provided and not required
      if (!config.required && (value === undefined || value === null)) {
        continue;
      }
      
      // Apply validators
      if (config.validator) {
        const validators = Array.isArray(config.validator) 
          ? config.validator 
          : [config.validator];
          
        for (const validator of validators) {
          if (this.validators[validator]) {
            try {
              this.validators[validator](value);
            } catch (error) {
              throw new Error(\`Parameter '\${param}': \${error.message}\`);
            }
          }
        }
      }
    }
  }
}
`
    },
    {
      path: 'initializers/database.ts',
      content: `import { Initializer, api } from 'actionhero';
import { Sequelize } from 'sequelize-typescript';
import { User } from '../models/User';
import { Product } from '../models/Product';
import { Order } from '../models/Order';
import { Session } from '../models/Session';
import { AuditLog } from '../models/AuditLog';

export class Database extends Initializer {
  constructor() {
    super();
    this.name = 'database';
    this.loadPriority = 100;
    this.startPriority = 100;
    this.stopPriority = 100;
  }

  async initialize() {
    const config = {
      database: process.env.DB_NAME || 'actionhero_dev',
      username: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASS || 'password',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      dialect: 'postgres' as const,
      logging: process.env.NODE_ENV === 'development' ? console.log : false,
      models: [User, Product, Order, Session, AuditLog]
    };

    api.sequelize = new Sequelize(config);
  }

  async start() {
    try {
      await api.sequelize.authenticate();
      api.log('Database connection established', 'info');
      
      // Sync models in development
      if (process.env.NODE_ENV === 'development') {
        await api.sequelize.sync({ alter: true });
        api.log('Database models synchronized', 'info');
      }
    } catch (error) {
      api.log(\`Database connection failed: \${error.message}\`, 'error');
      throw error;
    }
  }

  async stop() {
    if (api.sequelize) {
      await api.sequelize.close();
      api.log('Database connection closed', 'info');
    }
  }
}
`
    },
    {
      path: 'initializers/logger.ts',
      content: `import { Initializer, api, log } from 'actionhero';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

export class Logger extends Initializer {
  constructor() {
    super();
    this.name = 'logger';
    this.loadPriority = 10;
  }

  async initialize() {
    const logDir = process.env.LOG_DIR || './logs';
    
    // Console transport
    const consoleTransport = new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const metaString = Object.keys(meta).length ? JSON.stringify(meta) : '';
          return \`\${timestamp} [\${level}]: \${message} \${metaString}\`;
        })
      )
    });

    // File transport for errors
    const errorFileTransport = new DailyRotateFile({
      filename: \`\${logDir}/error-%DATE%.log\`,
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxSize: '20m',
      maxFiles: '14d',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    });

    // File transport for all logs
    const combinedFileTransport = new DailyRotateFile({
      filename: \`\${logDir}/combined-%DATE%.log\`,
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    });

    // Create winston logger
    api.winston = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      transports: [
        consoleTransport,
        errorFileTransport,
        combinedFileTransport
      ]
    });

    // Override ActionHero's log method
    const originalLog = api.log;
    api.log = (message: string, severity: string = 'info', data?: any) => {
      api.winston.log(severity, message, data);
      originalLog.call(api, message, severity, data);
    };
  }
}
`
    },
    {
      path: 'models/User.ts',
      content: `import {
  Table,
  Column,
  Model,
  DataType,
  CreatedAt,
  UpdatedAt,
  HasMany,
  BeforeCreate,
  BeforeUpdate
} from 'sequelize-typescript';
import bcrypt from 'bcrypt';
import { Order } from './Order';

@Table({
  tableName: 'users',
  timestamps: true
})
export class User extends Model {
  @Column({
    type: DataType.INTEGER,
    primaryKey: true,
    autoIncrement: true
  })
  id!: number;

  @Column({
    type: DataType.STRING,
    allowNull: false
  })
  name!: string;

  @Column({
    type: DataType.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  })
  email!: string;

  @Column({
    type: DataType.STRING,
    allowNull: false
  })
  password!: string;

  @Column({
    type: DataType.ENUM('user', 'admin'),
    defaultValue: 'user'
  })
  role!: 'user' | 'admin';

  @Column({
    type: DataType.DATE,
    allowNull: true
  })
  lastLoginAt?: Date;

  @Column({
    type: DataType.BOOLEAN,
    defaultValue: true
  })
  isActive!: boolean;

  @Column({
    type: DataType.JSONB,
    defaultValue: {}
  })
  metadata!: any;

  @CreatedAt
  createdAt!: Date;

  @UpdatedAt
  updatedAt!: Date;

  @HasMany(() => Order)
  orders!: Order[];

  // Instance methods
  async validatePassword(password: string): Promise<boolean> {
    return bcrypt.compare(password, this.password);
  }

  toSafeJSON() {
    const values = this.toJSON() as any;
    delete values.password;
    return values;
  }
}
`
    },
    {
      path: 'models/Product.ts',
      content: `import {
  Table,
  Column,
  Model,
  DataType,
  CreatedAt,
  UpdatedAt,
  HasMany,
  Index
} from 'sequelize-typescript';
import { Order } from './Order';

@Table({
  tableName: 'products',
  timestamps: true
})
export class Product extends Model {
  @Column({
    type: DataType.INTEGER,
    primaryKey: true,
    autoIncrement: true
  })
  id!: number;

  @Column({
    type: DataType.STRING,
    allowNull: false
  })
  name!: string;

  @Column({
    type: DataType.TEXT,
    allowNull: true
  })
  description?: string;

  @Column({
    type: DataType.STRING,
    allowNull: false,
    unique: true
  })
  @Index
  sku!: string;

  @Column({
    type: DataType.DECIMAL(10, 2),
    allowNull: false,
    validate: {
      min: 0
    }
  })
  price!: number;

  @Column({
    type: DataType.INTEGER,
    allowNull: false,
    defaultValue: 0,
    validate: {
      min: 0
    }
  })
  stock!: number;

  @Column({
    type: DataType.STRING,
    allowNull: true
  })
  @Index
  category?: string;

  @Column({
    type: DataType.ARRAY(DataType.STRING),
    defaultValue: []
  })
  tags!: string[];

  @Column({
    type: DataType.JSONB,
    defaultValue: {}
  })
  attributes!: any;

  @Column({
    type: DataType.BOOLEAN,
    defaultValue: true
  })
  @Index
  isActive!: boolean;

  @CreatedAt
  createdAt!: Date;

  @UpdatedAt
  updatedAt!: Date;

  // Associations would go here
  // @HasMany(() => OrderItem)
  // orderItems!: OrderItem[];
}
`
    },
    {
      path: 'test/actions/auth.test.ts',
      content: `import { Process, env, id, actionhero } from 'actionhero';
import { api } from 'actionhero';

const actionhero = new Process();

describe('Auth Actions', () => {
  beforeAll(async () => {
    await actionhero.start();
  });

  afterAll(async () => {
    await actionhero.stop();
  });

  describe('auth:register', () => {
    it('should register a new user', async () => {
      const response = await api.specHelper.runAction('auth:register', {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123'
      });

      expect(response.token).toBeDefined();
      expect(response.user).toBeDefined();
      expect(response.user.email).toBe('test@example.com');
      expect(response.user.password).toBeUndefined();
    });

    it('should fail with existing email', async () => {
      // First registration
      await api.specHelper.runAction('auth:register', {
        name: 'Test User',
        email: 'duplicate@example.com',
        password: 'password123'
      });

      // Duplicate registration
      const response = await api.specHelper.runAction('auth:register', {
        name: 'Another User',
        email: 'duplicate@example.com',
        password: 'password456'
      });

      expect(response.error).toBe('User already exists with this email');
    });

    it('should validate email format', async () => {
      const response = await api.specHelper.runAction('auth:register', {
        name: 'Test User',
        email: 'invalid-email',
        password: 'password123'
      });

      expect(response.error).toContain('Invalid email format');
    });
  });

  describe('auth:login', () => {
    beforeEach(async () => {
      await api.specHelper.runAction('auth:register', {
        name: 'Login Test User',
        email: 'login@example.com',
        password: 'correctpassword'
      });
    });

    it('should login with correct credentials', async () => {
      const response = await api.specHelper.runAction('auth:login', {
        email: 'login@example.com',
        password: 'correctpassword'
      });

      expect(response.token).toBeDefined();
      expect(response.user).toBeDefined();
      expect(response.user.email).toBe('login@example.com');
    });

    it('should fail with incorrect password', async () => {
      const response = await api.specHelper.runAction('auth:login', {
        email: 'login@example.com',
        password: 'wrongpassword'
      });

      expect(response.error).toBe('Invalid credentials');
    });

    it('should fail with non-existent user', async () => {
      const response = await api.specHelper.runAction('auth:login', {
        email: 'nonexistent@example.com',
        password: 'anypassword'
      });

      expect(response.error).toBe('Invalid credentials');
    });
  });

  describe('auth:refresh', () => {
    it('should refresh a valid token', async () => {
      // Register and login
      const loginResponse = await api.specHelper.runAction('auth:register', {
        name: 'Refresh Test User',
        email: 'refresh@example.com',
        password: 'password123'
      });

      const connection = await api.specHelper.buildConnection();
      connection.params = { token: loginResponse.token };

      const response = await api.specHelper.runAction('auth:refresh', {}, connection);

      expect(response.token).toBeDefined();
      expect(response.token).not.toBe(loginResponse.token);
    });
  });
});
`
    },
    {
      path: 'test/tasks/email.test.ts',
      content: `import { Process, env, id, actionhero, task } from 'actionhero';
import { api } from 'actionhero';

const actionhero = new Process();

describe('Email Tasks', () => {
  beforeAll(async () => {
    await actionhero.start();
  });

  afterAll(async () => {
    await actionhero.stop();
  });

  beforeEach(async () => {
    await api.resque.queue.delQueue('email');
  });

  describe('sendEmail', () => {
    it('should enqueue email task', async () => {
      await api.tasks.enqueue('sendEmail', {
        to: 'test@example.com',
        subject: 'Test Email',
        body: 'This is a test email'
      }, 'email');

      const queue = await api.resque.queue.queued('email', 0, 100);
      expect(queue.length).toBe(1);
      expect(queue[0].class).toBe('sendEmail');
      expect(queue[0].args[0].to).toBe('test@example.com');
    });

    it('should process email task', async () => {
      const result = await api.specHelper.runTask('sendEmail', {
        to: 'test@example.com',
        subject: 'Test Email',
        body: 'This is a test email'
      });

      expect(result.success).toBe(true);
      expect(result.to).toBe('test@example.com');
      expect(result.subject).toBe('Test Email');
    });
  });

  describe('sendBulkEmail', () => {
    it('should process bulk email task', async () => {
      const recipients = [
        'user1@example.com',
        'user2@example.com',
        'user3@example.com'
      ];

      const result = await api.specHelper.runTask('sendBulkEmail', {
        recipients,
        subject: 'Bulk Email',
        body: 'This is a bulk email',
        batchSize: 2
      });

      expect(result.success).toBe(true);
      expect(result.totalRecipients).toBe(3);
      expect(result.batches).toBe(2);

      // Check that individual emails were queued
      const queue = await api.resque.queue.queued('email', 0, 100);
      expect(queue.length).toBe(3);
    });
  });
});
`
    },
    {
      path: 'Dockerfile',
      content: `FROM node:20-alpine

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./
COPY pnpm-lock.yaml* ./

# Install pnpm
RUN npm install -g pnpm

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Build TypeScript
RUN pnpm run build

# Expose ports
EXPOSE 8080 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \\
  CMD node -e "require('http').get('http://localhost:8080/api/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

# Start the application
CMD ["pnpm", "start"]
`
    },
    {
      path: 'docker-compose.yml',
      content: `version: '3.8'

services:
  app:
    build: .
    container_name: actionhero-app
    restart: unless-stopped
    ports:
      - "8080:8080"  # HTTP/WebSocket
      - "5000:5000"  # TCP Socket
    environment:
      NODE_ENV: production
      REDIS_URL: redis://redis:6379
      DB_HOST: postgres
      DB_USER: actionhero
      DB_PASS: secretpassword
      DB_NAME: actionhero_production
      JWT_SECRET: \${JWT_SECRET:-your-secret-key}
      ALLOWED_HOSTS: localhost,actionhero.local
    depends_on:
      - redis
      - postgres
    volumes:
      - ./logs:/usr/src/app/logs
      - ./public:/usr/src/app/public
    networks:
      - actionhero-network

  redis:
    image: redis:7-alpine
    container_name: actionhero-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - actionhero-network

  postgres:
    image: postgres:15-alpine
    container_name: actionhero-postgres
    restart: unless-stopped
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: actionhero
      POSTGRES_PASSWORD: secretpassword
      POSTGRES_DB: actionhero_production
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - actionhero-network

  worker:
    build: .
    container_name: actionhero-worker
    restart: unless-stopped
    command: ["pnpm", "run", "start:cluster"]
    environment:
      NODE_ENV: production
      REDIS_URL: redis://redis:6379
      DB_HOST: postgres
      DB_USER: actionhero
      DB_PASS: secretpassword
      DB_NAME: actionhero_production
      WORKERS: 4
    depends_on:
      - redis
      - postgres
    networks:
      - actionhero-network

volumes:
  redis-data:
  postgres-data:

networks:
  actionhero-network:
    driver: bridge
`
    },
    {
      path: '.env.example',
      content: `# Node Environment
NODE_ENV=development

# Server Configuration
WEB_PORT=8080
SOCKET_PORT=5000
ALLOWED_HOSTS=localhost

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=actionhero
DB_PASS=password
DB_NAME=actionhero_dev

# Authentication
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=7d

# Email Configuration
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASS=your-password
ADMIN_EMAIL=admin@example.com

# Logging
LOG_LEVEL=info
LOG_DIR=./logs

# Worker Configuration
WORKER_COUNT=4
TASK_CONCURRENCY=5

# External Services
SENTRY_DSN=
ANALYTICS_KEY=
`
    },
    {
      path: 'README.md',
      content: `# ActionHero Multi-Transport API Server

A production-ready ActionHero.js backend with multi-transport support, clustering, and real-time capabilities.

## Features

- **Multi-Transport Support**: HTTP, WebSocket, and TCP Socket servers
- **Action-Based Architecture**: Modular action system with versioning
- **Real-Time Communication**: Built-in chat rooms and WebSocket support
- **Background Jobs**: Redis-backed task queue with scheduled jobs
- **Clustering**: Built-in cluster support with Redis coordination
- **Authentication**: JWT-based auth with middleware
- **Database Integration**: Sequelize ORM with PostgreSQL
- **Rate Limiting**: Configurable rate limits per action
- **API Documentation**: Auto-generated Swagger docs
- **Docker Ready**: Full Docker and Docker Compose setup
- **TypeScript**: Full TypeScript support

## Quick Start

\`\`\`bash
# Install dependencies
pnpm install

# Set up environment
cp .env.example .env

# Start Redis and PostgreSQL
docker-compose up -d redis postgres

# Run migrations
pnpm run actionhero migrate

# Start development server
pnpm run dev

# Or start production cluster
pnpm run start:cluster
\`\`\`

## Project Structure

\`\`\`
├── actions/          # API actions (controllers)
├── tasks/            # Background jobs
├── middleware/       # Action middleware
├── initializers/     # Server initializers
├── models/          # Sequelize models
├── config/          # Configuration files
├── servers/         # Custom server implementations
├── public/          # Static files
└── test/            # Test files
\`\`\`

## Multi-Transport Access

### HTTP API
\`\`\`bash
# REST endpoint
curl http://localhost:8080/api/status

# Action endpoint
curl -X POST http://localhost:8080/api/users \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer <token>" \\
  -d '{"name": "John", "email": "john@example.com"}'
\`\`\`

### WebSocket
\`\`\`javascript
const client = new ActionheroWebsocketClient();
client.connect((error, details) => {
  client.action('status', (data) => {
    console.log(data);
  });
});
\`\`\`

### TCP Socket
\`\`\`bash
telnet localhost 5000
> status
< {"id":"...","uptime":123,...}
\`\`\`

## Creating Actions

\`\`\`bash
# Generate new action
pnpm run actionhero generate action myAction

# Generate new task
pnpm run actionhero generate task myTask
\`\`\`

## Background Jobs

\`\`\`typescript
// Enqueue a job
await api.tasks.enqueue('sendEmail', {
  to: 'user@example.com',
  subject: 'Welcome!'
}, 'email');

// Schedule a job
await api.tasks.enqueueIn(60000, 'generateReport', {
  type: 'daily'
}, 'reports');
\`\`\`

## Testing

\`\`\`bash
# Run all tests
pnpm test

# Run specific test
pnpm test auth.test.ts

# Watch mode
pnpm run test:watch

# Coverage
pnpm run test:coverage
\`\`\`

## Deployment

### Docker
\`\`\`bash
# Build and run with Docker Compose
docker-compose up -d

# Scale workers
docker-compose up -d --scale worker=4
\`\`\`

### Manual Deployment
\`\`\`bash
# Build
pnpm run build

# Start production server
NODE_ENV=production pnpm start

# Start cluster
NODE_ENV=production pnpm run start:cluster
\`\`\`

## API Documentation

- Swagger UI: http://localhost:8080/api/swagger
- Status: http://localhost:8080/api/status
- Documentation: http://localhost:8080/api/documentation

## Environment Variables

See \`.env.example\` for all configuration options.

## License

MIT
`
    }
  ]
};
`