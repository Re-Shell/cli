import { BackendTemplate } from '../types';

export const meteorjsTemplate: BackendTemplate = {
  id: 'meteorjs',
  name: 'Meteor.js Full-Stack Platform',
  description: 'Real-time full-stack JavaScript platform with DDP, MongoDB, and reactive data',
  author: 'Re-shell Team',
  version: '1.0.0',
  language: 'javascript',
  framework: 'meteorjs',
  type: 'fullstack',
  category: 'api',
  features: [
    'Real-time data synchronization',
    'DDP (Distributed Data Protocol)',
    'Minimongo client-side database',
    'Built-in accounts system',
    'Hot code reload',
    'WebSocket support',
    'MongoDB integration',
    'Atmosphere package system',
    'Server-side rendering',
    'File uploads',
    'Email sending',
    'Cron jobs',
    'Docker support'
  ],
  dependencies: {
    production: {
      'meteor-node-stubs': '^1.2.5',
      '@babel/runtime': '^7.23.5',
      'bcrypt': '^5.1.1',
      'simpl-schema': '^3.4.3'
    },
    development: {
      '@types/meteor': '^2.9.7',
      '@typescript-eslint/eslint-plugin': '^6.13.2',
      '@typescript-eslint/parser': '^6.13.2',
      'eslint': '^8.55.0'
    }
  },
  structure: [
    {
      name: 'imports',
      type: 'directory',
      children: [
        {
          name: 'api',
          type: 'directory',
          children: [
            {
              name: 'tasks',
              type: 'directory',
              children: [
                {
                  name: 'tasks.js',
                  type: 'file',
                  content: `import { Mongo } from 'meteor/mongo';
import { check } from 'meteor/check';
import SimpleSchema from 'simpl-schema';

export const Tasks = new Mongo.Collection('tasks');

// Define schema
const TaskSchema = new SimpleSchema({
  text: {
    type: String,
    max: 200,
  },
  completed: {
    type: Boolean,
    defaultValue: false,
  },
  userId: {
    type: String,
    optional: true,
  },
  username: {
    type: String,
    optional: true,
  },
  private: {
    type: Boolean,
    defaultValue: false,
  },
  createdAt: {
    type: Date,
    autoValue: function() {
      if (this.isInsert) {
        return new Date();
      } else if (this.isUpsert) {
        return { $setOnInsert: new Date() };
      } else {
        this.unset();
      }
    },
  },
  updatedAt: {
    type: Date,
    autoValue: function() {
      if (this.isUpdate || this.isInsert || this.isUpsert) {
        return new Date();
      }
    },
    optional: true,
  },
});

Tasks.attachSchema(TaskSchema);

// Indexes for performance
if (Meteor.isServer) {
  Tasks.createIndex({ userId: 1 });
  Tasks.createIndex({ createdAt: -1 });
  Tasks.createIndex({ completed: 1 });
}`
                },
                {
                  name: 'methods.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { check } from 'meteor/check';
import { Tasks } from './tasks.js';

Meteor.methods({
  'tasks.insert'(text) {
    check(text, String);

    // Make sure the user is logged in before inserting a task
    if (!this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    // Insert task with user information
    return Tasks.insert({
      text,
      userId: this.userId,
      username: Meteor.users.findOne(this.userId).username,
    });
  },

  'tasks.remove'(taskId) {
    check(taskId, String);

    const task = Tasks.findOne(taskId);
    if (task.private && task.userId !== this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    Tasks.remove(taskId);
  },

  'tasks.setCompleted'(taskId, completed) {
    check(taskId, String);
    check(completed, Boolean);

    const task = Tasks.findOne(taskId);
    if (task.private && task.userId !== this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    Tasks.update(taskId, { $set: { completed } });
  },

  'tasks.setPrivate'(taskId, setToPrivate) {
    check(taskId, String);
    check(setToPrivate, Boolean);

    const task = Tasks.findOne(taskId);

    // Make sure only the task owner can make a task private
    if (task.userId !== this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    Tasks.update(taskId, { $set: { private: setToPrivate } });
  },

  'tasks.search'(searchTerm) {
    check(searchTerm, String);

    // Sanitize search term
    const regex = new RegExp(searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');

    return Tasks.find({
      $and: [
        {
          $or: [
            { private: { $ne: true } },
            { userId: this.userId },
          ],
        },
        { text: regex },
      ],
    }).fetch();
  },
});`
                },
                {
                  name: 'publications.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { Tasks } from './tasks.js';

// Publish tasks for the logged-in user
Meteor.publish('tasks', function publishTasks(limit = 10) {
  // Validate parameters
  check(limit, Match.Integer);

  if (!this.userId) {
    return this.ready();
  }

  // Reactive cursor that will update when data changes
  return Tasks.find(
    {
      $or: [
        { userId: this.userId },
        { private: { $ne: true } },
      ],
    },
    {
      limit,
      sort: { createdAt: -1 },
    }
  );
});

// Publish a single task
Meteor.publish('task.single', function publishSingleTask(taskId) {
  check(taskId, String);

  return Tasks.find({
    _id: taskId,
    $or: [
      { userId: this.userId },
      { private: { $ne: true } },
    ],
  });
});

// Publish task statistics
Meteor.publish('tasks.statistics', function publishTaskStatistics() {
  const self = this;
  let count = 0;
  let completedCount = 0;

  const handle = Tasks.find({
    $or: [
      { userId: this.userId },
      { private: { $ne: true } },
    ],
  }).observeChanges({
    added: (id, fields) => {
      count++;
      if (fields.completed) completedCount++;
      self.changed('taskStatistics', 'stats', { count, completedCount });
    },
    changed: (id, fields) => {
      if (fields.completed !== undefined) {
        completedCount += fields.completed ? 1 : -1;
        self.changed('taskStatistics', 'stats', { count, completedCount });
      }
    },
    removed: (id) => {
      const task = Tasks.findOne(id);
      count--;
      if (task?.completed) completedCount--;
      self.changed('taskStatistics', 'stats', { count, completedCount });
    },
  });

  self.added('taskStatistics', 'stats', { count, completedCount });
  self.ready();

  self.onStop(() => {
    handle.stop();
  });
});`
                }
              ]
            },
            {
              name: 'users',
              type: 'directory',
              children: [
                {
                  name: 'methods.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { Accounts } from 'meteor/accounts-base';
import { check } from 'meteor/check';

Meteor.methods({
  'users.updateProfile'(profileData) {
    check(profileData, {
      displayName: Match.Optional(String),
      bio: Match.Optional(String),
      avatar: Match.Optional(String),
      preferences: Match.Optional(Object),
    });

    if (!this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    // Update user profile
    Meteor.users.update(this.userId, {
      $set: {
        'profile.displayName': profileData.displayName,
        'profile.bio': profileData.bio,
        'profile.avatar': profileData.avatar,
        'profile.preferences': profileData.preferences,
      },
    });
  },

  'users.sendVerificationEmail'() {
    if (!this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    return Accounts.sendVerificationEmail(this.userId);
  },

  'users.changeUsername'(newUsername) {
    check(newUsername, String);

    if (!this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    // Check if username is already taken
    if (Accounts.findUserByUsername(newUsername)) {
      throw new Meteor.Error('username-exists', 'Username already taken');
    }

    Accounts.setUsername(this.userId, newUsername);
  },

  'users.deleteAccount'(password) {
    check(password, String);

    if (!this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    const user = Meteor.user();
    const result = Accounts._checkPassword(user, password);

    if (result.error) {
      throw new Meteor.Error('incorrect-password');
    }

    // Delete user data
    Tasks.remove({ userId: this.userId });
    
    // Delete user account
    Meteor.users.remove(this.userId);
  },
});`
                },
                {
                  name: 'publications.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';

// Publish current user data
Meteor.publish('userData', function publishUserData() {
  if (this.userId) {
    return Meteor.users.find(
      { _id: this.userId },
      {
        fields: {
          emails: 1,
          username: 1,
          profile: 1,
          createdAt: 1,
          'services.facebook.id': 1,
          'services.google.id': 1,
          'services.github.id': 1,
        },
      }
    );
  } else {
    this.ready();
  }
});

// Publish other users' public data
Meteor.publish('users.public', function publishPublicUsers(userIds) {
  check(userIds, [String]);

  return Meteor.users.find(
    { _id: { $in: userIds } },
    {
      fields: {
        username: 1,
        'profile.displayName': 1,
        'profile.avatar': 1,
      },
    }
  );
});

// Publish online users
Meteor.publish('users.online', function publishOnlineUsers() {
  return Meteor.users.find(
    { 'status.online': true },
    {
      fields: {
        username: 1,
        'profile.displayName': 1,
        'profile.avatar': 1,
        'status.online': 1,
        'status.lastActivity': 1,
      },
    }
  );
});`
                }
              ]
            },
            {
              name: 'files',
              type: 'directory',
              children: [
                {
                  name: 'methods.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { check } from 'meteor/check';
import fs from 'fs';
import path from 'path';

const uploadsDir = process.env.UPLOADS_DIR || '/tmp/uploads';

// Ensure uploads directory exists
if (Meteor.isServer) {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }
}

Meteor.methods({
  'files.upload'(fileName, fileData, fileType) {
    check(fileName, String);
    check(fileData, String); // Base64 encoded
    check(fileType, String);

    if (!this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (!allowedTypes.includes(fileType)) {
      throw new Meteor.Error('invalid-file-type', 'File type not allowed');
    }

    // Generate unique filename
    const fileId = Random.id();
    const extension = fileName.split('.').pop();
    const newFileName = \`\${fileId}.\${extension}\`;
    const filePath = path.join(uploadsDir, newFileName);

    try {
      // Convert base64 to buffer and save
      const buffer = Buffer.from(fileData, 'base64');
      
      // Check file size (10MB limit)
      if (buffer.length > 10 * 1024 * 1024) {
        throw new Meteor.Error('file-too-large', 'File size exceeds 10MB limit');
      }

      fs.writeFileSync(filePath, buffer);

      // Save file metadata to database
      return Files.insert({
        fileName: fileName,
        savedName: newFileName,
        fileType: fileType,
        size: buffer.length,
        userId: this.userId,
        uploadedAt: new Date(),
        path: filePath,
      });
    } catch (error) {
      throw new Meteor.Error('upload-failed', error.message);
    }
  },

  'files.download'(fileId) {
    check(fileId, String);

    const file = Files.findOne(fileId);
    if (!file) {
      throw new Meteor.Error('file-not-found');
    }

    // Check permissions
    if (file.private && file.userId !== this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    try {
      const data = fs.readFileSync(file.path);
      return {
        fileName: file.fileName,
        fileType: file.fileType,
        data: data.toString('base64'),
      };
    } catch (error) {
      throw new Meteor.Error('download-failed', error.message);
    }
  },

  'files.delete'(fileId) {
    check(fileId, String);

    const file = Files.findOne(fileId);
    if (!file) {
      throw new Meteor.Error('file-not-found');
    }

    if (file.userId !== this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    try {
      // Delete physical file
      if (fs.existsSync(file.path)) {
        fs.unlinkSync(file.path);
      }

      // Remove from database
      Files.remove(fileId);
    } catch (error) {
      throw new Meteor.Error('delete-failed', error.message);
    }
  },
});`
                },
                {
                  name: 'files.js',
                  type: 'file',
                  content: `import { Mongo } from 'meteor/mongo';
import SimpleSchema from 'simpl-schema';

export const Files = new Mongo.Collection('files');

const FileSchema = new SimpleSchema({
  fileName: {
    type: String,
  },
  savedName: {
    type: String,
  },
  fileType: {
    type: String,
  },
  size: {
    type: Number,
  },
  userId: {
    type: String,
  },
  private: {
    type: Boolean,
    defaultValue: false,
  },
  uploadedAt: {
    type: Date,
  },
  path: {
    type: String,
  },
});

Files.attachSchema(FileSchema);`
                }
              ]
            },
            {
              name: 'email',
              type: 'directory',
              children: [
                {
                  name: 'methods.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { Email } from 'meteor/email';
import { check } from 'meteor/check';
import { SSR } from 'meteor/meteorhacks:ssr';

Meteor.methods({
  'email.send'(to, subject, templateName, data) {
    check(to, String);
    check(subject, String);
    check(templateName, String);
    check(data, Object);

    if (!this.userId) {
      throw new Meteor.Error('not-authorized');
    }

    // Rate limiting
    const user = Meteor.user();
    const lastEmail = user.profile?.lastEmailSent;
    if (lastEmail && (new Date() - lastEmail) < 60000) { // 1 minute
      throw new Meteor.Error('rate-limited', 'Please wait before sending another email');
    }

    try {
      // Compile template
      SSR.compileTemplate(templateName, Assets.getText(\`email/\${templateName}.html\`));
      
      const html = SSR.render(templateName, data);

      Email.send({
        to,
        from: process.env.EMAIL_FROM || 'noreply@example.com',
        subject,
        html,
      });

      // Update last email sent time
      Meteor.users.update(this.userId, {
        $set: { 'profile.lastEmailSent': new Date() },
      });

      return { success: true };
    } catch (error) {
      throw new Meteor.Error('email-failed', error.message);
    }
  },

  'email.sendBulk'(recipients, subject, templateName, commonData) {
    check(recipients, [String]);
    check(subject, String);
    check(templateName, String);
    check(commonData, Object);

    // Admin only
    if (!this.userId || !Roles.userIsInRole(this.userId, 'admin')) {
      throw new Meteor.Error('not-authorized');
    }

    const results = [];
    
    recipients.forEach((email) => {
      try {
        Meteor.call('email.send', email, subject, templateName, commonData);
        results.push({ email, success: true });
      } catch (error) {
        results.push({ email, success: false, error: error.message });
      }
    });

    return results;
  },
});`
                }
              ]
            },
            {
              name: 'cron',
              type: 'directory',
              children: [
                {
                  name: 'jobs.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { SyncedCron } from 'meteor/littledata:synced-cron';
import { Tasks } from '../tasks/tasks.js';
import { Email } from 'meteor/email';

if (Meteor.isServer) {
  // Configure SyncedCron
  SyncedCron.config({
    log: true,
    collectionName: 'cronHistory',
    utc: true,
    collectionTTL: 172800, // 2 days
  });

  // Daily task cleanup
  SyncedCron.add({
    name: 'Clean up old completed tasks',
    schedule: function(parser) {
      return parser.text('every 1 day');
    },
    job: function() {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      const result = Tasks.remove({
        completed: true,
        updatedAt: { $lt: thirtyDaysAgo },
      });

      return \`Removed \${result} old completed tasks\`;
    },
  });

  // Hourly statistics email
  SyncedCron.add({
    name: 'Send hourly statistics',
    schedule: function(parser) {
      return parser.text('every 1 hour');
    },
    job: function() {
      const stats = {
        totalTasks: Tasks.find().count(),
        completedTasks: Tasks.find({ completed: true }).count(),
        activeTasks: Tasks.find({ completed: false }).count(),
        users: Meteor.users.find().count(),
      };

      // Send to admin
      const adminEmail = process.env.ADMIN_EMAIL;
      if (adminEmail) {
        Email.send({
          to: adminEmail,
          from: 'noreply@example.com',
          subject: 'Hourly Statistics Report',
          text: \`
            Total Tasks: \${stats.totalTasks}
            Completed: \${stats.completedTasks}
            Active: \${stats.activeTasks}
            Total Users: \${stats.users}
          \`,
        });
      }

      return stats;
    },
  });

  // Weekly digest for users
  SyncedCron.add({
    name: 'Send weekly digest',
    schedule: function(parser) {
      return parser.text('at 9:00 am on Monday');
    },
    job: function() {
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

      Meteor.users.find({ 'emails.verified': true }).forEach((user) => {
        const tasks = Tasks.find({
          userId: user._id,
          createdAt: { $gte: oneWeekAgo },
        }).fetch();

        if (tasks.length > 0) {
          Email.send({
            to: user.emails[0].address,
            from: 'noreply@example.com',
            subject: 'Your Weekly Task Summary',
            html: \`
              <h2>Hello \${user.username}!</h2>
              <p>You created \${tasks.length} tasks this week.</p>
              <p>Keep up the great work!</p>
            \`,
          });
        }
      });

      return 'Weekly digests sent';
    },
  });

  // Start cron jobs
  Meteor.startup(() => {
    SyncedCron.start();
  });
}`
                }
              ]
            }
          ]
        },
        {
          name: 'startup',
          type: 'directory',
          children: [
            {
              name: 'server',
              type: 'directory',
              children: [
                {
                  name: 'index.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { Accounts } from 'meteor/accounts-base';
import { ServiceConfiguration } from 'meteor/service-configuration';

// Import all API modules
import '../../api/tasks/methods.js';
import '../../api/tasks/publications.js';
import '../../api/users/methods.js';
import '../../api/users/publications.js';
import '../../api/files/methods.js';
import '../../api/email/methods.js';
import '../../api/cron/jobs.js';

// Security configurations
import './security.js';

// Configure accounts
Accounts.config({
  sendVerificationEmail: true,
  forbidClientAccountCreation: false,
  loginExpirationInDays: 30,
});

// Configure OAuth services
Meteor.startup(() => {
  // Facebook
  ServiceConfiguration.configurations.upsert(
    { service: 'facebook' },
    {
      $set: {
        appId: process.env.FACEBOOK_APP_ID,
        secret: process.env.FACEBOOK_APP_SECRET,
      },
    }
  );

  // Google
  ServiceConfiguration.configurations.upsert(
    { service: 'google' },
    {
      $set: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        secret: process.env.GOOGLE_CLIENT_SECRET,
      },
    }
  );

  // GitHub
  ServiceConfiguration.configurations.upsert(
    { service: 'github' },
    {
      $set: {
        clientId: process.env.GITHUB_CLIENT_ID,
        secret: process.env.GITHUB_CLIENT_SECRET,
      },
    }
  );

  // Email configuration
  process.env.MAIL_URL = process.env.MAIL_URL || 'smtp://localhost:1025';

  // Create admin user if not exists
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
  
  if (!Accounts.findUserByEmail(adminEmail)) {
    const adminId = Accounts.createUser({
      email: adminEmail,
      password: adminPassword,
      username: 'admin',
    });

    Roles.addUsersToRoles(adminId, ['admin']);
    console.log('Admin user created');
  }

  console.log('Server started successfully');
});

// User account creation hook
Accounts.onCreateUser((options, user) => {
  // Add custom fields
  user.profile = options.profile || {};
  user.profile.createdAt = new Date();
  
  // Send welcome email
  if (user.emails && user.emails[0]) {
    Meteor.setTimeout(() => {
      Email.send({
        to: user.emails[0].address,
        from: 'welcome@example.com',
        subject: 'Welcome to Meteor App!',
        text: \`Welcome \${user.username || 'User'}! We're glad to have you.\`,
      });
    }, 1000);
  }

  return user;
});`
                },
                {
                  name: 'security.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { DDPRateLimiter } from 'meteor/ddp-rate-limiter';
import { _ } from 'meteor/underscore';

// Security headers
WebApp.connectHandlers.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  next();
});

// Rate limiting rules
const rules = [
  {
    // Rate limit subscription attempts
    type: 'subscription',
    connectionId() { return true; },
    numRequests: 20,
    timeInterval: 5000,
  },
  {
    // Rate limit method calls
    type: 'method',
    userId() { return true; },
    numRequests: 50,
    timeInterval: 60000,
  },
  {
    // Specific rate limit for sensitive methods
    type: 'method',
    name(name) {
      return _.contains([
        'users.deleteAccount',
        'email.send',
        'email.sendBulk',
      ], name);
    },
    connectionId() { return true; },
    numRequests: 5,
    timeInterval: 60000,
  },
];

// Add the rules
rules.forEach((rule) => DDPRateLimiter.addRule(rule));

// Handle rate limit violations
DDPRateLimiter.setErrorMessage((rateLimitResult) => {
  return \`Error: Too many requests. Please slow down. [error-code: \${rateLimitResult.error}]\`;
});

// Disable client-side database writes
if (Meteor.isServer) {
  // Remove insecure package methods
  Meteor.users.deny({
    insert() { return true; },
    update() { return true; },
    remove() { return true; },
  });

  Tasks.deny({
    insert() { return true; },
    update() { return true; },
    remove() { return true; },
  });

  Files.deny({
    insert() { return true; },
    update() { return true; },
    remove() { return true; },
  });
}`
                }
              ]
            },
            {
              name: 'client',
              type: 'directory',
              children: [
                {
                  name: 'index.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { Tracker } from 'meteor/tracker';

// Import client modules
import './routes.js';
import './subscriptions.js';

// Configure accounts UI
Accounts.ui.config({
  passwordSignupFields: 'USERNAME_AND_EMAIL',
  minimumPasswordLength: 8,
});

// Global error handler
window.addEventListener('error', (event) => {
  console.error('Global error:', event.error);
  // Could send to error tracking service
});

// Connection status monitoring
Tracker.autorun(() => {
  const status = Meteor.status();
  if (!status.connected) {
    console.warn('Disconnected from server');
    // Show connection lost UI
  } else if (status.connected && status.retryCount > 0) {
    console.log('Reconnected to server');
    // Hide connection lost UI
  }
});

// Service worker registration (for PWA)
if ('serviceWorker' in navigator) {
  Meteor.startup(() => {
    navigator.serviceWorker.register('/sw.js')
      .then((registration) => console.log('Service Worker registered'))
      .catch((error) => console.error('Service Worker registration failed:', error));
  });
}

// Performance monitoring
if (window.performance && performance.navigation.type === 0) {
  window.addEventListener('load', () => {
    const perfData = performance.getEntriesByType('navigation')[0];
    console.log('Page load time:', perfData.loadEventEnd - perfData.fetchStart, 'ms');
  });
}`
                },
                {
                  name: 'subscriptions.js',
                  type: 'file',
                  content: `import { Meteor } from 'meteor/meteor';
import { Tracker } from 'meteor/tracker';
import { Session } from 'meteor/session';

// Global subscriptions manager
const subscriptions = {};

// User data subscription
subscriptions.userData = Meteor.subscribe('userData');

// Reactive task subscription
Tracker.autorun(() => {
  const limit = Session.get('taskLimit') || 10;
  subscriptions.tasks = Meteor.subscribe('tasks', limit);
});

// Online users subscription
subscriptions.onlineUsers = Meteor.subscribe('users.online');

// Statistics subscription
subscriptions.statistics = Meteor.subscribe('tasks.statistics');

// Handle subscription ready states
Tracker.autorun(() => {
  const allReady = Object.values(subscriptions).every(sub => sub.ready());
  Session.set('subscriptionsReady', allReady);
});

// Export for use in components
export { subscriptions };`
                },
                {
                  name: 'routes.js',
                  type: 'file',
                  content: `import { FlowRouter } from 'meteor/kadira:flow-router';
import { BlazeLayout } from 'meteor/kadira:blaze-layout';

// Route configuration
FlowRouter.wait();

// Trigger on every route
FlowRouter.triggers.enter([
  (context, redirect) => {
    // Analytics tracking
    if (window.analytics) {
      analytics.page(context.path);
    }
  },
]);

// Public routes
const publicRoutes = FlowRouter.group({
  name: 'public',
});

publicRoutes.route('/', {
  name: 'home',
  action() {
    BlazeLayout.render('mainLayout', { content: 'home' });
  },
});

publicRoutes.route('/about', {
  name: 'about',
  action() {
    BlazeLayout.render('mainLayout', { content: 'about' });
  },
});

// Authenticated routes
const authenticatedRoutes = FlowRouter.group({
  name: 'authenticated',
  triggersEnter: [
    () => {
      if (!Meteor.loggingIn() && !Meteor.userId()) {
        FlowRouter.go('login');
      }
    },
  ],
});

authenticatedRoutes.route('/dashboard', {
  name: 'dashboard',
  action() {
    BlazeLayout.render('mainLayout', { content: 'dashboard' });
  },
});

authenticatedRoutes.route('/tasks', {
  name: 'tasks',
  action() {
    BlazeLayout.render('mainLayout', { content: 'taskList' });
  },
});

authenticatedRoutes.route('/task/:taskId', {
  name: 'task.detail',
  action(params) {
    BlazeLayout.render('mainLayout', { 
      content: 'taskDetail',
      data: { taskId: params.taskId },
    });
  },
});

authenticatedRoutes.route('/profile', {
  name: 'profile',
  action() {
    BlazeLayout.render('mainLayout', { content: 'profile' });
  },
});

// Auth routes
publicRoutes.route('/login', {
  name: 'login',
  action() {
    if (Meteor.userId()) {
      FlowRouter.go('dashboard');
    } else {
      BlazeLayout.render('authLayout', { content: 'login' });
    }
  },
});

publicRoutes.route('/register', {
  name: 'register',
  action() {
    if (Meteor.userId()) {
      FlowRouter.go('dashboard');
    } else {
      BlazeLayout.render('authLayout', { content: 'register' });
    }
  },
});

// 404 route
FlowRouter.notFound = {
  action() {
    BlazeLayout.render('mainLayout', { content: 'notFound' });
  },
};

// Initialize router
Meteor.startup(() => {
  FlowRouter.initialize();
});`
                }
              ]
            }
          ]
        }
      ]
    },
    {
      name: 'server',
      type: 'directory',
      children: [
        {
          name: 'main.js',
          type: 'file',
          content: `import { Meteor } from 'meteor/meteor';
import '/imports/startup/server';

// Server-specific code
Meteor.startup(() => {
  // Enable Oplog tailing for better performance
  if (process.env.MONGO_OPLOG_URL) {
    console.log('Oplog tailing enabled');
  }

  // Log server information
  console.log('Meteor server running on:', process.env.ROOT_URL || 'http://localhost:3000');
  console.log('MongoDB URL:', process.env.MONGO_URL || 'mongodb://localhost:27017/meteor');
  console.log('Node version:', process.version);
  console.log('Meteor version:', Meteor.release);
});`
        }
      ]
    },
    {
      name: 'client',
      type: 'directory',
      children: [
        {
          name: 'main.js',
          type: 'file',
          content: `import { Meteor } from 'meteor/meteor';
import '/imports/startup/client';

// Client-specific initialization
Meteor.startup(() => {
  console.log('Meteor client started');
  
  // Check for browser features
  if (!window.WebSocket) {
    console.warn('WebSocket not supported');
  }
  
  if (!window.localStorage) {
    console.warn('LocalStorage not supported');
  }
});`
        },
        {
          name: 'main.html',
          type: 'file',
          content: `<head>
  <title>Meteor Real-time App</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Real-time full-stack JavaScript application built with Meteor">
  <link rel="manifest" href="/manifest.json">
  <link rel="icon" href="/favicon.ico">
</head>

<body>
  <div id="react-root"></div>
</body>`
        },
        {
          name: 'main.css',
          type: 'file',
          content: `/* Global styles */
* {
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  margin: 0;
  padding: 0;
  background-color: #f5f5f5;
  color: #333;
}

/* Layout styles */
.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 20px;
}

/* Header styles */
.header {
  background-color: #2c3e50;
  color: white;
  padding: 1rem 0;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.header h1 {
  margin: 0;
  font-size: 1.5rem;
}

/* Navigation styles */
.nav {
  display: flex;
  gap: 1rem;
  margin-top: 0.5rem;
}

.nav a {
  color: #ecf0f1;
  text-decoration: none;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  transition: background-color 0.3s;
}

.nav a:hover {
  background-color: #34495e;
}

.nav a.active {
  background-color: #3498db;
}

/* Task styles */
.task-item {
  background: white;
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 0.5rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  display: flex;
  align-items: center;
  gap: 1rem;
}

.task-item.completed {
  opacity: 0.7;
}

.task-item.completed .task-text {
  text-decoration: line-through;
}

.task-checkbox {
  width: 20px;
  height: 20px;
  cursor: pointer;
}

.task-text {
  flex: 1;
  font-size: 1rem;
}

.task-actions {
  display: flex;
  gap: 0.5rem;
}

/* Form styles */
.form-group {
  margin-bottom: 1rem;
}

.form-label {
  display: block;
  margin-bottom: 0.25rem;
  font-weight: 500;
}

.form-input {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
}

.form-input:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
}

/* Button styles */
.btn {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  transition: all 0.3s;
}

.btn-primary {
  background-color: #3498db;
  color: white;
}

.btn-primary:hover {
  background-color: #2980b9;
}

.btn-danger {
  background-color: #e74c3c;
  color: white;
}

.btn-danger:hover {
  background-color: #c0392b;
}

/* Loading states */
.loading {
  text-align: center;
  padding: 2rem;
}

.spinner {
  display: inline-block;
  width: 40px;
  height: 40px;
  border: 3px solid #f3f3f3;
  border-top: 3px solid #3498db;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Responsive design */
@media (max-width: 768px) {
  .nav {
    flex-direction: column;
    gap: 0.5rem;
  }
  
  .task-item {
    flex-direction: column;
    align-items: flex-start;
  }
}`
        }
      ]
    },
    {
      name: 'public',
      type: 'directory',
      children: [
        {
          name: 'manifest.json',
          type: 'file',
          content: `{
  "name": "Meteor Real-time App",
  "short_name": "MeteorApp",
  "description": "Real-time full-stack JavaScript application",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#3498db",
  "icons": [
    {
      "src": "/icons/icon-192x192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-512x512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}`
        },
        {
          name: 'sw.js',
          type: 'file',
          content: `// Service Worker for offline support
const CACHE_NAME = 'meteor-app-v1';
const urlsToCache = [
  '/',
  '/manifest.json',
  '/favicon.ico',
];

// Install event
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(urlsToCache))
  );
});

// Fetch event
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        // Cache hit - return response
        if (response) {
          return response;
        }

        // Clone the request
        const fetchRequest = event.request.clone();

        return fetch(fetchRequest).then((response) => {
          // Check if valid response
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }

          // Clone the response
          const responseToCache = response.clone();

          caches.open(CACHE_NAME)
            .then((cache) => {
              cache.put(event.request, responseToCache);
            });

          return response;
        });
      })
  );
});

// Activate event
self.addEventListener('activate', (event) => {
  const cacheWhitelist = [CACHE_NAME];
  
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});`
        }
      ]
    },
    {
      name: 'private',
      type: 'directory',
      children: [
        {
          name: 'email',
          type: 'directory',
          children: [
            {
              name: 'welcome.html',
              type: 'file',
              content: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background-color: #3498db; color: white; padding: 20px; text-align: center; }
    .content { padding: 20px; background-color: #f8f9fa; }
    .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
    .button { display: inline-block; padding: 10px 20px; background-color: #3498db; color: white; text-decoration: none; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Welcome to Meteor App!</h1>
    </div>
    <div class="content">
      <h2>Hello {{username}}!</h2>
      <p>Thank you for joining our real-time application. We're excited to have you on board!</p>
      <p>Here are some things you can do:</p>
      <ul>
        <li>Create and manage tasks in real-time</li>
        <li>Collaborate with other users</li>
        <li>Upload and share files</li>
        <li>Receive instant notifications</li>
      </ul>
      <p style="text-align: center; margin-top: 30px;">
        <a href="{{url}}" class="button">Get Started</a>
      </p>
    </div>
    <div class="footer">
      <p>&copy; 2024 Meteor App. All rights reserved.</p>
      <p>If you have any questions, reply to this email.</p>
    </div>
  </div>
</body>
</html>`
            },
            {
              name: 'digest.html',
              type: 'file',
              content: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
    .content { padding: 20px; }
    .task { background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }
    .stats { display: flex; justify-content: space-around; text-align: center; margin: 20px 0; }
    .stat-box { padding: 20px; background-color: #ecf0f1; border-radius: 8px; }
    .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Your Weekly Digest</h1>
      <p>{{date}}</p>
    </div>
    <div class="content">
      <h2>Hi {{username}},</h2>
      <p>Here's your activity summary for this week:</p>
      
      <div class="stats">
        <div class="stat-box">
          <h3>{{totalTasks}}</h3>
          <p>Tasks Created</p>
        </div>
        <div class="stat-box">
          <h3>{{completedTasks}}</h3>
          <p>Tasks Completed</p>
        </div>
        <div class="stat-box">
          <h3>{{completionRate}}%</h3>
          <p>Completion Rate</p>
        </div>
      </div>
      
      <h3>Recent Tasks:</h3>
      {{#each tasks}}
      <div class="task">
        <strong>{{text}}</strong>
        <br>
        <small>Status: {{#if completed}}Completed{{else}}Pending{{/if}}</small>
      </div>
      {{/each}}
    </div>
    <div class="footer">
      <p>Keep up the great work!</p>
      <p><a href="{{unsubscribeUrl}}">Unsubscribe</a> from these emails</p>
    </div>
  </div>
</body>
</html>`
            }
          ]
        }
      ]
    },
    {
      name: '.meteor',
      type: 'directory',
      children: [
        {
          name: 'packages',
          type: 'file',
          content: `# Meteor packages used by this project

meteor-base@1.5.1             # Core Meteor packages
mobile-experience@1.1.0       # Mobile experience packages
mongo@1.16.7                  # MongoDB driver
reactive-var@1.0.12          # Reactive variables
tracker@1.3.2                # Dependency tracker

standard-minifier-css@1.9.2   # CSS minifier
standard-minifier-js@2.8.1    # JavaScript minifier
es5-shim@4.8.0               # ECMAScript 5 compatibility
ecmascript@0.16.7            # ECMAScript features
typescript@4.9.4             # TypeScript support
shell-server@0.5.0           # Server-side shell

# UI packages
blaze-html-templates@2.0.0   # Compile .html files into Blaze
jquery@3.0.0                 # jQuery library
kadira:flow-router           # Client-side routing
kadira:blaze-layout          # Layout manager for Blaze

# Accounts
accounts-password@2.3.4      # Password authentication
accounts-ui@1.4.2           # Accounts UI
accounts-facebook@1.3.3     # Facebook OAuth
accounts-google@1.4.0       # Google OAuth
accounts-github@1.5.0       # GitHub OAuth
service-configuration@1.3.1  # OAuth service configuration

# Data
aldeed:collection2          # Schema validation
aldeed:simple-schema        # Schema definitions
dburles:collection-helpers  # Collection helpers
reywood:publish-composite   # Composite publications
matb33:collection-hooks     # Collection hooks

# Security
ddp-rate-limiter@1.2.0      # DDP rate limiting
browser-policy@1.1.0        # Browser policy
force-ssl@1.1.0            # Force SSL

# Utilities
meteorhacks:ssr            # Server-side rendering
email@2.2.5                # Email sending
littledata:synced-cron     # Cron jobs
ostrio:files               # File uploads
alanning:roles             # Role-based access control
meteorhacks:aggregate      # MongoDB aggregation
check@1.3.2                # Check arguments
random@1.2.1               # Random generator

# Development
insecure@1.0.7             # Allow DB writes (remove in production)
autopublish@1.0.7          # Publish all data (remove in production)`
        },
        {
          name: 'release',
          type: 'file',
          content: `METEOR@2.13.3`
        }
      ]
    },
    {
      name: 'package.json',
      type: 'file',
      content: `{
  "name": "meteor-realtime-app",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "start": "meteor run",
    "start:dev": "meteor run --settings settings-dev.json",
    "start:prod": "meteor run --production --settings settings-prod.json",
    "test": "meteor test --driver-package meteortesting:mocha",
    "test:watch": "TEST_WATCH=1 meteor test --driver-package meteortesting:mocha",
    "test:full": "meteor test --full-app --driver-package meteortesting:mocha",
    "visualize": "meteor --production --extra-packages bundle-visualizer",
    "deploy": "meteor deploy myapp.meteorapp.com --settings settings-prod.json",
    "build": "meteor build ../output --architecture os.linux.x86_64",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix"
  },
  "dependencies": {
    "@babel/runtime": "^7.23.5",
    "bcrypt": "^5.1.1",
    "meteor-node-stubs": "^1.2.5",
    "simpl-schema": "^3.4.3"
  },
  "devDependencies": {
    "@types/meteor": "^2.9.7",
    "@typescript-eslint/eslint-plugin": "^6.13.2",
    "@typescript-eslint/parser": "^6.13.2",
    "eslint": "^8.55.0",
    "eslint-config-meteor": "^0.1.1",
    "eslint-plugin-meteor": "^7.3.0"
  },
  "meteor": {
    "mainModule": {
      "client": "client/main.js",
      "server": "server/main.js"
    }
  },
  "eslintConfig": {
    "extends": [
      "meteor"
    ],
    "parser": "@typescript-eslint/parser",
    "parserOptions": {
      "ecmaVersion": 2020,
      "sourceType": "module"
    },
    "rules": {
      "no-console": "off",
      "meteor/no-session": "off"
    }
  }
}`
    },
    {
      name: 'settings-dev.json',
      type: 'file',
      content: `{
  "public": {
    "environment": "development",
    "analyticsKey": "dev-analytics-key",
    "features": {
      "enableNotifications": true,
      "enableFileUploads": true,
      "maxFileSize": 10485760
    }
  },
  "private": {
    "email": {
      "from": "noreply@dev.example.com",
      "smtp": {
        "host": "localhost",
        "port": 1025,
        "secure": false
      }
    },
    "oauth": {
      "facebook": {
        "appId": "dev-facebook-app-id",
        "secret": "dev-facebook-secret"
      },
      "google": {
        "clientId": "dev-google-client-id",
        "secret": "dev-google-secret"
      },
      "github": {
        "clientId": "dev-github-client-id",
        "secret": "dev-github-secret"
      }
    },
    "admin": {
      "email": "admin@dev.example.com",
      "password": "devadmin123"
    }
  },
  "galaxy.meteor.com": {
    "env": {
      "MONGO_URL": "mongodb://localhost:27017/meteor-dev",
      "ROOT_URL": "http://localhost:3000"
    }
  }
}`
    },
    {
      name: 'settings-prod.json',
      type: 'file',
      content: `{
  "public": {
    "environment": "production",
    "analyticsKey": "prod-analytics-key",
    "features": {
      "enableNotifications": true,
      "enableFileUploads": true,
      "maxFileSize": 52428800
    }
  },
  "private": {
    "email": {
      "from": "noreply@example.com",
      "smtp": {
        "host": "smtp.sendgrid.net",
        "port": 587,
        "secure": false,
        "auth": {
          "user": "apikey",
          "pass": "your-sendgrid-api-key"
        }
      }
    },
    "oauth": {
      "facebook": {
        "appId": "prod-facebook-app-id",
        "secret": "prod-facebook-secret"
      },
      "google": {
        "clientId": "prod-google-client-id",
        "secret": "prod-google-secret"
      },
      "github": {
        "clientId": "prod-github-client-id",
        "secret": "prod-github-secret"
      }
    },
    "admin": {
      "email": "admin@example.com",
      "password": "change-this-in-production"
    }
  },
  "galaxy.meteor.com": {
    "env": {
      "MONGO_URL": "mongodb+srv://user:pass@cluster.mongodb.net/dbname",
      "MONGO_OPLOG_URL": "mongodb+srv://user:pass@cluster.mongodb.net/local",
      "ROOT_URL": "https://myapp.com"
    }
  }
}`
    },
    {
      name: 'Dockerfile',
      type: 'file',
      content: `# Build stage
FROM geoffreybooth/meteor-base:2.13.3 as builder

# Copy app source
COPY . /app
WORKDIR /app

# Install dependencies and build
RUN meteor npm install
RUN meteor build --directory /built_app --architecture os.linux.x86_64

# Runtime stage
FROM node:14.21.3-alpine

# Install dependencies
RUN apk add --no-cache python3 make g++ curl

# Copy built app
COPY --from=builder /built_app/bundle /app
WORKDIR /app

# Install npm dependencies
RUN cd programs/server && npm install

# Set environment variables
ENV PORT=3000
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:$PORT/health || exit 1

# Expose port
EXPOSE 3000

# Start the app
CMD ["node", "main.js"]`
    },
    {
      name: 'docker-compose.yml',
      type: 'file',
      content: `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - ROOT_URL=http://localhost:3000
      - MONGO_URL=mongodb://mongo:27017/meteor
      - MONGO_OPLOG_URL=mongodb://mongo:27017/local
      - MAIL_URL=smtp://mailhog:1025
      - NODE_ENV=development
    depends_on:
      - mongo
      - mailhog
    volumes:
      - ./settings-dev.json:/app/settings.json
    command: node main.js --settings /app/settings.json

  mongo:
    image: mongo:6.0
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
      - mongo_config:/data/configdb
    command: mongod --replSet rs0 --oplogSize 128

  mongo-init:
    image: mongo:6.0
    depends_on:
      - mongo
    restart: "no"
    command: >
      mongosh --host mongo:27017 --eval 
      'rs.initiate({
        _id: "rs0",
        members: [{ _id: 0, host: "mongo:27017" }]
      })'

  mailhog:
    image: mailhog/mailhog
    ports:
      - "1025:1025"  # SMTP server
      - "8025:8025"  # Web UI

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  mongo_data:
  mongo_config:
  redis_data:`
    },
    {
      name: '.dockerignore',
      type: 'file',
      content: `node_modules/
.meteor/local/
.meteor/dev_bundle/
npm-debug.log*
.DS_Store
.git/
.gitignore
*.md
.dockerignore
Dockerfile
docker-compose.yml`
    },
    {
      name: 'README.md',
      type: 'file',
      content: `# Meteor.js Real-time Application

A full-stack JavaScript application built with Meteor.js, featuring real-time data synchronization, user authentication, and reactive UI.

## Features

- **Real-time Data Sync**: Automatic client-server data synchronization using DDP
- **User Authentication**: Built-in accounts system with OAuth providers
- **Reactive UI**: Automatic UI updates when data changes
- **MongoDB Integration**: Native MongoDB support with Minimongo on the client
- **File Uploads**: Secure file upload and management system
- **Email System**: Transactional email support with templates
- **Cron Jobs**: Scheduled tasks with SyncedCron
- **WebSocket Support**: Real-time bidirectional communication
- **Hot Code Reload**: Instant updates without losing client state
- **PWA Support**: Progressive Web App with offline capabilities

## Getting Started

### Prerequisites

- Node.js 14.x or higher
- MongoDB 4.4 or higher
- Meteor 2.13.3 or higher

### Installation

1. Install Meteor:
\`\`\`bash
curl https://install.meteor.com/ | sh
\`\`\`

2. Clone the repository and install dependencies:
\`\`\`bash
cd meteor-app
meteor npm install
\`\`\`

3. Run the development server:
\`\`\`bash
meteor run --settings settings-dev.json
\`\`\`

### Docker Setup

Run the entire stack with Docker:
\`\`\`bash
docker-compose up
\`\`\`

This starts:
- Meteor app on http://localhost:3000
- MongoDB on localhost:27017
- MailHog on http://localhost:8025
- Redis on localhost:6379

## Project Structure

\`\`\`
├── imports/          # Shared code between client and server
│   ├── api/         # API methods, publications, and collections
│   └── startup/     # Startup configuration
├── client/          # Client-only code
├── server/          # Server-only code
├── public/          # Public assets
├── private/         # Private assets (server only)
└── .meteor/         # Meteor configuration
\`\`\`

## Key Concepts

### Collections
\`\`\`javascript
// Define a collection
export const Tasks = new Mongo.Collection('tasks');

// Attach schema
Tasks.attachSchema(TaskSchema);
\`\`\`

### Methods (RPC)
\`\`\`javascript
Meteor.methods({
  'tasks.insert'(text) {
    check(text, String);
    return Tasks.insert({ text, userId: this.userId });
  }
});
\`\`\`

### Publications/Subscriptions
\`\`\`javascript
// Server: Publish data
Meteor.publish('tasks', function(limit) {
  return Tasks.find({ userId: this.userId }, { limit });
});

// Client: Subscribe to data
const subscription = Meteor.subscribe('tasks', 10);
\`\`\`

### Reactive Data
\`\`\`javascript
// Automatically re-runs when data changes
Tracker.autorun(() => {
  const tasks = Tasks.find().fetch();
  console.log(\`You have \${tasks.length} tasks\`);
});
\`\`\`

## Authentication

Configure OAuth providers in settings.json:
\`\`\`json
{
  "private": {
    "oauth": {
      "google": {
        "clientId": "your-client-id",
        "secret": "your-secret"
      }
    }
  }
}
\`\`\`

## Deployment

### Build for production:
\`\`\`bash
meteor build ../output --architecture os.linux.x86_64
\`\`\`

### Deploy to Meteor Galaxy:
\`\`\`bash
meteor deploy myapp.meteorapp.com --settings settings-prod.json
\`\`\`

### Environment Variables:
- \`ROOT_URL\`: Your app's URL
- \`MONGO_URL\`: MongoDB connection string
- \`MONGO_OPLOG_URL\`: MongoDB oplog URL (optional, for performance)
- \`MAIL_URL\`: SMTP connection string

## Security

- Rate limiting with DDPRateLimiter
- Method argument validation with check
- Browser policies for XSS protection
- Force SSL in production
- Secure file uploads with validation

## Testing

Run tests:
\`\`\`bash
meteor test --driver-package meteortesting:mocha
\`\`\`

## Performance Tips

1. Enable Oplog tailing for real-time performance
2. Use indexes on frequently queried fields
3. Limit publication data with field projections
4. Implement pagination for large datasets
5. Use Meteor.defer() for non-critical operations

## Learn More

- [Meteor Guide](https://guide.meteor.com)
- [Meteor API Docs](https://docs.meteor.com)
- [Meteor Forums](https://forums.meteor.com)
- [Atmosphere Packages](https://atmospherejs.com)`
    }
  ],
  setupInstructions: `# Meteor.js Setup Instructions

1. **Install Meteor CLI**:
   \`\`\`bash
   # macOS/Linux
   curl https://install.meteor.com/ | sh
   
   # Windows (PowerShell as Admin)
   choco install meteor
   \`\`\`

2. **Create new project**:
   \`\`\`bash
   meteor create my-app --bare
   cd my-app
   \`\`\`

3. **Install dependencies**:
   \`\`\`bash
   meteor npm install
   \`\`\`

4. **Configure settings**:
   - Copy settings-dev.json and update with your credentials
   - Set up OAuth providers (Facebook, Google, GitHub)
   - Configure email settings

5. **Run development server**:
   \`\`\`bash
   meteor run --settings settings-dev.json
   \`\`\`

6. **Access the application**:
   - Open http://localhost:3000
   - Create an account or login
   - Start creating real-time tasks

## Docker Development

For Docker-based development:
\`\`\`bash
docker-compose up
\`\`\`

## Production Deployment

1. **Build the application**:
   \`\`\`bash
   meteor build ../build --architecture os.linux.x86_64
   \`\`\`

2. **Deploy to Meteor Galaxy**:
   \`\`\`bash
   meteor deploy myapp.meteorapp.com --settings settings-prod.json
   \`\`\`

3. **Or deploy with Docker**:
   \`\`\`bash
   docker build -t myapp .
   docker run -e ROOT_URL=https://myapp.com -e MONGO_URL=mongodb://... myapp
   \`\`\``
};