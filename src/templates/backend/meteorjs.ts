import { BackendTemplate } from '../types';

export const meteorjsTemplate: BackendTemplate = {
  id: 'meteorjs',
  name: 'Meteor.js',
  displayName: 'Meteor.js',
  description: 'Real-time full-stack JavaScript platform with DDP, MongoDB, and reactive data',
  language: 'javascript',
  framework: 'meteorjs',
  version: '2.14.0',
  tags: ['fullstack', 'real-time', 'mongodb', 'ddp', 'reactive'],
  port: 3000,
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
    'meteor-node-stubs': '^1.2.5',
    '@babel/runtime': '^7.23.5',
    'bcrypt': '^5.1.1',
    'simpl-schema': '^3.4.3'
  },
  devDependencies: {
    '@types/meteor': '^2.9.7',
    '@typescript-eslint/eslint-plugin': '^6.13.2',
    '@typescript-eslint/parser': '^6.13.2',
    'eslint': '^8.55.0',
    'eslint-config-meteor': '^0.1.1',
    'eslint-plugin-meteor': '^7.3.0'
  },
  files: {
    'package.json': `{
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
}`,
    '.meteor/packages': `# Meteor packages used by this project

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
autopublish@1.0.7          # Publish all data (remove in production)`,
    '.meteor/release': `METEOR@2.13.3`,
    'server/main.js': `import { Meteor } from 'meteor/meteor';

Meteor.startup(() => {
  // Code to run on server startup
  console.log('Meteor server started');
  
  // Enable Oplog tailing for better performance
  if (process.env.MONGO_OPLOG_URL) {
    console.log('Oplog tailing enabled');
  }
  
  // Log server information
  console.log('Meteor server running on:', process.env.ROOT_URL || 'http://localhost:3000');
  console.log('MongoDB URL:', process.env.MONGO_URL || 'mongodb://localhost:27017/meteor');
  console.log('Node version:', process.version);
  console.log('Meteor version:', Meteor.release);
});`,
    'client/main.js': `import { Meteor } from 'meteor/meteor';
import { Template } from 'meteor/templating';
import { ReactiveVar } from 'meteor/reactive-var';

import './main.html';

Template.hello.onCreated(function helloOnCreated() {
  // counter starts at 0
  this.counter = new ReactiveVar(0);
});

Template.hello.helpers({
  counter() {
    return Template.instance().counter.get();
  },
});

Template.hello.events({
  'click button'(event, instance) {
    // increment the counter when button is clicked
    instance.counter.set(instance.counter.get() + 1);
  },
});`,
    'client/main.html': `<head>
  <title>Meteor Real-time App</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Real-time full-stack JavaScript application built with Meteor">
</head>

<body>
  <h1>Welcome to Meteor!</h1>
  {{> hello}}
  {{> info}}
</body>

<template name="hello">
  <button>Click Me</button>
  <p>You've pressed the button {{counter}} times.</p>
</template>

<template name="info">
  <h2>Learn Meteor!</h2>
  <ul>
    <li><a href="https://www.meteor.com/tutorials/blaze/creating-an-app" target="_blank">Do the Tutorial</a></li>
    <li><a href="http://guide.meteor.com" target="_blank">Follow the Guide</a></li>
    <li><a href="https://docs.meteor.com" target="_blank">Read the Docs</a></li>
    <li><a href="https://forums.meteor.com" target="_blank">Discussions</a></li>
  </ul>
</template>`,
    'client/main.css': `body {
  padding: 10px;
  font-family: sans-serif;
}`,
    'README.md': `# Meteor.js Real-time Application

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
meteor run
\`\`\`

The application will be available at http://localhost:3000

## Project Structure

\`\`\`
├── client/          # Client-only code
├── server/          # Server-only code
├── public/          # Public assets
├── private/         # Private assets (server only)
└── .meteor/         # Meteor configuration
\`\`\`

## Deployment

### Build for production:
\`\`\`bash
meteor build ../output --architecture os.linux.x86_64
\`\`\`

### Deploy to Meteor Galaxy:
\`\`\`bash
meteor deploy myapp.meteorapp.com
\`\`\`

## Learn More

- [Meteor Guide](https://guide.meteor.com)
- [Meteor API Docs](https://docs.meteor.com)
- [Meteor Forums](https://forums.meteor.com)
- [Atmosphere Packages](https://atmospherejs.com)`
  }
};