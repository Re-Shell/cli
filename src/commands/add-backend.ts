import * as fs from 'fs-extra';
import * as path from 'path';
import chalk from 'chalk';
import { selectBackendTemplate, getBackendTemplate, listBackendTemplates } from '../utils/backend-selector';
import { BackendTemplate } from '../templates/types';
import { ProgressSpinner } from '../utils/spinner';

interface AddBackendOptions {
  template?: string;
  port?: string;
  description?: string;
  list?: boolean;
  useCase?: string;
  spinner?: ProgressSpinner;
}

/**
 * Adds a new backend microservice to an existing Re-Shell project
 * 
 * @param name - Name of the backend service
 * @param options - Additional options for backend service creation
 */
export async function addBackend(
  name: string | undefined,
  options: AddBackendOptions
): Promise<void> {
  // If list flag is provided, show all templates and exit
  if (options.list) {
    listBackendTemplates();
    return;
  }

  // If no name provided, prompt for it
  if (!name) {
    console.log(chalk.red('Error: Service name is required'));
    console.log(chalk.gray('Usage: reshell add backend <service-name> [options]'));
    return;
  }

  const { template: templateId, port, description, useCase, spinner } = options;

  // Stop spinner for interactive selection
  if (spinner) {
    spinner.stop();
  }

  // Get template either by ID or through interactive selection
  let selectedTemplate: BackendTemplate | null = null;

  if (templateId) {
    selectedTemplate = getBackendTemplate(templateId);
    if (!selectedTemplate) {
      console.log(chalk.red(`Error: Template "${templateId}" not found`));
      console.log(chalk.gray('Use --list to see all available templates'));
      return;
    }
  } else {
    // Interactive selection
    selectedTemplate = await selectBackendTemplate(useCase);
    if (!selectedTemplate) {
      console.log(chalk.yellow('No template selected. Operation cancelled.'));
      return;
    }
  }

  // Restart spinner for file operations
  if (spinner) {
    spinner.start();
    spinner.setText('Creating backend service...');
  }

  // Normalize service name
  const normalizedName = name.toLowerCase().replace(/\s+/g, '-');
  const servicePath = path.resolve(process.cwd(), 'services', normalizedName);

  // Check if directory exists
  if (fs.existsSync(servicePath)) {
    if (spinner) spinner.stop();
    console.log(chalk.red(`Error: Service "${normalizedName}" already exists at ${servicePath}`));
    return;
  }

  try {
    // Create service directory
    await fs.ensureDir(servicePath);

    // Write template files
    for (const [filePath, content] of Object.entries(selectedTemplate.files)) {
      const fullPath = path.join(servicePath, filePath);
      await fs.ensureDir(path.dirname(fullPath));
      await fs.writeFile(fullPath, content as string);
    }

    // Update service-specific configurations
    await customizeService(servicePath, normalizedName, selectedTemplate, {
      port: port || selectedTemplate.port.toString(),
      description: description || `${normalizedName} backend service`
    });

    if (spinner) spinner.stop();

    // Success message
    console.log(chalk.green(`\n✅ Backend service "${normalizedName}" created successfully!`));
    console.log(chalk.cyan(`   Framework: ${selectedTemplate.displayName}`));
    console.log(chalk.cyan(`   Language: ${selectedTemplate.language}`));
    console.log(chalk.cyan(`   Location: ${servicePath}`));
    console.log(chalk.cyan(`   Port: ${port || selectedTemplate.port}`));

    // Next steps based on language
    console.log(chalk.bold('\n📋 Next steps:'));
    console.log(`   cd services/${normalizedName}`);
    
    if (selectedTemplate.language === 'python') {
      console.log('   python -m venv venv');
      console.log('   source venv/bin/activate  # On Windows: venv\\Scripts\\activate');
      console.log('   pip install -r requirements.txt');
      console.log('   python main.py  # or uvicorn main:app --reload for FastAPI');
    } else if (selectedTemplate.language === 'go') {
      console.log('   go mod init');
      console.log('   go mod tidy');
      console.log('   go run main.go');
    } else {
      console.log('   npm install  # or pnpm/yarn install');
      console.log('   npm run dev  # Start development server');
    }

    // Docker instructions
    console.log(chalk.bold('\n🐳 Docker:'));
    console.log('   docker build -t ' + normalizedName + ' .');
    console.log('   docker run -p ' + (port || selectedTemplate.port) + ':' + (port || selectedTemplate.port) + ' ' + normalizedName);

    // Integration hint
    if (fs.existsSync(path.join(process.cwd(), 'docker-compose.yml'))) {
      console.log(chalk.bold('\n🔗 Integration:'));
      console.log('   Add this service to your docker-compose.yml for full stack development');
    }

  } catch (error) {
    if (spinner) spinner.stop();
    console.log(chalk.red('Error creating backend service:'), error);
    // Clean up on error
    if (fs.existsSync(servicePath)) {
      await fs.remove(servicePath);
    }
  }
}

/**
 * Customize service files with project-specific values
 */
async function customizeService(
  servicePath: string,
  serviceName: string,
  template: BackendTemplate,
  options: { port: string; description: string }
): Promise<void> {
  // Update package.json if it exists
  const packageJsonPath = path.join(servicePath, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    const packageJson = await fs.readJson(packageJsonPath);
    packageJson.name = serviceName;
    packageJson.description = options.description;
    await fs.writeJson(packageJsonPath, packageJson, { spaces: 2 });
  }

  // Update Python project files
  const pyprojectPath = path.join(servicePath, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath)) {
    let content = await fs.readFile(pyprojectPath, 'utf-8');
    content = content.replace(/name = ".*"/, `name = "${serviceName}"`);
    content = content.replace(/description = ".*"/, `description = "${options.description}"`);
    await fs.writeFile(pyprojectPath, content);
  }

  // Update Go module
  const goModPath = path.join(servicePath, 'go.mod');
  if (fs.existsSync(goModPath)) {
    let content = await fs.readFile(goModPath, 'utf-8');
    content = content.replace(/module .*/, `module ${serviceName}`);
    await fs.writeFile(goModPath, content);
  }

  // Update environment files
  const envExamplePath = path.join(servicePath, '.env.example');
  if (fs.existsSync(envExamplePath)) {
    let content = await fs.readFile(envExamplePath, 'utf-8');
    content = content.replace(/PORT=\d+/, `PORT=${options.port}`);
    content = content.replace(/SERVICE_NAME=.*/, `SERVICE_NAME=${serviceName}`);
    await fs.writeFile(envExamplePath, content);
    
    // Also create .env file
    await fs.copy(envExamplePath, path.join(servicePath, '.env'));
  }

  // Update Dockerfile port
  const dockerfilePath = path.join(servicePath, 'Dockerfile');
  if (fs.existsSync(dockerfilePath)) {
    let content = await fs.readFile(dockerfilePath, 'utf-8');
    content = content.replace(/EXPOSE \d+/, `EXPOSE ${options.port}`);
    await fs.writeFile(dockerfilePath, content);
  }

  // Create README with service-specific information
  const readmePath = path.join(servicePath, 'README.md');
  const readmeContent = `# ${serviceName}

${options.description}

## Framework
- **Framework**: ${template.displayName}
- **Language**: ${template.language}
- **Port**: ${options.port}

## Features
${template.tags.map(tag => `- ${tag}`).join('\n')}

## Quick Start

### Development
${getQuickStartInstructions(template.language, template.framework)}

### Docker
\`\`\`bash
docker build -t ${serviceName} .
docker run -p ${options.port}:${options.port} ${serviceName}
\`\`\`

## API Endpoints

- \`GET /health\` - Health check endpoint
- \`GET /info\` - Service information

## Environment Variables

- \`PORT\` - Service port (default: ${options.port})
- \`NODE_ENV\` / \`ENVIRONMENT\` - Environment (development/production)
- \`LOG_LEVEL\` - Logging level (debug/info/warn/error)

## Integration

This service is part of the Re-Shell microservices architecture.

To integrate with other services:
1. Add to docker-compose.yml
2. Configure service discovery
3. Set up API gateway routing
`;

  await fs.writeFile(readmePath, readmeContent);
}

function getQuickStartInstructions(language: string, framework: string): string {
  if (language === 'python') {
    const pythonInstructions = `\`\`\`bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt`;

    if (framework === 'fastapi') {
      return pythonInstructions + `

# Run with auto-reload
uvicorn main:app --reload --port 8000
\`\`\``;
    } else if (framework === 'django') {
      return pythonInstructions + `

# Run migrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser

# Run development server
python manage.py runserver 0.0.0.0:8000
\`\`\``;
    } else {
      return pythonInstructions + `

# Run the application
python main.py
\`\`\``;
    }
  } else if (language === 'go') {
    return `\`\`\`bash
# Download dependencies
go mod download

# Run the application
go run main.go

# Or build and run
go build -o ${framework}-service
./${framework}-service
\`\`\``;
  } else {
    // Node.js/TypeScript
    return `\`\`\`bash
# Install dependencies
npm install  # or pnpm/yarn install

# Run in development mode
npm run dev

# Build for production
npm run build

# Run production build
npm start
\`\`\``;
  }
}