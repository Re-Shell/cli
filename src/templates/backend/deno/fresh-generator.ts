/**
 * Fresh Framework Template Generator
 * Next-gen web framework with islands architecture
 */

import { DenoBackendGenerator } from './deno-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class FreshGenerator extends DenoBackendGenerator {
  constructor() {
    super('Fresh');
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate Fresh-specific files
    await this.generateFreshConfig(projectPath, options);
    await this.generateMainApp(projectPath);
    await this.generateDevScript(projectPath);

    // Generate routes
    await this.generateRoutes(projectPath);

    // Generate islands (interactive components)
    await this.generateIslands(projectPath);

    // Generate components
    await this.generateComponents(projectPath);

    // Generate API routes
    await this.generateAPIRoutes(projectPath);

    // Generate utilities
    await this.generateUtilities(projectPath);

    // Generate static files
    await this.generateStaticFiles(projectPath);

    // Update Fresh-specific configurations
    await this.updateFreshConfig(projectPath, options);
  }

  private async generateFreshConfig(projectPath: string, options: any): Promise<void> {
    const freshConfig = `import { defineConfig } from "$fresh/server.ts";
import twindPlugin from "$fresh/plugins/twind.ts";
import twindConfig from "./twind.config.ts";

export default defineConfig({
  plugins: [twindPlugin(twindConfig)],
});
`;

    await fs.writeFile(
      path.join(projectPath, 'fresh.config.ts'),
      freshConfig
    );

    // Generate twind config
    const twindConfig = `import { Options } from "$fresh/plugins/twind.ts";

export default {
  selfURL: import.meta.url,
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
  preflight: {
    '@font-face': [
      {
        fontFamily: 'Inter',
        fontWeight: '100 900',
        fontDisplay: 'swap',
        fontStyle: 'normal',
        fontNamedInstance: 'Regular',
        src: 'url("/fonts/Inter.woff2") format("woff2")',
      },
    ],
  },
} as Options;
`;

    await fs.writeFile(
      path.join(projectPath, 'twind.config.ts'),
      twindConfig
    );
  }

  private async generateMainApp(projectPath: string): Promise<void> {
    const mainContent = `#!/usr/bin/env -S deno run -A --watch=static/,routes/

import dev from "$fresh/dev.ts";
import config from "./fresh.config.ts";

import "$std/dotenv/load.ts";

await dev(import.meta.url, "./main.ts", config);
`;

    await fs.writeFile(
      path.join(projectPath, 'dev.ts'),
      mainContent
    );

    const prodMainContent = `import { start } from "$fresh/server.ts";
import manifest from "./fresh.gen.ts";
import config from "./fresh.config.ts";

import "$std/dotenv/load.ts";

await start(manifest, config);
`;

    await fs.writeFile(
      path.join(projectPath, 'main.ts'),
      prodMainContent
    );
  }

  private async generateDevScript(projectPath: string): Promise<void> {
    // Update deno.json for Fresh
    const denoJsonPath = path.join(projectPath, 'deno.json');
    const denoConfig = JSON.parse(await fs.readFile(denoJsonPath, 'utf-8'));
    
    denoConfig.imports = {
      ...denoConfig.imports,
      "$fresh/": "https://deno.land/x/fresh@1.6.1/",
      "preact": "https://esm.sh/preact@10.19.2",
      "preact/": "https://esm.sh/preact@10.19.2/",
      "@preact/signals": "https://esm.sh/*@preact/signals@1.2.1",
      "@preact/signals-core": "https://esm.sh/*@preact/signals-core@1.5.0",
      "twind": "https://esm.sh/twind@0.16.19",
      "twind/": "https://esm.sh/twind@0.16.19/",
      "$std/": "https://deno.land/std@0.212.0/",
    };

    denoConfig.tasks = {
      ...denoConfig.tasks,
      "start": "deno run -A --watch=static/,routes/ dev.ts",
      "build": "deno run -A dev.ts build",
      "preview": "deno run -A main.ts",
      "update": "deno run -A -r https://fresh.deno.dev/update .",
    };

    denoConfig.exclude = ["**/_fresh/*"];

    await fs.writeFile(
      denoJsonPath,
      JSON.stringify(denoConfig, null, 2)
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'routes'), { recursive: true });

    // Index route
    const indexRouteContent = `import { Head } from "$fresh/runtime.ts";
import { Handlers, PageProps } from "$fresh/server.ts";
import Counter from "../islands/Counter.tsx";
import Header from "../components/Header.tsx";

interface Data {
  message: string;
  count: number;
}

export const handler: Handlers<Data> = {
  async GET(req, ctx) {
    // You can fetch data here
    const data = {
      message: "Welcome to Fresh!",
      count: 0,
    };
    return ctx.render(data);
  },
};

export default function Home({ data }: PageProps<Data>) {
  return (
    <>
      <Head>
        <title>Fresh App</title>
        <meta name="description" content="A Fresh Deno application" />
      </Head>
      <div class="min-h-screen bg-gray-50">
        <Header />
        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div class="text-center">
            <h1 class="text-4xl font-bold text-gray-900 mb-4">
              {data.message}
            </h1>
            <p class="text-xl text-gray-600 mb-8">
              Built with Fresh and Deno
            </p>
            <div class="flex justify-center">
              <Counter start={data.count} />
            </div>
          </div>

          <div class="mt-16 grid grid-cols-1 md:grid-cols-3 gap-8">
            <div class="bg-white p-6 rounded-lg shadow">
              <h2 class="text-xl font-semibold mb-2">Island Architecture</h2>
              <p class="text-gray-600">
                Fresh uses islands of interactivity for optimal performance.
              </p>
            </div>
            <div class="bg-white p-6 rounded-lg shadow">
              <h2 class="text-xl font-semibold mb-2">TypeScript First</h2>
              <p class="text-gray-600">
                Built with TypeScript for type safety and developer experience.
              </p>
            </div>
            <div class="bg-white p-6 rounded-lg shadow">
              <h2 class="text-xl font-semibold mb-2">No Build Step</h2>
              <p class="text-gray-600">
                Deploy directly without compilation or bundling.
              </p>
            </div>
          </div>
        </main>
      </div>
    </>
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'routes', 'index.tsx'),
      indexRouteContent
    );

    // About route
    const aboutRouteContent = `import { Head } from "$fresh/runtime.ts";
import Header from "../components/Header.tsx";

export default function About() {
  return (
    <>
      <Head>
        <title>About - Fresh App</title>
      </Head>
      <div class="min-h-screen bg-gray-50">
        <Header />
        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <h1 class="text-4xl font-bold text-gray-900 mb-8">About</h1>
          <div class="prose prose-lg">
            <p>
              This is a Fresh application built with Deno. Fresh is a next
              generation web framework, built for speed, reliability, and
              simplicity.
            </p>
            <h2>Features</h2>
            <ul>
              <li>Server-side rendering</li>
              <li>Island based architecture</li>
              <li>Zero runtime overhead</li>
              <li>TypeScript support out of the box</li>
              <li>No build step</li>
            </ul>
          </div>
        </main>
      </div>
    </>
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'routes', 'about.tsx'),
      aboutRouteContent
    );

    // 404 page
    const notFoundContent = `import { Head } from "$fresh/runtime.ts";

export default function NotFoundPage() {
  return (
    <>
      <Head>
        <title>404 - Page not found</title>
      </Head>
      <div class="min-h-screen bg-gray-50 flex items-center justify-center">
        <div class="text-center">
          <h1 class="text-6xl font-bold text-gray-900 mb-4">404</h1>
          <p class="text-xl text-gray-600 mb-8">Page not found</p>
          <a href="/" class="text-blue-600 hover:underline">
            Go back home
          </a>
        </div>
      </div>
    </>
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'routes', '_404.tsx'),
      notFoundContent
    );

    // App wrapper
    const appContent = `import { AppProps } from "$fresh/server.ts";

export default function App({ Component }: AppProps) {
  return (
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link rel="stylesheet" href="/styles.css" />
      </head>
      <body>
        <Component />
      </body>
    </html>
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'routes', '_app.tsx'),
      appContent
    );
  }

  private async generateIslands(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'islands'), { recursive: true });

    // Counter island (interactive component)
    const counterIslandContent = `import { useState } from "preact/hooks";
import { Button } from "../components/Button.tsx";

interface CounterProps {
  start: number;
}

export default function Counter(props: CounterProps) {
  const [count, setCount] = useState(props.start);

  return (
    <div class="flex gap-4 items-center">
      <Button onClick={() => setCount(count - 1)}>-1</Button>
      <p class="text-3xl font-mono">{count}</p>
      <Button onClick={() => setCount(count + 1)}>+1</Button>
    </div>
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'islands', 'Counter.tsx'),
      counterIslandContent
    );

    // Form island
    const formIslandContent = `import { useState } from "preact/hooks";
import { Button } from "../components/Button.tsx";

interface FormData {
  name: string;
  email: string;
  message: string;
}

export default function ContactForm() {
  const [formData, setFormData] = useState<FormData>({
    name: "",
    email: "",
    message: "",
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("/api/contact", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });

      const data = await response.json();
      setResult({
        success: response.ok,
        message: data.message,
      });

      if (response.ok) {
        setFormData({ name: "", email: "", message: "" });
      }
    } catch (error) {
      setResult({
        success: false,
        message: "An error occurred. Please try again.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: Event) => {
    const target = e.target as HTMLInputElement | HTMLTextAreaElement;
    setFormData({
      ...formData,
      [target.name]: target.value,
    });
  };

  return (
    <form onSubmit={handleSubmit} class="space-y-4">
      <div>
        <label htmlFor="name" class="block text-sm font-medium text-gray-700">
          Name
        </label>
        <input
          type="text"
          id="name"
          name="name"
          value={formData.name}
          onChange={handleChange}
          required
          class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
        />
      </div>

      <div>
        <label htmlFor="email" class="block text-sm font-medium text-gray-700">
          Email
        </label>
        <input
          type="email"
          id="email"
          name="email"
          value={formData.email}
          onChange={handleChange}
          required
          class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
        />
      </div>

      <div>
        <label htmlFor="message" class="block text-sm font-medium text-gray-700">
          Message
        </label>
        <textarea
          id="message"
          name="message"
          value={formData.message}
          onChange={handleChange}
          required
          rows={4}
          class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500"
        />
      </div>

      {result && (
        <div
          class={\`p-4 rounded-md \${
            result.success ? "bg-green-50 text-green-800" : "bg-red-50 text-red-800"
          }\`}
        >
          {result.message}
        </div>
      )}

      <Button type="submit" disabled={loading}>
        {loading ? "Sending..." : "Send Message"}
      </Button>
    </form>
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'islands', 'ContactForm.tsx'),
      formIslandContent
    );
  }

  private async generateComponents(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'components'), { recursive: true });

    // Header component
    const headerContent = `export default function Header() {
  return (
    <header class="bg-white shadow">
      <nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-16">
          <div class="flex">
            <div class="flex-shrink-0 flex items-center">
              <h1 class="text-xl font-bold">Fresh App</h1>
            </div>
            <div class="hidden sm:ml-6 sm:flex sm:space-x-8">
              <a
                href="/"
                class="border-primary-500 text-gray-900 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                Home
              </a>
              <a
                href="/about"
                class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                About
              </a>
              <a
                href="/api"
                class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                API
              </a>
            </div>
          </div>
        </div>
      </nav>
    </header>
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'components', 'Header.tsx'),
      headerContent
    );

    // Button component
    const buttonContent = `import { JSX } from "preact";
import { IS_BROWSER } from "$fresh/runtime.ts";

export function Button(props: JSX.HTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      disabled={!IS_BROWSER || props.disabled}
      class={\`px-4 py-2 bg-primary-600 text-white font-medium rounded-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed \${
        props.class ?? ""
      }\`}
    />
  );
}
`;

    await fs.writeFile(
      path.join(projectPath, 'components', 'Button.tsx'),
      buttonContent
    );
  }

  private async generateAPIRoutes(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'routes', 'api'), { recursive: true });

    // Health check API
    const healthAPIContent = `import { Handlers } from "$fresh/server.ts";

export const handler: Handlers = {
  GET(req) {
    return new Response(
      JSON.stringify({
        status: "healthy",
        timestamp: new Date().toISOString(),
        service: "fresh-api",
        version: "1.0.0",
      }),
      {
        headers: {
          "Content-Type": "application/json",
        },
      },
    );
  },
};
`;

    await fs.writeFile(
      path.join(projectPath, 'routes', 'api', 'health.ts'),
      healthAPIContent
    );

    // Users API
    const usersAPIContent = `import { Handlers } from "$fresh/server.ts";
import { getUserById, getUsers, createUser, updateUser, deleteUser } from "../../utils/db.ts";

export const handler: Handlers = {
  async GET(req) {
    const url = new URL(req.url);
    const id = url.searchParams.get("id");

    if (id) {
      const user = await getUserById(id);
      if (!user) {
        return new Response("User not found", { status: 404 });
      }
      return Response.json(user);
    }

    const page = parseInt(url.searchParams.get("page") || "1");
    const limit = parseInt(url.searchParams.get("limit") || "10");
    const users = await getUsers({ page, limit });

    return Response.json(users);
  },

  async POST(req) {
    try {
      const data = await req.json();
      const user = await createUser(data);
      return Response.json(user, { status: 201 });
    } catch (error) {
      return new Response(
        JSON.stringify({ error: error.message }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
  },

  async PUT(req) {
    const url = new URL(req.url);
    const id = url.searchParams.get("id");

    if (!id) {
      return new Response("User ID required", { status: 400 });
    }

    try {
      const data = await req.json();
      const user = await updateUser(id, data);
      if (!user) {
        return new Response("User not found", { status: 404 });
      }
      return Response.json(user);
    } catch (error) {
      return new Response(
        JSON.stringify({ error: error.message }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
  },

  async DELETE(req) {
    const url = new URL(req.url);
    const id = url.searchParams.get("id");

    if (!id) {
      return new Response("User ID required", { status: 400 });
    }

    const deleted = await deleteUser(id);
    if (!deleted) {
      return new Response("User not found", { status: 404 });
    }

    return new Response(null, { status: 204 });
  },
};
`;

    await fs.writeFile(
      path.join(projectPath, 'routes', 'api', 'users.ts'),
      usersAPIContent
    );

    // Contact API
    const contactAPIContent = `import { Handlers } from "$fresh/server.ts";

interface ContactData {
  name: string;
  email: string;
  message: string;
}

export const handler: Handlers = {
  async POST(req) {
    try {
      const data: ContactData = await req.json();

      // Validate data
      if (!data.name || !data.email || !data.message) {
        return new Response(
          JSON.stringify({ error: "All fields are required" }),
          {
            status: 400,
            headers: { "Content-Type": "application/json" },
          },
        );
      }

      // Here you would typically:
      // 1. Save to database
      // 2. Send email notification
      // 3. Add to queue for processing
      
      console.log("Contact form submission:", data);

      return Response.json({
        success: true,
        message: "Thank you for your message. We'll get back to you soon!",
      });
    } catch (error) {
      return new Response(
        JSON.stringify({ error: "Invalid request" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
  },
};
`;

    await fs.writeFile(
      path.join(projectPath, 'routes', 'api', 'contact.ts'),
      contactAPIContent
    );

    // Middleware example
    const middlewareContent = `import { MiddlewareHandlerContext } from "$fresh/server.ts";

export async function handler(
  req: Request,
  ctx: MiddlewareHandlerContext,
) {
  // Add CORS headers for API routes
  if (ctx.destination === "route" && req.url.includes("/api/")) {
    const origin = req.headers.get("Origin") || "*";
    const resp = await ctx.next();
    const headers = new Headers(resp.headers);
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    
    return new Response(resp.body, {
      status: resp.status,
      statusText: resp.statusText,
      headers,
    });
  }

  // Log requests in development
  if (Deno.env.get("DENO_ENV") === "development") {
    console.log(\`[\${new Date().toISOString()}] \${req.method} \${req.url}\`);
  }

  return await ctx.next();
}
`;

    await fs.writeFile(
      path.join(projectPath, 'routes', '_middleware.ts'),
      middlewareContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, 'utils'), { recursive: true });

    // Database utilities (mock)
    const dbUtilsContent = `// Mock database utilities
// In a real app, replace with actual database operations

interface User {
  id: string;
  name: string;
  email: string;
  createdAt: Date;
  updatedAt: Date;
}

const users: Map<string, User> = new Map();

export async function getUserById(id: string): Promise<User | null> {
  return users.get(id) || null;
}

export async function getUsers(params: { page: number; limit: number }) {
  const allUsers = Array.from(users.values());
  const start = (params.page - 1) * params.limit;
  const end = start + params.limit;
  
  return {
    users: allUsers.slice(start, end),
    total: allUsers.length,
    page: params.page,
    limit: params.limit,
  };
}

export async function createUser(data: Omit<User, "id" | "createdAt" | "updatedAt">): Promise<User> {
  const user: User = {
    ...data,
    id: crypto.randomUUID(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  
  users.set(user.id, user);
  return user;
}

export async function updateUser(id: string, data: Partial<Omit<User, "id" | "createdAt">>): Promise<User | null> {
  const user = users.get(id);
  if (!user) return null;
  
  const updated = {
    ...user,
    ...data,
    updatedAt: new Date(),
  };
  
  users.set(id, updated);
  return updated;
}

export async function deleteUser(id: string): Promise<boolean> {
  return users.delete(id);
}

// Initialize with some data
if (users.size === 0) {
  createUser({ name: "John Doe", email: "john@example.com" });
  createUser({ name: "Jane Smith", email: "jane@example.com" });
}
`;

    await fs.writeFile(
      path.join(projectPath, 'utils', 'db.ts'),
      dbUtilsContent
    );

    // Validation utilities
    const validationContent = `export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

export function sanitizeHtml(html: string): string {
  // Basic HTML sanitization
  return html
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}
`;

    await fs.writeFile(
      path.join(projectPath, 'utils', 'validation.ts'),
      validationContent
    );
  }

  private async generateStaticFiles(projectPath: string): Promise<void> {
    // Create static directory
    await fs.mkdir(path.join(projectPath, 'static'), { recursive: true });

    // Create a simple CSS file
    const cssContent = `/* Custom styles */
:root {
  --color-primary: #3b82f6;
  --color-primary-dark: #2563eb;
}

* {
  box-sizing: border-box;
}

html {
  font-family: Inter, system-ui, -apple-system, sans-serif;
}

body {
  margin: 0;
  padding: 0;
}

/* Utility classes */
.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 1rem;
}

/* Animations */
@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.animate-fade-in {
  animation: fadeIn 0.5s ease-out;
}
`;

    await fs.writeFile(
      path.join(projectPath, 'static', 'styles.css'),
      cssContent
    );

    // Create favicon
    const faviconContent = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <text y=".9em" font-size="90">🍋</text>
</svg>`;

    await fs.writeFile(
      path.join(projectPath, 'static', 'favicon.svg'),
      faviconContent
    );

    // Create logo
    const logoContent = `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 40 40">
  <rect width="40" height="40" rx="8" fill="#3b82f6"/>
  <text x="50%" y="50%" text-anchor="middle" dy=".3em" fill="white" font-family="Arial" font-size="20" font-weight="bold">F</text>
</svg>`;

    await fs.writeFile(
      path.join(projectPath, 'static', 'logo.svg'),
      logoContent
    );
  }

  private async updateFreshConfig(projectPath: string, options: any): Promise<void> {
    // Update .gitignore for Fresh
    const gitignorePath = path.join(projectPath, '.gitignore');
    const gitignoreContent = await fs.readFile(gitignorePath, 'utf-8');
    const freshIgnore = `\n# Fresh\n_fresh/\nfresh.gen.ts\n`;
    
    await fs.writeFile(
      gitignorePath,
      gitignoreContent + freshIgnore
    );

    // Create README specific to Fresh
    const readmeContent = `# ${options.name}

## Fresh + Deno Application

### 🍋 Built with Fresh

This project uses [Fresh](https://fresh.deno.dev/), a next-gen web framework for Deno.

### 🏃 Running

Start the project:

\`\`\`bash
deno task start
\`\`\`

This will watch the project directory and restart as necessary.

### 🚀 Deployment

#### Deno Deploy

1. Push your project to GitHub
2. Go to https://dash.deno.com
3. Create a new project and link your GitHub repository
4. Fresh will be automatically detected and deployed

#### Docker

\`\`\`bash
docker build -t ${options.name} .
docker run -p 8000:8000 ${options.name}
\`\`\`

### 📁 Project Structure

- \`routes/\` - File-based routing
- \`islands/\` - Interactive components
- \`components/\` - Reusable Preact components
- \`static/\` - Static assets
- \`utils/\` - Utility functions

### 🧪 Testing

\`\`\`bash
deno task test
\`\`\`

### 🎨 Styling

This project uses [Twind](https://twind.dev/) for styling, which is Tailwind CSS in JS.

---

For more information, see the [Fresh documentation](https://fresh.deno.dev/docs).
`;

    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readmeContent
    );
  }
}