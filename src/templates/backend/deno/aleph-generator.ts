/**
 * Aleph.js Framework Template Generator
 * React SSR/SSG framework for Deno
 */

import { DenoBackendGenerator } from './deno-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class AlephGenerator extends DenoBackendGenerator {
  constructor() {
    super('Aleph.js');
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate Aleph-specific configuration
    await this.generateAlephConfig(projectPath, options);
    
    // Generate main app component
    await this.generateApp(projectPath);
    
    // Generate pages
    await this.generatePages(projectPath);
    
    // Generate API routes
    await this.generateAPIRoutes(projectPath);
    
    // Generate components
    await this.generateComponents(projectPath);
    
    // Generate layouts
    await this.generateLayouts(projectPath);
    
    // Generate styles
    await this.generateStyles(projectPath);
    
    // Generate utilities
    await this.generateUtilities(projectPath);
    
    // Generate static assets
    await this.generateStaticAssets(projectPath);
    
    // Update Aleph-specific configurations
    await this.updateAlephConfig(projectPath, options);
  }

  private async generateAlephConfig(projectPath: string, options: any): Promise<void> {
    // Generate aleph.config.ts
    const alephConfig = `import type { Config } from "aleph/types";

export default <Config>{
  ssr: true,
  build: {
    target: "es2020",
    browsers: {
      chrome: 95,
      firefox: 90,
      safari: 14,
      edge: 95,
    },
  },
  server: {
    port: ${options.port || 8000},
    headers: {
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "X-XSS-Protection": "1; mode=block",
    },
  },
  plugins: [],
  env: async () => {
    const env = await import("./env.ts");
    return env.default;
  },
};
`;

    await fs.writeFile(
      path.join(projectPath, 'aleph.config.ts'),
      alephConfig
    );

    // Generate env.ts
    const envContent = `export default {
  API_URL: Deno.env.get("API_URL") || "http://localhost:8000/api",
  SITE_TITLE: Deno.env.get("SITE_TITLE") || "${options.name}",
  GA_TRACKING_ID: Deno.env.get("GA_TRACKING_ID") || "",
  SENTRY_DSN: Deno.env.get("SENTRY_DSN") || "",
};
`;

    await fs.writeFile(
      path.join(projectPath, 'env.ts'),
      envContent
    );

    // Update deno.json for Aleph
    const denoJsonPath = path.join(projectPath, 'deno.json');
    const denoConfig = JSON.parse(await fs.readFile(denoJsonPath, 'utf-8'));
    
    denoConfig.imports = {
      ...denoConfig.imports,
      "aleph/": "https://deno.land/x/aleph@1.0.0-rc.1/",
      "aleph/types": "https://deno.land/x/aleph@1.0.0-rc.1/types.d.ts",
      "react": "https://esm.sh/react@18.2.0",
      "react-dom": "https://esm.sh/react-dom@18.2.0",
      "react/jsx-runtime": "https://esm.sh/react@18.2.0/jsx-runtime",
      "@unocss/reset": "https://esm.sh/@unocss/reset@0.58.0/tailwind.css",
      "unocss": "https://esm.sh/@unocss/core@0.58.0",
      "swr": "https://esm.sh/swr@2.2.4",
      "zustand": "https://esm.sh/zustand@4.4.7",
    };

    denoConfig.tasks = {
      ...denoConfig.tasks,
      "dev": "deno run -A dev.ts",
      "start": "deno run -A server.ts",
      "build": "deno run -A build.ts",
      "preview": "deno run -A preview.ts",
    };

    denoConfig.compilerOptions = {
      ...denoConfig.compilerOptions,
      "jsx": "react-jsx",
      "jsxImportSource": "react",
    };

    await fs.writeFile(
      denoJsonPath,
      JSON.stringify(denoConfig, null, 2)
    );
  }

  private async generateApp(projectPath: string): Promise<void> {
    // Generate dev.ts
    const devContent = `import { serve } from "aleph/server";
import routes from "./routes.gen.ts";

serve({
  routes,
  baseUrl: import.meta.url,
  port: Deno.env.get("PORT") ? Number(Deno.env.get("PORT")) : 8000,
});
`;

    await fs.writeFile(
      path.join(projectPath, 'dev.ts'),
      devContent
    );

    // Generate server.ts
    const serverContent = `import { serve } from "aleph/server";
import routes from "./routes.gen.ts";

const port = Deno.env.get("PORT") ? Number(Deno.env.get("PORT")) : 8000;

serve({
  routes,
  baseUrl: import.meta.url,
  port,
  cert: Deno.env.get("CERT_FILE"),
  key: Deno.env.get("KEY_FILE"),
});

console.log(\`Server running on http://localhost:\${port}\`);
`;

    await fs.writeFile(
      path.join(projectPath, 'server.ts'),
      serverContent
    );

    // Generate build.ts
    const buildContent = `import { build } from "aleph/build";

await build({
  baseUrl: import.meta.url,
  outputDir: "./dist",
});
`;

    await fs.writeFile(
      path.join(projectPath, 'build.ts'),
      buildContent
    );

    // Generate app.tsx
    const appContent = `import React, { FC } from "react";
import "@unocss/reset";
import "./styles/global.css";

export const App: FC<{ Page: FC; pageProps: any }> = ({ Page, pageProps }) => {
  return (
    <>
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link rel="icon" href="/favicon.ico" />
      </head>
      <Page {...pageProps} />
    </>
  );
};

export default App;
`;

    await fs.writeFile(
      path.join(projectPath, 'app.tsx'),
      appContent
    );
  }

  private async generatePages(projectPath: string): Promise<void> {
    const pagesDir = path.join(projectPath, 'pages');
    await fs.mkdir(pagesDir, { recursive: true });

    // Index page
    const indexPageContent = `import React, { FC } from "react";
import { Head } from "aleph/react";
import { Header } from "../components/Header.tsx";
import { Hero } from "../components/Hero.tsx";
import { Features } from "../components/Features.tsx";

export const Page: FC = () => {
  return (
    <>
      <Head>
        <title>Welcome to Aleph.js</title>
        <meta name="description" content="A React SSR/SSG framework for Deno" />
      </Head>
      <div className="min-h-screen bg-gray-50">
        <Header />
        <main>
          <Hero />
          <Features />
        </main>
      </div>
    </>
  );
};

export default Page;
`;

    await fs.writeFile(
      path.join(pagesDir, 'index.tsx'),
      indexPageContent
    );

    // About page
    const aboutPageContent = `import React, { FC } from "react";
import { Head } from "aleph/react";
import { Header } from "../components/Header.tsx";

export const Page: FC = () => {
  return (
    <>
      <Head>
        <title>About - Aleph.js App</title>
      </Head>
      <div className="min-h-screen bg-gray-50">
        <Header />
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <h1 className="text-4xl font-bold text-gray-900 mb-8">About</h1>
          <div className="prose prose-lg">
            <p>
              This is an Aleph.js application built with React and Deno.
              Aleph.js is a full-stack framework that brings the best
              developer experience for building web applications.
            </p>
            <h2>Features</h2>
            <ul>
              <li>Server-side rendering (SSR)</li>
              <li>Static site generation (SSG)</li>
              <li>File-based routing</li>
              <li>Built-in CSS support</li>
              <li>TypeScript by default</li>
              <li>Hot module replacement</li>
              <li>Optimized production builds</li>
            </ul>
          </div>
        </main>
      </div>
    </>
  );
};

export default Page;
`;

    await fs.writeFile(
      path.join(pagesDir, 'about.tsx'),
      aboutPageContent
    );

    // Blog index page
    const blogDir = path.join(pagesDir, 'blog');
    await fs.mkdir(blogDir, { recursive: true });

    const blogIndexContent = `import React, { FC } from "react";
import { Head } from "aleph/react";
import { Header } from "../../components/Header.tsx";
import { useData } from "aleph/react";
import { BlogPost } from "../../types/blog.ts";

export const data = async () => {
  // In production, fetch from API or database
  const posts: BlogPost[] = [
    {
      id: "1",
      slug: "hello-world",
      title: "Hello World",
      excerpt: "Welcome to our blog built with Aleph.js",
      date: "2024-01-01",
      author: "John Doe",
    },
    {
      id: "2",
      slug: "getting-started",
      title: "Getting Started with Aleph.js",
      excerpt: "Learn how to build amazing apps with Aleph.js",
      date: "2024-01-02",
      author: "Jane Smith",
    },
  ];
  
  return { posts };
};

export const Page: FC = () => {
  const { posts } = useData<{ posts: BlogPost[] }>();

  return (
    <>
      <Head>
        <title>Blog - Aleph.js App</title>
      </Head>
      <div className="min-h-screen bg-gray-50">
        <Header />
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <h1 className="text-4xl font-bold text-gray-900 mb-8">Blog</h1>
          <div className="grid gap-6">
            {posts.map((post) => (
              <article
                key={post.id}
                className="bg-white rounded-lg shadow p-6 hover:shadow-lg transition-shadow"
              >
                <h2 className="text-2xl font-semibold mb-2">
                  <a
                    href={\`/blog/\${post.slug}\`}
                    className="text-gray-900 hover:text-blue-600"
                  >
                    {post.title}
                  </a>
                </h2>
                <p className="text-gray-600 mb-4">{post.excerpt}</p>
                <div className="text-sm text-gray-500">
                  By {post.author} on {post.date}
                </div>
              </article>
            ))}
          </div>
        </main>
      </div>
    </>
  );
};

export default Page;
`;

    await fs.writeFile(
      path.join(blogDir, 'index.tsx'),
      blogIndexContent
    );

    // Dynamic blog post page
    const blogPostContent = `import React, { FC } from "react";
import { Head } from "aleph/react";
import { Header } from "../../components/Header.tsx";
import { useData, useRouter } from "aleph/react";
import { BlogPost } from "../../types/blog.ts";

export const data = async ({ params }: { params: Record<string, string> }) => {
  const { slug } = params;
  
  // In production, fetch from API or database
  const post: BlogPost = {
    id: "1",
    slug,
    title: "Hello World",
    excerpt: "Welcome to our blog",
    content: "This is the full blog post content. In a real application, this would be fetched from a database or CMS.",
    date: "2024-01-01",
    author: "John Doe",
  };
  
  return { post };
};

export const Page: FC = () => {
  const { post } = useData<{ post: BlogPost }>();

  return (
    <>
      <Head>
        <title>{post.title} - Blog</title>
        <meta name="description" content={post.excerpt} />
      </Head>
      <div className="min-h-screen bg-gray-50">
        <Header />
        <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <article className="bg-white rounded-lg shadow p-8">
            <h1 className="text-4xl font-bold text-gray-900 mb-4">
              {post.title}
            </h1>
            <div className="text-sm text-gray-500 mb-8">
              By {post.author} on {post.date}
            </div>
            <div className="prose prose-lg max-w-none">
              {post.content}
            </div>
          </article>
        </main>
      </div>
    </>
  );
};

export default Page;
`;

    await fs.writeFile(
      path.join(blogDir, '[slug].tsx'),
      blogPostContent
    );

    // 404 page
    const notFoundContent = `import React, { FC } from "react";
import { Head } from "aleph/react";

export const Page: FC = () => {
  return (
    <>
      <Head>
        <title>404 - Page Not Found</title>
      </Head>
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-6xl font-bold text-gray-900 mb-4">404</h1>
          <p className="text-xl text-gray-600 mb-8">Page not found</p>
          <a
            href="/"
            className="inline-block px-6 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Go Home
          </a>
        </div>
      </div>
    </>
  );
};

export default Page;
`;

    await fs.writeFile(
      path.join(pagesDir, '404.tsx'),
      notFoundContent
    );
  }

  private async generateAPIRoutes(projectPath: string): Promise<void> {
    const apiDir = path.join(projectPath, 'api');
    await fs.mkdir(apiDir, { recursive: true });

    // Health check API
    const healthAPIContent = `export default {
  GET: () => {
    return Response.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      service: "aleph-api",
      version: "1.0.0",
    });
  },
};
`;

    await fs.writeFile(
      path.join(apiDir, 'health.ts'),
      healthAPIContent
    );

    // Users API
    const usersAPIContent = `import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";
import { getUsers, getUserById, createUser, updateUser, deleteUser } from "../utils/db.ts";

const UserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
});

export default {
  async GET(req: Request) {
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

  async POST(req: Request) {
    try {
      const data = await req.json();
      const validatedData = UserSchema.parse(data);
      const user = await createUser(validatedData);
      return Response.json(user, { status: 201 });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return Response.json(
          { error: "Validation failed", details: error.errors },
          { status: 400 }
        );
      }
      return Response.json(
        { error: "Internal server error" },
        { status: 500 }
      );
    }
  },

  async PUT(req: Request) {
    const url = new URL(req.url);
    const id = url.searchParams.get("id");

    if (!id) {
      return new Response("User ID required", { status: 400 });
    }

    try {
      const data = await req.json();
      const validatedData = UserSchema.partial().parse(data);
      const user = await updateUser(id, validatedData);
      if (!user) {
        return new Response("User not found", { status: 404 });
      }
      return Response.json(user);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return Response.json(
          { error: "Validation failed", details: error.errors },
          { status: 400 }
        );
      }
      return Response.json(
        { error: "Internal server error" },
        { status: 500 }
      );
    }
  },

  async DELETE(req: Request) {
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
      path.join(apiDir, 'users.ts'),
      usersAPIContent
    );

    // Auth API
    const authAPIContent = `import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";
import * as djwt from "https://deno.land/x/djwt@v3.0.1/mod.ts";

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

const RegisterSchema = LoginSchema.extend({
  name: z.string().min(1),
});

const JWT_SECRET = Deno.env.get("JWT_SECRET") || "your-secret-key";

export default {
  async POST(req: Request) {
    const url = new URL(req.url);
    const isLogin = url.pathname.endsWith("/login");

    try {
      const data = await req.json();
      
      if (isLogin) {
        const { email, password } = LoginSchema.parse(data);
        
        // In production, verify against database
        const hashedPassword = await bcrypt.hash(password);
        const passwordMatch = await bcrypt.compare(password, hashedPassword);
        
        if (!passwordMatch) {
          return Response.json(
            { error: "Invalid credentials" },
            { status: 401 }
          );
        }

        const token = await djwt.create(
          { alg: "HS256", typ: "JWT" },
          { 
            email,
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7), // 7 days
          },
          JWT_SECRET
        );

        return Response.json({
          token,
          user: { email },
        });
      } else {
        const { email, password, name } = RegisterSchema.parse(data);
        
        // In production, save to database
        const hashedPassword = await bcrypt.hash(password);
        
        const token = await djwt.create(
          { alg: "HS256", typ: "JWT" },
          { 
            email,
            name,
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7),
          },
          JWT_SECRET
        );

        return Response.json({
          token,
          user: { email, name },
        }, { status: 201 });
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        return Response.json(
          { error: "Validation failed", details: error.errors },
          { status: 400 }
        );
      }
      return Response.json(
        { error: "Internal server error" },
        { status: 500 }
      );
    }
  },
};
`;

    await fs.writeFile(
      path.join(apiDir, 'auth/[action].ts'),
      authAPIContent
    );
  }

  private async generateComponents(projectPath: string): Promise<void> {
    const componentsDir = path.join(projectPath, 'components');
    await fs.mkdir(componentsDir, { recursive: true });

    // Header component
    const headerContent = `import React, { FC } from "react";

export const Header: FC = () => {
  return (
    <header className="bg-white shadow">
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex">
            <div className="flex-shrink-0 flex items-center">
              <h1 className="text-xl font-bold">Aleph.js App</h1>
            </div>
            <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
              <a
                href="/"
                className="border-blue-500 text-gray-900 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                Home
              </a>
              <a
                href="/about"
                className="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                About
              </a>
              <a
                href="/blog"
                className="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium"
              >
                Blog
              </a>
            </div>
          </div>
        </div>
      </nav>
    </header>
  );
};
`;

    await fs.writeFile(
      path.join(componentsDir, 'Header.tsx'),
      headerContent
    );

    // Hero component
    const heroContent = `import React, { FC } from "react";

export const Hero: FC = () => {
  return (
    <section className="bg-gradient-to-r from-blue-500 to-purple-600 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 text-center">
        <h1 className="text-5xl font-bold mb-6">
          Welcome to Aleph.js
        </h1>
        <p className="text-xl mb-8 max-w-2xl mx-auto">
          The React framework for building fast, modern web applications
          with Deno. Server-side rendering, static generation, and more.
        </p>
        <div className="space-x-4">
          <a
            href="/docs"
            className="inline-block px-8 py-3 bg-white text-blue-600 rounded-md font-semibold hover:bg-gray-100"
          >
            Get Started
          </a>
          <a
            href="https://github.com"
            className="inline-block px-8 py-3 bg-transparent border-2 border-white rounded-md font-semibold hover:bg-white hover:text-blue-600"
          >
            View on GitHub
          </a>
        </div>
      </div>
    </section>
  );
};
`;

    await fs.writeFile(
      path.join(componentsDir, 'Hero.tsx'),
      heroContent
    );

    // Features component
    const featuresContent = `import React, { FC } from "react";

interface Feature {
  title: string;
  description: string;
  icon: string;
}

const features: Feature[] = [
  {
    title: "Server-Side Rendering",
    description: "Pre-render pages on the server for better SEO and performance",
    icon: "🚀",
  },
  {
    title: "Static Site Generation",
    description: "Generate static pages at build time for lightning-fast loads",
    icon: "⚡",
  },
  {
    title: "File-Based Routing",
    description: "Create pages by adding files to the pages directory",
    icon: "📁",
  },
  {
    title: "TypeScript First",
    description: "Built with TypeScript for type safety and better DX",
    icon: "📘",
  },
  {
    title: "Hot Module Replacement",
    description: "See changes instantly without losing application state",
    icon: "🔥",
  },
  {
    title: "Optimized Builds",
    description: "Automatic code splitting and optimization for production",
    icon: "📦",
  },
];

export const Features: FC = () => {
  return (
    <section className="py-16">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-gray-900 mb-4">
            Everything You Need
          </h2>
          <p className="text-xl text-gray-600 max-w-2xl mx-auto">
            Aleph.js provides all the tools you need to build modern web applications
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature) => (
            <div
              key={feature.title}
              className="bg-white p-6 rounded-lg shadow hover:shadow-lg transition-shadow"
            >
              <div className="text-4xl mb-4">{feature.icon}</div>
              <h3 className="text-xl font-semibold mb-2">{feature.title}</h3>
              <p className="text-gray-600">{feature.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
`;

    await fs.writeFile(
      path.join(componentsDir, 'Features.tsx'),
      featuresContent
    );

    // Button component
    const buttonContent = `import React, { FC, ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "outline";
  size?: "sm" | "md" | "lg";
}

export const Button: FC<ButtonProps> = ({
  children,
  variant = "primary",
  size = "md",
  className = "",
  ...props
}) => {
  const baseStyles = "font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2";
  
  const variants = {
    primary: "bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500",
    secondary: "bg-gray-600 text-white hover:bg-gray-700 focus:ring-gray-500",
    outline: "bg-transparent border-2 border-gray-300 text-gray-700 hover:bg-gray-50 focus:ring-gray-500",
  };
  
  const sizes = {
    sm: "px-3 py-1.5 text-sm",
    md: "px-4 py-2 text-base",
    lg: "px-6 py-3 text-lg",
  };

  return (
    <button
      className={\`\${baseStyles} \${variants[variant]} \${sizes[size]} \${className}\`}
      {...props}
    >
      {children}
    </button>
  );
};
`;

    await fs.writeFile(
      path.join(componentsDir, 'Button.tsx'),
      buttonContent
    );
  }

  private async generateLayouts(projectPath: string): Promise<void> {
    const layoutsDir = path.join(projectPath, 'layouts');
    await fs.mkdir(layoutsDir, { recursive: true });

    // Default layout
    const defaultLayoutContent = `import React, { FC, ReactNode } from "react";
import { Header } from "../components/Header.tsx";
import { Footer } from "../components/Footer.tsx";

interface DefaultLayoutProps {
  children: ReactNode;
}

export const DefaultLayout: FC<DefaultLayoutProps> = ({ children }) => {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <main className="flex-1">
        {children}
      </main>
      <Footer />
    </div>
  );
};
`;

    await fs.writeFile(
      path.join(layoutsDir, 'DefaultLayout.tsx'),
      defaultLayoutContent
    );

    // Create Footer component
    const footerContent = `import React, { FC } from "react";

export const Footer: FC = () => {
  return (
    <footer className="bg-gray-900 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex justify-between items-center">
          <p>&copy; 2024 Aleph.js App. All rights reserved.</p>
          <div className="flex space-x-6">
            <a href="/privacy" className="hover:text-gray-300">Privacy</a>
            <a href="/terms" className="hover:text-gray-300">Terms</a>
            <a href="/contact" className="hover:text-gray-300">Contact</a>
          </div>
        </div>
      </div>
    </footer>
  );
};
`;

    const componentsDir = path.join(projectPath, 'components');
    await fs.mkdir(componentsDir, { recursive: true });
    
    await fs.writeFile(
      path.join(componentsDir, 'Footer.tsx'),
      footerContent
    );
  }

  private async generateStyles(projectPath: string): Promise<void> {
    const stylesDir = path.join(projectPath, 'styles');
    await fs.mkdir(stylesDir, { recursive: true });

    // Global styles
    const globalStyles = `/* Global Styles */

:root {
  --color-primary: #3b82f6;
  --color-primary-dark: #2563eb;
  --color-secondary: #6b7280;
  --color-success: #10b981;
  --color-danger: #ef4444;
  --color-warning: #f59e0b;
}

* {
  box-sizing: border-box;
}

html {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  margin: 0;
  padding: 0;
  background-color: #f9fafb;
  color: #111827;
}

/* Utility Classes */
.container {
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 1rem;
}

/* Animation Classes */
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

/* Loading Spinner */
.spinner {
  border: 2px solid #f3f4f6;
  border-top: 2px solid var(--color-primary);
  border-radius: 50%;
  width: 20px;
  height: 20px;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Prose Styles for Content */
.prose {
  color: #374151;
  max-width: 65ch;
}

.prose h1 {
  font-size: 2.25rem;
  font-weight: 800;
  line-height: 2.5rem;
  margin-bottom: 2rem;
}

.prose h2 {
  font-size: 1.875rem;
  font-weight: 700;
  line-height: 2.25rem;
  margin-top: 3rem;
  margin-bottom: 1.5rem;
}

.prose p {
  margin-bottom: 1.25rem;
  line-height: 1.75;
}

.prose ul,
.prose ol {
  margin-bottom: 1.25rem;
  padding-left: 1.5rem;
}

.prose li {
  margin-bottom: 0.5rem;
}

.prose a {
  color: var(--color-primary);
  text-decoration: underline;
}

.prose a:hover {
  color: var(--color-primary-dark);
}

/* Form Styles */
.form-input {
  display: block;
  width: 100%;
  padding: 0.5rem 0.75rem;
  font-size: 1rem;
  line-height: 1.5;
  color: #374151;
  background-color: #fff;
  border: 1px solid #d1d5db;
  border-radius: 0.375rem;
  transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
}

.form-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

/* Responsive Grid */
@media (min-width: 640px) {
  .sm\\:grid-cols-2 {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (min-width: 768px) {
  .md\\:grid-cols-3 {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (min-width: 1024px) {
  .lg\\:grid-cols-4 {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
}
`;

    await fs.writeFile(
      path.join(stylesDir, 'global.css'),
      globalStyles
    );

    // UnoCSS config
    const unoConfig = `import { defineConfig, presetUno, presetTypography } from "unocss";

export default defineConfig({
  presets: [
    presetUno(),
    presetTypography(),
  ],
  theme: {
    colors: {
      primary: {
        DEFAULT: '#3b82f6',
        dark: '#2563eb',
        light: '#60a5fa',
      },
    },
  },
});
`;

    await fs.writeFile(
      path.join(projectPath, 'uno.config.ts'),
      unoConfig
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    const utilsDir = path.join(projectPath, 'utils');
    await fs.mkdir(utilsDir, { recursive: true });

    // Database utilities
    const dbContent = `// Mock database utilities
// Replace with actual database integration

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
`;

    await fs.writeFile(
      path.join(utilsDir, 'db.ts'),
      dbContent
    );

    // API client utilities
    const apiClientContent = `import { useSWR } from "swr";

const API_BASE = "/api";

async function fetcher(url: string) {
  const res = await fetch(url);
  
  if (!res.ok) {
    const error = new Error("An error occurred while fetching the data.");
    throw error;
  }
  
  return res.json();
}

export function useAPI<T = any>(endpoint: string) {
  const { data, error, mutate } = useSWR<T>(\`\${API_BASE}\${endpoint}\`, fetcher);
  
  return {
    data,
    isLoading: !error && !data,
    isError: error,
    mutate,
  };
}

export async function apiRequest(endpoint: string, options?: RequestInit) {
  const response = await fetch(\`\${API_BASE}\${endpoint}\`, {
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    ...options,
  });
  
  if (!response.ok) {
    throw new Error(\`API request failed: \${response.statusText}\`);
  }
  
  return response.json();
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'api.ts'),
      apiClientContent
    );

    // Validation utilities
    const validationContent = `export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
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
  return html
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\\//g, "&#x2F;");
}

export function formatDate(date: string | Date): string {
  const d = new Date(date);
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'validation.ts'),
      validationContent
    );
  }

  private async generateStaticAssets(projectPath: string): Promise<void> {
    const publicDir = path.join(projectPath, 'public');
    await fs.mkdir(publicDir, { recursive: true });

    // Create favicon
    const faviconContent = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" fill="#3b82f6"/>
  <text x="50" y="65" text-anchor="middle" font-family="Arial" font-size="50" font-weight="bold" fill="white">A</text>
</svg>`;

    await fs.writeFile(
      path.join(publicDir, 'favicon.svg'),
      faviconContent
    );

    // Create robots.txt
    const robotsContent = `User-agent: *
Allow: /

Sitemap: https://example.com/sitemap.xml
`;

    await fs.writeFile(
      path.join(publicDir, 'robots.txt'),
      robotsContent
    );
  }

  private async generateTypes(projectPath: string): Promise<void> {
    const typesDir = path.join(projectPath, 'types');
    await fs.mkdir(typesDir, { recursive: true });

    // Blog types
    const blogTypesContent = `export interface BlogPost {
  id: string;
  slug: string;
  title: string;
  excerpt: string;
  content?: string;
  author: string;
  date: string;
  tags?: string[];
  featured?: boolean;
  coverImage?: string;
}

export interface BlogCategory {
  id: string;
  name: string;
  slug: string;
  description?: string;
}
`;

    await fs.writeFile(
      path.join(typesDir, 'blog.ts'),
      blogTypesContent
    );

    // API types
    const apiTypesContent = `export interface APIResponse<T = any> {
  data?: T;
  error?: APIError;
  meta?: APIMeta;
}

export interface APIError {
  code: string;
  message: string;
  details?: any;
}

export interface APIMeta {
  page?: number;
  limit?: number;
  total?: number;
  hasMore?: boolean;
}

export interface User {
  id: string;
  email: string;
  name: string;
  avatar?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}
`;

    await fs.writeFile(
      path.join(typesDir, 'api.ts'),
      apiTypesContent
    );
  }

  private async updateAlephConfig(projectPath: string, options: any): Promise<void> {
    // Update .gitignore
    const gitignorePath = path.join(projectPath, '.gitignore');
    const gitignoreContent = await fs.readFile(gitignorePath, 'utf-8');
    const alephIgnore = `
# Aleph.js
.aleph/
dist/
`;
    
    await fs.writeFile(
      gitignorePath,
      gitignoreContent + alephIgnore
    );

    // Create routes.gen.ts placeholder
    const routesGenContent = `// This file is auto-generated by Aleph.js
// Do not edit this file manually

export default [];
`;

    await fs.writeFile(
      path.join(projectPath, 'routes.gen.ts'),
      routesGenContent
    );

    // Update README
    const readmeContent = `# ${options.name}

## Aleph.js + React Application

### 🚀 Built with Aleph.js

This project uses [Aleph.js](https://alephjs.org/), a full-stack React framework for Deno.

### 🏃 Running

#### Development

\`\`\`bash
deno task dev
\`\`\`

The application will start at http://localhost:${options.port || 8000}

#### Production

\`\`\`bash
deno task build
deno task start
\`\`\`

### 🚀 Deployment

#### Deno Deploy

1. Push your project to GitHub
2. Go to https://dash.deno.com
3. Create a new project and link your GitHub repository
4. Set entry point to \`server.ts\`

#### Docker

\`\`\`bash
docker build -t ${options.name} .
docker run -p ${options.port || 8000}:${options.port || 8000} ${options.name}
\`\`\`

### 📁 Project Structure

- \`pages/\` - File-based routing
- \`api/\` - API routes
- \`components/\` - React components
- \`layouts/\` - Layout components
- \`styles/\` - CSS files
- \`utils/\` - Utility functions
- \`types/\` - TypeScript types
- \`public/\` - Static assets

### 🧪 Testing

\`\`\`bash
deno task test
\`\`\`

### 🎨 Features

- Server-side rendering (SSR)
- Static site generation (SSG)
- File-based routing
- API routes
- TypeScript by default
- Hot module replacement
- Optimized production builds

---

For more information, see the [Aleph.js documentation](https://alephjs.org/docs).
`;

    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readmeContent
    );
  }
}