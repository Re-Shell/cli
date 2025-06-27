# Re-Shell TUI - Interactive Terminal User Interface

The Re-Shell CLI now includes a powerful Terminal User Interface (TUI) built with Go and Bubble Tea, providing an interactive and visual way to manage your full-stack projects.

## 🚀 Features

### **Main Menu**
- 📊 **Project Dashboard** - Overview of your Re-Shell project with real-time stats
- 🚀 **Initialize Project** - Interactive project creation wizard
- ⚙️ **Service Manager** - Manage microfrontends and microservices with visual status
- 📁 **File Explorer** - Browse project files and structure
- 🔧 **Configuration** - Visual configuration editor
- ❓ **Help** - Documentation and keyboard shortcuts

### **Dashboard View**
- Project information display (name, version, description, path)
- Quick statistics (microfrontends, microservices, build status)
- Recent activity feed
- Real-time status indicators

### **Interactive Elements**
- Smooth navigation with arrow keys
- Color-coded status indicators
- Responsive layout that adapts to terminal size
- Loading spinners and progress indicators
- Help tooltips and contextual information

## 🎯 Quick Start

### Launch TUI
```bash
# Launch with default dashboard mode
re-shell tui

# Launch with specific mode
re-shell tui --mode dashboard
re-shell tui --mode init
re-shell tui --mode manage
re-shell tui --mode config

# Launch for specific project
re-shell tui --project /path/to/project

# Enable debug output
re-shell tui --debug
```

### Keyboard Navigation
- **Arrow Keys (↑/↓)** - Navigate menu items
- **Enter** - Select item or execute action
- **Esc** - Go back to main menu
- **q** - Quit application
- **Tab** - Switch between sections (in complex views)

## 🏗️ Architecture

### **Hybrid Design**
The TUI uses a hybrid architecture combining:
- **Node.js CLI** - Existing command logic and file operations
- **Go TUI** - Interactive interface with Bubble Tea framework
- **IPC Bridge** - JSON-RPC communication between Node.js and Go

```
┌─────────────────┐    ┌──────────────────┐
│   TypeScript    │    │      Go TUI      │
│   CLI (Node.js) │◄──►│  (Bubble Tea)    │
├─────────────────┤    ├──────────────────┤
│ • Commands      │    │ • Interactive UI │
│ • Business Logic│    │ • State Management│
│ • File Operations│   │ • Key Bindings   │
│ • Templates     │    │ • Views/Models   │
└─────────────────┘    └──────────────────┘
         ▲                       ▲
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────┐
│         IPC Bridge                      │
│ • JSON-RPC over stdin/stdout           │
│ • Command delegation                    │
│ • State synchronization                 │
└─────────────────────────────────────────┘
```

### **TUI Components**
- **Models** - Application state and data structures
- **Views** - UI rendering and layout
- **Components** - Reusable UI elements (lists, inputs, viewports)
- **Styles** - Consistent color schemes and formatting

## 🔧 Development

### **Prerequisites**
- Go 1.21+ (for TUI compilation)
- Node.js 16+ (for CLI functionality)

### **Project Structure**
```
src/
├── commands/
│   └── tui.ts              # TUI command integration
├── tui/                    # Go TUI module
│   ├── main.go            # TUI entry point
│   ├── go.mod             # Go dependencies
│   └── go.sum             # Go dependency checksums
└── ...
```

### **Building**
The TUI is automatically built when the CLI is compiled:
```bash
npm run build
```

Go dependencies are managed automatically and installed on first run.

### **Testing**
```bash
# Test CLI integration
node dist/index.js tui --help

# Test Go TUI directly (requires TTY)
cd src/tui && go run main.go

# Run with debug output
node dist/index.js tui --debug
```

## 🎨 UI Design

### **Color Scheme**
- **Primary** - Purple (`#7D56F4`) for titles and headers
- **Secondary** - Pink (`#F25D94`) for sections
- **Success** - Green (`#50FA7B`) for positive status
- **Error** - Red (`#FF5555`) for errors and warnings
- **Info** - Cyan (`#8BE9FD`) for informational content
- **Focus** - Magenta (`#FF79C6`) for selected items

### **Layout**
- Header with title and status
- Main content area with scrolling support
- Footer with help text and shortcuts
- Responsive design adapts to terminal dimensions

## ⚡ Advanced Features

### **IPC Communication**
The TUI communicates with the CLI through Inter-Process Communication:

```typescript
// Example IPC message
{
  "type": "get-project-info",
  "id": "unique-id",
  "data": {
    "path": "/path/to/project"
  }
}
```

### **Command Integration**
All existing CLI commands are available through the TUI:
- Project initialization
- Microfrontend management
- Build and serve operations
- Configuration management

### **Real-time Updates**
- File system watching
- Build status monitoring
- Service health checking
- Configuration change detection

## 🚀 Future Enhancements

### **Planned Features**
- **Log Viewer** - Real-time log streaming with filtering
- **Performance Monitor** - Resource usage and build metrics
- **Git Integration** - Visual git status and operations
- **Plugin Manager** - Interactive plugin installation and management
- **Template Browser** - Visual template selection and preview
- **Dependency Graph** - Interactive dependency visualization

### **Advanced Views**
- **Multi-pane Layout** - Split views for complex operations
- **Tabbed Interface** - Multiple concurrent tasks
- **Form Validation** - Real-time input validation
- **Progress Tracking** - Detailed progress for long operations

## 🐛 Troubleshooting

### **Common Issues**

**"Go is not installed" Error**
```bash
# Install Go from https://golang.org/dl/
# Or using package manager:
brew install go        # macOS
sudo apt install go    # Ubuntu/Debian
choco install golang   # Windows
```

**"TUI process exited with code 1"**
- Ensure terminal supports TUI applications
- Check if running in proper terminal (not IDE console)
- Verify Go dependencies with `go mod tidy`

**"could not open a new TTY" Error**
- TUI requires a proper terminal environment
- Cannot run in some IDE consoles or CI environments
- Use regular CLI commands in headless environments

### **Debug Mode**
Enable debug output to troubleshoot issues:
```bash
re-shell tui --debug
```

This will show:
- IPC message exchanges
- Go TUI startup logs
- Error details and stack traces

## 📚 Examples

### **Dashboard Usage**
```bash
# Launch dashboard for current project
re-shell tui

# View specific project
re-shell tui --project /path/to/my-app

# Dashboard shows:
# - Project information
# - Service status
# - Recent activity
# - Quick actions
```

### **Project Initialization**
```bash
# Interactive project creation
re-shell tui --mode init

# Guides through:
# - Project name selection
# - Template choice
# - Configuration options
# - Dependency installation
```

### **Service Management**
```bash
# Manage services interactively
re-shell tui --mode manage

# Features:
# - Start/stop services
# - View service logs
# - Monitor health status
# - Resource usage
```

The Re-Shell TUI provides a modern, interactive way to work with complex full-stack projects, making development more visual and user-friendly while maintaining the power and flexibility of the command-line interface.