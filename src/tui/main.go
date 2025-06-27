package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// IPC Message structure
type IPCMessage struct {
	Type string      `json:"type"`
	ID   string      `json:"id"`
	Data interface{} `json:"data"`
}

// Application modes
type AppMode int

const (
	ModeMenu AppMode = iota
	ModeDashboard
	ModeProjectInit
	ModeServiceManager
	ModeFileExplorer
	ModeConfigEditor
	ModeHelp
)

// Project information
type ProjectInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Path        string `json:"path"`
	Type        string `json:"type"`
}

// Main application model
type Model struct {
	mode           AppMode
	projectInfo    ProjectInfo
	spinner        spinner.Model
	textInput      textinput.Model
	list           list.Model
	viewport       viewport.Model
	width          int
	height         int
	ready          bool
	err            error
	menuItems      []list.Item
	currentView    string
	loading        bool
	statusMessage  string
}

// Menu item for navigation
type MenuItem struct {
	title string
	desc  string
	mode  AppMode
}

func (i MenuItem) Title() string       { return i.title }
func (i MenuItem) Description() string { return i.desc }
func (i MenuItem) FilterValue() string { return i.title }

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#F25D94")).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5555")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#50FA7B")).
			Bold(true)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8BE9FD"))

	focusedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF79C6"))

	docStyle = lipgloss.NewStyle().Padding(1, 2, 1, 2)
)

func main() {
	// Initialize the TUI
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("Re-Shell TUI v1.0.0")
		return
	}

	// Create initial model
	m := initialModel()

	// Set up stdin reader for IPC
	go handleIPC()

	// Start the Bubble Tea program
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	if _, err := p.Run(); err != nil {
		log.Fatal("Error running TUI:", err)
	}
}

func initialModel() Model {
	// Create spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6"))

	// Create text input
	ti := textinput.New()
	ti.Placeholder = "Enter command..."
	ti.Focus()

	// Create menu items
	menuItems := []list.Item{
		MenuItem{title: "📊 Project Dashboard", desc: "Overview of your Re-Shell project", mode: ModeDashboard},
		MenuItem{title: "🚀 Initialize Project", desc: "Create a new Re-Shell project", mode: ModeProjectInit},
		MenuItem{title: "⚙️  Service Manager", desc: "Manage microfrontends and microservices", mode: ModeServiceManager},
		MenuItem{title: "📁 File Explorer", desc: "Browse project files and structure", mode: ModeFileExplorer},
		MenuItem{title: "🔧 Configuration", desc: "Edit Re-Shell configuration", mode: ModeConfigEditor},
		MenuItem{title: "❓ Help", desc: "Get help and documentation", mode: ModeHelp},
	}

	// Create list
	l := list.New(menuItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Re-Shell TUI"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	return Model{
		mode:          ModeMenu,
		spinner:       s,
		textInput:     ti,
		list:          l,
		loading:       true,
		statusMessage: "Loading...",
		menuItems:     menuItems,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		requestProjectInfo(),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		if !m.ready {
			m.viewport = viewport.New(msg.Width, msg.Height-4)
			m.viewport.YPosition = 1
			m.list.SetSize(msg.Width, msg.Height-4)
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - 4
			m.list.SetSize(msg.Width, msg.Height-4)
		}

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.mode == ModeMenu {
				return m, tea.Quit
			}
			m.mode = ModeMenu
			return m, nil

		case "enter":
			if m.mode == ModeMenu {
				if item, ok := m.list.SelectedItem().(MenuItem); ok {
					m.mode = item.mode
					m.loading = true
					cmds = append(cmds, m.enterMode(item.mode))
				}
			}

		case "esc":
			m.mode = ModeMenu
			return m, nil
		}

	case ProjectInfoMsg:
		m.projectInfo = ProjectInfo(msg)
		m.loading = false
		m.statusMessage = fmt.Sprintf("Project: %s (%s)", m.projectInfo.Name, m.projectInfo.Version)

	case ErrorMsg:
		m.err = error(msg)
		m.loading = false
		m.statusMessage = "Error: " + msg.Error()

	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	// Update active component
	switch m.mode {
	case ModeMenu:
		m.list, cmd = m.list.Update(msg)
		cmds = append(cmds, cmd)
	default:
		m.textInput, cmd = m.textInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m Model) View() string {
	if !m.ready {
		return "\n  Loading Re-Shell TUI..."
	}

	// Header
	header := titleStyle.Render("🐚 Re-Shell TUI") + " " +
		infoStyle.Render(m.statusMessage)

	// Content based on mode
	var content string
	switch m.mode {
	case ModeMenu:
		content = m.renderMenu()
	case ModeDashboard:
		content = m.renderDashboard()
	case ModeProjectInit:
		content = m.renderProjectInit()
	case ModeServiceManager:
		content = m.renderServiceManager()
	case ModeFileExplorer:
		content = m.renderFileExplorer()
	case ModeConfigEditor:
		content = m.renderConfigEditor()
	case ModeHelp:
		content = m.renderHelp()
	default:
		content = "Unknown mode"
	}

	// Footer
	footer := helpStyle.Render("Press 'q' to quit, 'esc' to go back to menu")

	return docStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			header,
			"",
			content,
			"",
			footer,
		),
	)
}

func (m Model) renderMenu() string {
	return m.list.View()
}

func (m Model) renderDashboard() string {
	if m.loading {
		return m.spinner.View() + " Loading project dashboard..."
	}

	dashboard := headerStyle.Render("📊 Project Dashboard") + "\n\n"

	// Project info section
	dashboard += lipgloss.NewStyle().Bold(true).Render("Project Information:") + "\n"
	dashboard += fmt.Sprintf("Name: %s\n", infoStyle.Render(m.projectInfo.Name))
	dashboard += fmt.Sprintf("Version: %s\n", infoStyle.Render(m.projectInfo.Version))
	dashboard += fmt.Sprintf("Description: %s\n", infoStyle.Render(m.projectInfo.Description))
	dashboard += fmt.Sprintf("Path: %s\n\n", infoStyle.Render(m.projectInfo.Path))

	// Quick stats (mock data for now)
	dashboard += lipgloss.NewStyle().Bold(true).Render("Quick Stats:") + "\n"
	dashboard += "Microfrontends: " + successStyle.Render("3 active") + "\n"
	dashboard += "Microservices: " + successStyle.Render("5 running") + "\n"
	dashboard += "Build Status: " + successStyle.Render("✓ All builds passing") + "\n"
	dashboard += "Dependencies: " + infoStyle.Render("12 packages up to date") + "\n\n"

	// Recent activity
	dashboard += lipgloss.NewStyle().Bold(true).Render("Recent Activity:") + "\n"
	dashboard += "• " + infoStyle.Render("Built frontend app") + " - 2 minutes ago\n"
	dashboard += "• " + infoStyle.Render("Updated API service") + " - 15 minutes ago\n"
	dashboard += "• " + successStyle.Render("Deployed to staging") + " - 1 hour ago\n"

	return dashboard
}

func (m Model) renderProjectInit() string {
	content := headerStyle.Render("🚀 Project Initialization") + "\n\n"
	content += "Initialize a new Re-Shell project:\n\n"
	content += m.textInput.View() + "\n\n"
	content += helpStyle.Render("Enter project name and press Enter to create")
	return content
}

func (m Model) renderServiceManager() string {
	content := headerStyle.Render("⚙️ Service Manager") + "\n\n"
	content += "Manage your microfrontends and microservices:\n\n"

	// Services list (mock data)
	services := []struct {
		name   string
		type_  string
		status string
		port   string
	}{
		{"user-auth", "microservice", "running", "3001"},
		{"product-catalog", "microservice", "running", "3002"},
		{"payment-gateway", "microservice", "stopped", "3003"},
		{"main-shell", "microfrontend", "running", "3000"},
		{"user-dashboard", "microfrontend", "running", "3004"},
	}

	for _, service := range services {
		status := errorStyle.Render("●")
		if service.status == "running" {
			status = successStyle.Render("●")
		}

		content += fmt.Sprintf("%s %s (%s) - Port %s\n",
			status,
			focusedStyle.Render(service.name),
			infoStyle.Render(service.type_),
			service.port,
		)
	}

	content += "\n" + helpStyle.Render("Use arrow keys to select, Enter to manage service")
	return content
}

func (m Model) renderFileExplorer() string {
	content := headerStyle.Render("📁 File Explorer") + "\n\n"
	content += "Browse project structure:\n\n"
	content += "📁 " + focusedStyle.Render("src/") + "\n"
	content += "  📁 " + infoStyle.Render("apps/") + "\n"
	content += "    📄 main-shell/\n"
	content += "    📄 user-dashboard/\n"
	content += "  📁 " + infoStyle.Render("services/") + "\n"
	content += "    📄 user-auth/\n"
	content += "    📄 product-catalog/\n"
	content += "📄 " + infoStyle.Render("package.json") + "\n"
	content += "📄 " + infoStyle.Render("reshell.config.js") + "\n"
	return content
}

func (m Model) renderConfigEditor() string {
	content := headerStyle.Render("🔧 Configuration Editor") + "\n\n"
	content += "Edit Re-Shell configuration:\n\n"
	content += lipgloss.NewStyle().Bold(true).Render("Current Configuration:") + "\n"
	content += "Framework: " + infoStyle.Render("React") + "\n"
	content += "Package Manager: " + infoStyle.Render("pnpm") + "\n"
	content += "Module Federation: " + successStyle.Render("Enabled") + "\n"
	content += "TypeScript: " + successStyle.Render("Enabled") + "\n"
	content += "Testing: " + infoStyle.Render("Jest + React Testing Library") + "\n"
	return content
}

func (m Model) renderHelp() string {
	content := headerStyle.Render("❓ Help & Documentation") + "\n\n"
	content += "Welcome to Re-Shell TUI!\n\n"
	content += lipgloss.NewStyle().Bold(true).Render("Keyboard Shortcuts:") + "\n"
	content += "• " + focusedStyle.Render("q") + " - Quit application\n"
	content += "• " + focusedStyle.Render("esc") + " - Return to main menu\n"
	content += "• " + focusedStyle.Render("↑/↓") + " - Navigate menu items\n"
	content += "• " + focusedStyle.Render("Enter") + " - Select item\n\n"
	content += lipgloss.NewStyle().Bold(true).Render("Features:") + "\n"
	content += "• Interactive project dashboard\n"
	content += "• Real-time service management\n"
	content += "• Visual configuration editing\n"
	content += "• Integrated file browser\n"
	return content
}

func (m Model) enterMode(mode AppMode) tea.Cmd {
	switch mode {
	case ModeDashboard:
		return requestProjectInfo()
	default:
		return func() tea.Msg {
			time.Sleep(500 * time.Millisecond) // Simulate loading
			return LoadingCompleteMsg{}
		}
	}
}

// Messages
type ProjectInfoMsg ProjectInfo
type ErrorMsg error
type LoadingCompleteMsg struct{}

// IPC Commands
func requestProjectInfo() tea.Cmd {
	return func() tea.Msg {
		msg := IPCMessage{
			Type: "get-project-info",
			ID:   generateID(),
			Data: map[string]string{
				"path": os.Getenv("RESHELL_PROJECT_PATH"),
			},
		}

		response, err := sendIPCMessage(msg)
		if err != nil {
			return ErrorMsg(err)
		}

		var projectInfo ProjectInfo
		if err := json.Unmarshal(response, &projectInfo); err != nil {
			return ErrorMsg(err)
		}

		return ProjectInfoMsg(projectInfo)
	}
}

func sendIPCMessage(msg IPCMessage) ([]byte, error) {
	// Send message to Node.js process via stdin
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%s\n", data)

	// For now, return mock data
	// In real implementation, this would wait for response from Node.js
	mockProjectInfo := ProjectInfo{
		Name:        "my-reshell-app",
		Version:     "1.0.0",
		Description: "A Re-Shell full-stack application",
		Path:        "/path/to/project",
		Type:        "re-shell",
	}

	return json.Marshal(mockProjectInfo)
}

func handleIPC() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var msg IPCMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue // Ignore invalid JSON
		}

		// Handle incoming IPC messages
		// This would process responses from Node.js CLI
	}
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}