package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gophkeeper/internal/models"
)

const (
	DefaultServerURL = "http://localhost:8080"
	ConfigFileName   = ".gophkeeper"
)

// Client представляет клиент приложения
type Client struct {
	serverURL string
	token     string
	client    *http.Client
}

// NewClient создает новый клиент
func NewClient(serverURL string) *Client {
	return &Client{
		serverURL: serverURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetToken устанавливает токен аутентификации
func (c *Client) SetToken(token string) {
	c.token = token
}

// Register регистрирует нового пользователя
func (c *Client) Register(username, email, password string) error {
	req := models.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.client.Post(c.serverURL+"/api/v1/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s", string(body))
	}

	var authResp models.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	c.SetToken(authResp.Token)
	c.saveConfig(authResp.Token)
	fmt.Println("Registration successful!")
	return nil
}

// Login выполняет вход в систему
func (c *Client) Login(username, password string) error {
	req := models.LoginRequest{
		Username: username,
		Password: password,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.client.Post(c.serverURL+"/api/v1/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed: %s", string(body))
	}

	var authResp models.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	c.SetToken(authResp.Token)
	c.saveConfig(authResp.Token)
	fmt.Println("Login successful!")
	return nil
}

// GetData получает все данные пользователя
func (c *Client) GetData() ([]*models.SecretDataResponse, error) {
	req, err := http.NewRequest("GET", c.serverURL+"/api/v1/data", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get data: %s", string(body))
	}

	var data []*models.SecretDataResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return data, nil
}

// CreateData создает новые данные
func (c *Client) CreateData(dataType, title, description, metadata string) (*models.SecretDataResponse, error) {
	req := models.CreateSecretDataRequest{
		Type:        models.DataType(dataType),
		Title:       title,
		Description: description,
		Metadata:    metadata,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.serverURL+"/api/v1/data", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create data: %s", string(body))
	}

	var response models.SecretDataResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// saveConfig сохраняет конфигурацию
func (c *Client) saveConfig(token string) {
	config := map[string]string{
		"server_url": c.serverURL,
		"token":      token,
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		return
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	configFile := fmt.Sprintf("%s/%s", homeDir, ConfigFileName)
	if err := os.WriteFile(configFile, jsonData, 0600); err != nil {
		fmt.Printf("Warning: failed to save config: %v\n", err)
	}
}

// loadConfig загружает конфигурацию
func (c *Client) loadConfig() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	configFile := fmt.Sprintf("%s/%s", homeDir, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}

	var config map[string]string
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	if serverURL, ok := config["server_url"]; ok {
		c.serverURL = serverURL
	}
	if token, ok := config["token"]; ok {
		c.token = token
	}
}

func main() {
	version := "1.0.0"
	buildDate := "unknown"
	if v := os.Getenv("VERSION"); v != "" {
		version = v
	}
	if bd := os.Getenv("BUILD_DATE"); bd != "" {
		buildDate = bd
	}

	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("GophKeeper Client v%s\nBuild Date: %s\n", version, buildDate)
		return
	}

	client := NewClient(DefaultServerURL)
	client.loadConfig()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("gophkeeper> ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]

		switch command {
		case "register":
			if len(parts) < 4 {
				fmt.Println("Usage: register <username> <email> <password>")
				continue
			}
			err := client.Register(parts[1], parts[2], parts[3])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		case "login":
			if len(parts) < 3 {
				fmt.Println("Usage: login <username> <password>")
				continue
			}
			err := client.Login(parts[1], parts[2])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		case "list":
			data, err := client.GetData()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			if len(data) == 0 {
				fmt.Println("No data found")
				continue
			}
			for _, item := range data {
				fmt.Printf("ID: %s, Type: %s, Title: %s\n", item.ID, item.Type, item.Title)
			}

		case "add":
			if len(parts) < 5 {
				fmt.Println("Usage: add <type> <title> <description> <metadata>")
				fmt.Println("Types: login_password, text, binary, bank_card")
				continue
			}
			response, err := client.CreateData(parts[1], parts[2], parts[3], parts[4])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Created data with ID: %s\n", response.ID)
			}

		case "help":
			fmt.Println("Available commands:")
			fmt.Println("  register <username> <email> <password> - Register new user")
			fmt.Println("  login <username> <password> - Login")
			fmt.Println("  list - List all data")
			fmt.Println("  add <type> <title> <description> <metadata> - Add new data")
			fmt.Println("  help - Show this help")
			fmt.Println("  exit - Exit the program")

		case "exit":
			fmt.Println("Goodbye!")
			return

		default:
			fmt.Printf("Unknown command: %s. Type 'help' for available commands.\n", command)
		}
	}
}
