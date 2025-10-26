package configs

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/caarlos0/env/v6"
)

// JSONConfig структура для загрузки конфигурации из JSON файла
type JSONConfig struct {
	ServerAddress     string `json:"server_address"`
	GRPCServerAddress string `json:"grpc_server_address"`
	DatabaseDSN       string `json:"database_dsn"`
	EnableHTTPS       bool   `json:"enable_https"`
	JWTSecret         string `json:"jwt_secret"`
	EncryptionKey     string `json:"encryption_key"`
}

// loadJSONConfig загружает конфигурацию из JSON файла
func loadJSONConfig(filename string) (*JSONConfig, error) {
	if filename == "" {
		return nil, nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("ошибка при чтении файла конфигурации %s: %w", filename, err)
	}

	var jsonConfig JSONConfig
	if err := json.Unmarshal(data, &jsonConfig); err != nil {
		return nil, fmt.Errorf("ошибка при парсинге JSON файла %s: %w", filename, err)
	}

	return &jsonConfig, nil
}

// Config содержит настройки приложения
// Может быть загружен из переменных окружения, флагов командной строки или JSON файла
type Config struct {
	ServerAddress     string `env:"SERVER_ADDRESS" envDefault:"localhost:8080"`      // Адрес HTTP сервера
	GRPCServerAddress string `env:"GRPC_SERVER_ADDRESS" envDefault:"localhost:8081"` // Адрес gRPC сервера
	DatabaseDSN       string `env:"DATABASE_DSN" envDefault:""`                      // DSN для подключения к БД
	EnableHTTPS       bool   `env:"ENABLE_HTTPS" envDefault:"false"`                 // Включить HTTPS
	JWTSecret         string `env:"JWT_SECRET" envDefault:"your-secret-key"`         // Секретный ключ для JWT
	EncryptionKey     string `env:"ENCRYPTION_KEY" envDefault:"your-encryption-key"` // Ключ для шифрования данных
	ConfigFile        string `env:"CONFIG" envDefault:""`                            // Путь к JSON файлу конфигурации
}

// LoadConfig используется для загрузки конфига
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("ошибка при парсинге переменных окружения: %v", err)
	}

	addressFlag := flag.String("a", "", "HTTP server address (host:port)")
	grpcAddressFlag := flag.String("g", "", "gRPC server address (host:port)")
	databaseFlag := flag.String("d", "", "Database connection string")
	enableHTTPSFlag := flag.Bool("s", false, "Enable HTTPS")
	jwtSecretFlag := flag.String("jwt", "", "JWT secret key")
	encryptionKeyFlag := flag.String("enc", "", "Encryption key")
	configFlag := flag.String("c", "", "Path to JSON config file")
	configFlagLong := flag.String("config", "", "Path to JSON config file")

	flag.Parse()

	configFile := cfg.ConfigFile
	if *configFlag != "" {
		configFile = *configFlag
	}
	if *configFlagLong != "" {
		configFile = *configFlagLong
	}

	jsonConfig, err := loadJSONConfig(configFile)
	if err != nil {
		return nil, err
	}

	if jsonConfig != nil {
		if jsonConfig.ServerAddress != "" {
			cfg.ServerAddress = jsonConfig.ServerAddress
		}
		if jsonConfig.GRPCServerAddress != "" {
			cfg.GRPCServerAddress = jsonConfig.GRPCServerAddress
		}
		if jsonConfig.DatabaseDSN != "" {
			cfg.DatabaseDSN = jsonConfig.DatabaseDSN
		}
		if jsonConfig.JWTSecret != "" {
			cfg.JWTSecret = jsonConfig.JWTSecret
		}
		if jsonConfig.EncryptionKey != "" {
			cfg.EncryptionKey = jsonConfig.EncryptionKey
		}

		cfg.EnableHTTPS = jsonConfig.EnableHTTPS
	}

	if *addressFlag != "" {
		cfg.ServerAddress = *addressFlag
	}
	if *grpcAddressFlag != "" {
		cfg.GRPCServerAddress = *grpcAddressFlag
	}
	if *databaseFlag != "" {
		cfg.DatabaseDSN = *databaseFlag
	}
	if *jwtSecretFlag != "" {
		cfg.JWTSecret = *jwtSecretFlag
	}
	if *encryptionKeyFlag != "" {
		cfg.EncryptionKey = *encryptionKeyFlag
	}
	if *enableHTTPSFlag {
		cfg.EnableHTTPS = true
	}

	serverAddr := strings.TrimPrefix(cfg.ServerAddress, "http://")
	serverAddr = strings.TrimPrefix(serverAddr, "https://")
	serverAddr = strings.TrimSuffix(serverAddr, "/")

	if serverAddr == "" {
		return nil, fmt.Errorf("адрес сервера не предоставлен")
	}

	return cfg, nil
}
