package models

import (
	"time"

	"github.com/google/uuid"
)

// DataType представляет тип хранимых данных
type DataType string

const (
	DataTypeLoginPassword DataType = "login_password"
	DataTypeText          DataType = "text"
	DataTypeBinary        DataType = "binary"
	DataTypeBankCard      DataType = "bank_card"
)

// SecretData представляет базовую структуру для всех типов секретных данных
type SecretData struct {
	ID          uuid.UUID `json:"id" db:"id"`
	UserID      uuid.UUID `json:"user_id" db:"user_id"`
	Type        DataType  `json:"type" db:"type"`
	Title       string    `json:"title" db:"title"`
	Description string    `json:"description" db:"description"`
	Metadata    string    `json:"metadata" db:"metadata"` // JSON строка с дополнительными данными (хранится как JSONB в БД)
	Encrypted   bool      `json:"encrypted" db:"encrypted"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// LoginPasswordData представляет данные логина и пароля
type LoginPasswordData struct {
	Website  string `json:"website"`
	Username string `json:"username"`
	Password string `json:"password"`
	Notes    string `json:"notes"`
}

// TextData представляет произвольные текстовые данные
type TextData struct {
	Content string `json:"content"`
	Notes   string `json:"notes"`
}

// BinaryData представляет бинарные данные
type BinaryData struct {
	FileName    string `json:"file_name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Data        []byte `json:"data"`
	Notes       string `json:"notes"`
}

// BankCardData представляет данные банковской карты
type BankCardData struct {
	CardNumber string `json:"card_number"`
	ExpiryDate string `json:"expiry_date"`
	CVV        string `json:"cvv"`
	Cardholder string `json:"cardholder"`
	Bank       string `json:"bank"`
	Notes      string `json:"notes"`
}

// User представляет пользователя системы
type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// CreateSecretDataRequest представляет запрос на создание секретных данных
type CreateSecretDataRequest struct {
	Type        DataType `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Metadata    string   `json:"metadata"`
}

// UpdateSecretDataRequest представляет запрос на обновление секретных данных
type UpdateSecretDataRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Metadata    string `json:"metadata"`
}

// SecretDataResponse представляет ответ с секретными данными
type SecretDataResponse struct {
	ID          uuid.UUID `json:"id"`
	Type        DataType  `json:"type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Metadata    string    `json:"metadata"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// LoginRequest представляет запрос на вход
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RegisterRequest представляет запрос на регистрацию
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse представляет ответ аутентификации
type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// ErrorResponse представляет ответ с ошибкой
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
