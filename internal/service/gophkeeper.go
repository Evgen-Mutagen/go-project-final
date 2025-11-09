package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gophkeeper/internal/auth"
	"github.com/gophkeeper/internal/crypto"
	"github.com/gophkeeper/internal/models"
	"github.com/gophkeeper/internal/storage"
)

// GophKeeperService основной сервис приложения
type GophKeeperService struct {
	repo      storage.Repository
	jwtMgr    *auth.JWTManager
	encryptor *crypto.Encryptor
}

// NewGophKeeperService создает новый экземпляр сервиса
func NewGophKeeperService(repo storage.Repository, jwtSecret string, jwtExpiration time.Duration, encryptionKey string) *GophKeeperService {
	return &GophKeeperService{
		repo:      repo,
		jwtMgr:    auth.NewJWTManager(jwtSecret, jwtExpiration),
		encryptor: crypto.NewEncryptor(encryptionKey),
	}
}

// Register регистрирует нового пользователя
func (s *GophKeeperService) Register(ctx context.Context, req *models.RegisterRequest) (*models.AuthResponse, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("database not configured")
	}

	existingUser, err := s.repo.GetUserByUsernameOrEmail(ctx, req.Username, req.Email)
	if err == nil && existingUser != nil {
		if existingUser.Username == req.Username {
			return nil, fmt.Errorf("username already exists")
		}
		if existingUser.Email == req.Email {
			return nil, fmt.Errorf("email already exists")
		}
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	token, err := s.jwtMgr.GenerateToken(user.ID, user.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &models.AuthResponse{
		Token: token,
		User:  *user,
	}, nil
}

// Login аутентифицирует пользователя
func (s *GophKeeperService) Login(ctx context.Context, req *models.LoginRequest) (*models.AuthResponse, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("database not configured")
	}

	user, err := s.repo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := auth.CheckPassword(user.PasswordHash, req.Password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	token, err := s.jwtMgr.GenerateToken(user.ID, user.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &models.AuthResponse{
		Token: token,
		User:  *user,
	}, nil
}

// ValidateToken валидирует JWT токен
func (s *GophKeeperService) ValidateToken(token string) (*auth.Claims, error) {
	return s.jwtMgr.ValidateToken(token)
}

// CreateSecretData создает новые секретные данные
func (s *GophKeeperService) CreateSecretData(ctx context.Context, userID uuid.UUID, req *models.CreateSecretDataRequest) (*models.SecretDataResponse, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("database not configured")
	}
	metadata := req.Metadata
	encrypted := false
	if req.Metadata != "" {
		encryptedMetadata, err := s.encryptor.Encrypt(req.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt metadata: %w", err)
		}
		metadata = encryptedMetadata
		encrypted = true
	}

	data := &models.SecretData{
		ID:          uuid.New(),
		UserID:      userID,
		Type:        req.Type,
		Title:       req.Title,
		Description: req.Description,
		Metadata:    metadata,
		Encrypted:   encrypted,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repo.CreateSecretData(ctx, data); err != nil {
		return nil, fmt.Errorf("failed to create secret data: %w", err)
	}

	return &models.SecretDataResponse{
		ID:          data.ID,
		Type:        data.Type,
		Title:       data.Title,
		Description: data.Description,
		Metadata:    data.Metadata,
		CreatedAt:   data.CreatedAt,
		UpdatedAt:   data.UpdatedAt,
	}, nil
}

// GetSecretData получает секретные данные по ID
func (s *GophKeeperService) GetSecretData(ctx context.Context, userID uuid.UUID, dataID uuid.UUID) (*models.SecretDataResponse, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("database not configured")
	}

	data, err := s.repo.GetSecretDataByID(ctx, dataID, userID)
	if err != nil {
		return nil, err
	}

	metadata := data.Metadata
	if data.Encrypted {
		decryptedMetadata, err := s.encryptor.Decrypt(data.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
		}
		metadata = decryptedMetadata
	}

	return &models.SecretDataResponse{
		ID:          data.ID,
		Type:        data.Type,
		Title:       data.Title,
		Description: data.Description,
		Metadata:    metadata,
		CreatedAt:   data.CreatedAt,
		UpdatedAt:   data.UpdatedAt,
	}, nil
}

// GetUserSecretData получает все секретные данные пользователя
func (s *GophKeeperService) GetUserSecretData(ctx context.Context, userID uuid.UUID) ([]*models.SecretDataResponse, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("database not configured")
	}

	dataList, err := s.repo.GetUserSecretData(ctx, userID)
	if err != nil {
		return nil, err
	}

	var response []*models.SecretDataResponse
	for _, data := range dataList {
		metadata := data.Metadata
		if data.Encrypted {
			decryptedMetadata, err := s.encryptor.Decrypt(data.Metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt metadata for data ID %s: %w", data.ID, err)
			}
			metadata = decryptedMetadata
		}

		response = append(response, &models.SecretDataResponse{
			ID:          data.ID,
			Type:        data.Type,
			Title:       data.Title,
			Description: data.Description,
			Metadata:    metadata,
			CreatedAt:   data.CreatedAt,
			UpdatedAt:   data.UpdatedAt,
		})
	}

	return response, nil
}

// UpdateSecretData обновляет секретные данные
func (s *GophKeeperService) UpdateSecretData(ctx context.Context, userID uuid.UUID, dataID uuid.UUID, req *models.UpdateSecretDataRequest) (*models.SecretDataResponse, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("database not configured")
	}

	data, err := s.repo.GetSecretDataByID(ctx, dataID, userID)
	if err != nil {
		return nil, err
	}

	metadata := req.Metadata
	encrypted := data.Encrypted
	if req.Metadata != "" {
		encryptedMetadata, err := s.encryptor.Encrypt(req.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt metadata: %w", err)
		}
		metadata = encryptedMetadata
		encrypted = true
	}

	data.Title = req.Title
	data.Description = req.Description
	data.Metadata = metadata
	data.Encrypted = encrypted
	data.UpdatedAt = time.Now()

	if err := s.repo.UpdateSecretData(ctx, data); err != nil {
		return nil, fmt.Errorf("failed to update secret data: %w", err)
	}

	responseMetadata := metadata
	if encrypted {
		decryptedMetadata, err := s.encryptor.Decrypt(metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
		}
		responseMetadata = decryptedMetadata
	}

	return &models.SecretDataResponse{
		ID:          data.ID,
		Type:        data.Type,
		Title:       data.Title,
		Description: data.Description,
		Metadata:    responseMetadata,
		CreatedAt:   data.CreatedAt,
		UpdatedAt:   data.UpdatedAt,
	}, nil
}

// DeleteSecretData удаляет секретные данные
func (s *GophKeeperService) DeleteSecretData(ctx context.Context, userID uuid.UUID, dataID uuid.UUID) error {
	if s.repo == nil {
		return fmt.Errorf("database not configured")
	}

	return s.repo.DeleteSecretData(ctx, dataID, userID)
}

// ParseLoginPasswordData парсит данные логина и пароля из JSON
func ParseLoginPasswordData(metadata string) (*models.LoginPasswordData, error) {
	var data models.LoginPasswordData
	if err := json.Unmarshal([]byte(metadata), &data); err != nil {
		return nil, fmt.Errorf("failed to parse login password data: %w", err)
	}
	return &data, nil
}

// ParseTextData парсит текстовые данные из JSON
func ParseTextData(metadata string) (*models.TextData, error) {
	var data models.TextData
	if err := json.Unmarshal([]byte(metadata), &data); err != nil {
		return nil, fmt.Errorf("failed to parse text data: %w", err)
	}
	return &data, nil
}

// ParseBankCardData парсит данные банковской карты из JSON
func ParseBankCardData(metadata string) (*models.BankCardData, error) {
	var data models.BankCardData
	if err := json.Unmarshal([]byte(metadata), &data); err != nil {
		return nil, fmt.Errorf("failed to parse bank card data: %w", err)
	}
	return &data, nil
}
