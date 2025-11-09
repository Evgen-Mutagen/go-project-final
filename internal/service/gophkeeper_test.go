package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gophkeeper/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRepository мок репозитория для тестов
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateUser(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockRepository) GetUserByUsernameOrEmail(ctx context.Context, username, email string) (*models.User, error) {
	args := m.Called(ctx, username, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockRepository) CreateSecretData(ctx context.Context, data *models.SecretData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockRepository) GetSecretDataByID(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*models.SecretData, error) {
	args := m.Called(ctx, id, userID)
	return args.Get(0).(*models.SecretData), args.Error(1)
}

func (m *MockRepository) GetUserSecretData(ctx context.Context, userID uuid.UUID) ([]*models.SecretData, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*models.SecretData), args.Error(1)
}

func (m *MockRepository) UpdateSecretData(ctx context.Context, data *models.SecretData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockRepository) DeleteSecretData(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	args := m.Called(ctx, id, userID)
	return args.Error(0)
}

func TestGophKeeperService_Register(t *testing.T) {
	mockRepo := new(MockRepository)
	service := NewGophKeeperService(mockRepo, "test-secret", 24*time.Hour, "test-encryption-key")

	ctx := context.Background()
	req := &models.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	// Настраиваем мок
	mockRepo.On("GetUserByUsernameOrEmail", ctx, "testuser", "test@example.com").Return((*models.User)(nil), assert.AnError)
	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*models.User")).Return(nil)

	// Выполняем тест
	response, err := service.Register(ctx, req)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.Token)
	assert.Equal(t, "testuser", response.User.Username)
	assert.Equal(t, "test@example.com", response.User.Email)

	mockRepo.AssertExpectations(t)
}
