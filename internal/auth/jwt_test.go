package auth

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTManager(t *testing.T) {
	secretKey := "test-secret-key"
	jwtMgr := NewJWTManager(secretKey)

	userID := uuid.New()
	username := "testuser"

	// Тест генерации токена
	token, err := jwtMgr.GenerateToken(userID, username)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Тест валидации токена
	claims, err := jwtMgr.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, username, claims.Username)

	// Тест с неверным токеном
	_, err = jwtMgr.ValidateToken("invalid-token")
	assert.Error(t, err)

	// Тест с токеном другого секрета
	otherJwtMgr := NewJWTManager("other-secret")
	otherToken, _ := otherJwtMgr.GenerateToken(userID, username)
	_, err = jwtMgr.ValidateToken(otherToken)
	assert.Error(t, err)
}

func TestPasswordHashing(t *testing.T) {
	password := "test-password"

	// Тест хеширования
	hashedPassword, err := HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hashedPassword)
	assert.NotEqual(t, password, hashedPassword)

	// Тест проверки правильного пароля
	err = CheckPassword(hashedPassword, password)
	assert.NoError(t, err)

	// Тест проверки неправильного пароля
	err = CheckPassword(hashedPassword, "wrong-password")
	assert.Error(t, err)
}
