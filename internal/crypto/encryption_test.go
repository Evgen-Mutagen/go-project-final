package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	key := "test-encryption-key"
	encryptor := NewEncryptor(key)

	plaintext := "sensitive data to encrypt"

	// Тест шифрования
	ciphertext, err := encryptor.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	// Тест расшифровки
	decryptedText, err := encryptor.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedText)

	// Тест с разными ключами
	otherEncryptor := NewEncryptor("other-key")
	_, err = otherEncryptor.Decrypt(ciphertext)
	assert.Error(t, err)

	// Тест с пустой строкой
	emptyCipher, err := encryptor.Encrypt("")
	require.NoError(t, err)
	emptyPlain, err := encryptor.Decrypt(emptyCipher)
	require.NoError(t, err)
	assert.Equal(t, "", emptyPlain)
}
