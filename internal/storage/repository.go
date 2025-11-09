package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/gophkeeper/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository интерфейс для работы с хранилищем
type Repository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByUsernameOrEmail(ctx context.Context, username, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)

	CreateSecretData(ctx context.Context, data *models.SecretData) error
	GetSecretDataByID(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*models.SecretData, error)
	GetUserSecretData(ctx context.Context, userID uuid.UUID) ([]*models.SecretData, error)
	UpdateSecretData(ctx context.Context, data *models.SecretData) error
	DeleteSecretData(ctx context.Context, id uuid.UUID, userID uuid.UUID) error
}

// PostgresRepository реализация репозитория для PostgreSQL
type PostgresRepository struct {
	db *pgxpool.Pool
}

// NewPostgresRepository создает новый PostgreSQL репозиторий
func NewPostgresRepository(db *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// CreateUser создает нового пользователя
func (r *PostgresRepository) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, username, email, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.Exec(ctx, query, user.ID, user.Username, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt)
	return err
}

// GetUserByUsername получает пользователя по имени
func (r *PostgresRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, created_at, updated_at FROM users WHERE username = $1`
	row := r.db.QueryRow(ctx, query, username)

	user := &models.User{}
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return user, nil
}

// GetUserByEmail получает пользователя по email
func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, created_at, updated_at FROM users WHERE email = $1`
	row := r.db.QueryRow(ctx, query, email)

	user := &models.User{}
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return user, nil
}

// GetUserByUsernameOrEmail получает пользователя по имени или email (для проверки существования)
func (r *PostgresRepository) GetUserByUsernameOrEmail(ctx context.Context, username, email string) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, created_at, updated_at FROM users WHERE username = $1 OR email = $2`
	row := r.db.QueryRow(ctx, query, username, email)

	user := &models.User{}
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return user, nil
}

// GetUserByID получает пользователя по ID
func (r *PostgresRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `SELECT id, username, email, password_hash, created_at, updated_at FROM users WHERE id = $1`
	row := r.db.QueryRow(ctx, query, id)

	user := &models.User{}
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return user, nil
}

// CreateSecretData создает новые секретные данные
func (r *PostgresRepository) CreateSecretData(ctx context.Context, data *models.SecretData) error {
	query := `
		INSERT INTO secret_data (id, user_id, type, title, description, metadata, encrypted, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.db.Exec(ctx, query, data.ID, data.UserID, data.Type, data.Title, data.Description, data.Metadata, data.Encrypted, data.CreatedAt, data.UpdatedAt)
	return err
}

// GetSecretDataByID получает секретные данные по ID
func (r *PostgresRepository) GetSecretDataByID(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*models.SecretData, error) {
	query := `
		SELECT id, user_id, type, title, description, metadata, encrypted, created_at, updated_at
		FROM secret_data
		WHERE id = $1 AND user_id = $2
	`
	row := r.db.QueryRow(ctx, query, id, userID)

	data := &models.SecretData{}
	err := row.Scan(&data.ID, &data.UserID, &data.Type, &data.Title, &data.Description, &data.Metadata, &data.Encrypted, &data.CreatedAt, &data.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("secret data not found")
		}
		return nil, err
	}

	return data, nil
}

// GetUserSecretData получает все секретные данные пользователя
func (r *PostgresRepository) GetUserSecretData(ctx context.Context, userID uuid.UUID) ([]*models.SecretData, error) {
	query := `
		SELECT id, user_id, type, title, description, metadata, encrypted, created_at, updated_at
		FROM secret_data
		WHERE user_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dataList []*models.SecretData
	for rows.Next() {
		data := &models.SecretData{}
		err := rows.Scan(&data.ID, &data.UserID, &data.Type, &data.Title, &data.Description, &data.Metadata, &data.Encrypted, &data.CreatedAt, &data.UpdatedAt)
		if err != nil {
			return nil, err
		}
		dataList = append(dataList, data)
	}

	return dataList, nil
}

// UpdateSecretData обновляет секретные данные
func (r *PostgresRepository) UpdateSecretData(ctx context.Context, data *models.SecretData) error {
	query := `
		UPDATE secret_data
		SET title = $1, description = $2, metadata = $3, encrypted = $4, updated_at = $5
		WHERE id = $6 AND user_id = $7
	`
	result, err := r.db.Exec(ctx, query, data.Title, data.Description, data.Metadata, data.Encrypted, data.UpdatedAt, data.ID, data.UserID)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("secret data not found or not owned by user")
	}

	return nil
}

// DeleteSecretData удаляет секретные данные
func (r *PostgresRepository) DeleteSecretData(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	query := `DELETE FROM secret_data WHERE id = $1 AND user_id = $2`
	result, err := r.db.Exec(ctx, query, id, userID)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("secret data not found or not owned by user")
	}

	return nil
}
