-- Создание таблицы пользователей
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Создание таблицы секретных данных
CREATE TABLE IF NOT EXISTS secret_data (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('login_password', 'text', 'binary', 'bank_card')),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    metadata JSONB NOT NULL,
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Создание индексов для улучшения производительности
CREATE INDEX IF NOT EXISTS idx_secret_data_user_id ON secret_data(user_id);
CREATE INDEX IF NOT EXISTS idx_secret_data_type ON secret_data(type);
CREATE INDEX IF NOT EXISTS idx_secret_data_created_at ON secret_data(created_at);
CREATE INDEX IF NOT EXISTS idx_secret_data_metadata_gin ON secret_data USING GIN (metadata);

-- Создание функции для автоматического обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Создание триггеров для автоматического обновления updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_secret_data_updated_at BEFORE UPDATE ON secret_data
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

