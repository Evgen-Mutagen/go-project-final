# Примеры использования GophKeeper

## Запуск сервера

```bash
# С переменными окружения
export DATABASE_DSN="postgres://user:password@localhost/gophkeeper?sslmode=disable"
export JWT_SECRET="your-secret-key"
export ENCRYPTION_KEY="your-encryption-key"

./bin/server

# Или с флагами
./bin/server -d "postgres://user:password@localhost/gophkeeper?sslmode=disable" -jwt "your-secret-key" -enc "your-encryption-key"
```

## Использование CLI клиента

### Регистрация и вход

```bash
# Запуск клиента
./bin/client

# Регистрация нового пользователя
gophkeeper> register john john@example.com password123
Registration successful!

# Вход в систему
gophkeeper> login john password123
Login successful!
```

### Работа с данными

#### Добавление логина и пароля

```bash
gophkeeper> add login_password "Gmail" "My Gmail account" '{"website":"gmail.com","username":"john@gmail.com","password":"mypassword","notes":"Personal email"}'
Created data with ID: 123e4567-e89b-12d3-a456-426614174000
```

#### Добавление текстовых данных

```bash
gophkeeper> add text "API Key" "GitHub API key" '{"content":"ghp_xxxxxxxxxxxxxxxxxxxx","notes":"For GitHub API"}'
Created data with ID: 123e4567-e89b-12d3-a456-426614174001
```

#### Добавление данных банковской карты

```bash
gophkeeper> add bank_card "Visa Card" "Main credit card" '{"card_number":"4111111111111111","expiry_date":"12/25","cvv":"123","cardholder":"John Doe","bank":"Chase","notes":"Primary card"}'
Created data with ID: 123e4567-e89b-12d3-a456-426614174002
```

#### Просмотр всех данных

```bash
gophkeeper> list
ID: 123e4567-e89b-12d3-a456-426614174000, Type: login_password, Title: Gmail
ID: 123e4567-e89b-12d3-a456-426614174001, Type: text, Title: API Key
ID: 123e4567-e89b-12d3-a456-426614174002, Type: bank_card, Title: Visa Card
```

## API примеры

### Регистрация пользователя

```bash
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "password123"
  }'
```

### Вход в систему

```bash
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "password": "password123"
  }'
```

### Создание данных

```bash
curl -X POST http://localhost:8080/api/v1/data \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "type": "login_password",
    "title": "Gmail",
    "description": "My Gmail account",
    "metadata": "{\"website\":\"gmail.com\",\"username\":\"john@gmail.com\",\"password\":\"mypassword\"}"
  }'
```

### Получение всех данных

```bash
curl -X GET http://localhost:8080/api/v1/data \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Настройка базы данных

### PostgreSQL

```sql
-- Создание базы данных
CREATE DATABASE gophkeeper;

-- Создание пользователя
CREATE USER gophkeeper_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE gophkeeper TO gophkeeper_user;

-- Выполнение миграций
\c gophkeeper
\i migrations/001_init.sql
```

### Переменные окружения

```bash
# Основные настройки
export SERVER_ADDRESS="localhost:8080"
export DATABASE_DSN="postgres://gophkeeper_user:your_password@localhost/gophkeeper?sslmode=disable"
export JWT_SECRET="your-super-secret-jwt-key"
export ENCRYPTION_KEY="your-super-secret-encryption-key"

# Опциональные настройки
export ENABLE_HTTPS="true"
export GRPC_SERVER_ADDRESS="localhost:8081"
```

## Безопасность

### Рекомендации по ключам

- **JWT_SECRET**: Используйте случайную строку длиной не менее 32 символов
- **ENCRYPTION_KEY**: Используйте случайную строку длиной не менее 32 символов
- Никогда не коммитьте эти ключи в репозиторий
- Используйте разные ключи для разных окружений (dev, staging, production)

### Пример генерации ключей

```bash
# Генерация JWT секрета
openssl rand -base64 32

# Генерация ключа шифрования
openssl rand -base64 32
```

## Мониторинг и логирование

Сервер использует структурированное логирование с помощью zap. Логи включают:

- Запросы HTTP
- Ошибки аутентификации
- Ошибки базы данных
- Ошибки шифрования

## Производительность

### Рекомендации по настройке PostgreSQL

```sql
-- Настройки для производительности
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
```

### Мониторинг

- Используйте `pg_stat_activity` для мониторинга активных соединений
- Настройте алерты на ошибки в логах
- Мониторьте использование памяти и CPU

