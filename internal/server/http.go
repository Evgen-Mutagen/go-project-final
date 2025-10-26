package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/gophkeeper/internal/models"
	"github.com/gophkeeper/internal/service"
	"go.uber.org/zap"
)

// HTTPServer HTTP сервер
type HTTPServer struct {
	service *service.GophKeeperService
	logger  *zap.Logger
}

// NewHTTPServer создает новый HTTP сервер
func NewHTTPServer(service *service.GophKeeperService, logger *zap.Logger) *HTTPServer {
	return &HTTPServer{
		service: service,
		logger:  logger,
	}
}

// SetupRoutes настраивает маршруты
func (s *HTTPServer) SetupRoutes() *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	r.Route("/api/v1", func(r chi.Router) {
		// Публичные маршруты
		r.Post("/register", s.handleRegister)
		r.Post("/login", s.handleLogin)

		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Get("/data", s.handleGetUserData)
			r.Post("/data", s.handleCreateData)
			r.Get("/data/{id}", s.handleGetData)
			r.Put("/data/{id}", s.handleUpdateData)
			r.Delete("/data/{id}", s.handleDeleteData)
		})
	})

	return r
}

// authMiddleware middleware для аутентификации
func (s *HTTPServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.writeError(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			s.writeError(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		claims, err := s.service.ValidateToken(tokenString)
		if err != nil {
			s.writeError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// handleRegister обрабатывает регистрацию
func (s *HTTPServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	response, err := s.service.Register(r.Context(), &req)
	if err != nil {
		s.logger.Error("Registration failed", zap.Error(err))
		s.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.writeJSON(w, response, http.StatusCreated)
}

// handleLogin обрабатывает вход
func (s *HTTPServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	response, err := s.service.Login(r.Context(), &req)
	if err != nil {
		s.logger.Error("Login failed", zap.Error(err))
		s.writeError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	s.writeJSON(w, response, http.StatusOK)
}

// handleGetUserData получает все данные пользователя
func (s *HTTPServer) handleGetUserData(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(uuid.UUID)

	data, err := s.service.GetUserSecretData(r.Context(), userID)
	if err != nil {
		s.logger.Error("Failed to get user data", zap.Error(err))
		s.writeError(w, "Failed to get data", http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, data, http.StatusOK)
}

// handleCreateData создает новые данные
func (s *HTTPServer) handleCreateData(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(uuid.UUID)

	var req models.CreateSecretDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	response, err := s.service.CreateSecretData(r.Context(), userID, &req)
	if err != nil {
		s.logger.Error("Failed to create data", zap.Error(err))
		s.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.writeJSON(w, response, http.StatusCreated)
}

// handleGetData получает данные по ID
func (s *HTTPServer) handleGetData(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(uuid.UUID)
	dataIDStr := chi.URLParam(r, "id")

	dataID, err := uuid.Parse(dataIDStr)
	if err != nil {
		s.writeError(w, "Invalid data ID", http.StatusBadRequest)
		return
	}

	data, err := s.service.GetSecretData(r.Context(), userID, dataID)
	if err != nil {
		s.logger.Error("Failed to get data", zap.Error(err))
		s.writeError(w, "Data not found", http.StatusNotFound)
		return
	}

	s.writeJSON(w, data, http.StatusOK)
}

// handleUpdateData обновляет данные
func (s *HTTPServer) handleUpdateData(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(uuid.UUID)
	dataIDStr := chi.URLParam(r, "id")

	dataID, err := uuid.Parse(dataIDStr)
	if err != nil {
		s.writeError(w, "Invalid data ID", http.StatusBadRequest)
		return
	}

	var req models.UpdateSecretDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	response, err := s.service.UpdateSecretData(r.Context(), userID, dataID, &req)
	if err != nil {
		s.logger.Error("Failed to update data", zap.Error(err))
		s.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.writeJSON(w, response, http.StatusOK)
}

// handleDeleteData удаляет данные
func (s *HTTPServer) handleDeleteData(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(uuid.UUID)
	dataIDStr := chi.URLParam(r, "id")

	dataID, err := uuid.Parse(dataIDStr)
	if err != nil {
		s.writeError(w, "Invalid data ID", http.StatusBadRequest)
		return
	}

	if err := s.service.DeleteSecretData(r.Context(), userID, dataID); err != nil {
		s.logger.Error("Failed to delete data", zap.Error(err))
		s.writeError(w, "Failed to delete data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// writeJSON записывает JSON ответ
func (s *HTTPServer) writeJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// writeError записывает ошибку
func (s *HTTPServer) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error: message,
	})
}
