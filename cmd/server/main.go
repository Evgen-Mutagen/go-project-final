package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gophkeeper/internal/configs"
	"github.com/gophkeeper/internal/server"
	"github.com/gophkeeper/internal/service"
	"github.com/gophkeeper/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func main() {
	cfg, err := configs.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	var repo storage.Repository
	if cfg.DatabaseDSN != "" {
		pool, err := pgxpool.New(context.Background(), cfg.DatabaseDSN)
		if err != nil {
			logger.Fatal("Failed to connect to database", zap.Error(err))
		}
		defer pool.Close()

		repo = storage.NewPostgresRepository(pool)
		logger.Info("Connected to PostgreSQL database")
	} else {
		logger.Warn("No database configured, using in-memory storage")
	}

	gophKeeperService := service.NewGophKeeperService(repo, cfg.JWTSecret, cfg.EncryptionKey)

	httpServer := server.NewHTTPServer(gophKeeperService, logger)
	router := httpServer.SetupRoutes()

	srv := &http.Server{
		Addr:    cfg.ServerAddress,
		Handler: router,
	}

	go func() {
		logger.Info("Starting HTTP server", zap.String("addr", cfg.ServerAddress))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start HTTP server", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server exited")
}
