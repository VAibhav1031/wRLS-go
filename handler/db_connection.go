package handler

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ConnectDB(connString string) *pgxpool.Pool {

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		log.Fatal("Cant parse config", err)
	}

	config.MaxConns = 20
	config.MinConns = 5
	config.MaxConnIdleTime = 10 * time.Second
	config.MaxConnLifetime = 10 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), config)

	if err != nil {
		log.Fatal("Cant connect to the DB", err)
	}
	return pool
}
