package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/VAibhav1031/wRLS-go/handler"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

// This project aim is for the particular feature testing (How they work with this and without this) not the real world/production  one

func MuxServerHandler(pool *pgxpool.Pool) *http.ServeMux {
	mux := http.NewServeMux()

	auth_tracker := handler.NewAuthTracker()
	db_pool := handler.NewPooler(pool)
	new_handler := handler.NewHandler(auth_tracker, db_pool)

	mux.HandleFunc("POST /register", db_pool.HandleRegister)
	mux.HandleFunc("POST /login", new_handler.HandleLogin)
	mux.HandleFunc("POST /checkout", db_pool.HandleOrders)
	mux.HandleFunc("POST /checkoutRLS", db_pool.HandleOrdersRLS)
	mux.HandleFunc("GET /invoice/{invoice_id}", db_pool.HandleGInvoiceShadow)
	mux.HandleFunc("GET /invoice", db_pool.HandleGInvoiceRLS)
	mux.HandleFunc("GET /orders", db_pool.HandleGetAllOrders)
	mux.HandleFunc("GET /orderRLS", db_pool.HandleGetAllOrdersRLS)
	return mux
}

func main() {

	err := godotenv.Load() // loading .env file
	if err != nil {
		log.Println("No .env file found, using system enviromentt ..")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatalf("DATABASE_URL not set: '%v'", dbURL)
	}

	pool := handler.ConnectDB(dbURL) // connecting to the DB , will get the pool connection
	defer pool.Close()

	err = pool.Ping(context.Background())
	if err != nil {
		log.Fatalf("Database is reachable but not responding: %v", err)
	} else {
		log.Println("DB!! , ALL SET ")
	}

	mux := MuxServerHandler(pool)
	server := &http.Server{
		Addr:           ":9895",
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	server.ListenAndServe()
}
