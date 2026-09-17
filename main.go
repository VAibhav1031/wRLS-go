package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/VAibhav1031/wRLS-go/handler"
	"github.com/joho/godotenv"
)

// This project aim is for the particular feature testing not the real world/production  one

func MuxServerHandler() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /orders", handler.HandleOrders)
	mux.HandleFunc("GET /invoice/{invoice_id}", handler.HandleGInvoiceShadow)
	mux.HandleFunc("GET /invoice", handler.HandleGInvoiceRLS)
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

	mux := MuxServerHandler()
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
