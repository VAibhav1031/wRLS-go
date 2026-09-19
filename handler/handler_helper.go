package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

type Response struct {
	Code       string `json:"code"`
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}
type AuthTracker struct {
	store *cache.Cache
}

func NewAuthTracker() *AuthTracker {
	return &AuthTracker{
		store: cache.New(blockedTime, 30*time.Second),
	}
}
func (w *DBPooler) invoiceDbCommit(ctx context.Context, orders []OrderDet, user_id int) string {

	bt := &pgx.Batch{}

	for _, order := range orders {

		bt.Queue(`INSERT into orders (product_name, price, quantity) VALUES ($1,$2,$3)`, order.ProductName, order.Price, order.Quantity)
	}
	fmt.Println(user_id)
	bt.Queue(`SELECT public_invoice_id from orders where user_id=($1)`, user_id)

	results := w.dbPool.SendBatch(ctx, bt)
	defer results.Close()

	for i := 0; i < len(orders); i++ {
		insertTag, err := results.Exec()
		if err != nil || !insertTag.Insert() {
			log.Printf("[InvoiceDBCommit]: Insertion Failed :", err)
			return ""
		}
	}

	var public_invoice_id string
	err := results.QueryRow().Scan(&public_invoice_id)
	if err != nil {
		log.Printf("[InvoiceDBCommit]: Selection Query Failed..", err)
		return ""
	}

	return public_invoice_id
}

func (w *DBPooler) invoiceDbCommitRLS(ctx context.Context, orders []OrderDet, user_id int) int {

	bt := &pgx.Batch{}

	// setting the role as the app_user for this
	for _, order := range orders {

		bt.Queue(`INSERT into orders_rls (product_name, price, quantity) VALUES ($1,$2,$3)`, order.ProductName, order.Price, order.Quantity)
	}

	bt.Queue(`SELECT invoice_id from orders_rls where user_id=($1)`, user_id)

	results := w.dbPool.SendBatch(ctx, bt)
	defer results.Close()

	for i := 0; i < len(orders); i++ {
		insertTag, err := results.Exec()
		if err != nil || !insertTag.Insert() {
			log.Printf("[InvoiceDBCommit-RLS]: Insertion Failed", err)
			return -1
		}
	}

	var invoice_id int
	err := results.QueryRow().Scan(&invoice_id)
	if err != nil {
		log.Printf("[InvoiceDBCommit-RLS]: Selection Query Failed..", err)
		return -1
	}

	return invoice_id
}

func response(code string, statuscode int, msg string) []byte {
	resp := Response{
		Code:       code,
		StatusCode: statuscode,
		Message:    msg,
	}
	u, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Marshalling error: %v", err)
		return []byte{}
	}
	return u
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func jwtCreation(user_id int) string {

	claims := jwt.MapClaims{
		"user_id": user_id,
		"exp":     time.Now().Add(time.Minute * 10).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(scrt_key)

	if err != nil || tokenString == "" {
		log.Printf("Failed to generate the token :", err)
	}

	return tokenString
}

func jwtVerifcation(tkn_str string) (float64, bool) {

	token, err := jwt.Parse(tkn_str, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected Signing Method", t.Header["alg"])
		}
		return scrt_key, nil
	})

	if err != nil || !token.Valid {

		fmt.Println(token, token.Valid)
		log.Printf("Token is Expired or Invalid", err)
		return -1, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims["user_id"].(float64), true
	}

	return -1, false
}

func (at *AuthTracker) trackFailedAttempts(username string) bool {
	err := at.store.Increment(username, 1)
	if err != nil {
		at.store.Set(username, 1, cache.DefaultExpiration)
		return false
	}

	if attempts, found := at.store.Get(username); found {
		if attempts.(int) >= maxAttempts {
			at.store.Set(username, attempts.(int), blockedTime)
			return true
		}
	}
	return false
}

func (at *AuthTracker) isBlocked(username string) bool {
	if attempts, found := at.store.Get(username); found {

		return attempts.(int) >= maxAttempts
	}
	return false

}

func internalServerError(w http.ResponseWriter, message string) {

	ret_json := response("INTERNAL_SERVER_ERROR", 500, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write(ret_json)
}
