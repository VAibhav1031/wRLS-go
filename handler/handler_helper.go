package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
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
func (w *DBPooler) invoiceDbCommit(ctx context.Context, tx pgx.Tx, orders []OrderDet, user_id int, publicInvoiceID uuid.UUID) error {

	bt := &pgx.Batch{}

	for _, order := range orders {

		bt.Queue(`INSERT into orders (user_id, public_invoice_id, product_name, price, quantity) VALUES ($1,$2,$3,$4,$5);`, user_id, publicInvoiceID, order.ProductName, order.Price, order.Quantity)
	}

	results := tx.SendBatch(ctx, bt)
	defer results.Close()

	for range orders {
		insertTag, err := results.Exec()
		if err != nil {
			log.Printf("[InvoiceDBCommit]: Insertion Failed : %v", err)
			return err
		}
		if insertTag.RowsAffected() != 1 {
			log.Printf(
				"[InvoiceDBCommit]: expected one inserted row, affected %d",
				insertTag.RowsAffected(),
			)
			return fmt.Errorf("[InvoiceDBCommit]: No Rows Are Changed")
		}
	}

	return nil

}

func (w *DBPooler) invoiceDbCommitRLS(ctx context.Context, tx pgx.Tx, orders []OrderDet, user_id int, invoiceID int64) error {

	bt := &pgx.Batch{}
	query := fmt.Sprintf("SET LOCAL app.current_invoice_id = '%d'", invoiceID)
	_, err := tx.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("[InvoiceDBCommit-RLS]: Failed to set local RLS context : %v", err)
	}

	// setting the role as the app_user for this
	for _, order := range orders {

		bt.Queue(`INSERT into orders_rls (user_id,invoice_id, product_name, price, quantity) VALUES ($1,$2,$3,$4,$5);`, user_id, invoiceID, order.ProductName, order.Price, order.Quantity)
	}

	results := tx.SendBatch(ctx, bt)
	defer results.Close()

	for range orders {
		insertTag, err := results.Exec()
		if err != nil {
			log.Printf("[InvoiceDBCommit-RLS]: Insertion Failed : %v", err)
			return err
		}
		if insertTag.RowsAffected() != 1 {
			log.Printf(
				"[InvoiceDBCommit]: expected one inserted row, affected %d",
				insertTag.RowsAffected(),
			)

			return fmt.Errorf("[InvoiceDBCommit]: No Rows are Affected ")
		}
	}

	return nil
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

func JWTAuthCheck(w http.ResponseWriter, req *http.Request) (int, error) {

	auth_token := req.Header.Get("Authorization")

	if auth_token == "" || !strings.HasPrefix(auth_token, "Bearer") {
		// AUTH FAILED, EMPTY TOKEN
		resp := response("AUTH_TOKEN_INVALID", 401, "Invalid Authorization Token..")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(resp)
		return -1, fmt.Errorf("Auth Token is Invalid")
	}

	token := strings.TrimPrefix(auth_token, "Bearer ")
	user_id, verified := jwtVerifcation(token)
	if user_id == -1 && !verified {
		resp := response("AUTH_TOKEN_EXPIRED", 401, "Authorization token is Expired or Invalid")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(resp)
		return -1, fmt.Errorf("Auth Token is Expired..")
		//EXPIRED
	}

	return int(user_id), nil
}

func internalServerError(w http.ResponseWriter, message string) {

	ret_json := response("INTERNAL_SERVER_ERROR", 500, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write(ret_json)
}
