package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

var scrt_key string
var blockedTime = 15 * time.Minute
var maxAttempts = 5

func init() {
	err := godotenv.Load() // loading .env file
	if err != nil {
		log.Println("No .env file found, using system enviromentt ..")
		return
	}
	scrt_key := os.Getenv("SECRET_KEY")

	if scrt_key == "" {
		log.Println("No Secret_key is there brother..")
		return
	}
}

// like to simulate this i need to have the from the start where i would create trhre post request and tht would make the request in the redis and all shit with TTL and whenever we havew the get request we would use the  mapping why redis reason we can store it on the disk without any problem also , else we have to implement the parsing and all shit to handle mapping like json format and allshit.

// before that we need to make sure of the post request smoothly

type AuthTracker struct {
	store *cache.Cache
}

type OrderDet struct {
	ProductName string `json:"product_name"`
	Quantity    int    `json:"quantity"`
	Price       int    `json:"price"`
}

type register struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Passsword string `json:"password"`
}

type Response struct {
	Code       string `json:"code"`
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}

type DBPooler struct {
	dbPool *pgxpool.Pool
}

type handler struct {
	at *AuthTracker
	db *DBPooler
}

// creation .....
func NewAuthTracker() *AuthTracker {
	return &AuthTracker{
		store: cache.New(blockedTime, 30*time.Second),
	}
}
func NewPooler(pool *pgxpool.Pool) *DBPooler {

	return &DBPooler{dbPool: pool}
}

func NewHandler(authTrack *AuthTracker, dbPooler *DBPooler) *handler {

	return &handler{at: authTrack, db: dbPooler}
}

// Handlers..
func (db *DBPooler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	// user would send request in the form of the
	// username ,email , password
	// we will give sucess nothing else , with just make sure password is of atleast 8  character
	// email part also correct format of thing , not with the regex bit different because of regex management in the golang

	// password should be hashed before committing in the db

	defer r.Body.Close()

	var user_det register
	err := json.NewDecoder(r.Body).Decode(&user_det)
	if err != nil {
		log.Println("")
		return
	}

	//basic-checks

	if user_det.Username == "" || len(user_det.Username) < 4 {
		ret_json := response("BAD_REQUEST", 502, "Invalid Username ")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		log.Println("Invalid Username")
	}
	if user_det.Passsword == "" || len(user_det.Passsword) < 8 {
		ret_json := response("BAD_REQUEST", 502, "Invalid Password, Password  must be atleast 8 character and mix of Upper_case and lower_case Char")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		log.Println("Invalid Password")
		return
	}

	if user_det.Email == "" {
		ret_json := response("BAD_REQUEST", 502, "Invalid Email")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		log.Println("Invalid Email")
	}

	hashed_password, err := hashPassword(user_det.Passsword)
	if err != nil {
		log.Printf("Error in hashing", err)
		return
	}

	query := `INSERT into users (username, email, password) VALUES ($1, $2, $3)`
	cmd_tag, err := db.dbPool.Exec(context.Background(), query, user_det.Username, user_det.Email, hashed_password)
	if err != nil || cmd_tag.RowsAffected() == 0 {
		log.Printf("Insertion Failed", err)
		return
	}

	ret_json := response("ACCEPTED", 200, "DONE")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write(ret_json)
}

func (h *handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// we need only username , password
	// check the hash and compare function nothing else
	// if true move and give the JWT produced auth token and on any

	defer r.Body.Close()

	var user_det register
	err := json.NewDecoder(r.Body).Decode(&user_det)
	if err != nil {
		log.Println("Marshalling Error : ", err)
		return
	}

	//basic-checks
	// return of bad REQuest
	if user_det.Username == "" || len(user_det.Username) < 4 {
		ret_json := response("BAD_REQUEST", 502, "Invalid Username")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)

		log.Println("Invalid Username")
		return
	}
	if user_det.Passsword == "" || len(user_det.Passsword) < 8 {
		ret_json := response("BAD_REQUEST", 502, "Invalid Password")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)

		log.Println("Invalid Password")
		return
	}

	if user_det.Email == "" {
		ret_json := response("BAD_REQUEST", 502, "Invalid Email")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		log.Println("Invalid Email")
		return
	}

	if h.at.isBlocked(user_det.Username) {
		/// you are blocked please try again later..
		ret_json := response("TOO_MANY_REQUEST", 429, "User is Blocked...")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(ret_json)

		return
	}

	query_string := `SELECT user_id, password from users where username=($1) and email=($2)`

	var hashed_password string
	var user_id int
	err = h.db.dbPool.QueryRow(context.Background(), query_string, user_det.Username, user_det.Passsword).Scan(&hashed_password, &user_id)
	if err != nil {
		log.Printf("Select Query Error", err)
		// most probably user doesnt exist
		ret_json := response("USERNAME_ERROR", 404, "This Username doesnt Exist!!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(ret_json)
		return
	}

	if !checkPasswordHash(hashed_password, user_det.Passsword) {

		nBlocked := h.at.trackFailedAttempts(user_det.Username)

		if nBlocked {
			ret_json := response("BLOCKED", 404, "User is blocked for Many Incorrect Attempts")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write(ret_json)
			return
		} else {
			ret_json := response("INCORRECT_PASSWORD", 404, "Password is incorrect, Be careful :)")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write(ret_json)
			return
		}
	}

	// reset the thing
	if _, found := h.at.store.Get(user_det.Username); found {
		h.at.store.Delete(user_det.Username)
	}

	// return the jwt token as the ..
	token := jwtCreation(user_id)

	ret_json := response("AUTH_TOKEN", 200, token)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write(ret_json)
	return
}

// every other function first check is just the validation of the auth token which is just for the integrity
func (db *DBPooler) HandleOrders(w http.ResponseWriter, r *http.Request) {

	token := r.Header.Get("Authorization")

	if token == "" || !strings.HasPrefix(token, "Bearer") {
		// AUTH FAILED, EMPTY TOKEN
		resp := response("AUTH_TOKEN_EMPTY", 404, "Authorization token is empty")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(resp)
		return
	}
	user_id, verified := jwtVerifcation(token)
	if user_id == -1 && !verified {
		resp := response("AUTH_TOKEN_EXPIRED", 404, "Authorization token is Expired or Invalid")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(resp)
		return
		//EXPIRED
	}

	defer r.Body.Close()

	var order_det []OrderDet

	if err := json.NewDecoder(r.Body).Decode(&order_det); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		fmt.Println("json NewDecoder", err)
		return
	}

	// product_name, quantity , price  most important should come here ,other part like order_id, user_id refrencing
	// basic checks :
	//  - quantity of any product should between 0 and 10
	//  - Price cant be negative
	//  - Product name must be all char no number

	for _, order := range order_det {
		if order.Quantity < 0 || order.Quantity > 10 {

			ret_json := response("BAD_REQUEST", 502, "Incorrect Quantity")
			if ret_json == nil {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(ret_json)
			return
		}
		if order.Price < 0 {
			ret_json := response("BAD_REQUEST", 502, "Invalid Price Value")
			if ret_json == nil {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(ret_json)
			return
		}
	}
	// normal
	// call to the db save the detail related to the thingand have the invoice_id , generated by the  db saved in the redis without TTL

	invoice_id := db.invoiceDbCommit(context.Background(), order_det, user_id)
	if invoice_id == "" { // insertion Failure mostly
		return
	}

	invoice_id_rls := db.invoiceDbCommit(context.Background(), order_det, user_id)
	if invoice_id_rls == "" {
		return
	}

	resp := response("ACCEPTED", 201, "Request Accepted")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write(resp)
}

func (db *DBPooler) HandleGInvoiceShadow(w http.ResponseWriter, r *http.Request) {
	// now this is basically the GET request with mapping
	token := r.Header.Get("Authorization")

	if token == "" || !strings.HasPrefix(token, "Bearer") {
		// AUTH FAILED, EMPTY TOKEN
		resp := response("AUTH_TOKEN_EMPTY", 404, "Authorization token is empty")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(resp)
		return
	}

	user_id, verified := jwtVerifcation(token)
	if user_id == -1 && !verified {
		resp := response("AUTH_TOKEN_EXPIRED", 404, "Authorization token is Expired or Invalid")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(resp)
		return
		//EXPIRED
	}

	// ---- ------- ------ ------

	p_id := r.PathValue("public_invoice_id")
	var orders []OrderDet
	// we just need to the select the required id

	query_str := `SELECT  product_name, quantity , price, public_id from orders where public_invoice_id=$1 and user_id=$2`
	rows, err := db.dbPool.Query(context.Background(), query_str, p_id, user_id)

	if err != nil {
		log.Printf("ERROR querying ")
		return
	}

	defer rows.Close()

	for rows.Next() {

		var (
			product_name string
			quantity     int
			price        float32
		)

		err := rows.Scan(&product_name, &quantity, &price)
		if err != nil {
			log.Printf("Error In Fetching detail ", err)
			return
		}

		orders = append(orders, OrderDet{ProductName: product_name, Quantity: quantity, Price: int(price)})

	}

	if err := rows.Err(); err != nil {
		log.Printf("Error in Scannig of the order Details", err)
		return
	}

	re, err := json.Marshal(orders)
	if err != nil {
		log.Printf("Error in Marshalling", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(re)

}

func (db *DBPooler) HandleGInvoiceRLS(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")

	if token == "" || !strings.HasPrefix(token, "Bearer") {
		// AUTH FAILED, EMPTY TOKEN
		resp := response("AUTH_TOKEN_EMPTY", 404, "Authorization token is empty")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(resp)
		return
	}

	user_id, verified := jwtVerifcation(token)
	if user_id == -1 && !verified {
		resp := response("AUTH_TOKEN_EXPIRED", 404, "Authorization token is Expired or Invalid")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(resp)
		return
		//EXPIRED
	}

	//-------------------
	// you have to use the query parameter

	queryParams := r.URL.Query()

	invoice_id := queryParams.Get("invoice_id")
	var orders []OrderDet
	// we just need to the select the required id

	query_str := `SELECT  product_name, quantity , price, public_id from orders_rls where public_invoice_id=$1 and user_id=$2`
	rows, err := db.dbPool.Query(context.Background(), query_str, invoice_id, user_id)

	if err != nil {
		log.Printf("ERROR querying ")
		return
	}

	defer rows.Close()

	for rows.Next() {

		var (
			product_name string
			quantity     int
			price        float32
		)

		err := rows.Scan(&product_name, &quantity, &price)
		if err != nil {
			log.Printf("Error In Fetching detail ", err)
			return
		}

		orders = append(orders, OrderDet{ProductName: product_name, Quantity: quantity, Price: int(price)})

	}

	if err := rows.Err(); err != nil {
		log.Printf("Error in Scannig of the order Details", err)
		return
	}

	re, err := json.Marshal(orders)
	if err != nil {
		log.Printf("Error in Marshalling", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(re)

}

func (w *DBPooler) invoiceDbCommit(ctx context.Context, orders []OrderDet, user_id int) string {

	bt := &pgx.Batch{}
	for _, order := range orders {

		bt.Queue(`INSERT into orders (product_name, price, quantity) VALUES ($1,$2,$3)`, order.ProductName, order.Price, order.Quantity)
	}

	bt.Queue(`SELECT public_invoice_id from orders where user_id=($1)`, user_id)

	results := w.dbPool.SendBatch(ctx, bt)
	defer results.Close()

	for i := 0; i < len(orders); i++ {
		_, err := results.Exec()
		if err != nil {
			log.Printf("[InvoiceDBCommit]: Insertion Failed :", err)
			return ""
		}
	}

	var public_invoice_id string
	err := results.QueryRow().Scan(&public_invoice_id)
	if err != nil {
		log.Printf("[InvoiceDBCommit]: Selection Query Failed..")
		return ""
	}

	return public_invoice_id
}

func (w *DBPooler) invoiceDbCommitRLS(ctx context.Context, orders []OrderDet, user_id int) string {

	bt := &pgx.Batch{}
	for _, order := range orders {

		bt.Queue(`INSERT into orders_rls (product_name, price, quantity) VALUES ($1,$2,$3)`, order.ProductName, order.Price, order.Quantity)
	}

	bt.Queue(`SELECT invoice_id from orders where user_id=($1)`, user_id)

	results := w.dbPool.SendBatch(ctx, bt)
	defer results.Close()

	for i := 0; i < len(orders); i++ {
		_, err := results.Exec()
		if err != nil {
			log.Printf("Insertion Failed", err)
			return ""
		}
	}

	var invoice_id string
	err := results.QueryRow().Scan(&invoice_id)
	if err != nil {
		log.Printf("Selection Query Failed..")
		return ""
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
		"userid": user_id,
		"exp":    time.Now().Add(time.Minute * 10).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(scrt_key)

	if err != nil {
		log.Printf("Failed to generate the token :", err)
	}
	return tokenString
}

func jwtVerifcation(tkn_str string) (int, bool) {

	token, err := jwt.Parse(tkn_str, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected Signing Method", t.Header["alg"])
		}
		return scrt_key, nil
	})

	if err != nil || !token.Valid {
		log.Printf("Token is Expired or Invalid")
		return -1, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims["user_id"].(int), true
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
