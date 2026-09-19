package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

var scrt_key []byte
var blockedTime = 15 * time.Minute
var maxAttempts = 5

func init() {
	err := godotenv.Load() // loading .env file
	if err != nil {
		log.Println("No .env file found, using system enviromentt ..")
		return
	}
	scrt_key := []byte(os.Getenv("SECRET_KEY"))

	if scrt_key == nil {
		log.Println("No Secret_key is there brother..")
		return
	}
}

// like to simulate this i need to have the from the start where i would create trhre post request and tht would make the request in the redis and all shit with TTL and whenever we havew the get request we would use the  mapping why redis reason we can store it on the disk without any problem also , else we have to implement the parsing and all shit to handle mapping like json format and allshit.

// before that we need to make sure of the post request smoothly

type OrderDet struct {
	ProductName string  `json:"product_name"`
	Quantity    int     `json:"quantity"`
	Price       float32 `json:"price"`
}

type OrderDetList struct {
	OrderList []OrderDet `json:"order_list"`
}

type register struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Passsword string `json:"password"`
}

type DBPooler struct {
	dbPool *pgxpool.Pool
}

type handler struct {
	at *AuthTracker
	db *DBPooler
}

// creation .....

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
		log.Println("JSON Decoder Error : %v", err)
		internalServerError(w, "JSON Decoding Problem")
		return
	}

	//basic-checks

	if user_det.Username == "" || len(user_det.Username) < 4 {
		ret_json := response("BAD_REQUEST", 400, "Invalid Username ")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		log.Println("Invalid Username")
	}
	if user_det.Passsword == "" || len(user_det.Passsword) < 8 {
		ret_json := response("BAD_REQUEST", 400, "Invalid Password, Password  must be atleast 8 character and mix of Upper_case and lower_case Char")
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
		ret_json := response("BAD_REQUEST", 400, "Invalid Email")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		log.Println("Invalid Email")
	}

	hashedPassword, err := hashPassword(user_det.Passsword)
	if err != nil {
		log.Printf("Error in hashing", err)
		internalServerError(w, "")
		return
	}

	query := `INSERT into users (username, email, hashed_password) VALUES ($1, $2, $3)`
	cmd_tag, err := db.dbPool.Exec(context.Background(), query, user_det.Username, user_det.Email, hashedPassword)
	if err != nil || cmd_tag.RowsAffected() == 0 {
		log.Printf("Insertion Failed", err)
		internalServerError(w, "")
		return
	}

	ret_json := response("Ok", 201, "DONE")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
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
		log.Println("JSON Decoder Error : ", err)
		internalServerError(w, "JSON Decoding Problem")
		return
	}

	//basic-checks
	// return of bad REQuest
	if user_det.Username == "" || len(user_det.Username) < 4 {
		ret_json := response("BAD_REQUEST", 400, "Invalid Username")
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
		ret_json := response("BAD_REQUEST", 400, "Invalid Password")
		if ret_json == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)

		log.Println("Invalid Password")
		return
	}

	if h.at.isBlocked(user_det.Username) {
		/// you are blocked please try again later..
		ret_json := response("TOO_MANY_REQUEST", 429, "User is Blocked...")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write(ret_json)

		return
	}

	query_string := `SELECT user_id, hashed_password from users where username=($1) or  email=($2)`

	var hashedPassword string
	var user_id int
	err = h.db.dbPool.QueryRow(context.Background(), query_string, user_det.Username, user_det.Passsword).Scan(&user_id, &hashedPassword)
	if err != nil {
		log.Printf("Select Query Error", err)
		// most probably user doesnt exist
		ret_json := response("USERNAME_ERROR", 401, "This Username doesnt Exist!!")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(ret_json)
		return
	}

	if !checkPasswordHash(user_det.Passsword, hashedPassword) {

		nBlocked := h.at.trackFailedAttempts(user_det.Username)

		if nBlocked {
			ret_json := response("BLOCKED", 401, "User is blocked for Many Incorrect Attempts")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(ret_json)
			return
		} else {
			ret_json := response("INCORRECT_PASSWORD", 401, "Password is incorrect, Be careful :)")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
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
	if token == "" {
		log.Println("Token Creation Failed..")
		return
	}

	ret_json := response("AUTH_TOKEN", 200, token)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(ret_json)
	return
}

// every other function first check is just the validation of the auth token which is just for the integrity
func (db *DBPooler) HandleOrders(w http.ResponseWriter, r *http.Request) {

	auth_token := r.Header.Get("Authorization")

	if auth_token == "" || !strings.HasPrefix(auth_token, "Bearer") {
		// AUTH FAILED, EMPTY TOKEN
		resp := response("AUTH_TOKEN_INVALID", 401, "Invalid Authorization Token..")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(resp)
		return
	}

	token := strings.TrimPrefix(auth_token, "Bearer ")
	user_id, verified := jwtVerifcation(token)
	if user_id == -1 && !verified {
		resp := response("AUTH_TOKEN_EXPIRED", 401, "Authorization token is Expired or Invalid")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(resp)
		return
		//EXPIRED
	}

	defer r.Body.Close()

	var order_det OrderDetList

	if err := json.NewDecoder(r.Body).Decode(&order_det); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		internalServerError(w, "Invalid Json Body")
		log.Println("JSON NewDecoder  Error: ", err)
		return
	}

	// product_name, quantity , price  most important should come here ,other part like order_id, user_id refrencing
	// basic checks :
	//  - quantity of any product should between 0 and 10
	//  - Price cant be negative
	//  - Product name must be all char no number

	for _, order := range order_det.OrderList {
		if order.Quantity < 0 || order.Quantity > 10 {

			ret_json := response("BAD_REQUEST", 400, "Incorrect Quantity")
			if ret_json == nil {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(ret_json)
			return
		}
		if order.Price < 0 {
			ret_json := response("BAD_REQUEST", 400, "Invalid Price Value")
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

	invoice_id := db.invoiceDbCommit(context.Background(), order_det.OrderList, int(user_id))
	if invoice_id == "" { // insertion Failure mostly
		log.Println("Insertion Failure [Orders]")
		internalServerError(w, "")
		return
	}

	invoice_id_rls := db.invoiceDbCommitRLS(context.Background(), order_det.OrderList, int(user_id))
	if invoice_id_rls == -1 {
		log.Println("Insertion Failure [Orders_RLS] ")
		internalServerError(w, "")
		return
	}

	resp := response("OK", 200, "Request Accepted")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (db *DBPooler) HandleGInvoiceShadow(w http.ResponseWriter, r *http.Request) {
	// now this is basically the GET request with mapping
	auth_token := r.Header.Get("Authorization")

	if auth_token == "" || !strings.HasPrefix(auth_token, "Bearer") {
		// AUTH FAILED, EMPTY TOKEN
		resp := response("AUTH_TOKEN_INVALID", 401, "Invalid Authorization Token..")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(resp)
		return
	}

	token := strings.TrimPrefix(auth_token, "Bearer ")
	user_id, verified := jwtVerifcation(token)
	if user_id == -1 && !verified {
		resp := response("AUTH_TOKEN_EXPIRED", 401, "Authorization token is Expired or Invalid")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
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
		log.Printf("ERROR querying order table: %v", err)
		internalServerError(w, "")
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
			log.Printf("Error In Fetching detail : %v", err)
			internalServerError(w, "")
			return
		}

		orders = append(orders, OrderDet{ProductName: product_name, Quantity: quantity, Price: price})

	}

	if err := rows.Err(); err != nil {
		log.Printf("Error in Scannig of the order Details : %v", err)
		internalServerError(w, "")
		return
	}

	re, err := json.Marshal(orders)
	if err != nil {
		log.Printf("Error in Marshalling", err)
		internalServerError(w, "Marshalling Error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(re)

}

func (db *DBPooler) HandleGInvoiceRLS(w http.ResponseWriter, r *http.Request) {
	auth_token := r.Header.Get("Authorization")

	if auth_token == "" || !strings.HasPrefix(auth_token, "Bearer") {
		// AUTH FAILED, EMPTY TOKEN
		resp := response("AUTH_TOKEN_INVALID", 401, "Invalid Authorization Token..")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(resp)
		return
	}

	token := strings.TrimPrefix(auth_token, "Bearer ")
	user_id, verified := jwtVerifcation(token)
	if user_id == -1 && !verified {
		resp := response("AUTH_TOKEN_EXPIRED", 401, "Authorization token is Expired or Invalid")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(resp)
		return
		//EXPIRED
	}

	//-------------------
	// you have to use the query parameter

	queryParams := r.URL.Query()
	invoice_id := queryParams.Get("invoice_id")

	// slice of OrderDet
	var orders_rls []OrderDet

	bt := &pgx.Batch{}
	bt.Queue(`SET LOCAL app.current_invoice_id=$1`, invoice_id)
	// we just need to the select the required id
	bt.Queue(`SELECT  product_name, quantity , price, public_id from orders_rls where public_invoice_id=$1 and user_id=$2`, invoice_id, user_id)

	// send the whole batch...
	results := db.dbPool.SendBatch(context.Background(), bt)
	defer results.Close()

	_, err := results.Exec()
	if err != nil {
		log.Printf("ERROR querying ")
		internalServerError(w, "")
		return
	}

	rows, err := results.Query() // Query All rows
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
			internalServerError(w, "")
			return
		}
		orders_rls = append(orders_rls, OrderDet{ProductName: product_name, Quantity: quantity, Price: price})

	}
	if err := rows.Err(); err != nil {
		log.Printf("Error in Scannig of the order Details", err)
		internalServerError(w, "")
		return
	}

	re, err := json.Marshal(orders_rls)
	if err != nil {
		log.Printf("Error in Marshalling", err)
		internalServerError(w, "Marshalling Error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(re)

}
