package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
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

type SingleOrdersResponse struct {
	InvoiceId   uuid.UUID  `json:"invoice_id"`
	TotalAmount int        `json:"total_amount"`
	Order       []OrderDet `json:"items"`
}

type SingleOrdersRlsResponse struct {
	InvoiceId   int        `json:"invoice_id"`
	TotalAmount int        `json:"total_amount "`
	Order       []OrderDet `json:"items"`
}

type AllOrdersResponse struct {
	Orders []SingleOrdersResponse `json:"orders"`
	Count  int                    `json:"count"`
}

type AllOrdersRlsResponse struct {
	Orders []SingleOrdersRlsResponse `json:"orders"`
	Count  int                       `json:"count"`
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

	ctx := r.Context()
	query := `INSERT into users (username, email, hashed_password) VALUES ($1, $2, $3)`
	cmd_tag, err := db.dbPool.Exec(ctx, query, user_det.Username, user_det.Email, hashedPassword)
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

	query_string := `SELECT user_id, hashed_password from users where username=($1) or  email=($2);`

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
			ret_json := response("INVALID_CREDENTIALS", 401, "Invalid Credential , Be careful :)")
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

	user_id, err := JWTAuthCheck(w, r)
	if err != nil && user_id == -1 {
		//Response already being called by function
		return //just exit normally here
	}

	defer r.Body.Close()

	var order_det []OrderDet

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

	for _, order := range order_det {
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

	//creation of th uuid for the use, which can be more unique unguessable , and pack whole order in one invoice_id
	public_invoice_id := uuid.New()
	err = db.invoiceDbCommit(context.Background(), order_det, int(user_id), public_invoice_id)

	if err != nil { // insertion Failure mostly
		log.Println("Insertion Failure [Orders]")
		internalServerError(w, "")
		return
	}

	resp := response("OK", 200, "Request Accepted")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (db *DBPooler) HandleOrdersRLS(w http.ResponseWriter, r *http.Request) {

	user_id, err := JWTAuthCheck(w, r)
	if err != nil && user_id == -1 {
		//Response already being called by function
		return //just exit normally here
	}

	defer r.Body.Close()

	var order_det []OrderDet

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

	for _, order := range order_det {
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

	// Getting the invoice_id of the orders_rls (which is beeing  the sequence  object start with 1000) and for every
	// whole order bunch to get  the new  single invoice we are using this and allshit
	var invoice_id int
	query_str := `SELECT nextval(invoice_id_seq) ;`
	err = db.dbPool.QueryRow(context.Background(), query_str).Scan(invoice_id)
	if err != nil {
		log.Printf("Querying 'invoice_id_seq' Failed: %v", err)
	}

	err = db.invoiceDbCommitRLS(context.Background(), order_det, int(user_id), invoice_id)
	if err != nil {
		log.Println("Insertion Failure [Orders_RLS] ")
		internalServerError(w, "")
		return
	}

	resp := response("OK", 200, "Request Accepted")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("url", "")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (db *DBPooler) HandleGInvoiceShadow(w http.ResponseWriter, r *http.Request) {
	// now this is basically the GET request with mapping
	user_id, err := JWTAuthCheck(w, r)
	if err != nil && user_id == -1 {
		//Response already being called by function
		return //just exit normally here
	}

	// ---- ------- ------ ------

	// we need this because we will send the public_invoice_id to them which
	// is the random and cant be guess and nice to be good to prevent IDOR

	p_id := r.PathValue("public_invoice_id")
	var OneOrder SingleOrdersResponse

	public_invoice_uuid, err := uuid.Parse(p_id)
	if err != nil {
		log.Printf("Error in Parsing uuid: %v", err)
		re := response("NOT_FOUND", 404, "Unable to find the particular Service")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write(re)
		return
		//
	}

	// we just need to the select the required id

	query_str := `SELECT  
		product_name, 
		quantity ,
		price,
		(SELECT sum(price * quantity)  from orders) as total_amount from orders 
		where public_invoice_id=$1 and user_id=$2;`

	rows, err := db.dbPool.Query(context.Background(), query_str, public_invoice_uuid, user_id)
	if err != nil {
		log.Printf("ERROR querying order table: %v", err)
		internalServerError(w, "")
		return
	}

	defer rows.Close()

	OneOrder.InvoiceId = public_invoice_uuid

	// we need the  invoice_id , total_amount,
	for rows.Next() {

		var (
			product_name string
			quantity     int
			price        float32
		)

		err := rows.Scan(&product_name, &quantity, &price, &OneOrder.TotalAmount)
		if err != nil {
			log.Printf("Error In Fetching detail : %v", err)
			internalServerError(w, "")
			return
		}

		OneOrder.Order = append(OneOrder.Order, OrderDet{ProductName: product_name, Quantity: quantity, Price: price})

	}

	if err := rows.Err(); err != nil {
		log.Printf("Error in Scanning of the order Details : %v", err)
		internalServerError(w, "")
		return
	}

	re, err := json.Marshal(OneOrder)
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

	user_id, err := JWTAuthCheck(w, r)
	if err != nil && user_id == -1 {
		//Response already being called by function
		return //just exit normally here
	}

	//-------------------
	// you have to use the query parameter

	queryParams := r.URL.Query()
	invoice_id, err := strconv.Atoi(queryParams.Get("invoice_id"))
	if err != nil {
		log.Printf("Provided Invoice id in the query_paramater : %v", err)
		internalServerError(w, "")
		return
	}

	// slice of OrderDet
	var OneOrdersRLS SingleOrdersRlsResponse

	bt := &pgx.Batch{}
	bt.Queue(`SET LOCAL app.current_invoice_id=$1`, invoice_id)
	// we just need to the select the required id

	query_str := `SELECT  
		product_name,
		quantity ,
		price, 
		(SELECT sum(price * quantity) from orders) as total_amount
		from orders_rls 
		where invoice_id=$1 and user_id=$2;`

	bt.Queue(query_str, invoice_id, user_id)

	// send the whole batch...
	results := db.dbPool.SendBatch(context.Background(), bt)
	defer results.Close()

	_, err = results.Exec()
	if err != nil {
		log.Printf("ERROR querying ")
		internalServerError(w, "")
		return
	}

	rows, err := results.Query() // Query All rows
	defer rows.Close()

	OneOrdersRLS.InvoiceId = invoice_id
	for rows.Next() {
		var (
			product_name string
			quantity     int
			price        float32
		)
		err := rows.Scan(&product_name, &quantity, &price, &OneOrdersRLS.TotalAmount)
		if err != nil {
			log.Printf("Error In Scanning detail ", err)
			internalServerError(w, "")
			return
		}
		OneOrdersRLS.Order = append(OneOrdersRLS.Order, OrderDet{ProductName: product_name, Quantity: quantity, Price: price})

	}
	if err := rows.Err(); err != nil {
		log.Printf("Error in Scannig of the order Details", err)
		internalServerError(w, "")
		return
	}

	re, err := json.Marshal(OneOrdersRLS)
	if err != nil {
		log.Printf("Error in Marshalling", err)
		internalServerError(w, "Marshalling Error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(re)

}

// these thing should focus on giving the {} but the orders should come under clubbing
// example  if these rows belong to these particular invoice , then they should come in single {}
// for that we should have that
func (db *DBPooler) HandleGetAllOrders(w http.ResponseWriter, req *http.Request) {
	user_id, err := JWTAuthCheck(w, req)
	if err != nil && user_id == -1 {
		//Response already being called by function
		return //just exit normally here
	}

	// joining some thing with  invoice_id_first = invoice_id_second , will not make thing nicer i think
	// i can have this like where order by would happen and each row would come  whenever  we got the diffefrenmt then and allshit
	query_str := `SELECT 
	public_invoice_id
	json_agg(
		json_body_object(
		'product_name',product_name,
		'quantity',quantity,
		'price',price 
		)
	) as  items ,
	sum(price * quantity) as total_amount from orders 
	where user_id = $1 group by public_invoice_id;
	`

	var response AllOrdersResponse
	ctx := req.Context()
	rows, err := db.dbPool.Query(ctx, query_str, user_id)
	if err != nil {
		log.Printf("[Get-All Orders] Query Failed : %v", err)
		internalServerError(w, "")
		return
	}

	for rows.Next() {
		var order SingleOrdersResponse

		if err := rows.Scan(&order.InvoiceId, &order.Order, &order.TotalAmount); err != nil {
			log.Printf("[Get-All Orders] Scanning Failed : %v", err)
			internalServerError(w, "")
			return
		}
		response.Orders = append(response.Orders, order)
	}
	response.Count = len(response.Orders)

	ret_all_orders, err := json.Marshal(response)
	if err != nil {
		log.Printf("Json Marshalling Error :%v", err)
		internalServerError(w, "Marshalling  Error ")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(ret_all_orders)
}

func (db *DBPooler) HandleGetAllOrdersRLS(w http.ResponseWriter, req *http.Request) {
	userID, err := JWTAuthCheck(w, req)
	if err != nil && userID == -1 {
		//Response already being called by function
		return //just exit normally here
	}

	ctx := req.Context()

	// we need to send the all in the {} manner man
	tx, err := db.dbPool.Begin(ctx)
	if err != nil {
		log.Printf("Error in initialization of Transaction : %v", err)
		internalServerError(w, "")
		return
	}
	defer tx.Rollback(ctx)

	// 1. Set User Context (No invoice_id set -> Allows fetching ALL invoices for this user)
	_, err = tx.Exec(ctx, "SET LOCAL app.current_user_id = $1", userID)
	if err != nil {
		log.Printf("Error in Setting setting namespace :  %v", err)
		internalServerError(w, "")
		return
	}
	query_str := `SELECT 
	invoice_id,
	json_agg(
		json_body_object(
		'product_name',product_name
		'quantity',quantity
		'price',price
		)
	) AS  items , 
	SUM(price * quantity) as total_amount
	FROM orders 
	group by invoice_id order by invoice_id DESC;
	`

	rows, err := tx.Query(ctx, query_str)
	if err != nil {
		log.Printf("Query Failure: %v", err)
		internalServerError(w, "")
		return
	}

	var response AllOrdersRlsResponse
	for rows.Next() {
		var order SingleOrdersRlsResponse
		if err := rows.Scan(&order.InvoiceId, &order.Order, &order.TotalAmount); err != nil {
			log.Printf("Error in Scanning : %v", err)
			internalServerError(w, "")
			return
		}
		response.Orders = append(response.Orders, order)
	}

	response.Count = len(response.Orders)

	ret_all_orders, err := json.Marshal(response)
	if err != nil {
		log.Printf("Json Marshalling Error :%v", err)
		internalServerError(w, "Marshalling  Error ")
		return
	}

	err = tx.Commit(ctx)
	if err != nil {
		log.Printf("Failed Execution of The Transaction: %v", err)
		internalServerError(w, "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(ret_all_orders)
}
