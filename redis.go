package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var store = sessions.NewCookieStore([]byte("super-secret-key"))

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func initDB() {
	var err error
	db, err = sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/sessiondb")
	if err != nil {
		log.Fatal(err)
	}
}

// REGISTER
func Register(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 14)

	_, err := db.Exec("INSERT INTO users(email, password) VALUES (?, ?)",
		user.Email, hashedPassword)

	if err != nil {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	w.Write([]byte("User Registered"))
}

// LOGIN
func Login(w http.ResponseWriter, r *http.Request) {
	var user User
	var storedPassword string

	json.NewDecoder(r.Body).Decode(&user)

	err := db.QueryRow("SELECT password FROM users WHERE email=?",
		user.Email).Scan(&storedPassword)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword),
		[]byte(user.Password))

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// CREATE SESSION
	session, _ := store.Get(r, "session-name")
	session.Values["email"] = user.Email
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
	}

	session.Save(r, w)

	w.Write([]byte("Login successful - session created"))
}

// LOGOUT
func Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	session.Options.MaxAge = -1
	session.Save(r, w)

	w.Write([]byte("Logged out"))
}

// MIDDLEWARE
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session, _ := store.Get(r, "session-name")

		if session.Values["email"] == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// PROTECTED ROUTE
func Dashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	email := session.Values["email"]

	fmt.Fprintf(w, "Welcome %v to Dashboard", email)
}

func main() {

	initDB()

	r := mux.NewRouter()

	r.HandleFunc("/register", Register).Methods("POST")
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/logout", Logout).Methods("GET")

	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(AuthMiddleware)
	protected.HandleFunc("/dashboard", Dashboard).Methods("GET")

	fmt.Println("Server running at :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

