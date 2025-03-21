package main

import (
	"log"
	"net/http"

	"github.com/Skythrill256/auth-service/internals/config"
	"github.com/Skythrill256/auth-service/internals/db"
	"github.com/Skythrill256/auth-service/internals/handlers"
	"github.com/Skythrill256/auth-service/internals/models"
	"github.com/gorilla/mux"
)

func main() {
	cfg := config.LoadConfig()

	conn, err := db.Connect(cfg)
	if err != nil {
		log.Fatal("Error connecting to database")
	}
	defer conn.Close()
	err = models.RunMigrations(conn)
	if err != nil {
		log.Fatal("Error running migrations")
	}

	repository := db.NewRepository(conn)
	handler := handlers.NewHandler(repository, cfg)

	router := mux.NewRouter()
	router.HandleFunc("/signup", handler.SignUpUser).Methods("POST")
	router.HandleFunc("/login", handler.Login).Methods("POST")
	router.HandleFunc("/verify-email", handler.VerifyEmail).Methods("GET")
	router.HandleFunc("/auth/google", handler.GoogleOAuthConsentRedirect).Methods("GET")
	router.HandleFunc("/auth/google/callback", handler.GoogleLogin).Methods("GET")
	router.HandleFunc("/auth/github", handler.GithubOAuthConsentRedirect).Methods("GET")
	router.HandleFunc("/auth/github/callback", handler.GithubLogin).Methods("GET")
	router.HandleFunc("/auth/facebook/callback", handler.FacebookLogin).Methods("GET")
	router.HandleFunc("/auth/linkedin", handler.LinkedinOAuthConsentRedirect).Methods("GET")
	router.HandleFunc("/auth/linkedin/callback", handler.LinkedinLogin).Methods("GET")
	router.HandleFunc("/forget-password", handler.ForgotPassword).Methods("GET")
	router.HandleFunc("/get-user", handler.GetUserById).Methods("GET")
	router.HandleFunc("/reset-password", handler.ResetPassword).Methods("GET", "POST")
	log.Println("Server is running on port", cfg.AppPort)
	log.Fatal(http.ListenAndServe(":"+cfg.AppPort, router))
}
