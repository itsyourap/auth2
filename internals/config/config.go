package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	AppPort               string
	DBHost                string
	DBPort                string
	DBUser                string
	DBPassword            string
	DBName                string
	JWTSecret             string
	EmailHost             string
	EmailPort             string
	EmailSender           string
	EmailUsername         string
	EmailPass             string
	GoogleClientID        string
	GoogleClientSecret    string
	GoogleRedirectURL     string
	GithubClientID        string
	GithubClientSecret    string
	GithubRedirectURL     string
	FacebookClientID      string
	FacebookClientSecret  string
	FacebookRedirectURL   string
	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftRedirectURL  string
	LinkedInClientID      string
	LinkedInClientSecret  string
	LinkedInRedirectURL   string
}

func LoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return &Config{
		AppPort:               os.Getenv("APP_PORT"),
		DBHost:                os.Getenv("DB_HOST"),
		DBPort:                os.Getenv("DB_PORT"),
		DBUser:                os.Getenv("DB_USER"),
		DBPassword:            os.Getenv("DB_PASSWORD"),
		DBName:                os.Getenv("DB_NAME"),
		JWTSecret:             os.Getenv("JWT_SECRET"),
		EmailHost:             os.Getenv("EMAIL_HOST"),
		EmailPort:             os.Getenv("EMAIL_PORT"),
		EmailSender:           os.Getenv("EMAIL_SENDER"),
		EmailUsername:         os.Getenv("EMAIL_USERNAME"),
		EmailPass:             os.Getenv("EMAIL_PASSWORD"),
		GoogleClientID:        os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:    os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:     os.Getenv("GOOGLE_REDIRECT_URL"),
		GithubClientID:        os.Getenv("GITHUB_CLIENT_ID"),
		GithubClientSecret:    os.Getenv("GITHUB_CLIENT_SECRET"),
		GithubRedirectURL:     os.Getenv("GITHUB_REDIRECT_URL"),
		FacebookClientID:      os.Getenv("FACEBOOK_CLIENT_ID"),
		FacebookClientSecret:  os.Getenv("FACEBOOK_CLIENT_SECRET"),
		FacebookRedirectURL:   os.Getenv("FACEBOOK_REDIRECT_URL"),
		MicrosoftClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
		MicrosoftClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
		MicrosoftRedirectURL:  os.Getenv("MICROSOFT_REDIRECT_URL"),
		LinkedInClientID:      os.Getenv("LINKEDIN_CLIENT_ID"),
		LinkedInClientSecret:  os.Getenv("LINKEDIN_CLIENT_SECRET"),
		LinkedInRedirectURL:   os.Getenv("LINKEDIN_REDIRECT_URL"),
	}
}
