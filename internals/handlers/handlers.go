package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/Skythrill256/auth-service/internals/config"
	"github.com/Skythrill256/auth-service/internals/db"
	"github.com/Skythrill256/auth-service/internals/services"
	"github.com/Skythrill256/auth-service/internals/utils"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Repository *db.Repository
	Config     *config.Config
}

func NewHandler(repository *db.Repository, config *config.Config) *Handler {
	return &Handler{
		Repository: repository,
		Config:     config,
	}
}

func (h *Handler) SignUpUser(w http.ResponseWriter, r *http.Request) {
	var user utils.UserDTO
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	err = services.SignUpUser(user, h.Repository, h.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User Registered, Please verify your email"})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var userDTO utils.UserDTO
	err := json.NewDecoder(r.Body).Decode(&userDTO)
	if err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}
	token, err := services.LoginUser(userDTO, h.Repository, h.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token:": token})

}

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	err := services.VerifyEmail(token, h.Repository, h.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Email Verified Successfully"})
}

func (h *Handler) GoogleOAuthConsentRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, services.GoogleOAuthConsentURL(h.Config), http.StatusTemporaryRedirect)
}

func (h *Handler) GithubOAuthConsentRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, services.GithubOAuthConsentURL(h.Config), http.StatusTemporaryRedirect)
}

func (h *Handler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code is required", http.StatusBadRequest)
		return
	}
	token, err := services.GoogleLogin(h.Config, h.Repository, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (h *Handler) GithubLogin(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code is required", http.StatusBadRequest)
		return
	}
	token, err := services.GithubLogin(h.Config, h.Repository, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (h *Handler) FacebookLogin(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code is required", http.StatusBadRequest)
		return
	}
	token, err := services.FacebookLogin(h.Config, h.Repository, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (h *Handler) MicrosoftLogin(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code is required", http.StatusBadRequest)
		return
	}
	token, err := services.MicrosoftLogin(h.Config, h.Repository, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (h *Handler) GetUserById(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Id is required", http.StatusBadRequest)
	}
	user, err := services.GetUserByID(id, h.Repository)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(user)
}

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}
	err := services.ForgotPassword(email, h.Repository, h.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Reset Password link sent to your email"})
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "Token is required", http.StatusBadRequest)
			return
		}

		tmpl, err := template.New("reset").Parse(`
			<!DOCTYPE html>
			<html>
			<head>
				<title>Reset Password</title>
			</head>
			<body>
				<h2>Reset Password</h2>
				<form method="POST" action="/reset-password">
					<input type="hidden" name="token" value="{{.Token}}">
					<p><label>New Password:</label></p>
					<p><input type="password" name="password" required></p>
					<p><button type="submit">Reset Password</button></p>
				</form>
			</body>
			</html>
		`)
		if err != nil {
			http.Error(w, "Error loading form", http.StatusInternalServerError)
			return
		}

		tmpl.Execute(w, struct{ Token string }{Token: token})
	} else if r.Method == "POST" {
		token := r.FormValue("token")
		newPassword := r.FormValue("password")

		if token == "" || newPassword == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		email, err := utils.ParseJWT(token, h.Config.JWTSecret)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		err = h.Repository.UpdateUserPassword(email, string(hashedPassword))
		if err != nil {
			http.Error(w, "Error updating password", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Password successfully reset"})
	}
}
