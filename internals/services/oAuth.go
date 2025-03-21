package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Skythrill256/auth-service/internals/config"
	"github.com/Skythrill256/auth-service/internals/db"
	"github.com/Skythrill256/auth-service/internals/models"
	"github.com/Skythrill256/auth-service/internals/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
	"golang.org/x/oauth2/microsoft"
)

func GetGoogleOAuthConfig(cfg *config.Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
}

func GetGithubOAuthConfig(cfg *config.Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.GithubClientID,
		ClientSecret: cfg.GithubClientSecret,
		RedirectURL:  cfg.GithubRedirectURL,
		Scopes:       []string{"user"},
		Endpoint:     github.Endpoint,
	}
}

func GetFacebookOAuthConfig(cfg *config.Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.FacebookClientID,
		ClientSecret: cfg.FacebookClientSecret,
		RedirectURL:  cfg.FacebookRedirectURL,
		Scopes:       []string{"email"},
		Endpoint:     facebook.Endpoint,
	}
}

func GetMicrosoftOAuthConfig(cfg *config.Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.MicrosoftClientID,
		ClientSecret: cfg.MicrosoftClientSecret,
		RedirectURL:  cfg.MicrosoftRedirectURL,
		Scopes:       []string{"openid", "profile", "email", "offline_access", "User.Read"},
		Endpoint:     microsoft.AzureADEndpoint("common"),
	}
}

func GetLinkedinOAuthConfig(cfg *config.Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.LinkedInClientID,
		ClientSecret: cfg.LinkedInClientSecret,
		RedirectURL:  cfg.LinkedInRedirectURL,
		Scopes:       []string{"r_emailaddress", "r_liteprofile"},
		Endpoint:     linkedin.Endpoint,
	}
}

func GoogleOAuthConsentURL(cfg *config.Config) string {
	oauthConfig := GetGoogleOAuthConfig(cfg)

	return oauthConfig.AuthCodeURL("state")
}

func GithubOAuthConsentURL(cfg *config.Config) string {
	oauthConfig := GetGithubOAuthConfig(cfg)

	return oauthConfig.AuthCodeURL("state")
}

func FacebookOAuthConsentURL(cfg *config.Config) string {
	oauthConfig := GetFacebookOAuthConfig(cfg)

	return oauthConfig.AuthCodeURL("state")
}

func GoogleLogin(cfg *config.Config, repository *db.Repository, code string) (string, error) {
	oauthConfig := GetGoogleOAuthConfig(cfg)

	oauthToken, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}

	client := oauthConfig.Client(context.Background(), oauthToken)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var googleUser map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return "", err
	}

	email, ok := googleUser["email"].(string)
	if !ok {
		return "", errors.New("failed to get email from Google response")
	}
	googleID, ok := googleUser["sub"].(string)
	if !ok {
		return "", errors.New("failed to get Google ID from response")
	}

	user, err := repository.GetUserByGoogleID(googleID)
	if err != nil {
		return "", err
	}

	if user == nil {
		newUser := &models.User{
			Email:      email,
			IsVerified: true,
			GoogleID:   &googleID,
		}
		err := repository.CreateUser(newUser)
		if err != nil {
			return "", err
		}
		user = newUser
	}

	jwtToken, err := utils.GenerateJWT(user.Email, cfg.JWTSecret)
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}

func GithubLogin(cfg *config.Config, repository *db.Repository, code string) (string, error) {
	oauthConfig := GetGithubOAuthConfig(cfg)

	oauthToken, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}

	client := oauthConfig.Client(context.Background(), oauthToken)

	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var githubEmails []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&githubEmails); err != nil {
		return "", err
	}

	var email string
	for _, githubEmail := range githubEmails {
		if primary, ok := githubEmail["primary"].(bool); ok && primary {
			if emailStr, ok := githubEmail["email"].(string); ok {
				email = emailStr
				break
			}
		}
	}

	if email == "" {
		return "", errors.New("failed to get primary email from Github response")
	}

	resp, err = client.Get("https://api.github.com/user")
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	var githubUser map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
		return "", err
	}

	githubID, ok := githubUser["id"].(float64)
	if !ok {
		return "", errors.New("failed to get Github ID from response")
	}

	githubIDInt := int64(githubID)

	user, err := repository.GetUserByGithubID(githubIDInt)
	if err != nil {
		return "", err
	}

	if user == nil {
		newUser := &models.User{
			Email:      email,
			IsVerified: true,
			GithubID:   &githubIDInt,
		}
		err := repository.CreateUser(newUser)
		if err != nil {
			return "", err
		}
		user = newUser
	}

	jwtToken, err := utils.GenerateJWT(user.Email, cfg.JWTSecret)
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}

func FacebookLogin(cfg *config.Config, repository *db.Repository, code string) (string, error) {
	oauthConfig := GetFacebookOAuthConfig(cfg)

	oauthToken, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}

	client := oauthConfig.Client(context.Background(), oauthToken)

	resp, err := client.Get("https://graph.facebook.com/me?fields=email")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var facebookUser map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&facebookUser); err != nil {
		return "", err
	}

	fmt.Println(facebookUser)

	email, ok := facebookUser["email"].(string)
	if !ok {
		return "", errors.New("failed to get email from Facebook response")
	}

	facebookID, ok := facebookUser["id"].(string)
	if !ok {
		return "", errors.New("failed to get Facebook ID from response")
	}

	facebookIDInt, err := strconv.ParseInt(facebookID, 10, 64)
	if err != nil {
		return "", err
	}

	user, err := repository.GetUserByFacebookID(facebookIDInt)
	if err != nil {
		return "", err
	}

	if user == nil {
		newUser := &models.User{
			Email:      email,
			IsVerified: true,
			FacebookID: &facebookIDInt,
		}
		err := repository.CreateUser(newUser)
		if err != nil {
			return "", err
		}
		user = newUser
	}

	jwtToken, err := utils.GenerateJWT(user.Email, cfg.JWTSecret)
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}

func MicrosoftLogin(cfg *config.Config, repository *db.Repository, code string) (string, error) {
	oauthConfig := GetMicrosoftOAuthConfig(cfg)

	oauthToken, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}

	accessToken := oauthToken.AccessToken
	if accessToken == "" {
		return "", errors.New("failed to retrieve access token")
	}

	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var microsoftUser struct {
		ID    string `json:"id"`
		Email string `json:"mail"`
		UPN   string `json:"userPrincipalName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&microsoftUser); err != nil {
		return "", err
	}

	if microsoftUser.Email == "" {
		microsoftUser.Email = microsoftUser.UPN
	}

	if microsoftUser.Email == "" {
		return "", errors.New("failed to retrieve email from Microsoft API")
	}

	user, err := repository.GetUserByMicrosoftID(microsoftUser.ID)
	if err != nil {
		return "", err
	}

	if user == nil {
		newUser := &models.User{
			Email:       microsoftUser.Email,
			IsVerified:  true,
			MicrosoftID: &microsoftUser.ID,
		}
		if err := repository.CreateUser(newUser); err != nil {
			return "", err
		}
		user = newUser
	}

	jwtToken, err := utils.GenerateJWT(user.Email, cfg.JWTSecret)
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}

func LinkedinLogin(cfg *config.Config, repository *db.Repository, code string) (string, error) {
	oauthConfig := GetLinkedinOAuthConfig(cfg)

	oauthToken, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}

	client := oauthConfig.Client(context.Background(), oauthToken)

	resp, err := client.Get("https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var emailResponse struct {
		Elements []struct {
			Handle struct {
				EmailAddress string `json:"emailAddress"`
			} `json:"handle~"`
		} `json:"elements"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emailResponse); err != nil {
		return "", err
	}

	if len(emailResponse.Elements) == 0 {
		return "", errors.New("failed to get email from LinkedIn response")
	}

	email := emailResponse.Elements[0].Handle.EmailAddress

	resp, err = client.Get("https://api.linkedin.com/v2/me")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var linkedinUser struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&linkedinUser); err != nil {
		return "", err
	}

	linkedinID, err := strconv.ParseInt(linkedinUser.ID, 10, 64)
	if err != nil {
		return "", err
	}

	user, err := repository.GetUserByLinkedinID(linkedinID)
	if err != nil {
		return "", err
	}

	if user == nil {
		newUser := &models.User{
			Email:      email,
			IsVerified: true,
			LinkedinID: &linkedinID,
		}
		err := repository.CreateUser(newUser)
		if err != nil {
			return "", err
		}
		user = newUser
	}

	jwtToken, err := utils.GenerateJWT(user.Email, cfg.JWTSecret)
	if err != nil {
		return "", err
	}

	return jwtToken, nil
}
