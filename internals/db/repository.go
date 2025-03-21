package db

import (
	"database/sql"
	"errors"

	"github.com/Skythrill256/auth-service/internals/models"
)

type Repository struct {
	DB *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{DB: db}
}

func (repo *Repository) CreateUser(user *models.User) error {
	query := `INSERT INTO users (email, password, is_verified, google_id, github_id, facebook_id, linkedin_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
	err := repo.DB.QueryRow(query, user.Email, user.Password, user.IsVerified, user.GoogleID, user.GithubID, user.FacebookID, user.LinkedinID).Scan(&user.ID)
	if err != nil {
		return err
	}
	return nil
}

func (repo *Repository) GetUserByID(id string) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, password, is_verified, created_at, updated_at, google_id, github_id, facebook_id, linkedin_id FROM users WHERE id=$1`
	err := repo.DB.QueryRow(query, id).Scan(&user.ID, &user.Email, &user.Password, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt, &user.GoogleID, &user.GithubID, &user.FacebookID, &user.LinkedinID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (repo *Repository) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, password, is_verified, created_at, updated_at, google_id, github_id, facebook_id, linkedin_id FROM users WHERE email=$1`
	err := repo.DB.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.Password, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt, &user.GoogleID, &user.GithubID, &user.FacebookID, &user.LinkedinID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (repo *Repository) VerifyUserEmail(email string) error {
	query := `UPDATE users SET is_verified = true, updated_at = CURRENT_TIMESTAMP WHERE email = $1`
	_, err := repo.DB.Exec(query, email)
	if err != nil {
		return err
	}
	return nil
}

func (repo *Repository) GetUserByGoogleID(googleID string) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, password, is_verified, created_at, updated_at, google_id FROM users WHERE google_id = $1`
	err := repo.DB.QueryRow(query, googleID).Scan(&user.ID, &user.Email, &user.Password, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt, &user.GoogleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (repo *Repository) GetUserByGithubID(githubID int64) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, password, is_verified, created_at, updated_at, github_id FROM users WHERE github_id = $1`
	err := repo.DB.QueryRow(query, githubID).Scan(&user.ID, &user.Email, &user.Password, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt, &user.GithubID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (repo *Repository) GetUserByFacebookID(facebookID int64) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, password, is_verified, created_at, updated_at, facebook_id FROM users WHERE facebook_id = $1`
	err := repo.DB.QueryRow(query, facebookID).Scan(&user.ID, &user.Email, &user.Password, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt, &user.FacebookID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (repo *Repository) GetUserByLinkedinID(linkedinID int64) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, password, is_verified, created_at, updated_at, linkedin_id FROM users WHERE linkedin_id = $1`
	err := repo.DB.QueryRow(query, linkedinID).Scan(&user.ID, &user.Email, &user.Password, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt, &user.LinkedinID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (repo *Repository) GetUserById(id int) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, is_verified, created_at, updated_at, google_id, github_id, facebook_id FROM users WHERE id = $1`
	err := repo.DB.QueryRow(query, id).Scan(&user.ID, &user.Email, &user.IsVerified, &user.CreatedAt, &user.UpdatedAt, &user.GoogleID, &user.GithubID, &user.FacebookID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (repo *Repository) ForgotPassword(email string) error {
	query := `UPDATE users SET password = $1 WHERE email = $2`
	_, err := repo.DB.Exec(query, email, "password")
	if err != nil {
		return err
	}
	return nil
}
func (repo *Repository) UpdateUserPassword(email string, newPassword string) error {
	query := `UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE email = $2`

	_, err := repo.DB.Exec(query, newPassword, email)
	if err != nil {
		return err
	}
	return nil
}
