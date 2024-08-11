package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"

	//忘記密碼相關
	"crypto/rand"
	"encoding/base64"

	_ "github.com/go-sql-driver/mysql"
	//"github.com/gorilla/mux"
	//"log"
)

var jwtKey = []byte("your_secret_key")

type User struct {
	ID        int
	Username  string
	Password  string
	CreatedAt time.Time
	Email     string
}

// 用户的登录凭证
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// JWT（JSON Web Token）的声明（Claims） 生成凭证時用
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// 使用者註冊
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	currentTime := time.Now()
	_, err = DB.Exec("INSERT INTO users (username, password,created_at) VALUES (?, ?,?)", creds.Username, hashedPassword, currentTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User registered successfully")
}

// 使用者登入
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("Attempting login for username: %s\n", creds.Username)

	var storedUser User
	err = DB.QueryRow("SELECT id, password FROM users WHERE username = ?", creds.Username).Scan(&storedUser.ID, &storedUser.Password)
	if err == sql.ErrNoRows {
		fmt.Println("Username not found")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("Stored password hash: %s\n", storedUser.Password)

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(creds.Password))
	if err != nil {
		fmt.Println("Password does not match")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	fmt.Fprintf(w, "User logged in successfully")
}

// 歡迎
func WelcomeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "No token", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			http.Error(w, "Invalid token signature", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Welcome %s!", claims.Username)
}

// 忘记密码处理函数
func ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var storedUser User
	err = DB.QueryRow("SELECT id, email FROM users WHERE email = ?", creds.Email).Scan(&storedUser.ID, &storedUser.Email)
	if err == sql.ErrNoRows {
		http.Error(w, "Email not found", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resetToken, err := generateResetToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	expirationTime := time.Now().Add(1 * time.Hour)

	_, err = DB.Exec("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)", storedUser.ID, resetToken, expirationTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resetURL := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", resetToken)
	err = sendResetEmail(storedUser.Email, resetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Password reset email sent")
}

// 重置密码处理函数
func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token := requestBody.Token
	if token == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}
	fmt.Printf("Received reset token: %s\n", token)

	var userID int
	var expiresAt []uint8
	err = DB.QueryRow("SELECT user_id, expires_at FROM password_resets WHERE token = ?", token).Scan(&userID, &expiresAt)
	if err == sql.ErrNoRows {
		fmt.Printf("Invalid token: %s\n", token)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	} else if err != nil {
		fmt.Printf("Error querying token: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// 转换 expiresAt 为 time.Time
	expiresAtTime, err := time.Parse("2006-01-02 15:04:05", string(expiresAt))
	if err != nil {
		fmt.Printf("Error parsing expires_at: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("Token valid. UserID: %d, ExpiresAt: %v\n", userID, expiresAtTime)

	if time.Now().After(expiresAtTime) {
		fmt.Printf("Token expired: %s\n", token)
		http.Error(w, "Token has expired", http.StatusUnauthorized)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestBody.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Error hashing password: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = DB.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userID)
	if err != nil {
		fmt.Printf("Error updating password: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = DB.Exec("DELETE FROM password_resets WHERE token = ?", token)
	if err != nil {
		fmt.Printf("Error deleting reset token: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Password reset successfully")
}

// 生成重置密码令牌
func generateResetToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// 发送重置密码邮件
func sendResetEmail(toEmail, resetURL string) error {
	// e := email.NewEmail()
	// e.From = "YourAppName <no-reply@yourapp.com>"
	// e.To = []string{toEmail}
	// e.Subject = "Password Reset Request"
	// e.Text = []byte("To reset your password, please click the following link: " + resetURL)
	// err := e.Send("smtp.your-email-provider.com:587", smtp.PlainAuth("", "ceshi9028@gmail.com", "ceshi90282412", "smtp.your-email-provider.com"))
	// return err
	// 在开发环境中，打印重置链接而不是发送电子邮件
	fmt.Printf("Password reset link for %s: %s\n", toEmail, resetURL)
	return nil
}
