package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"context"
	"github.com/golang-jwt/jwt"
)

// User represents a user in the system
type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// In-memory database to store user data
var users = make(map[string]User)

func signUpHandler(writer http.ResponseWriter, request *http.Request) {
	var user User
	err := json.NewDecoder(request.Body).Decode(&user)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(writer, "Bad Request: %v", err)
		return
	}

	if _, exists := users[user.Email]; exists {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(writer, "Bad Request: User already exists")
		return
	}

	users[user.Email] = user

	writer.WriteHeader(http.StatusOK)
	fmt.Fprintf(writer, "User registered successfully")
}

func signInHandler(writer http.ResponseWriter, request *http.Request) {
	var user User
	err := json.NewDecoder(request.Body).Decode(&user)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(writer, "Bad Request: %v", err)
		return
	}

	storedUser, exists := users[user.Email]
	if !exists || storedUser.Password != user.Password {
		writer.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(writer, "Unauthorized: Invalid email or password")
		return
	}

	// Generate JWT token
	tokenString, err := generateJWT(user.Email)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(writer, "Internal Server Error: %v", err)
		return
	}

	// Send JWT token back to the client
	response := struct {
		Token string `json:"token"`
	}{
		Token: tokenString,
	}

	writer.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(writer).Encode(response)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(writer, "Internal Server Error: %v", err)
		return
	}
}
func authHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		tokenString := request.Header.Get("Token")
		if tokenString == "" {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(writer, "Unauthorized: Missing token")
			return
		}

		// Parse the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return []byte("error"), fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("yourSecretKey"), nil // Replace "yourSecretKey" with your actual secret key
		})
		if err != nil || token == nil || !token.Valid {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(writer, "Unauthorized: Invalid token")
			return
		}

		// Extract email from token claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			writer.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(writer, "Failed to retrieve claims from token")
			return
		}
		email, ok := claims["email"].(string)
		if !ok {
			writer.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(writer, "Failed to retrieve email from token claims")
			return
		}

		// Add email to the request context
		ctx := context.WithValue(request.Context(), "email", email)
		request = request.WithContext(ctx)


		next(writer, request)
	}
}

type UserProfile struct {
	Email string `json:"email"`
}
func userProfileHandler(writer http.ResponseWriter, request *http.Request) {
	email := request.Context().Value("email")
	if email == nil {
		http.Error(writer, "Email not found in context", http.StatusInternalServerError)
		return
	}

	emailStr, ok := email.(string)
	if !ok {
		http.Error(writer, "Failed to retrieve email from context", http.StatusInternalServerError)
		return
	}

	// Create a UserProfile struct with the email
	userProfile := UserProfile{Email: emailStr}

	// Encode the UserProfile as JSON
	jsonData, err := json.Marshal(userProfile)
	if err != nil {
		http.Error(writer, "Failed to encode user profile as JSON", http.StatusInternalServerError)
		return
	}

	// Set Content-Type header to application/json
	writer.Header().Set("Content-Type", "application/json")

	// Write the JSON data to the response writer
	writer.Write(jsonData)
}

func main() {
	server := &http.Server{
		Addr:         ":8080",
		Handler:      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/signup":
				signUpHandler(w, r)
			case "/signin":
				signInHandler(w, r)
			case "/userProfile":
				authHandler(userProfileHandler)(w, r)
			default:
				http.NotFound(w, r)
			}
		}),
		ReadTimeout:  10 * time.Second, // Set read timeout to 10 seconds
		WriteTimeout: 10 * time.Second, // Set write timeout to 10 seconds
		// Add other configurations as needed
	}

	log.Fatal(server.ListenAndServe())
}

// JWT token generation function
func generateJWT(email string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
	claims["email"] = email
	tokenString, err := token.SignedString([]byte("yourSecretKey"))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
