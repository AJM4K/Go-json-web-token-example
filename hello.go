package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"context"
	"time"

	"github.com/golang-jwt/jwt"
)

// User represents a user in the system
type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
var users = make(map[string]User)

func main() {
	fmt.Println("Starting -------")
	http.HandleFunc("/home", verifyJWT(handlePage))
	//http.HandleFunc("/auth", authPage)
	http.HandleFunc("/signin", signInPage)
	http.HandleFunc("/user", verifyToken(userProfileHandler))


	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Println("There was an error listening on port :8080", err)
	}
}

type Message struct {
	Status string `json:"status"`
	Info   string `json:"info"`
}

func handlePage(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	var message Message
	err := json.NewDecoder(request.Body).Decode(&message)
	if err != nil {
		return
	}
	err = json.NewEncoder(writer).Encode(message)
	if err != nil {
		return
	}
}

// func authPage(writer http.ResponseWriter, request *http.Request) {
// 	writer.Header().Set("Content-Type", "application/json")

// 	// Generate JWT token
// 	tokenString, err := generateJWT()
// 	if err != nil {
// 		writer.WriteHeader(http.StatusInternalServerError)
// 		_, err := writer.Write([]byte("Internal Server Error"))
// 		if err != nil {
// 			log.Println("Error writing response:", err)
// 		}
// 		return
// 	}

// 	// Create a response JSON containing the token
// 	response := struct {
// 		Token string `json:"token"`
// 	}{
// 		Token: tokenString,
// 	}

// 	// Encode response JSON and send it back
// 	err = json.NewEncoder(writer).Encode(response)
// 	if err != nil {
// 		log.Println("Error encoding JSON response:", err)
// 		writer.WriteHeader(http.StatusInternalServerError)
// 		_, err := writer.Write([]byte("Internal Server Error"))
// 		if err != nil {
// 			log.Println("Error writing response:", err)
// 		}
// 		return
// 	}
// }

func signInPage(writer http.ResponseWriter, request *http.Request) {
	// Parse request body to get email and password
	type Credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var creds Credentials
	err := json.NewDecoder(request.Body).Decode(&creds)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Bad Request"))
		if err != nil {
			log.Println("Error writing response:", err)
		}
		return
	}

	// Authenticate user (example: check against a user database)
	validUser := authenticateUser(creds.Email, creds.Password)
	if !validUser {
		writer.WriteHeader(http.StatusUnauthorized)
		_, err := writer.Write([]byte("Unauthorized"))
		if err != nil {
			log.Println("Error writing response:", err)
		}
		return
	}

	// Generate JWT token with email as claim
	tokenString, err := generateJWT(creds.Email)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Internal Server Error"))
		if err != nil {
			log.Println("Error writing response:", err)
		}
		return
	}

	// Send JWT token back to client
	response := struct {
		Token string `json:"token"`
	}{
		Token: tokenString,
	}

	writer.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(writer).Encode(response)
	if err != nil {
		log.Println("Error encoding JSON response:", err)
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Internal Server Error"))
		if err != nil {
			log.Println("Error writing response:", err)
		}
		return
	}
}
func authenticateUser(email, password string) bool {
    // Here you would implement your authentication logic, such as checking against a database
    // For demonstration purposes, let's assume a hardcoded user/password pair
    validEmail := "user@example.com"
    validPassword := "password123"
    return email == validEmail && password == validPassword
}
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

// func generateJWT() (string, error) {
// 	token := jwt.New(jwt.SigningMethodHS256) // Use the same signing method here
// 	claims := token.Claims.(jwt.MapClaims)
// 	claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
// 	claims["authorized"] = true
// 	claims["user"] = "username"
// 	tokenString, err := token.SignedString([]byte("sampleSecretKey")) // Use []byte for the secret key
// 	if err != nil {
// 		return "", err
// 	}

// 	return tokenString, nil
// }

func verifyJWT(endpointHandler http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		tokenString := request.Header.Get("Token")
		if tokenString == "" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, err := writer.Write([]byte("You're Unauthorized due to No token in the header"))
			if err != nil {
				return
			}
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Check the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("sampleSecretKey"), nil // Return the actual key used for signing the token
		})
		if err != nil || !token.Valid {
			writer.WriteHeader(http.StatusUnauthorized)
			_, err := writer.Write([]byte("You're Unauthorized due to invalid token"))
			if err != nil {
				return
			}
			return
		}

		endpointHandler(writer, request)
	}
}
func userProfileHandler(writer http.ResponseWriter, request *http.Request) {
	// Retrieve the email claim from the request context
	email := request.Context().Value("email").(string)

	// You can now use the email address as needed
	fmt.Fprintf(writer, "User profile for: %s", email)
}

func verifyToken(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		// Get the JWT token from the request header
		tokenString := request.Header.Get("Authorization")
		if tokenString == "" {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(writer, "Unauthorized: Missing token")
			return
		}

		// Extract the token from the "Bearer" tokenString
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

		// Parse the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Check the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("yourSecretKey"), nil // Use the same secret key used for token generation
		})
		if err != nil || !token.Valid {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(writer, "Unauthorized: Invalid token")
			return
		}

		// Extract the email claim from the token
		claims := token.Claims.(jwt.MapClaims)
		email, ok := claims["email"].(string)
		if !ok {
			writer.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(writer, "Internal Server Error: Email claim missing")
			return
		}

		// Add the email claim to the request context
		ctx := context.WithValue(request.Context(), "email", email)

		// Call the next handler with the modified request
		next(writer, request.WithContext(ctx))
	}
}