# JWT Authentication API in Go

This is a simple JWT authentication API written in Go. It allows users to sign up, sign in, and view their user profile by providing a JWT token in the request headers.

## Features

- User sign-up: Users can register by providing an email and password.
- User sign-in: Users can authenticate by providing their registered email and password, and receive a JWT token.
- User profile: Authenticated users can view their user profile by providing the JWT token in the request headers.

## Installation

1. Clone this repository:
2. Navigate to the project directory:
3. Install dependencies:

   ```bash
   go mod tidy
   ```

4. Build and run the server:

   ```bash
   go run jwtExample.go
   ```

   The server will start running at `http://localhost:8080`.

## Endpoints

- `POST /signup`: Register a new user.
  - Request Body: JSON object with `email` and `password` fields.
  - Response: `200 OK` on success, `400 Bad Request` if the user already exists, or if the request body is invalid.

- `POST /signin`: Authenticate a user and generate a JWT token.
  - Request Body: JSON object with `email` and `password` fields.
  - Response: `200 OK` with a JWT token on success, `401 Unauthorized` if the email or password is incorrect.

- `GET /userProfile`: Get the user profile.
  - Request Headers: `Token` with the JWT token obtained after sign-in.
  - Response: `200 OK` with the user profile JSON containing the email, `401 Unauthorized` if the token is missing or invalid.

## Dependencies

- [github.com/golang-jwt/jwt](https://github.com/golang-jwt/jwt): Go implementation of JSON Web Tokens (JWT).

## Author

[Ahmed Mahdi](https://github.com/ajm4k)

https://ajm4k.webflow.io