package main

import (
    "context"
    "fmt"
    "net/http"
    "github.com/gin-gonic/gin"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
)

// AuthMiddleware checks for a valid JWT token in the Authorization header
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")

        if tokenString == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
            c.Abort()
            return
        }

        // Remove "Bearer " prefix if present
        if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
            tokenString = tokenString[7:]
        }

        // Parse the token using the jwtSecret from auth.go
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return jwtSecret, nil // Use the jwtSecret from auth.go
        })

        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
            c.Abort()
            return
        }

        // Proceed to the next handler
        c.Next()
    }
}

// SignupHandler handles the user registration
func SignupHandler(c *gin.Context) {
    var user User
    if err := c.BindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Check if the username already exists
    var existingUser User
    err := userCollection.FindOne(context.TODO(), bson.M{"username": user.Username}).Decode(&existingUser)
    if err == nil {
        // User already exists, return an error
        c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
        return
    } else if err != mongo.ErrNoDocuments {
        // Handle any other errors with the database query
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking for existing user"})
        return
    }

    // Hash the password before storing
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
        return
    }
    user.Password = string(hashedPassword)

    // Insert user into MongoDB
    _, err = userCollection.InsertOne(context.TODO(), user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error inserting user into database"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Signup successful!"})
}

// LoginHandler handles the login and returns a JWT token
func LoginHandler(c *gin.Context) {
    var user User
    if err := c.BindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var foundUser User
    err := userCollection.FindOne(context.TODO(), bson.M{"username": user.Username}).Decode(&foundUser)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
        } else {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user from database"})
        }
        return
    }

    // Compare the hashed password
    err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
        return
    }

    // Generate JWT token
    token, err := GenerateJWT(user.Username)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token": token})
}

// Protected route handler (e.g., user profile or dashboard)
func ProfileHandler(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "Welcome to your protected profile!"})
}
