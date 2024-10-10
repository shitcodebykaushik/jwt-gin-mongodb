package main

import (
    "github.com/gin-gonic/gin"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "context"
    "log"
    "time"
)

var userCollection *mongo.Collection

func main() {
    // Initialize Gin router
    router := gin.Default() 
     // Serve static HTML file for login


    // Connect to MongoDB
    client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
    if err != nil {
        log.Fatal(err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    err = client.Connect(ctx)
    if err != nil {
        log.Fatal(err)
    }

    userCollection = client.Database("testdb").Collection("users")

    // Public routes (signup, login)
    router.POST("/signup", SignupHandler)
    router.POST("/login", LoginHandler)

    // Protected route group with Role-Based Access Control
    protected := router.Group("/protected")
    protected.Use(AuthMiddleware())
    {
        protected.GET("/profile", ProfileHandler)  // Protected profile route
        protected.GET("/admin", AdminHandler)      // Admin route, RBAC check required
    }

    // Run the server
    router.Run(":8080")
}
