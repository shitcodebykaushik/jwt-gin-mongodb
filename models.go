package main

type User struct {
    Username string   `json:"username" bson:"username"`
    Password string   `json:"password" bson:"password"`
    Roles    []string `json:"roles" bson:"roles"` // Include roles in user model
}
