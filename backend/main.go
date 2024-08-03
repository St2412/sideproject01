package main

import (
	"fmt"
	"log"
	"net/http"
	"vtuber-sideproject/backend/handlers"

	"github.com/gorilla/mux"
)

func main() {
	dsn := "root:123456@tcp(localhost:3306)/vtuber_sideproject"
	handlers.InitDB(dsn)

	r := mux.NewRouter()
	r.HandleFunc("/register", handlers.RegisterHandler).Methods("POST")
	r.HandleFunc("/login", handlers.LoginHandler).Methods("POST")

	fmt.Println("Starting server at port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
