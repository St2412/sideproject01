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
	//使用者相關功能
	r.HandleFunc("/register", handlers.RegisterHandler).Methods("POST")
	r.HandleFunc("/login", handlers.LoginHandler).Methods("POST")
	r.HandleFunc("/welcome", handlers.WelcomeHandler).Methods("GET")
	r.HandleFunc("/forgot-password", handlers.ForgotPasswordHandler).Methods("POST")
	r.HandleFunc("/reset-password", handlers.ResetPasswordHandler).Methods("POST")

	// VTuber後台管理功能
	r.HandleFunc("/get/vtubers", handlers.GetAllVTubersHandler).Methods("GET")
	r.HandleFunc("/get/vtuber", handlers.GetVTuberHandler).Methods("GET")
	r.HandleFunc("/insert/vtuber", handlers.CreateVTuberHandler).Methods("POST")
	r.HandleFunc("/update/vtuber/{id}", handlers.UpdateVTuberHandler).Methods("PUT")
	r.HandleFunc("/delete/vtuber/{id}", handlers.DeleteVTuberHandler).Methods("DELETE")

	// 启动HTTP服务器
	fmt.Println("Starting server at port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
