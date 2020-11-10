package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AlimByWater/auth-service/controllers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	port, exist := os.LookupEnv("PORT")
	if !exist {
		port = "8080"
		fmt.Println("port variable not found. port by default: " + port)
	}

	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "AuthService") }).Methods("GET")
	router.HandleFunc("/token/{guid}", controllers.CreateToken).Methods("GET")
	router.HandleFunc("/refresh", controllers.Refresh).Methods("POST")
	router.HandleFunc("/token", controllers.RemoveToken).Methods("DELETE")
	router.HandleFunc("/token/{guid}", controllers.RemoveAllTokens).Methods("DELETE")
	//defer models.Disconnect()

	http.ListenAndServe(":"+port, router)
}
