package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/AlimByWater/auth-service/controllers"
	"github.com/AlimByWater/auth-service/models"
	"github.com/gorilla/mux"
)

func main() {
	port := os.Getenv("PORT")
	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "AuthService") })
	router.HandleFunc("/token/{guid}", controllers.CreateToken).Methods("GET")
	router.HandleFunc("/refresh", controllers.Refresh).Methods("POST")
	router.HandleFunc("/token", controllers.RemoveToken).Methods("DELETE")
	router.HandleFunc("/token/{guid}", controllers.RemoveAllTokens).Methods("DELETE")
	defer models.Disconnect()

	http.ListenAndServe(":"+port, router)
}
