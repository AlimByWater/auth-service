package main

import (
	"net/http"

	"github.com/AlimByWater/auth-service/controllers"
	"github.com/AlimByWater/auth-service/models"
	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("AuthService")) })
	router.HandleFunc("/token/{guid}", controllers.CreateToken).Methods("GET")
	router.HandleFunc("/refresh", controllers.Refresh).Methods("POST")
	router.HandleFunc("/token", controllers.RemoveToken).Methods("DELETE")
	router.HandleFunc("/token/{guid}", controllers.RemoveAllTokens).Methods("DELETE")
	defer models.Disconnect()

	http.ListenAndServe("127.0.0.1:8080", router)
}
