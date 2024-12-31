package main

import (
	"fmt"
	"log"
	"net/http"

	"main.go/handlers"
)

func main() {
	router := http.NewServeMux()
	router.HandleFunc("/auth", handlers.HandleAuth)
	router.HandleFunc("/callback", handlers.HandleCallback)

	// Запускаем сервер и обрабатываем возможные ошибки
	log.Println("Запуск сервера на порту :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		fmt.Printf("Ошибка при запуске сервера: %s\n", err)
	}

}
