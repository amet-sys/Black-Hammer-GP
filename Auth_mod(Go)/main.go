package main

import (
	"fmt"
	"log"
	"net/http"

	handlers "main.go/handlers"
)

func main() {
	router := http.NewServeMux()
	router.HandleFunc("/login", handlers.HandleAuth)
	router.HandleFunc("/callback", handlers.HandleCallback)

	// Запускаем сервер и обрабатываем возможные ошибки
	log.Println("Запуск сервера на порту :5501")
	if err := http.ListenAndServe(":5501", router); err != nil {
		fmt.Printf("Ошибка при запуске сервера: %s\n", err)
	}
}
