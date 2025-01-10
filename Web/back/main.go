package main

import (
	"back/handlers"
	"fmt"
	"log"
	"net/http"
)

func main() {
	router := http.NewServeMux()

	router.HandleFunc("/submit", handlers.SubmitHandler)
	router.HandleFunc("/delete-coockie", handlers.DeleteCoockie)
	router.HandleFunc("/login", handlers.LoginHandler)
	router.HandleFunc("/logout", handlers.LogoutHandler)
	router.HandleFunc("/start", handlers.Starter)
	router.HandleFunc("/personal_cabinet", handlers.About)
	router.HandleFunc("/creating", handlers.TestCreator)
	router.HandleFunc("/index", handlers.IndexHandler)

	router.HandleFunc("/", handlers.Starter)
	fileServer := http.FileServer(http.Dir("/public"))
	router.Handle("/public/", http.StripPrefix("/public/", fileServer))

	// Запускаем сервер и обрабатываем возможные ошибки
	log.Println("Запуск сервера на порту :5502 ")
	if err := http.ListenAndServe(":5502", router); err != nil {
		fmt.Printf("Ошибка при запуске сервера: %s\n", err)
	}

}
