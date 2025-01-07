package handlers

import (
	//"encoding/json"
	"log"
	"net/http"
	//"github.com/google/uuid"
	// "back/databases"
	// "context"
)

// var rdb = databases.ConnectToRedis()
// var ctx = context.Background()

// func HomeHandler(w http.ResponseWriter, r *http.Request) {
// 	// Проверка наличия токена сессии в куках
// 	sessionToken, err := r.Cookie("session_token")
// 	if err != nil {
// 		// Если куки нет, показываем страницу авторизации
// 		http.ServeFile(w, r, "./public/login.html") // Предполагается, что у Вас есть login.html
// 		return
// 	}

// 	// Проверка токена в Redis
// 	_, err = rdb.Get(ctx, sessionToken.Value).Result()
// 	if err == redis.Nil {
// 		// Токен не найден, показываем страницу авторизации
// 		http.ServeFile(w, r, "./public/login.html")
// 		return
// 	} else if err != nil {
// 		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
// 		return
// 	}

// 	// Если токен найден, показываем главную страницу
// 	http.ServeFile(w, r, "./public/index.html")
// }

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Print("Login")
	http.ServeFile(w, r, "./public/login.html")
}

func Starter(w http.ResponseWriter, r *http.Request) {
	log.Print("Start")
	http.ServeFile(w, r, "./public/start.html")

}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	log.Print("Index")
	http.ServeFile(w, r, "./public/index.html")
}

func About(w http.ResponseWriter, r *http.Request) {
	log.Print("Cabinet")
	http.ServeFile(w, r, "./public/personal_cabinet.html")
}

func TestCreator(w http.ResponseWriter, r *http.Request) {
	log.Print("Creator")
	http.ServeFile(w, r, "./public/creating.html")
}

// if r.Method == http.MethodGet {
// 	// Если URL /login без параметров, редирект на главную
// 	http.Redirect(w, r, "/", http.StatusFound)
// 	return
// }

// // Если URL /login с параметром type
// type LoginRequest struct {
// 	Type string `json:"type"`
// }

// var req LoginRequest
// if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 	http.Error(w, "Bad Request", http.StatusBadRequest)
// 	return
// }

// // Генерация нового токена сессии и токена входа
// sessionToken := uuid.New().String()
// //entryToken := uuid.New().String()

// // Сохранение токена сессии в Redis
// err := rdb.Set(ctx, sessionToken, "Anonymous", 0).Err()
// if err != nil {
// 	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
// 	return
// }

// // Установка куки с токеном сессии
// http.SetCookie(w, &http.Cookie{
// 	Name:  "session_token",
// 	Value: sessionToken,
// 	Path:  "/",
// })

// // Здесь можно добавить логику для запроса к модулю авторизации

// // Редирект на главную страницу
