package handlers

import (
	// "back/structs"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"

	//"github.com/google/uuid"
	"back/databases"
	"context"

	"github.com/dgrijalva/jwt-go"
)

const MySecretKey = ""

var rdb = databases.ConnectToRedis()
var ctx = context.Background()

func IndexHandler(w http.ResponseWriter, r *http.Request) {

	log.Print("Index")
	http.ServeFile(w, r, "./public/index.html")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем куки из запроса
	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// Кука не найдена
			sessionToken, err := GenerateToken()
			if err != nil {
				log.Print("Токен сессии провален")
			}
			loginToken, err := GenerateToken()
			if err != nil {
				log.Print("Токен входа провален")
			}

			// Сохранение в Redis
			err = rdb.Set(ctx, sessionToken, fmt.Sprintf("Анонимный:%s", loginToken), 0).Err()
			if err != nil {
				http.Error(w, "Ошибка сохранения в Redis", http.StatusInternalServerError)
				return
			}

			tmpl, err := template.ParseFiles("./public/login.html")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Передаем токен в шаблон
			err = tmpl.Execute(w, struct {
				LoginToken string
			}{
				LoginToken: loginToken,
			})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

			// Устанавливаем токен в куки
			http.SetCookie(w, &http.Cookie{
				Name:  "session_token",
				Value: sessionToken,
				Path:  "/",
			})

			http.Error(w, "Session token not found", http.StatusUnauthorized)
			return
		}
		// Обработка других ошибок
		http.Error(w, "Error retrieving cookie", http.StatusInternalServerError)
		return
	}

	// Если кука найдена, получаем значение токена
	sessionToken := cookie.Value
	log.Printf("Session Token: %s", sessionToken)
	log.Print("Login")
	http.ServeFile(w, r, "./public/login.html")
}

func Starter(w http.ResponseWriter, r *http.Request) {
	log.Print("Start")
	http.ServeFile(w, r, "./public/start.html")

}

func About(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusUnauthorized)
		return
	}
	// Раскодирование JWT
	tokenString := cookie.Value
	// Парсим токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Недопустимый метод подписи")
		}
		return []byte(MySecretKey), nil
	})
	if err != nil {
		log.Print(err)
		return
	}
	var name, email string
	// Проверяем, действителен ли токен
	if token.Valid {
		// Проверяем, что токен валиден
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Извлекаем электронную почту
			email = claims["email"].(string)
			name = claims["name"].(string)
		}
	}
	// Создаем и выполняем шаблон
	tmpl, err := template.ParseFiles("./public/personal_cabinet.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Передаем токен в шаблон
	err = tmpl.Execute(w, struct {
		Email string
		Name  string
	}{
		Email: email,
		Name:  name,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func TestCreator(w http.ResponseWriter, r *http.Request) {
	log.Print("Creator")
	http.ServeFile(w, r, "./public/creating.html")
}

func GenerateToken() (string, error) {
	// Создаем массив байтов для токена
	b := make([]byte, 32) // 32 байта = 256 бит
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	// Кодируем токен в base64
	return base64.StdEncoding.EncodeToString(b), nil
}
