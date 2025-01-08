package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	structs "main.go/structs"

	database "main.go/Mongo-db"
	generators "main.go/generators"
)

var mongoConn = database.ConnectToMongo()
var dbConn = mongoConn.Database("authDB")
var UserCollection = dbConn.Collection("users")

const clientIDGitHub = "Ov23liVkA4a0IpHIuOzp"             //Заменить на своё значение, после регистрацции приложения на соответсвующей платформе
const clientIDYandex = "6785f7558d124ef8ad9f626c091f5e18" //Заменить на своё значение, после регистрацции приложения на соответсвующей платформе
const redirectURI = "http://localhost:5501/callback"      //Для продуктивной версии Вашего приложения Redirect URI должен указывать на адрес Вашего сервера, например, https://yourdomain.com/callback.

var stateStore = make(map[string]*structs.AuthState)
var CodeStateStore = make(map[string]*structs.CodeAuthState)
var types = []string{}
var tokens = []string{}

func HandleAuth(w http.ResponseWriter, r *http.Request) {

	authType := r.URL.Query().Get("type")
	token := r.URL.Query().Get("state")
	types = append(types, authType)
	tokens = append(tokens, token)

	var authURL string
	if authType == "github" {
		authURL = fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=%s&redirect_uri=%s", clientIDGitHub, token, redirectURI)
	} else if authType == "yandex" {
		authURL = fmt.Sprintf("https://oauth.yandex.com/authorize?client_id=%s&state=%s&redirect_uri=%s", clientIDYandex, token, redirectURI)
	} else if authType == "code" {
		code := CodeAuth(token)
		stateStore[token] = &structs.AuthState{
			ExpiresAt: time.Now().Add(5 * time.Minute),
			Status:    "Не получен",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"code": code}) //Отправляем код пользователю
		return
	} else {
		http.Error(w, "Введённого варианта авторизации не существует", http.StatusBadRequest)
		return
	}

	stateStore[token] = &structs.AuthState{
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Status:    "Не получен",
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	token := tokens[0]
	Type := types[0]
	types = []string{}
	tokens = []string{}
	if Type == "code" {
		code := r.URL.Query().Get("code")
		codeAuthState, exists := CodeStateStore[code]
		if !exists || time.Now().After(codeAuthState.ExpiresAt) {
			http.Error(w, "Кода не существует или его срок действия истёк", http.StatusUnauthorized)
			return
		}
		refreshToken := r.Header.Get("Authorization")
		email, err := generators.GetEmailFromRefreshToken(refreshToken)
		if err != "" {
			http.Error(w, err, http.StatusUnauthorized)
			return
		}
		// Поиск и запись пользователя в MongoDB
		var user structs.User
		var erro string
		var name string
		user, erro = generators.DatabaseUserWriter(email, name, UserCollection)
		if erro != "" {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		// Генерация JWT токенов
		accessToken, refreshToken := generators.GenerateTokens(user)
		user.Tokens = append(user.Tokens, refreshToken)
		// Обновление состояния
		authState := stateStore[token]
		authState.AccessToken = accessToken
		authState.RefreshToken = refreshToken
		authState.Status = "Доступ предоставлен"
		// Устанавливаем токены в куки
		http.SetCookie(w, &http.Cookie{
			Name:  "access_token",
			Value: accessToken,
			Path:  "/",
		})

		http.SetCookie(w, &http.Cookie{
			Name:  "refresh_token",
			Value: refreshToken,
			Path:  "/",
		})

		// Устанавливаем заголовок Content-Type
		w.Header().Set("Content-Type", "text/html")
		// Отправляем ответ
		http.Redirect(w, r, "http://localhost:5502/personal_cabinet", http.StatusFound)

	} else {
		if authState, exists := stateStore[token]; exists {
			if err := r.URL.Query().Get("error"); err != "" {
				authState.Status = "В доступе отказано"
				http.Error(w, "Authorization failed", http.StatusUnauthorized)
				return
			}
			log.Print("Начало процесса")
			// Обмен кода на токен доступа
			code := r.URL.Query().Get("code") //Получение кода
			var name, token, email string
			var err error
			if code == "" {
				log.Print("Don't have the code")
				return
			} else {
				switch Type {
				case "github":
					token, err = generators.CodeExchancherGitHub(code, clientIDGitHub)
				case "yandex":
					token, err = generators.CodeExchancherYandex(code, clientIDYandex)
				default:
					log.Print("Undefind")
				}
			}
			if err != nil {
				log.Print("Haven't token", token)
				return
			}
			// Получение данных о пользователе(только мыло)
			switch Type {
			case "github":
				email, name, err = generators.GetEmailGithub(token)
				log.Print(email)
				if err != nil {
					log.Print("Undefind")
				}

			case "yandex":
				email, name, err = generators.GetEmailYandex(token)
				if err != nil {
					log.Print("Undefind")
				}

			default:
				log.Print("Undefind")
			}

			// Поиск и запись пользователя в MongoDB
			var user structs.User
			var erro string
			log.Print(name)
			user, erro = generators.DatabaseUserWriter(email, name, UserCollection)
			if erro != "" {
				http.Error(w, "Failed to create user", http.StatusInternalServerError)
				return
			}

			// Генерация JWT токенов
			accessToken, refreshToken := generators.GenerateTokens(user)
			log.Print(user)
			user.Tokens = append(user.Tokens, refreshToken)
			// Обновление состояния\
			authState.AccessToken = accessToken
			authState.RefreshToken = refreshToken
			authState.Status = "Доступ предоставлен"

			// Устанавливаем токены в куки
			http.SetCookie(w, &http.Cookie{
				Name:  "access_token",
				Value: accessToken,
				Path:  "/",
			})

			http.SetCookie(w, &http.Cookie{
				Name:  "refresh_token",
				Value: refreshToken,
				Path:  "/",
			})

			// Устанавливаем заголовок Content-Type
			w.Header().Set("Content-Type", "text/html")
			//Отправляем ответ
			http.Redirect(w, r, "http://localhost:5502/personal_cabinet", http.StatusFound)
		} else {
			http.Error(w, "Invalid state", http.StatusBadRequest)
		}
	}
}

func CodeAuth(token string) string {
	code := generators.GenerateAuthCode()
	CodeStateStore[code] = &structs.CodeAuthState{
		ExpiresAt: time.Now().Add(1 * time.Minute),
		Status:    token,
	}
	return code
}
