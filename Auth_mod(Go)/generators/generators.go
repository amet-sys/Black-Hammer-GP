package gens

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"math/rand"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	structs "main.go/structs"

	"github.com/dgrijalva/jwt-go"
)

var MySecretKey string = ""

// Ссылка для обмена кода на токен доступа в Гитхаб и Яндекс
const GitHubTokenURL = "https://github.com/login/oauth/access_token"
const clientSecretGitHub = "5ba53d9ee5f32ba008e6e9a416e3f69bf50d0f46"
const YandexTokenURL = "https://oauth.yandex.com/token"

// Меняем код на токен доступа Гитхаба
func CodeExchancherGitHub(code string, client_id string) (string, error) {
	data := map[string]string{
		"client_id":     client_id,
		"client_secret": clientSecretGitHub,
		"code":          code,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return "", err
	}

	// Отправляем POST-запрос
	resp, err := http.Post(GitHubTokenURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error making request:", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Print(err)
		return "Error1", err
	}
	log.Printf("Response body: %s", body) // Выводим тело ответа для отладки
	responseString := string(body)
	values, err := url.ParseQuery(responseString)
	if err != nil {
		// обработка ошибки
	}

	// Получаем access_token
	AccessToken := values.Get("access_token")
	log.Print(AccessToken)
	return AccessToken, nil
}

// Меняем код на токен доступа Яндекса
func CodeExchancherYandex(code string, client_id string) (string, error) {
	data := []byte(fmt.Sprintf(`{"grant_type": "authorization_code", "client_id": "%s", "code": "%s"}`, client_id, code))
	req, err := http.NewRequest("POST", YandexTokenURL, bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to exchange code: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tokenResponse structs.TokenResponseYandex
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

// Получаем почту с помощью токена в Гитхабе
func GetEmailGithub(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Изменяем способ обработки ответа
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var user *structs.GitHubUser
	err = json.Unmarshal([]byte(body), &user)
	if err != nil {
		fmt.Println("Ошибка при парсинге JSON:", err)
		return "", err
	}
	return user.Email, nil
}

// Получаем почту с помощью токена в Яндексе
func GetEmailYandex(token string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.yandex.com/userinfo", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "OAuth "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var userInfo structs.YandexUser
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", err
	}

	return userInfo.Email, nil
}

// Генерация JWT токена
func GenerateTokens(user structs.User) (string, string) {
	// Генерация JWT токена доступа
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"access": user.Access,
		"exp":    time.Now().Add(1 * time.Minute).Unix(),
	})

	// Генерация JWT токена обновления
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(7 * 24 * time.Hour).Unix(),
	})

	// Подпись токенов
	accessTokenString, _ := accessToken.SignedString([]byte(MySecretKey))
	refreshTokenString, _ := refreshToken.SignedString([]byte(MySecretKey))

	return accessTokenString, refreshTokenString
}

// Генератор случайного 5-значного кода для авторизации через код
func GenerateAuthCode() string {
	return fmt.Sprintf("%05d", rand.Intn(100000))
}

func GetEmailFromRefreshToken(tokenString string) (string, string) {
	// Парсим токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Недопустимый метод подписи")
		}
		return MySecretKey, nil
	})

	if err != nil {
		return "", "1"
	}

	// Проверяем, действителен ли токен
	if token.Valid {
		// Проверяем, что токен валиден
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Извлекаем электронную почту
			email := claims["email"].(string)
			return email, ""
		}
	}
	return "", "Токен не действителен"
}

func DatabaseUserWriter(email string, UserCollection *mongo.Collection) (structs.User, string) {
	var user structs.User
	var err error
	var Role string

	err = UserCollection.FindOne(context.TODO(), bson.M{"email": email}).Decode(&user)

	if err != nil {
		// Если пользователь не найден, создаем нового
		log.Print("начало создания")
		cnt, _ := UserCollection.CountDocuments(context.TODO(), struct{}{})
		if cnt <= 4 {
			Role = "Admin"
		} else {
			Role = "Student"
		}
		user = structs.User{
			Name:   "Anonyim" + strconv.Itoa(int(cnt)+1),
			Email:  email,
			Roles:  []string{Role},
			Tokens: []string{},
		}
		for _, i := range user.Roles {
			switch i {
			case "Admin":
				user.Access = structs.AdminAccess
			case "Teacher":
				user.Access = structs.TeacherAccess
			default:
				user.Access = structs.StudentAccess
			}
		}
		_, err = UserCollection.InsertOne(context.TODO(), user)
		if err != nil {
			log.Print("Не удалось добавить пользователя", err)
			return user, "Не удалось добавить пользователя"
		}
	}
	return user, ""
}
