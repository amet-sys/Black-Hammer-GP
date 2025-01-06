package structs

import (
	"fmt"
	"time"
)

var AdminAccess = []string{
	"user:list:read",
	"user:fullName:write",
	"user:data:read",
	"user:roles:read",
	"user:roles:write",
	"user:block:read",
	"user:block:write",
	"course:info:write",
	"course:testList",
	"course:test:read",
	"course:test:write",
	"course:test:add",
	"course:test:del",
	"course:userList",
	"course:user:add",
	"course:user:del",
	"course:add",
	"course:del",
	"quest:list:read",
	"quest:read",
	"quest:update",
	"quest:create",
	"quest:del",
	"test:quest:del",
	"test:quest:add",
	"test:quest:update",
	"test:answer:read",
	"answer:read",
	"answer:update",
	"answer:del",
}

var StudentAccess = []string{}

var TeacherAccess = []string{
	"user:list:read",
	"user:fullName:write",
	"user:data:read",
	"course:userList",
	"course:user:add",
	"course:user:del",
	"quest:create",
}

type TokenResponseGitHub struct {
	AccessToken string `json:" access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type TokenResponseYandex struct {
	AccessToken string `json:"access_token"`
	Expiry      int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type AuthState struct {
	ExpiresAt    time.Time `json:"expires_at"`
	Status       string    `json:"status"`
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
}

type User struct {
	Name   string   `bson:"name"`
	Email  string   `bson:"email"`
	Roles  []string `bson:"roles"`
	Access []string `bson:"access"`
	Tokens []string `bson:"tokens"`
}

type GitHubUser struct {
	Email string `json:"email"`
}

type YandexUser struct {
	Email string `json:"default_email"`
}

type CodeAuthState struct {
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Формируем HTML-страницу с сообщением об успешной авторизации
var AppLink = "http://127.0.0.1:5502/Full_project/Black-Hammer-GP/Web/index.html" // Ссылка на приложение
var HtmlResponse = fmt.Sprintf(`
	<!DOCTYPE html>
		<html lang="ru">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Успешная авторизация</title>
		</head>
		<body>
			<h1>Авторизация успешна!</h1>
			<p>Вы можете вернуться в приложение, нажав на ссылку ниже:</p>
			<a href="%s">Перейти в приложение</a>
		</body>
	</html>
`, AppLink)
