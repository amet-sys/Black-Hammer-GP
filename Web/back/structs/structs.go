package structs

type UserSession struct {
	Status     string `json:"status"`
	LoginToken string `json:"login_token"`
}
