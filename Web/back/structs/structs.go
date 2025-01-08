package structs

type UserSession struct {
	Status     string `json:"status"`
	LoginToken string `json:"login_token"`
}

type LoginRequest struct {
	Type string `json:"type"`
}

type PageVariables struct {
	Token string
}
