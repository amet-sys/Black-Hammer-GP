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

type Test struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Subject     string     `json:"subject"`
	Questions   []Question `json:"questions"`
}

type Question struct {
	QuestionText string   `json:"question"`
	Options      []string `json:"options"`
	Correct      string   `json:"correct"`
}

type TestVivod struct {
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Subject     string `json:"subject" bson:"subject"`
}

type QuestionVivod struct {
	QuestionText string   `json:"question" bson:"QuestionText"`
	Options      []string `json:"options" bson:"Options"`
	Correct      string   `json:"correct" bson:"Correct"`
}
