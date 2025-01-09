package structs

import "go.mongodb.org/mongo-driver/bson/primitive"

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

type Questionvivod struct {
	QuestionText string   `json:"questiontext" bson:"questiontext"`
	Options      []string `json:"options" bson:"options"`
	Correct      string   `json:"correct" bson:"correct"`
}

type TestVivod struct {
	ID          primitive.ObjectID `json:"_id" bson:"_id"`
	Cnt         int                `json:"cnt"`
	Title       string             `json:"title" bson:"title"`
	Description string             `json:"description" bson:"description"`
	Subject     string             `json:"subject" bson:"subject"`
	Questions   []Question         `json:"questions" bson:"questions"`
}

func (t *TestVivod) GetID() string {
	return t.ID.Hex() // Возвращает строку без ObjectID()
}
