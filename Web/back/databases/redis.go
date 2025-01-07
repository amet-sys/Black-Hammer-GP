package databases

import (
	"back/structs"
	"context"

	"github.com/go-redis/redis/v8"
)

func ConnectToRedis() *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Адрес сервера Redis
		Password: "",               // Пароль не установлен
		DB:       0,                // использовать базу данных по умолчанию
	})
	//проверка подключения к Redis
	if _, err := rdb.Ping(context.Background()).Result(); err != nil {
		return nil
	}
	return rdb
}

// Получение статуса пользователя из Redis
func GetUserStatus(sessionToken string, rdb *redis.Client) (structs.UserSession, error) {
	val, err := rdb.HGetAll(context.Background(), sessionToken).Result()
	if err != nil {
		return structs.UserSession{}, err
	}

	if len(val) == 0 {
		return structs.UserSession{}, nil
	}

	return structs.UserSession{
		Status:     val["status"],
		LoginToken: val["login_token"],
	}, nil
}
