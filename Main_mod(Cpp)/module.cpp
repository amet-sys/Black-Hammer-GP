#include <iostream>
#include <string>
#include <vector>
#include <sqlite3.h>
#include "crow_all.h"
#include "jwt-cpp/jwt.h"
#include <nlohmann/json.hpp>

// Функция для выполнения SQL-запросов
bool executeSQL(sqlite3 *db, const std::string &query, std::vector<std::vector<std::string>> &result) {
    char *errMsg = nullptr;
    result.clear();

    auto callback = [](void *data, int argc, char **argv, char **colName) -> int {
        auto *res = static_cast<std::vector<std::vector<std::string>> *>(data);
        std::vector<std::string> row;
        for (int i = 0; i < argc; i++) {
            row.push_back(argv[i] ? argv[i] : "NULL");
        }
        res->push_back(row);
        return 0;
    };

    if (sqlite3_exec(db, query.c_str(), callback, &result, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

// Проверка JWT-токена
bool validateJWT(const std::string &token) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{"secret_key"})
            .with_issuer("auth_service");

        verifier.verify(decoded);
        return true;
    } catch (const std::exception &e) {
        std::cerr << "JWT validation failed: " << e.what() << std::endl;
        return false;
    }
}

// Инициализация базы данных
sqlite3* initializeDatabase() {
    sqlite3 *db;
    if (sqlite3_open("test_system.db", &db)) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return nullptr;
    }

    std::string createUsersTable = R"(
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            roles TEXT NOT NULL,
            is_blocked INTEGER DEFAULT 0
        );
    )";

    std::string createCoursesTable = R"(
        CREATE TABLE IF NOT EXISTS Courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            teacher_id INTEGER NOT NULL
        );
    )";

    std::string createTestsTable = R"(
        CREATE TABLE IF NOT EXISTS Tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            active INTEGER NOT NULL
        );
    )";

    std::string createQuestionsTable = R"(
        CREATE TABLE IF NOT EXISTS Questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            text TEXT NOT NULL,
            correct_answer INTEGER NOT NULL
        );
    )";

    std::string createAttemptsTable = R"(
        CREATE TABLE IF NOT EXISTS Attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            state TEXT NOT NULL,
            FOREIGN KEY(test_id) REFERENCES Tests(id)
        );
    )";

    std::string createAnswersTable = R"(
        CREATE TABLE IF NOT EXISTS Answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question_id INTEGER NOT NULL,
            attempt_id INTEGER NOT NULL,
            answer_index INTEGER DEFAULT -1,
            FOREIGN KEY(question_id) REFERENCES Questions(id),
            FOREIGN KEY(attempt_id) REFERENCES Attempts(id)
        );
    )";

    std::vector<std::vector<std::string>> result;
    if (!executeSQL(db, createUsersTable, result) ||
        !executeSQL(db, createCoursesTable, result) ||
        !executeSQL(db, createTestsTable, result) ||
        !executeSQL(db, createQuestionsTable, result) ||
        !executeSQL(db, createAttemptsTable, result) ||
        !executeSQL(db, createAnswersTable, result)) {
        std::cerr << "Failed to initialize database." << std::endl;
        sqlite3_close(db);
        return nullptr;
    }

    return db;
}

// Главный модуль с реализацией endpoint'ов
int main() {
    sqlite3 *db = initializeDatabase();
    if (!db) {
        return 1;
    }

    crow::SimpleApp app;
// Получить список пользователей
    CROW_ROUTE(app, "/users").methods(crow::HTTPMethod::GET)([db](const crow::request &req) {
        if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
            return crow::response(401, "Unauthorized");
        }

        std::string token = req.get_header_value("Authorization").substr(7);
        if (!validateJWT(token)) {
            return crow::response(401, "Invalid JWT token");
        }

        std::vector<std::vector<std::string>> result;
        std::string query = "SELECT id, full_name FROM Users";

        if (!executeSQL(db, query, result)) {
            return crow::response(500, "Database error");
        }

        nlohmann::json response;
        for (const auto &row : result) {
            response.push_back({{"id", row[0]}, {"full_name", row[1]}});
        }

        return crow::response(200, response.dump());
    });

    // Добавить нового пользователя
    CROW_ROUTE(app, "/users").methods(crow::HTTPMethod::POST)([db](const crow::request &req) {
        if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
            return crow::response(401, "Unauthorized");
        }

        std::string token = req.get_header_value("Authorization").substr(7);
        if (!validateJWT(token)) {
            return crow::response(401, "Invalid JWT token");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("full_name") || !body.contains("roles")) {
            return crow::response(400, "Invalid JSON format");
        }

        std::string fullName = body["full_name"].get<std::string>();
        std::string roles = body["roles"].get<std::string>();

        std::string query = "INSERT INTO Users (full_name, roles) VALUES ('" +
                            fullName + "', '" + roles + "');";

        std::vector<std::vector<std::string>> result;
        if (!executeSQL(db, query, result)) {
            return crow::response(500, "Database error");
        }

        return crow::response(201, "User added successfully");
    });

    // Получить информацию о пользователе
    CROW_ROUTE(app, "/users/<int>").methods(crow::HTTPMethod::GET)([db](const crow::request &req, int userId) {
        if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
            return crow::response(401, "Unauthorized");
        }

        std::string token = req.get_header_value("Authorization").substr(7);
        if (!validateJWT(token)) {
            return crow::response(401, "Invalid JWT token");
        }

        std::vector<std::vector<std::string>> result;
        std::string query = "SELECT full_name, roles, is_blocked FROM Users WHERE id = " + std::to_string(userId);

        if (!executeSQL(db, query, result) || result.empty()) {
            return crow::response(404, "User not found");
        }

        nlohmann::json response = {
            {"full_name", result[0][0]},
            {"roles", result[0][1]},
            {"is_blocked", result[0][2] == "1"}
        };

        return crow::response(200, response.dump());
    });
// Изменить информацию о пользователе
CROW_ROUTE(app, "/users/<int>").methods(crow::HTTPMethod::PUT)([db](const crow::request &req, int userId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || (!body.contains("full_name") && !body.contains("roles") && !body.contains("is_blocked"))) {
        return crow::response(400, "Invalid JSON format");
    }

    std::string query = "UPDATE Users SET ";
    bool first = true;

    if (body.contains("full_name")) {
        query += "full_name = '" + body["full_name"].get<std::string>() + "'";
        first = false;
    }
    if (body.contains("roles")) {
        if (!first) query += ", ";
        query += "roles = '" + body["roles"].get<std::string>() + "'";
        first = false;
    }
    if (body.contains("is_blocked")) {
        if (!first) query += ", ";
        query += "is_blocked = " + std::to_string(body["is_blocked"].get<bool>());
    }

    query += " WHERE id = " + std::to_string(userId);

    std::vector<std::vector<std::string>> result;
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "User updated successfully");
});

// Удалить пользователя
CROW_ROUTE(app, "/users/<int>").methods(crow::HTTPMethod::DELETE)([db](const crow::request &req, int userId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::string query = "DELETE FROM Users WHERE id = " + std::to_string(userId);

    std::vector<std::vector<std::string>> result;
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "User deleted successfully");
});
// Дисциплины
CROW_ROUTE(app, "/courses").methods(crow::HTTPMethod::GET)([db](const crow::request &req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT id, name, description FROM Courses";

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    nlohmann::json response;
    for (const auto &row : result) {
        response.push_back({{"id", row[0]}, {"name", row[1]}, {"description", row[2]}});
    }

    return crow::response(200, response.dump());
});

CROW_ROUTE(app, "/courses/<int>").methods(crow::HTTPMethod::GET)([db](const crow::request &req, int courseId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT name, description, teacher_id FROM Courses WHERE id = " + std::to_string(courseId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Course not found");
    }

    nlohmann::json response = {
        {"name", result[0][0]},
        {"description", result[0][1]},
        {"teacher_id", result[0][2]}
    };

    return crow::response(200, response.dump());
});

// Тесты
CROW_ROUTE(app, "/tests/<int>").methods(crow::HTTPMethod::GET)([db](const crow::request &req, int testId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT name, course_id, active FROM Tests WHERE id = " + std::to_string(testId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Test not found");
    }

    nlohmann::json response = {
        {"name", result[0][0]},
        {"course_id", result[0][1]},
        {"active", result[0][2] == "1"}
    };

    return crow::response(200, response.dump());
});

// Вопросы
CROW_ROUTE(app, "/questions/<int>").methods(crow::HTTPMethod::GET)([db](const crow::request &req, int questionId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT title, text, correct_answer FROM Questions WHERE id = " + std::to_string(questionId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Question not found");
    }

    nlohmann::json response = {
        {"title", result[0][0]},
        {"text", result[0][1]},
        {"correct_answer", std::stoi(result[0][2])}
    };

    return crow::response(200, response.dump());
});

// Попытки
CROW_ROUTE(app, "/attempts").methods(crow::HTTPMethod::GET)([db](const crow::request &req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT id, test_id, user_id, state FROM Attempts";

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    nlohmann::json response;
    for (const auto &row : result) {
        response.push_back({{"id", row[0]}, {"test_id", row[1]}, {"user_id", row[2]}, {"state", row[3]}});
    }

    return crow::response(200, response.dump());
});

CROW_ROUTE(app, "/attempts/<int>").methods(crow::HTTPMethod::GET)([db](const crow::request &req, int attemptId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT test_id, user_id, state FROM Attempts WHERE id = " + std::to_string(attemptId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Attempt not found");
    }

    nlohmann::json response = {
        {"test_id", result[0][0]},
        {"user_id", result[0][1]},
        {"state", result[0][2]}
    };

    return crow::response(200, response.dump());
});

// Ответы
CROW_ROUTE(app, "/answers").methods(crow::HTTPMethod::GET)([db](const crow::request &req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT id, question_id, attempt_id, answer_index FROM Answers";

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    nlohmann::json response;
    for (const auto &row : result) {
        response.push_back({{"id", row[0]}, {"question_id", row[1]}, {"attempt_id", row[2]}, {"answer_index", row[3]}});
    }

    return crow::response(200, response.dump());
});

CROW_ROUTE(app, "/answers/<int>").methods(crow::HTTPMethod::GET)([db](const crow::request &req, int answerId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT question_id, attempt_id, answer_index FROM Answers WHERE id = " + std::to_string(answerId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Answer not found");
    }

    nlohmann::json response = {
        {"question_id", result[0][0]},
        {"attempt_id", result[0][1]},
        {"answer_index", std::stoi(result[0][2])}
    };

    return crow::response(200, response.dump());
});
