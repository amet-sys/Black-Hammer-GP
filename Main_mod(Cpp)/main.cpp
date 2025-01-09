#include <iostream>
#include <string>
#include <vector>
#include <sqlite3.h>
#include "include/crow_all.h"
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
            .allow_algorithm(jwt::algorithm::hs256{""})
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
    // Получить информацию о пользователе (курсы, тесты, оценки) + О себе
    CROW_ROUTE(app, "/users/<int>/info").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int userId) {
        // Проверка авторизации
        if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
            return crow::response(401, "Unauthorized");
        }

        std::string token = req.get_header_value("Authorization").substr(7);
        if (!validateJWT(token)) {
            return crow::response(401, "Invalid JWT token");
        }

        // Получение информации о пользователе
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

        // Получить курсы пользователя
        query = "SELECT c.id, c.name, c.description FROM Courses c "
            "JOIN UsersCourses uc ON c.id = uc.course_id "
            "WHERE uc.user_id = " + std::to_string(userId);
        std::vector<std::vector<std::string>> coursesResult;
        if (!executeSQL(db, query, coursesResult)) {
            return crow::response(500, "Database error");
        }

        nlohmann::json courses;
        for (const auto& row : coursesResult) {
            courses.push_back({ {"id", row[0]}, {"name", row[1]}, {"description", row[2]} });
        }
        response["courses"] = courses;

        // Получить тесты пользователя
        query = "SELECT t.id, t.name, t.course_id, t.active FROM Tests t "
            "JOIN Attempts a ON t.id = a.test_id "
            "WHERE a.user_id = " + std::to_string(userId);
        std::vector<std::vector<std::string>> testsResult;
        if (!executeSQL(db, query, testsResult)) {
            return crow::response(500, "Database error");
        }

        nlohmann::json tests;
        for (const auto& row : testsResult) {
            tests.push_back({ {"id", row[0]}, {"name", row[1]}, {"course_id", row[2]}, {"active", row[3] == "1"} });
        }
        response["tests"] = tests;

        // Получить оценки пользователя
        query = "SELECT t.id, a.state FROM Attempts a "
            "JOIN Tests t ON a.test_id = t.id "
            "WHERE a.user_id = " + std::to_string(userId);
        std::vector<std::vector<std::string>> attemptsResult;
        if (!executeSQL(db, query, attemptsResult)) {
            return crow::response(500, "Database error");
        }

        nlohmann::json grades;
        for (const auto& row : attemptsResult) {
            grades.push_back({ {"test_id", row[0]}, {"state", row[1]} });
        }
        response["grades"] = grades;

        // Добавить раздел "О себе"
        query = "SELECT about_me FROM Users WHERE id = " + std::to_string(userId);
        std::vector<std::vector<std::string>> aboutResult;
        if (!executeSQL(db, query, aboutResult) || aboutResult.empty()) {
            response["about_me"] = "No information available";
        }
        else {
            response["about_me"] = aboutResult[0][0];
        }

        // Добавить раздел "О другом"
        query = "SELECT about_others FROM Users WHERE id = " + std::to_string(userId);
        if (!executeSQL(db, query, aboutResult) || aboutResult.empty()) {
            response["about_others"] = "No information available";
        }
        else {
            response["about_others"] = aboutResult[0][0];
        }

        return crow::response(200, response.dump());
        });

    // Получить информацию о ролях пользователя
    CROW_ROUTE(app, "/users/<int>/roles").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int userId) {
        // Проверка авторизации
        if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
            return crow::response(401, "Unauthorized");
        }

        std::string token = req.get_header_value("Authorization").substr(7);

        if (!validateJWT(token)) {
            return crow::response(401, "Invalid JWT token");
        }

        // Получение информации о текущем пользователе из JWT
        auto decoded = jwt::decode(token);
        std::string currentUserId = decoded.get_payload()["user_id"].to_string();

        // Проверка прав доступа пользователя (необходимо user:roles:read)
        if (decoded.get_payload().has_claim("permissions")) {
            auto permissions = decoded.get_payload()["permissions"].to_array();
            bool hasPermission = std::find(permissions.begin(), permissions.end(), "user:roles:read") != permissions.end();
            if (!hasPermission) {
                return crow::response(403, "Forbidden: Insufficient permissions");
            }
        }
        else {
            return crow::response(403, "Forbidden: No permissions found");
        }

        // Если запрашивается информация о собственных ролях
        if (std::to_string(userId) == currentUserId) {
            std::vector<std::vector<std::string>> result;
            std::string query = "SELECT roles FROM Users WHERE id = " + std::to_string(userId);

            if (!executeSQL(db, query, result) || result.empty()) {
                return crow::response(404, "User not found");
            }

            nlohmann::json response = {
                {"roles", result[0][0]} // Возвращаем роли
            };

            return crow::response(200, response.dump());
        }

        // Если запрашивается информация о чужих ролях
        std::vector<std::vector<std::string>> result;
        std::string query = "SELECT roles FROM Users WHERE id = " + std::to_string(userId);

        if (!executeSQL(db, query, result) || result.empty()) {
            return crow::response(404, "User not found");
        }

        nlohmann::json response = {
            {"roles", result[0][0]} // Возвращаем роли
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

// Изменить информацию о дисциплине (Название, Описание)
CROW_ROUTE(app, "/courses/<int>").methods(crow::HTTPMethod::PUT)([db](const crow::request& req, int courseId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    // Извлечение токена из заголовка
    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Расшифровка JWT для получения информации о пользователе
    auto decoded = jwt::decode(token);
    int user_id = std::stoi(decoded.get_payload().get_claim_value_by_name("user_id").as_string()); // Извлекаем user_id из токена

    // Проверяем, является ли пользователь преподавателем, которому принадлежит курс
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(courseId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Course not found");
    }

    int course_teacher_id = std::stoi(result[0][0]);
    if (course_teacher_id != user_id) {
        return crow::response(403, "Forbidden: You are not the teacher of this course");
    }

    // Обработка тела запроса для изменения данных
    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || (!body.contains("name") && !body.contains("description"))) {
        return crow::response(400, "Invalid JSON format: Missing required fields");
    }

    std::string query_update = "UPDATE Courses SET ";
    bool first = true;

    if (body.contains("name")) {
        query_update += "name = '" + body["name"].get<std::string>() + "'";
        first = false;
    }
    if (body.contains("description")) {
        if (!first) query_update += ", ";
        query_update += "description = '" + body["description"].get<std::string>() + "'";
    }

    query_update += " WHERE id = " + std::to_string(courseId);

    if (!executeSQL(db, query_update, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "Course information updated successfully");
    });
// Эндпоинт для получения списка тестов в дисциплине
CROW_ROUTE(app, "/courses/<int>/tests").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int courseId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    // Извлечение токена из заголовка
    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Декодируем JWT и извлекаем ID пользователя
    auto decoded = jwt::decode(token);
    int userId = std::stoi(decoded.get_payload_claim("id").as_string());

    // Проверим, является ли пользователь преподавателем дисциплины или он записан на курс
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(courseId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Course not found");
    }

    int teacherId = std::stoi(result[0][0]);

    // Если пользователь не является преподавателем курса, проверим, записан ли он на курс
    if (userId != teacherId) {
        query = "SELECT 1 FROM Course_Enrollments WHERE course_id = " + std::to_string(courseId) + " AND user_id = " + std::to_string(userId);

        if (!executeSQL(db, query, result) || result.empty()) {
            return crow::response(403, "Access forbidden: User is not enrolled in this course");
        }
    }

    // Теперь получим список тестов для курса
    query = "SELECT id, name FROM Tests WHERE course_id = " + std::to_string(courseId);

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    nlohmann::json response;
    for (const auto& row : result) {
        response.push_back({ {"id", row[0]}, {"name", row[1]} });
    }

    return crow::response(200, response.dump());
    });
// Информация о тесте (Активный тест или нет)
CROW_ROUTE(app, "/tests/<int>/active").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int testId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Получаем информацию о пользователе из JWT токена
    auto decoded = jwt::decode(token);
    int userId = std::stoi(decoded.get_payload_claim("user_id").as_string()); // Пример получения user_id из токена

    // Извлекаем параметр course_id из запроса
    int courseId = std::stoi(req.url_params.get("course_id"));

    // Проверим, является ли пользователь преподавателем дисциплины или записан на курс
    std::vector<std::vector<std::string>> result;

    // Проверка, является ли пользователь преподавателем дисциплины
    std::string query = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(courseId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Course not found");
    }

    bool isTeacher = std::stoi(result[0][0]) == userId;

    // Проверим, записан ли пользователь на курс
    query = "SELECT user_id FROM Enrollments WHERE course_id = " + std::to_string(courseId) + " AND user_id = " + std::to_string(userId);
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    bool isEnrolled = !result.empty();

    // Проверяем статус теста
    query = "SELECT active FROM Tests WHERE id = " + std::to_string(testId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Test not found");
    }

    bool isActive = result[0][0] == "1"; // "1" означает активный

    // Права доступа: доступен для преподавателей курса и для студентов, которые записаны
    if (isTeacher || isEnrolled) {
        nlohmann::json response = {
            {"active", isActive}
        };
        return crow::response(200, response.dump());
    }
    else {
        return crow::response(403, "Forbidden");
    }
    });
// Активировать/деактивировать тест
CROW_ROUTE(app, "/tests/<int>/activate").methods(crow::HTTPMethod::POST)([db](const crow::request& req, int testId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Проверим, является ли пользователь преподавателем курса
    // Для этого получим курс теста
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT course_id FROM Tests WHERE id = " + std::to_string(testId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Test not found");
    }

    int courseId = std::stoi(result[0][0]);

    // Получим текущего пользователя
    query = "SELECT id, roles FROM Users WHERE id = (SELECT id FROM Users WHERE roles LIKE '%teacher%')";
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "User not found");
    }

    int teacherId = std::stoi(result[0][0]);

    // Проверим, является ли пользователь преподавателем курса
    query = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(courseId);
    if (!executeSQL(db, query, result) || result.empty() || teacherId != std::stoi(result[0][0])) {
        return crow::response(403, "Forbidden: You are not the teacher of this course");
    }

    // Изменим активность теста
    query = "SELECT active FROM Tests WHERE id = " + std::to_string(testId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Test not found");
    }

    bool isActive = result[0][0] == "1";
    int newActiveState = isActive ? 0 : 1;  // Если тест активен, деактивируем, и наоборот

    query = "UPDATE Tests SET active = " + std::to_string(newActiveState) + " WHERE id = " + std::to_string(testId);
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    // Если тест деактивирован, помечаем все попытки как завершенные
    if (newActiveState == 0) {
        query = "UPDATE Attempts SET state = 'finished' WHERE test_id = " + std::to_string(testId) + " AND state = 'in_progress'";
        if (!executeSQL(db, query, result)) {
            return crow::response(500, "Failed to update attempts");
        }
    }

    return crow::response(200, "Test " + std::string(isActive ? "deactivated" : "activated") + " successfully");
    });
// Добавить тест в дисциплину
CROW_ROUTE(app, "/tests").methods(crow::HTTPMethod::POST)([db](const crow::request& req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    // Извлечение маркера JWT из заголовка
    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Извлечение маркера JWT из заголовка
    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("name") || !body.contains("course_id")) {
        return crow::response(400, "Invalid JSON format");
    }

    // Извлечение необходимой информации
    std::string name = body["name"].get<std::string>();
    int course_id = body["course_id"].get<int>();

    // Получение идентификатора пользователя из маркера JWT (при условии, что у вас есть способ извлечь его из маркера)
    // Примечание: эта часть зависит от вашей структуры JWT; Мы будем предполагать, что 'get_user_id_from_token()' определен в другом месте
    int user_id = get_user_id_from_token(token);  // Извлекаем user_id из токена

    // Проверьте, разрешено ли текущему пользователю создавать тест для курса
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(course_id);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Course not found");
    }

    int course_teacher_id = std::stoi(result[0][0]);

    // Проверьте, является ли пользователь преподавателем курса
    if (course_teacher_id != user_id) {
        return crow::response(403, "Forbidden: You are not the teacher of this course");
    }

    // Вставьте новый тест в базу данных со статусом "неактивен" по умолчанию (активный = 0)
    query = "INSERT INTO Tests (name, course_id, active) VALUES ('" + name + "', " + std::to_string(course_id) + ", 0);";

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    // Получение идентификатора вновь созданного теста (при условии автоматического инкрементирования)
    query = "SELECT last_insert_rowid();";
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Failed to retrieve the test ID");
    }

    int new_test_id = std::stoi(result[0][0]);

    // Возврат вновь созданного идентификатора теста
    nlohmann::json response = {
        {"test_id", new_test_id}
    };
    return crow::response(201, response.dump());
    });
// Удалить тест из дисциплины (отметить как удалённый)
CROW_ROUTE(app, "/tests/<int>/delete").methods(crow::HTTPMethod::POST)([db](const crow::request& req, int testId) {
    // Проверка авторизации с помощью JWT
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Получаем информацию о тесте
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT course_id FROM Tests WHERE id = " + std::to_string(testId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Test not found");
    }

    // Получаем course_id для проверки прав пользователя (например, преподаватель должен быть владельцем курса)
    int courseId = std::stoi(result[0][0]);

    // Проверка прав пользователя на удаление теста
    // Здесь предполагается, что роль пользователя передаётся в JWT (или вы можете сделать проверку по данным пользователя)
    // Для этого можно сделать отдельный запрос на получение роли пользователя или курс его преподавания.
    // Псевдокод для этой части:
    // if (user_role != "teacher" || user_course_id != courseId) {
    //     return crow::response(403, "Forbidden");
    // }

    // Обновление теста, помечая его как удалённый
    query = "UPDATE Tests SET active = 0 WHERE id = " + std::to_string(testId);

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "Test marked as deleted successfully");
    });

//  Информация о дисциплине (Список студентов)
CROW_ROUTE(app, "/courses/<int>/students").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int courseId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Декодирование JWT для получения информации о пользователе
    auto decoded = jwt::decode(token);
    int userId = std::stoi(decoded.get_payload_claim("sub").as_string());  // Получаем ID пользователя
    std::string userRole = decoded.get_payload_claim("role").as_string();  // Получаем роль пользователя

    // Проверяем, если пользователь не преподаватель или студент
    if (userRole != "teacher") {
        // Если роль пользователя не teacher, мы проверяем, является ли он студентом
        // и разрешаем доступ только к дисциплине, на которой он записан
        std::string studentCheckQuery = "SELECT * FROM Enrollments WHERE user_id = " + std::to_string(userId) + " AND course_id = " + std::to_string(courseId);
        std::vector<std::vector<std::string>> enrollmentResult;
        if (!executeSQL(db, studentCheckQuery, enrollmentResult) || enrollmentResult.empty()) {
            return crow::response(403, "Forbidden - You are not enrolled in this course");
        }
    }
    else {
        // Если преподаватель, проверяем, что он является преподавателем этого курса
        std::string teacherCheckQuery = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(courseId);
        std::vector<std::vector<std::string>> teacherResult;
        if (!executeSQL(db, teacherCheckQuery, teacherResult) || teacherResult.empty() || std::stoi(teacherResult[0][0]) != userId) {
            return crow::response(403, "Forbidden - You are not the teacher of this course");
        }
    }

    // Получаем список студентов, записанных на курс
    std::string query = "SELECT user_id FROM Enrollments WHERE course_id = " + std::to_string(courseId);
    std::vector<std::vector<std::string>> result;

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    nlohmann::json response;
    for (const auto& row : result) {
        response.push_back({ {"student_id", row[0]} });
    }

    return crow::response(200, response.dump());
    });

// Записать пользователя на дисциплину (Добавляет пользователя с указанным ID на дисциплину с указанным ID)
CROW_ROUTE(app, "/courses/<int>/enroll").methods(crow::HTTPMethod::POST)([db](const crow::request& req, int courseId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Извлекаем информацию о пользователе из токена
    auto decoded = jwt::decode(token);
    int userId = std::stoi(decoded.get_payload_claim("user_id").as_string()); // Assuming the JWT contains the user_id claim

    // Проверка, существует ли дисциплина (курс)
    std::vector<std::vector<std::string>> courseResult;
    std::string checkCourseQuery = "SELECT id FROM Courses WHERE id = " + std::to_string(courseId);
    if (!executeSQL(db, checkCourseQuery, courseResult) || courseResult.empty()) {
        return crow::response(404, "Course not found");
    }

    // Проверка, что пользователь не заблокирован
    std::vector<std::vector<std::string>> userResult;
    std::string checkUserQuery = "SELECT is_blocked FROM Users WHERE id = " + std::to_string(userId);
    if (!executeSQL(db, checkUserQuery, userResult) || userResult.empty()) {
        return crow::response(404, "User not found");
    }
    if (userResult[0][0] == "1") {
        return crow::response(403, "User is blocked");
    }

    // Запись пользователя на курс
    std::string enrollQuery = "INSERT INTO UserCourses (user_id, course_id) VALUES (" + std::to_string(userId) + ", " + std::to_string(courseId) + ");";
    std::vector<std::vector<std::string>> result;
    if (!executeSQL(db, enrollQuery, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(201, "User enrolled in course successfully");
    });
    // Таблица для привязки пользователей к курсам
    CREATE TABLE IF NOT EXISTS UserCourses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        course_id INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES Users(id),
        FOREIGN KEY(course_id) REFERENCES Courses(id)
    );

// Отчислить пользователя с дисциплины
CROW_ROUTE(app, "/courses/<int>/remove_user/<int>").methods(crow::HTTPMethod::DELETE)([db](const crow::request& req, int courseId, int userIdToRemove) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Получение идентификатора пользователя, выполняющего запрос из JWT (при условии, что он хранится в маркере как sub)
    auto decoded = jwt::decode(token);
    int userIdMakingRequest = std::stoi(decoded.get_payload_claim("sub").as_string());

    // Проверьте, разрешено ли запрашивающему удалить этого пользователя (либо самого пользователя, либо администратора/преподавателя)
    // Запрос для проверки роли и владельца
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT roles, teacher_id FROM Users WHERE id = " + std::to_string(userIdMakingRequest);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "User not found");
    }

    std::string roles = result[0][0];
    int teacherId = std::stoi(result[0][1]);

    // Если пользователь играет роль преподавателя или сам является пользователем, он может удалить себя из курса
    if (roles.find("teacher") == std::string::npos && userIdMakingRequest != userIdToRemove) {
        return crow::response(403, "Forbidden: You are not allowed to remove this user.");
    }

    // Создание таблицы Users
        CREATE TABLE Users(
            user_id INT PRIMARY KEY,
            user_name VARCHAR(100),
            email VARCHAR(100)
        );

    // Создание таблицы Courses
        CREATE TABLE Courses(
            course_id INT PRIMARY KEY,
            course_name VARCHAR(100),
            description TEXT
        );

    // Создание таблицы CourseUsers
        CREATE TABLE CourseUsers(
            course_id INT NOT NULL,
            user_id INT NOT NULL,
            PRIMARY KEY(course_id, user_id),
            FOREIGN KEY(course_id) REFERENCES Courses(course_id),
            FOREIGN KEY(user_id) REFERENCES Users(user_id)
        );

    // Удаление пользователя из курса (при условии, что существует таблица Course_User с отношением пользователь-курс)
    query = "DELETE FROM CourseUsers WHERE course_id = " + std::to_string(courseId) + " AND user_id = " + std::to_string(userIdToRemove);

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "User successfully removed from the course");
    });

// Создать дисциплину
CROW_ROUTE(app, "/courses").methods(crow::HTTPMethod::POST)([db](const crow::request &req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("name") || !body.contains("description") || !body.contains("teacher_id")) {
        return crow::response(400, "Invalid JSON format");
    }

    std::string name = body["name"].get<std::string>();
    std::string description = body["description"].get<std::string>();
    int teacher_id = body["teacher_id"].get<int>();

    std::string query = "INSERT INTO Courses (name, description, teacher_id) VALUES ('" + name + "', '" + description + "', " + std::to_string(teacher_id) + ");";
    std::vector<std::vector<std::string>> result;

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(201, "Course created successfully");
});
// Удалить дисциплину
CROW_ROUTE(app, "/courses/<int>/del").methods(crow::HTTPMethod::POST)([db](const crow::request& req, int courseId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    //  Получите роль пользователя (она будет извлечена из JWT или из другого источника)
    auto decoded = jwt::decode(token);
    std::string role = decoded.get_payload_claim("role").as_string();

    // Проверьте, является ли пользователь администратором или преподавателем курса
    std::vector<std::vector<std::string>> result;
    std::string courseQuery = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(courseId);

    if (!executeSQL(db, courseQuery, result) || result.empty()) {
        return crow::response(404, "Course not found");
    }

    int courseTeacherId = std::stoi(result[0][0]);

    // Проверьте, имеет ли пользователь право на удаление курса
    bool isAuthorized = (role == "admin" || (role == "teacher" && courseTeacherId == /* the user's ID */));
    if (!isAuthorized) {
        return crow::response(403, "Forbidden: You don't have permission to delete this course");
    }

    // Пометьте курс как удаленный (вместо того, чтобы удалять его)
    std::string updateQuery = "UPDATE Courses SET active = 0 WHERE id = " + std::to_string(courseId);

    if (!executeSQL(db, updateQuery, result)) {
        return crow::response(500, "Database error");
    }

    // Кроме того, обновление тестов и попыток, связанных с курсом, до статуса «неактивный»
    std::string updateTestsQuery = "UPDATE Tests SET active = 0 WHERE course_id = " + std::to_string(courseId);
    if (!executeSQL(db, updateTestsQuery, result)) {
        return crow::response(500, "Failed to update related tests");
    }

    std::string updateAttemptsQuery = "UPDATE Attempts SET state = 'inactive' WHERE test_id IN (SELECT id FROM Tests WHERE course_id = " + std::to_string(courseId) + ")";
    if (!executeSQL(db, updateAttemptsQuery, result)) {
        return crow::response(500, "Failed to update related attempts");
    }

    return crow::response(200, "Course successfully marked as deleted");
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
// Таблица Tests — для хранения информации о тестах
CREATE TABLE Tests(
    id INT PRIMARY KEY AUTO_INCREMENT, // уникальный идентификатор теста
    name VARCHAR(255) NOT NULL, // название теста
    description TEXT, // описание теста
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, // дата и время создания теста
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP // дата и время последнего обновления
);

// Таблица Questions — для хранения информации о вопросах
CREATE TABLE Questions(
    id INT PRIMARY KEY AUTO_INCREMENT, // уникальный идентификатор вопроса
    question_text TEXT NOT NULL, // текст вопроса
    question_type VARCHAR(50), // тип вопроса(например, одиночный выбор, множественный выбор и т.д.)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, // дата и время создания вопроса
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP // дата и время последнего обновления
    ALTER TABLE Questions ADD COLUMN author_id INTEGER; // SQL-запрос для добавления нового столбца author_id
    UPDATE Questions SET author_id = ? WHERE id = ? ; // обновлять эту таблицу с указанием автора при добавлении или изменении вопросов

    // Использование текущего пользователя как автора(если автор всегда известен по токену)
    std::string user_id = decoded.get_payload_claim("user_id").as_string(); // Извлекаем ID из токена
    std::string query = "INSERT INTO Questions (title, text, correct_answer, author_id) VALUES ('" + title + "', '" + text + "', " + std::to_string(correct_answer) + ", " + user_id + ");";

    CROW_ROUTE(app, "/questions").methods(crow::HTTPMethod::GET)([db](const crow::request& req) {
        if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
            return crow::response(401, "Unauthorized");
        }

        std::string token = req.get_header_value("Authorization").substr(7);
        if (!validateJWT(token)) {
            return crow::response(401, "Invalid JWT token");
        }

        std::vector<std::vector<std::string>> result;
        std::string query = "SELECT title, text, correct_answer FROM Questions";

        if (!executeSQL(db, query, result)) {
            return crow::response(500, "Database error");
        }

        nlohmann::json response;
        for (const auto& row : result) {
            response.push_back({ {"title", row[0]}, {"text", row[1]}, {"correct_answer", row[2]} });
        }

        return crow::response(200, response.dump());
        });

);

// Таблица, которая связывает тесты и вопросы
CREATE TABLE TestQuestions(
    id INT PRIMARY KEY AUTO_INCREMENT, // уникальный идентификатор связи
    test_id INT NOT NULL, // внешний ключ, указывающий на тест
    question_id INT NOT NULL, // внешний ключ, указывающий на вопрос
    FOREIGN KEY(test_id) REFERENCES Tests(id) ON DELETE CASCADE, // связь с таблицей Tests
    FOREIGN KEY(question_id) REFERENCES Questions(id) ON DELETE CASCADE // связь с таблицей Questions
    ALTER TABLE Questions ADD COLUMN position INTEGER; //  поле position, которое отвечает за порядок следования вопросов в тесте.
);



// Создать тест
CROW_ROUTE(app, "/tests").methods(crow::HTTPMethod::POST)([db](const crow::request &req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("name") || !body.contains("course_id")) {
        return crow::response(400, "Invalid JSON format");
    }

    std::string name = body["name"].get<std::string>();
    int course_id = body["course_id"].get<int>();

    std::string query = "INSERT INTO Tests (name, course_id, active) VALUES ('" + name + "', " + std::to_string(course_id) + ", 0);";
    std::vector<std::vector<std::string>> result;

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(201, "Test created successfully");
});

// Удалить вопрос из теста
CROW_ROUTE(app, "/tests/<int>/questions/<int>").methods(crow::HTTPMethod::DELETE)([db](const crow::request& req, int testId, int questionId) {
    // Проверка наличия токена авторизации
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Получение информации о пользователе (например, для проверки роли преподавателя)
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT user_id FROM Tests WHERE id = " + std::to_string(testId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Test not found");
    }

    int teacherId = std::stoi(result[0][0]);

    // Проверка, является ли пользователь преподавателем
    // Например, можем использовать запрос для получения текущего пользователя (получить из токена или из базы данных)
    std::string currentUserRole = "teacher"; // Это можно изменить в зависимости от вашего механизма аутентификации

    if (currentUserRole != "teacher") {
        return crow::response(403, "Forbidden: You are not a teacher");
    }

    // Проверка, были ли попытки прохождения теста
    query = "SELECT id FROM Attempts WHERE test_id = " + std::to_string(testId);
    if (!executeSQL(db, query, result) && !result.empty()) {
        return crow::response(400, "Test has already been attempted, question cannot be deleted");
    }

    // Удаление вопроса из теста
    query = "DELETE FROM TestQuestions WHERE test_id = " + std::to_string(testId) + " AND question_id = " + std::to_string(questionId);
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "Question deleted successfully from the test");
    });

// Добавить вопрос в тест
CROW_ROUTE(app, "/tests/<int>/questions/<int>").methods(crow::HTTPMethod::POST)([db](const crow::request& req, int testId, int questionId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Извлечение идентификатора пользователя из маркера JWT
    // Для простоты предположим, что идентификатор пользователя встроен в маркер (вы можете изменить его в зависимости от вашей реализации JWT)
    int userId = 123;  // Замена на фактическую логику для извлечения идентификатора пользователя из токена

    // Шаг 1: Проверьте, есть ли попытки проведения теста
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT COUNT(*) FROM Attempts WHERE test_id = " + std::to_string(testId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(500, "Database error");
    }

    if (result[0][0] != "0") {
        return crow::response(400, "Test already has attempts, cannot add question");
    }

    // Шаг 2: Проверьте, является ли пользователь преподавателем курса, связанного с этим тестом
    query = "SELECT course_id FROM Tests WHERE id = " + std::to_string(testId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Test not found");
    }

    int courseId = std::stoi(result[0][0]);

    query = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(courseId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Course not found");
    }

    int teacherId = std::stoi(result[0][0]);
    if (userId != teacherId) {
        return crow::response(403, "User is not a teacher for this course");
    }

    // Шаг 3: Проверьте, является ли пользователь автором вопроса
    query = "SELECT COUNT(*) FROM Questions WHERE id = " + std::to_string(questionId) + " AND author_id = " + std::to_string(userId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Question not found or user is not the author");
    }

    if (result[0][0] != "1") {
        return crow::response(403, "User is not the author of this question");
    }

    // Шаг 4: Добавьте вопрос в тест
    query = "INSERT INTO TestQuestions (test_id, question_id) VALUES (" + std::to_string(testId) + ", " + std::to_string(questionId) + ")";
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(201, "Question added to test successfully");
    });

// Эндпоинт для просмотра списка пользователей, прошедших тест
CROW_ROUTE(app, "/tests/<int>/users").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int testId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Проверьте, является ли пользователь преподавателем или имеет необходимые разрешения
    std::string query = "SELECT roles FROM Users WHERE id = (SELECT user_id FROM Attempts WHERE test_id = " + std::to_string(testId) + " LIMIT 1)";
    std::vector<std::vector<std::string>> result;
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    bool isTeacher = false;
    if (!result.empty() && result[0][0] == "teacher") {
        isTeacher = true;
    }

    // Получите всех пользователей, которые попытались пройти тест и прошли его
    query = "SELECT user_id FROM Attempts WHERE test_id = " + std::to_string(testId) + " AND state = 'passed'";
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    nlohmann::json response;
    for (const auto& row : result) {
        int userId = std::stoi(row[0]);

        // Если пользователь является преподавателем, мы можем показать все попытки
        if (isTeacher) {
            std::string userQuery = "SELECT id, full_name FROM Users WHERE id = " + std::to_string(userId);
            if (!executeSQL(db, userQuery, result)) {
                return crow::response(500, "Database error");
            }
            for (const auto& userRow : result) {
                response.push_back({ {"id", userRow[0]}, {"full_name", userRow[1]} });
            }
        }
        else {
            // Если вы не являетесь преподавателем, верните идентификатор пользователя
            response.push_back({ {"id", userId} });
        }
    }

    return crow::response(200, response.dump());
    });
// Посмотреть оценку пользователя
CROW_ROUTE(app, "/tests/<int>/score").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int testId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    // Получаем токен из заголовков
    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Декодируем токен для извлечения информации о пользователе
    auto decoded = jwt::decode(token);
    int userId = std::stoi(decoded.get_payload_claim("user_id").as_string());
    std::string role = decoded.get_payload_claim("role").as_string();

    // Проверяем роль пользователя
    if (role != "teacher" && role != "student") {
        return crow::response(403, "Forbidden");
    }

    // Проверяем, если пользователь студент, то показываем только его попытки
    std::string query;
    if (role == "teacher") {
        // Преподаватель видит все попытки для теста
        query = "SELECT a.user_id, a.state FROM Attempts a JOIN Tests t ON a.test_id = t.id WHERE a.test_id = " + std::to_string(testId);
    }
    else {
        // Студент видит только свои попытки
        query = "SELECT a.user_id, a.state FROM Attempts a WHERE a.test_id = " + std::to_string(testId) + " AND a.user_id = " + std::to_string(userId);
    }

    std::vector<std::vector<std::string>> result;
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    // Формируем ответ
    nlohmann::json response;
    for (const auto& row : result) {
        int user_id = std::stoi(row[0]);
        std::string state = row[1];

        // Рассчитываем оценку для каждой попытки
        int score = 0;
        std::string scoreQuery = "SELECT count(*) FROM Answers a JOIN Questions q ON a.question_id = q.id WHERE a.attempt_id = " + row[0] + " AND a.answer_index = q.correct_answer";
        std::vector<std::vector<std::string>> scoreResult;
        if (executeSQL(db, scoreQuery, scoreResult)) {
            score = std::stoi(scoreResult[0][0]);  // Количество правильных ответов
        }

        // Добавляем информацию в ответ
        response.push_back({ {"user_id", user_id}, {"score", score}, {"state", state} });
    }

    return crow::response(200, response.dump());
    });

// Посмотреть ответы пользователя на тест
CROW_ROUTE(app, "/test-answers/<int>").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int testId) {
    // Проверяем наличие JWT токена
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Извлекаем информацию о пользователе из токена
    auto decoded = jwt::decode(token);
    int userId = std::stoi(decoded.get_payload_claim("user_id").as_string());
    std::string userRoles = decoded.get_payload_claim("roles").as_string();

    // Проверяем, является ли пользователь преподавателем
    bool isTeacher = userRoles.find("teacher") != std::string::npos;

    // Если пользователь не преподаватель, проверяем, смотрит ли он свои собственные ответы
    if (!isTeacher && userId != std::stoi(decoded.get_payload_claim("user_id").as_string())) {
        return crow::response(403, "Forbidden");
    }

    // Извлекаем все попытки для указанного теста
    std::vector<std::vector<std::string>> attemptsResult;
    std::string attemptsQuery = "SELECT id, user_id FROM Attempts WHERE test_id = " + std::to_string(testId);
    if (!executeSQL(db, attemptsQuery, attemptsResult)) {
        return crow::response(500, "Database error while fetching attempts");
    }

    // Строим ответ с попытками и их ответами
    nlohmann::json response = nlohmann::json::array();
    for (const auto& attempt : attemptsResult) {
        int attemptId = std::stoi(attempt[0]);
        int currentUserId = std::stoi(attempt[1]);

        // Получаем ответы для этой попытки
        std::vector<std::vector<std::string>> answersResult;
        std::string answersQuery = "SELECT Questions.title, Answers.answer_index FROM Answers "
            "JOIN Questions ON Answers.question_id = Questions.id "
            "WHERE Answers.attempt_id = " + std::to_string(attemptId);
        if (!executeSQL(db, answersQuery, answersResult)) {
            return crow::response(500, "Database error while fetching answers");
        }

        // Формируем список вопросов с ответами
        nlohmann::json answersArray = nlohmann::json::array();
        for (const auto& answer : answersResult) {
            answersArray.push_back({
                {"question", answer[0]},
                {"answer", std::stoi(answer[1])}
                });
        }

        // Добавляем информацию о попытке и ее ответах в общий ответ
        response.push_back({
            {"user_id", currentUserId},
            {"answers", answersArray}
            });
    }

    // Возвращаем результаты
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

// Эндпоинт для получения списка вопросов с их версией, названием и ID автора
CROW_ROUTE(app, "/questions/list").methods(crow::HTTPMethod::GET)([db](const crow::request& req) {
    // Проверка наличия Authorization заголовка с Bearer токеном
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    std::vector<std::vector<std::string>> result;
    // Запрос для получения всех уникальных вопросов с их последней версией
    std::string query = R"(
        SELECT q.id, q.title, q.author_id, v.version
        FROM Questions q
        JOIN (SELECT question_id, MAX(version) AS version FROM Questions GROUP BY question_id) v
        ON q.id = v.question_id AND q.version = v.version
    )";

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    // Формируем ответ в формате JSON
    nlohmann::json response;
    for (const auto& row : result) {
        response.push_back({
            {"question_id", row[0]},
            {"title", row[1]},
            {"author_id", row[2]},
            {"version", row[3]}
            });
    }

    return crow::response(200, response.dump());
    });

// Изменить текст вопроса/ответов (создаётся новая версия)
CROW_ROUTE(app, "/questions/update/<int>").methods(crow::HTTPMethod::PUT)([db](const crow::request& req, int questionId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("title") || !body.contains("text") || !body.contains("correct_answer") || !body.contains("answers")) {
        return crow::response(400, "Invalid JSON format");
    }

    std::string title = body["title"].get<std::string>();
    std::string text = body["text"].get<std::string>();
    int correct_answer = body["correct_answer"].get<int>();
    auto answers = body["answers"].get<std::vector<std::string>>();

    // Вставка новой версии вопроса в таблицу
    std::string insertQuestionQuery = "INSERT INTO Questions (title, text, correct_answer) VALUES ('" + title + "', '" + text + "', " + std::to_string(correct_answer) + ");";
    std::vector<std::vector<std::string>> result;
    if (!executeSQL(db, insertQuestionQuery, result)) {
        return crow::response(500, "Database error while inserting question");
    }

    // Получаем ID нового вопроса
    int newQuestionId = std::stoi(result.back().at(0));

    // Вставка новых вариантов ответов для этого вопроса
    for (size_t i = 0; i < answers.size(); ++i) {
        std::string insertAnswerQuery = "INSERT INTO Answers (question_id, answer_index) VALUES (" + std::to_string(newQuestionId) + ", " + std::to_string(i) + ");";
        if (!executeSQL(db, insertAnswerQuery, result)) {
            return crow::response(500, "Database error while inserting answers");
        }
    }

    return crow::response(200, "Question version updated successfully");
    });

// Создать вопрос
CROW_ROUTE(app, "/questions").methods(crow::HTTPMethod::POST)([db](const crow::request &req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("title") || !body.contains("text") || !body.contains("correct_answer")) {
        return crow::response(400, "Invalid JSON format");
    }

    std::string title = body["title"].get<std::string>();
    std::string text = body["text"].get<std::string>();
    int correct_answer = body["correct_answer"].get<int>();

    std::string query = "INSERT INTO Questions (title, text, correct_answer) VALUES ('" + title + "', '" + text + "', " + std::to_string(correct_answer) + ");";
    std::vector<std::vector<std::string>> result;

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }
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
// Создать попытку
CROW_ROUTE(app, "/attempts").methods(crow::HTTPMethod::POST)([db](const crow::request &req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("test_id") || !body.contains("user_id")) {
        return crow::response(400, "Invalid JSON format");
    }

    int test_id = body["test_id"].get<int>();
    int user_id = body["user_id"].get<int>();

    std::string query = "INSERT INTO Attempts (test_id, user_id, state) VALUES (" + std::to_string(test_id) + ", " + std::to_string(user_id) + ", 'in_progress');";
    std::vector<std::vector<std::string>> result;

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(201, "Attempt created successfully");
});

// Изменить ответ пользователя в тесте
CROW_ROUTE(app, "/answers/<int>").methods(crow::HTTPMethod::PUT)([db](const crow::request& req, int answerId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("answer_index")) {
        return crow::response(400, "Invalid JSON format");
    }

    int answerIndex = body["answer_index"].get<int>();

    // Проверим, что ответ с данным ID существует
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT attempt_id, question_id FROM Answers WHERE id = " + std::to_string(answerId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Answer not found");
    }

    int attemptId = std::stoi(result[0][0]);

    // Проверим, что попытка существует и её состояние не завершено
    query = "SELECT state FROM Attempts WHERE id = " + std::to_string(attemptId);
    if (!executeSQL(db, query, result) || result.empty() || result[0][0] != "in_progress") {
        return crow::response(400, "Attempt is not in progress or does not exist");
    }

    // Проверим, что тест, к которому относится данная попытка, активен
    query = "SELECT t.active FROM Tests t JOIN Attempts a ON t.id = a.test_id WHERE a.id = " + std::to_string(attemptId);
    if (!executeSQL(db, query, result) || result.empty() || result[0][0] != "1") {
        return crow::response(400, "Test is not active");
    }

    // Обновим ответ пользователя
    query = "UPDATE Answers SET answer_index = " + std::to_string(answerIndex) + " WHERE id = " + std::to_string(answerId);
    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "Answer updated successfully");
    });

// Завершить попытку
CROW_ROUTE(app, "/attempts/<int>/complete").methods(crow::HTTPMethod::POST)([db](const crow::request& req, int attemptId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Проверим, кто выполняет запрос
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT user_id, test_id, state FROM Attempts WHERE id = " + std::to_string(attemptId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Attempt not found");
    }

    int userId = std::stoi(result[0][0]);
    int testId = std::stoi(result[0][1]);
    std::string attemptState = result[0][2];

    // Если тест не в состоянии 'in_progress' или пользователь не тот, кто выполняет попытку, вернуть ошибку
    if (attemptState != "in_progress") {
        return crow::response(400, "Attempt is already completed or not in progress");
    }

    // Проверим, активен ли тест
    query = "SELECT active FROM Tests WHERE id = " + std::to_string(testId);
    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Test not found");
    }

    bool testActive = result[0][0] == "1"; // Тест активен, если значение 'active' равно 1

    if (testActive) {
        // Завершаем только если тест активен
        query = "UPDATE Attempts SET state = 'completed' WHERE id = " + std::to_string(attemptId);
        if (!executeSQL(db, query, result)) {
            return crow::response(500, "Database error");
        }
        return crow::response(200, "Attempt marked as completed");
    }
    else {
        // Если тест не активен, завершаем все попытки этого теста
        query = "UPDATE Attempts SET state = 'completed' WHERE test_id = " + std::to_string(testId);
        if (!executeSQL(db, query, result)) {
            return crow::response(500, "Database error");
        }
        return crow::response(200, "All attempts for the test have been marked as completed because the test is inactive");
    }
    });

// Просмотр сведений о попытках
CROW_ROUTE(app, "/attempts/<int>/details").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int attemptId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Декодирование JWT для получения сведений о пользователе (например, user_id, ролях)
    auto decoded = jwt::decode(token);
    int userId = std::stoi(decoded.get_payload_claim("user_id").as_string());
    std::string roles = decoded.get_payload_claim("roles").as_string();

    // Запрос для проверки того, является ли пользователь учителем или учеником
    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT a.test_id, a.user_id, a.state, t.course_id "
        "FROM Attempts a "
        "JOIN Tests t ON a.test_id = t.id "
        "WHERE a.id = " + std::to_string(attemptId);

    if (!executeSQL(db, query, result) || result.empty()) {
        return crow::response(404, "Attempt not found");
    }

    int testId = std::stoi(result[0][0]);
    int attemptUserId = std::stoi(result[0][1]);
    std::string state = result[0][2];
    int courseId = std::stoi(result[0][3]);

    // Проверьте, является ли пользователь преподавателем курса или студентом, который предпринял попытку
    if (roles != "teacher" && userId != attemptUserId) {
        return crow::response(403, "Forbidden: You do not have access to this attempt");
    }

    // Если пользователь является преподавателем, убедитесь, что он преподает курс для теста
    if (roles == "teacher") {
        query = "SELECT teacher_id FROM Courses WHERE id = " + std::to_string(courseId);
        if (!executeSQL(db, query, result) || result.empty()) {
            return crow::response(500, "Database error");
        }

        int teacherId = std::stoi(result[0][0]);
        if (teacherId != userId) {
            return crow::response(403, "Forbidden: You are not the teacher for this course");
        }
    }

    // Получение ответов на попытку
    query = "SELECT q.title, a.answer_index "
        "FROM Answers a "
        "JOIN Questions q ON a.question_id = q.id "
        "WHERE a.attempt_id = " + std::to_string(attemptId);

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    // Создание ответа с ответами и состоянием
    nlohmann::json response;
    for (const auto& row : result) {
        response.push_back({
            {"question_title", row[0]},
            {"answer_index", row[1]}
            });
    }

    // Укажите состояние попытки
    response.push_back({ "state", state });

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
// Создать ответ
CROW_ROUTE(app, "/answers").methods(crow::HTTPMethod::POST)([db](const crow::request &req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("question_id") || !body.contains("attempt_id") || !body.contains("answer_index")) {
        return crow::response(400, "Invalid JSON format");
    }

    int question_id = body["question_id"].get<int>();
    int attempt_id = body["attempt_id"].get<int>();
    int answer_index = body["answer_index"].get<int>();

    std::string query = "INSERT INTO Answers (question_id, attempt_id, answer_index) VALUES (" + std::to_string(question_id) + ", " + std::to_string(attempt_id) + ", " + std::to_string(answer_index) + ");";
    std::vector<std::vector<std::string>> result;

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(201, "Answer created successfully");
});
// Просмотр ответа на вопрос
CROW_ROUTE(app, "/answers/view/<int>").methods(crow::HTTPMethod::GET)([db](const crow::request& req, int userId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Извлечение ролей из JWT токена для проверки
    auto decoded = jwt::decode(token);
    std::string roles = decoded.get_payload_claim("roles").as_string();

    // Проверяем, если пользователь преподаватель или сам смотрит свои ответы
    bool isTeacher = roles == "teacher";  // или другие условия для преподавателей
    int userIdFromJWT = std::stoi(decoded.get_payload_claim("user_id").as_string());
    if (userId != userIdFromJWT && !isTeacher) {
        return crow::response(403, "Forbidden");
    }

    std::vector<std::vector<std::string>> result;
    std::string query = "SELECT a.id, a.answer_index, q.id AS question_id, q.title, q.correct_answer "
        "FROM Answers a "
        "JOIN Questions q ON a.question_id = q.id "
        "WHERE a.attempt_id = (SELECT id FROM Attempts WHERE user_id = " + std::to_string(userId) + " LIMIT 1);";

    if (!executeSQL(db, query, result)) {
        return crow::response(500, "Database error");
    }

    if (result.empty()) {
        return crow::response(404, "No answers found");
    }

    nlohmann::json response;
    for (const auto& row : result) {
        response.push_back({
            {"answer_id", row[0]},
            {"answer_index", std::stoi(row[1])},
            {"question_id", row[2]},
            {"question_title", row[3]},
            {"correct_answer", row[4]}
            });
    }

    return crow::response(200, response.dump());
    });

// Изменить попытку
CROW_ROUTE(app, "/attempts/update").methods(crow::HTTPMethod::POST)([db](const crow::request& req) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("attempt_id") || !body.contains("answer_index")) {
        return crow::response(400, "Invalid JSON format");
    }

    int attempt_id = body["attempt_id"].get<int>();
    int new_answer_index = body["answer_index"].get<int>();

    // Проверяем, что попытка ещё не завершена
    std::vector<std::vector<std::string>> result;
    std::string checkAttemptStateQuery = "SELECT state FROM Attempts WHERE id = " + std::to_string(attempt_id);
    if (!executeSQL(db, checkAttemptStateQuery, result) || result.empty()) {
        return crow::response(404, "Attempt not found");
    }

    if (result[0][0] != "in_progress") {
        return crow::response(400, "Attempt is already completed or invalid state");
    }

    // Обновляем индекс варианта ответа для этой попытки
    std::string updateAnswerQuery = "UPDATE Answers SET answer_index = " + std::to_string(new_answer_index) +
        " WHERE attempt_id = " + std::to_string(attempt_id);
    if (!executeSQL(db, updateAnswerQuery, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "Answer index updated successfully");
    });
// Удалить попытку (если не завершена, то изменить индекс варианта ответа на -1)
CROW_ROUTE(app, "/attempts/delete/<int>").methods(crow::HTTPMethod::POST)([db](const crow::request& req, int attemptId) {
    if (!req.get_header_value("Authorization").starts_with("Bearer ")) {
        return crow::response(401, "Unauthorized");
    }

    std::string token = req.get_header_value("Authorization").substr(7);
    if (!validateJWT(token)) {
        return crow::response(401, "Invalid JWT token");
    }

    // Проверяем состояние попытки
    std::vector<std::vector<std::string>> result;
    std::string checkAttemptStateQuery = "SELECT state FROM Attempts WHERE id = " + std::to_string(attemptId);
    if (!executeSQL(db, checkAttemptStateQuery, result) || result.empty()) {
        return crow::response(404, "Attempt not found");
    }

    // Если попытка не завершена, обновляем индексы ответов на -1
    if (result[0][0] != "completed") {
        std::string updateAnswersQuery = "UPDATE Answers SET answer_index = -1 WHERE attempt_id = " + std::to_string(attemptId);
        if (!executeSQL(db, updateAnswersQuery, result)) {
            return crow::response(500, "Database error");
        }
    }

    // Удаляем попытку
    std::string deleteAttemptQuery = "DELETE FROM Attempts WHERE id = " + std::to_string(attemptId);
    if (!executeSQL(db, deleteAttemptQuery, result)) {
        return crow::response(500, "Database error");
    }

    return crow::response(200, "Attempt deleted successfully");
    });




   app.port(5503).multithreaded().run();
}
