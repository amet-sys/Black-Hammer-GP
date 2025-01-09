from flask import Flask, jsonify
from pymongo import MongoClient

app = Flask(__name__)

# Подключение к MongoDB
# Укажите свои параметры подключения
client = MongoClient("mongodb://localhost:27017/")
db = client["Tests"]

# Коллекция
tests_collection = db["Tests"]

# Эндпоинт для получения списка дисциплин


@app.route('/bot_logic/disciplines', methods=['GET'])
def get_disciplines():
    # Извлекаем уникальные значения поля `subject`
    disciplines = tests_collection.distinct("subject")
    return jsonify(disciplines)

# Эндпоинт для получения списка тестов по названию дисциплины


@app.route('/bot_logic/disciplines/<subject>/tests', methods=['GET'])
def get_tests_by_discipline(subject):
    filtered_tests = list(tests_collection.find(
        {"subject": subject}, {"_id": 0, "title": 1, "description": 1}))
    return jsonify(filtered_tests)

# Эндпоинт для получения теста с вопросами и вариантами ответов


@app.route('/bot_logic/tests/<string:test_title>', methods=['GET'])
def get_test(test_title):
    # Находим тест по названию
    test = tests_collection.find_one({"title": test_title}, {"_id": 0})
    if not test:
        return jsonify({"error": "Test not found"}), 404

    return jsonify({
        "title": test["title"],
        "description": test.get("description", ""),
        "subject": test["subject"],
        "questions": test["questions"]
    })


if __name__ == '__main__':
    app.run(debug=True)
