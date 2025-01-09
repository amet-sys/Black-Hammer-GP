import json
from aiogram import Router, Bot, types, F
from aiogram.fsm.context import FSMContext
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder
import aiohttp
from utils.types import ButtonInfo
from utils.tokens_generator import generate_jwt
from bot.keyboards.user import builder_kb
from config import AUTHORIZATION_URL, API_URL

router = Router()

# Функция для безопасной отправки сообщений


async def safe_send_message(bot: Bot, chat_id: int, text: str, reply_markup=None):
    try:
        await bot.send_message(chat_id=chat_id, text=text, reply_markup=reply_markup)
    except Exception as e:
        print(f"Не удалось отправить сообщение пользователю {chat_id}: {e}")


async def fetch_disciplines():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_URL}/disciplines") as response:
                if response.status == 200:
                    return await response.json()
                return []
    except Exception as e:
        print(f"Ошибка при запросе дисциплин: {e}")
        return []


async def fetch_tests_by_discipline(discipline_name):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_URL}/disciplines/{discipline_name}/tests") as response:
                if response.status == 200:
                    return await response.json()
                return []
    except Exception as e:
        print(f"Ошибка при запросе тестов дисциплины {discipline_name}: {e}")
        return []


async def fetch_test(test_name):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_URL}/tests/{test_name}") as response:
                if response.status == 200:
                    return await response.json()
                return {}
    except Exception as e:
        print(f"Ошибка при запросе теста {test_name}: {e}")
        return {}

# Callback для списка дисциплин


@router.callback_query(F.data == "disciplines_callback")
async def disciplines_callbacks_start(callback: types.CallbackQuery, bot: Bot) -> None:
    disciplines = await fetch_disciplines()
    if disciplines:
        await safe_send_message(
            bot=bot,
            chat_id=callback.from_user.id,
            text="Дисциплины:",
            reply_markup=builder_kb([ButtonInfo(
                text=discipline, callback=f"{discipline}_discipline_callback")
                for discipline in disciplines
            ])
        )
    else:
        await safe_send_message(bot, callback.from_user.id, "Не удалось загрузить дисциплины.")
    await callback.answer()

# Callback для тестов по дисциплине


@router.callback_query(F.data.contains("discipline"))
async def discipline_callbacks_start(callback: types.CallbackQuery, bot: Bot) -> None:
    try:
        parts = callback.data.split("_")
        if len(parts) < 2:
            raise ValueError("Некорректные данные callback")

        discipline_name = parts[0]
        tests = await fetch_tests_by_discipline(discipline_name)

        if tests:
            await safe_send_message(
                bot=bot,
                chat_id=callback.from_user.id,
                text="Тесты:",
                reply_markup=builder_kb([ButtonInfo(
                    text=test['title'], callback=f"{test['title']}_test_callback")
                    for test in tests
                ])
            )
        else:
            await safe_send_message(bot, callback.from_user.id, "Не удалось загрузить тесты.")
    except Exception as e:
        print(f"Ошибка обработки callback дисциплины: {e}")
        await safe_send_message(bot, callback.from_user.id, "Произошла ошибка.")
    finally:
        await callback.answer()

# Callback для вопросов теста


@router.callback_query(F.data.contains("test"))
async def test_callbacks_start(callback: types.CallbackQuery, bot: Bot, state: FSMContext) -> None:
    try:
        test_name = callback.data.split("_")[0]
        test = await fetch_test(test_name)

        if test:
            questions = test.get("questions", [])
            if questions:
                await state.set_data({"test_name": test_name, "questions": questions, "current_index": 0})
                await send_question(callback.from_user.id, bot, state)
            else:
                await safe_send_message(bot, callback.from_user.id, "Не удалось загрузить вопросы.")
        else:
            await safe_send_message(bot, callback.from_user.id, "Не удалось загрузить тест.")
    except Exception as e:
        print(f"Ошибка обработки callback теста: {e}")
        await safe_send_message(bot, callback.from_user.id, "Произошла ошибка.")
    finally:
        await callback.answer()

# Функция для отправки текущего вопроса


async def check_answer(question, selected_answer):
    correct_answer = question.get("correct", "")
    return selected_answer == correct_answer

# Callback for processing answers


@router.callback_query(F.data.contains("answer"))
async def answer_callbacks_start(callback: types.CallbackQuery, bot: Bot, state: FSMContext) -> None:
    data = await state.get_data()
    current_index = data.get("current_index", 0)
    questions = data.get("questions", [])
    # Get the number of correct answers so far
    correct_answers = data.get("correct_answers", 0)

    # Extract the selected answer index
    answer_index = int(callback.data.split("_")[1])
    selected_answer = questions[current_index]["options"][answer_index]

    # Check if the answer is correct
    if await check_answer(questions[current_index], selected_answer):
        correct_answers += 1

    # Update the correct_answers in the state
    await state.update_data(correct_answers=correct_answers)

    # Move to the next question
    await state.update_data(current_index=current_index + 1)
    await send_question(callback.from_user.id, bot, state)

    # Respond to the callback
    await callback.answer()

# Function to send the final results


async def send_results(user_id: int, bot: Bot, state: FSMContext) -> None:
    data = await state.get_data()
    correct_answers = data.get("correct_answers", 0)
    total_questions = len(data.get("questions", []))

    # Send the result message
    await safe_send_message(
        bot=bot,
        chat_id=user_id,
        text=f"Тест завершён! Вы ответили правильно на {correct_answers} из {total_questions} вопросов."
    )
    await state.clear()

# Updated send_question function with check for test completion


async def send_question(user_id: int, bot: Bot, state: FSMContext) -> None:
    data = await state.get_data()
    questions = data.get("questions", [])
    current_index = data.get("current_index", 0)

    if not questions or current_index >= len(questions):
        # Send the results when the test is complete
        await send_results(user_id, bot, state)
        return

    question = questions[current_index]
    question_text = question.get("questiontext", "Нет вопроса")
    answers = question.get("options", [])

    await safe_send_message(
        bot=bot,
        chat_id=user_id,
        text=f"Вопрос: {question_text}",
        reply_markup=builder_kb([ButtonInfo(
            text=answer, callback=f"answer_{i}") for i, answer in enumerate(answers)]
        )
    )


@router.callback_query(F.data.contains("authorize"))
async def login_callback(callback: types.CallbackQuery, bot: Bot, redis_client):
    try:
        chat_id = callback.from_user.id
        login_type = callback.data.split("_")[-2].strip()

        login_token = generate_jwt({"chat_id": chat_id})
        redis_client.set(chat_id, json.dumps(
            {"status": "Anonymous", "login_token": login_token}), ex=300)

        url = f"{AUTHORIZATION_URL}/login?type={login_type}&state={login_token}"
        auth_kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text="Авторизация", url=url)]
            ]
        )
        await safe_send_message(bot, chat_id, "Авторизуйтесь и введите /start", reply_markup=auth_kb)
        redis_client.set(chat_id, json.dumps(
            {"status": "Authorized", "login_token": login_token}))
    except Exception as e:
        print(f"Ошибка авторизации: {e}")
        await safe_send_message(bot, callback.from_user.id, "Произошла ошибка при авторизации.")
