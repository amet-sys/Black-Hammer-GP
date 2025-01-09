
import json

from aiogram import Router, F
from aiogram.types import Message
from aiogram.fsm.context import FSMContext
from aiogram.filters import Command


from bot.keyboards.user import main_kb, login_kb


router = Router()


@router.message(Command('start'))
async def start_handler(message: Message, redis_client):
    chat_id = message.chat.id
    print(chat_id)
    user_data = redis_client.get(chat_id)
    print(user_data)
    if user_data:
        user_data = eval(user_data)
        if user_data.get('status') == 'Authorized':
            await message.reply("Вы зарегистрированы.", reply_markup=main_kb)
        else:
            await message.reply("Войдите.", reply_markup=login_kb)
    else:
        redis_client.set(chat_id, json.dumps({"status": "Unknown"}))
        await message.reply("Авторизуйтесь.", reply_markup=login_kb)


@router.message(Command('logout'))
async def start_handler(message: Message, redis_client):
    chat_id = message.chat.id
    user_data = redis_client.get(chat_id)
    if user_data:
        user_data = eval(user_data)
        if user_data.get('status') == 'Authorized':
            redis_client.set(chat_id, json.dumps({"status": "Unknown"}))
            await message.reply("Вы успешно вышли!")
        else:
            redis_client.set(chat_id, json.dumps({"status": "Unknown"}))
            await message.reply("Вы успешно вышли!")
    else:
        redis_client.set(chat_id, json.dumps({"status": "Unknown"}))
        await message.reply("Вы не авторизованы!")


@router.message()
async def handle_unknown_message(message: Message):
    await message.answer("Нет такой команды.")
