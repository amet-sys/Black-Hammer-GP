import asyncio
import logging
import sys

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from redis import Redis

from bot.handlers import user_handlers
from bot.callbacks import user_callbacks
from config import BOT_TOKEN, REDIS_HOST, REDIS_PORT

redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


async def main() -> None:
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher(redis_client=redis_client)

    # Подключение маршрутизаторов
    dp.include_routers(user_callbacks.router, user_handlers.router)

    # Удаление вебхука и запуск long polling
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    asyncio.run(main())
