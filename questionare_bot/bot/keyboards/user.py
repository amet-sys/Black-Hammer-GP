from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder

from utils.types import ButtonInfo

main_kb = InlineKeyboardMarkup(
    inline_keyboard=[
        [
            InlineKeyboardButton(
                text="Дисциплины", callback_data="disciplines_callback")
        ]
    ]
)

login_kb = InlineKeyboardMarkup(
    inline_keyboard=[
        [
            InlineKeyboardButton(
                text="Github", callback_data="authorize_github_callback")
        ],
        [
            InlineKeyboardButton(
                text="Yandex", callback_data="authorize_yandex_callback")
        ]
    ]
)



def builder_kb(button_data: list[ButtonInfo], abjust: int = 3) -> InlineKeyboardMarkup:
    keyboard = InlineKeyboardBuilder()

    for button in button_data:
        key = InlineKeyboardButton(
            text=button["text"], callback_data=button['callback'])
        keyboard.add(key)
    keyboard.adjust(abjust)
    return keyboard.as_markup()
