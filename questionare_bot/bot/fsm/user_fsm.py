from aiogram.fsm.state import StatesGroup, State


class TestStates(StatesGroup):
    IN_TEST = State()  # Состояние прохождения теста
