import inquirer3.themes as themes
from inquirer3.render.console import ConsoleRender


def prompt(questions, render=None, answers=None, theme=themes.Default(), raise_keyboard_interrupt=False):
    render = render or ConsoleRender(theme=theme, raise_keyboard_interrupt=raise_keyboard_interrupt)
    answers = answers or {}

    for question in questions:
        answers[question.name] = render.render(question, answers)
    return answers
