from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()  # Инициализация объекта базы данных

def create_database(app):
    """
    Проверяет наличие файла базы данных и создает его, если он отсутствует.
    """
    if not os.path.exists('site.db'):  # Проверка, существует ли база данных
        with app.app_context():  # Необходимо создать контекст приложения
            db.create_all()  # Создание таблиц в базе данных
            print("Database created.")  # Контрольная точка
    else:
        print("Database already exists.")  # Контрольная точка