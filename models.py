from database import db  # Импортируем объект базы данных

class User(db.Model):
    __tablename__ = 'user'  # Явное указание имени таблицы
    id = db.Column(db.Integer, primary_key=True)  # Идентификатор пользователя
    username = db.Column(db.String(150), unique=True, nullable=False)  # Имя пользователя
    email = db.Column(db.String(150), unique=True, nullable=False)  # Email пользователя
    password = db.Column(db.LargeBinary, nullable=False)  # Хэш пароля