from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from models import User  # Импортируем модель пользователя

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя (логин)', validators=[DataRequired(), Length(min=1, max=150)])  # Поле имени пользователя
    email = StringField('Email', validators=[DataRequired(), Email()])  # Поле email
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=8)])  # Поле пароля
    submit = SubmitField('Сохранить')  # Кнопка отправки формы

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()  # Проверяем существующего пользователя
        if user:
            raise ValidationError('Это имя пользователя занято. Пожалуйста, выберите другое.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()  # Проверяем существующего пользователя
        if user:
            raise ValidationError('Этот адрес электронной почты уже зарегистрирован. Пожалуйста, выберите другой.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])  # Поле email для входа
    password = PasswordField('Пароль', validators=[DataRequired()])  # Поле пароля для входа
    submit = SubmitField('Login')  # Кнопка отправки формы

class EditProfileForm(FlaskForm):
    username = StringField('Пользователь', validators=[DataRequired(), Length(min=1, max=150)])  # Поле имени пользователя
    email = StringField('Email', validators=[DataRequired(), Email()])  # Поле email
    password = PasswordField('Новый пароль (оставьте пустым, чтобы сохранить текущий)', validators=[Length(min=8)])  # Поле нового пароля
    submit = SubmitField('Update')  # Кнопка отправки формы