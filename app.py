from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from forms import RegistrationForm, LoginForm, EditProfileForm
from flask_wtf.csrf import CSRFProtect
import bcrypt
from database import db, create_database  # Импорт создаваемых функций для работы с БД

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Ghjcnjyf,jhcbvdjkjd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db.init_app(app)  # Инициализация базы данных с приложением
csrf = CSRFProtect(app)  # Инициализация защиты от CSRF

login_manager = LoginManager(app)  # Инициализация менеджера для управления сессией
login_manager.login_view = 'login'  # Перенаправление на страницу логина для анонимных пользователей


class User(db.Model, UserMixin):  # Определение модели пользователя
    __tablename__ = 'user'  # Явное указание имени таблицы
    id = db.Column(db.Integer, primary_key=True)  # Идентификатор пользователя
    username = db.Column(db.String(150), unique=True, nullable=False)  # Имя пользователя
    email = db.Column(db.String(150), unique=True, nullable=False)  # Email пользователя
    password = db.Column(db.LargeBinary, nullable=False)  # Хэш пароля

    __table_args__ = {'extend_existing': True}  # Позволяет переопределять параметры существующей таблицы


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Загрузка пользователя по идентификатору


@app.route('/')
def home():
    print("Home page accessed")  # Контрольная точка
    return render_template('home.html')  # Отображение главной страницы


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Создание формы регистрации
    if form.validate_on_submit():  # Проверка на успешное заполнение формы
        try:
            # Хэширование пароля пользователя с помощью bcrypt
            hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
            user = User(username=form.username.data, email=form.email.data,
                        password=hashed_password)  # Создание объекта User
            db.session.add(user)  # Добавление пользователя в сессию базы данных
            db.session.commit()  # Сохранение изменений в базе данных
            flash('Account created!', 'success')  # Успешное уведомление
            print("User account created")  # Контрольная точка
            return redirect(url_for('login'))  # Перенаправление на страницу входа
        except Exception as e:
            flash('An error occurred while creating the account. Please try again.', 'danger')  # Ошибка
            print(f"Error: {e}")  # Логирование ошибки для отладки
    return render_template('register.html', form=form)  # Отображение формы регистрации


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Создание формы входа
    if form.validate_on_submit():  # Проверка валидации формы
        user = User.query.filter_by(email=form.email.data).first()  # Поиск пользователя по email
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password):  # Проверка пароля
            login_user(user)  # Вход пользователя
            print("User logged in")  # Контрольная точка
            return redirect(url_for('edit_profile'))  # Перенаправление на страницу редактирования профиля
        flash('Login unsuccessful. Please check email and password', 'danger')  # Ошибка входа
    return render_template('login.html', form=form)  # Отображение формы входа


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)  # Создание формы редактирования профиля
    if form.validate_on_submit():  # Проверка валидации формы
        try:
            # Проверка уникальности email
            if User.query.filter((User.email == form.email.data) & (User.id != current_user.id)).first():
                flash('Email is already registered. Please choose a different one.', 'danger')
                return redirect(url_for('edit_profile'))

            # Проверка уникальности имени пользователя
            if User.query.filter((User.username == form.username.data) & (User.id != current_user.id)).first():
                flash('Username is already taken. Please choose a different one.', 'danger')
                return redirect(url_for('edit_profile'))

            current_user.username = form.username.data  # Обновление имени пользователя
            current_user.email = form.email.data  # Обновление email
            if form.password.data:  # Если пользователь ввел новый пароль
                current_user.password = bcrypt.hashpw(form.password.data.encode('utf-8'),
                                                      bcrypt.gensalt())  # Хэширование нового пароля
            db.session.commit()  # Сохранение изменений в базе данных
            flash('Your account has been updated!', 'success')  # Успешное уведомление
            print("User account updated")  # Контрольная точка
            return redirect(url_for('edit_profile'))  # Перенаправление на страницу редактирования
        except Exception as e:
            flash('An error occurred while updating the profile. Please try again.',
                  'danger')  # Ошибка при обновлении профиля
            print(f"Error: {e}")  # Логирование ошибки для отладки
    return render_template('edit.html', form=form)  # Отображение формы редактирования


@app.route('/logout')
@login_required
def logout():
    logout_user()  # Выход пользователя
    print("User logged out")  # Отладочная точка
    return redirect(url_for('home'))  # Перенаправление на главную страницу


if __name__ == '__main__':
    create_database(app)  # Вызов функции для подготовки базы данных
    app.run(debug=True)  # Запуск приложения в режиме отладки