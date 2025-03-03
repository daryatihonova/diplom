import os
import re
from flask import Flask, render_template, request, redirect, url_for,  flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename




app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///goldenring.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)

app.config['MAIL_SERVER'] = 'smtp.mail.ru'  
app.config['MAIL_PORT'] = 465 
app.config['MAIL_USE_TLS'] = False  
app.config['MAIL_USE_SSL'] = True   
app.config['MAIL_USERNAME'] = 'forsitediplom@internet.ru'  
app.config['MAIL_PASSWORD'] = 'e6RrNbjtDrfBCYdtFsLF'  
app.config['MAIL_DEFAULT_SENDER'] = 'forsitediplom@internet.ru' 

mail = Mail(app)


def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email



class User(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(40), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)

    def get_id(self):
        return self.user_id

class City(db.Model):
    city_id = db.Column(db.Integer, primary_key=True)
    city_name = db.Column(db.String(20), nullable=False)
    photo = db.Column(db.LargeBinary, nullable=False)
    description = db.Column(db.Text, nullable=False)
    
class Attraction(db.Model):
    attraction_id = db.Column(db.Integer, primary_key=True)
    attraction_name = db.Column(db.String(50), nullable=False)
    photo = db.Column(db.LargeBinary, nullable=False)
    description = db.Column(db.Text, nullable=False)
    attraction_type = db.Column(db.String(80), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.city_id'), nullable=False)
    latitude = db.Column(db.Float, nullable=True)  # Широта
    longitude = db.Column(db.Float, nullable=True) # Долгота

class Favourite(db.Model):
    favourite_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    attraction_id = db.Column(db.Integer, db.ForeignKey('attraction.attraction_id'), nullable=False)

class Event(db.Model):
    event_id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(50), nullable=False)
    photo = db.Column(db.String(255), nullable=True)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=True)
    link = db.Column(db.String(40), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.city_id'), nullable=False)

class Feedback(db.Model):
    feedback_id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    attraction_id = db.Column(db.Integer, db.ForeignKey('attraction.attraction_id'), nullable=False)
    
@app.context_processor
def inject_cities():
    cities = City.query.all()
    return dict(cities=cities)


@app.route("/")
def index():
    city = City.query.all()
    return render_template('index.html', city = city)


@app.route("/city_detail/<int:city_id>")
def city_detail(city_id):
    city = City.query.get(city_id)
    city_slug = transliterate(city.city_name) 
    return render_template('city_detail.html', city=city, city_slug=city_slug)


@app.route("/attractions/<int:city_id>", methods=['GET'])
def attractions(city_id):
    category_filter = request.args.get('attraction_type')
    if category_filter:
        attractions = Attraction.query.filter_by(city_id=city_id, attraction_type=category_filter).all()
    else:
        attractions = Attraction.query.filter_by(city_id=city_id).all()
    city = City.query.get(city_id)  
    return render_template('attraction.html', attractions=attractions, city=city)


@app.route("/attraction_detail/<int:attraction_id>", methods=['POST', 'GET'])
def attraction_detail(attraction_id):
    attraction = Attraction.query.get(attraction_id)
    
    if request.method == 'POST':
        # Проверяем, что пользователь авторизован
        if not current_user.is_authenticated:
            flash('Вы должны быть авторизованы для добавления комментария.', 'warning')
            return redirect(f'/attraction_detail/{attraction_id}') 

        comment = request.form['comment']
        
        # Проверяем, что комментарий не пустой
        if comment:
            feedback = Feedback(comment=comment, user_id=current_user.user_id, attraction_id=attraction_id)

            try:
                db.session.add(feedback)
                db.session.commit()
                flash('Комментарий успешно добавлен!', 'success')
                return redirect(f'/attraction_detail/{attraction_id}')  
            except Exception as e:
                db.session.rollback()  
                flash('При добавлении комментария произошла ошибка: {}'.format(str(e)), 'danger')
        else:
            flash('Комментарий не может быть пустым!', 'warning')

    comments = db.session.query(Feedback, User.name).join(User).filter(Feedback.attraction_id == attraction_id).all()

    coordinates = {'latitude': attraction.latitude, 'longitude': attraction.longitude}
    
    return render_template('attraction_detail.html', attraction=attraction, comments=comments, coordinates=coordinates)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
         # Проверка на администратора
        if email == 'admin@mail.ru' and password == 'admin':
            admin_user = User.query.filter_by(email=email).first()
            if not admin_user:
                admin_user = User(name='Admin', email=email, password=bcrypt.generate_password_hash(password).decode('utf-8'))
                db.session.add(admin_user)
                db.session.commit()

            login_user(admin_user)
            return redirect(url_for('admin_page'))  

        # Проверка пользователя в бд
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('lk'))
        else:
            flash("Введены неверные данные. Попробуйте снова.")
    
    return render_template('login.html')


@app.route("/lk")
@login_required
def lk():
    favorites = Favourite.query.filter_by(user_id=current_user.user_id).all()
    favorite_attractions = []
    for favorite in favorites:
        attraction = Attraction.query.get(favorite.attraction_id)
        if attraction:
            favorite_attractions.append(attraction)
 
    user_comments = Feedback.query.filter_by(user_id=current_user.user_id).all()  # Получаем все комментарии пользователя


    comments_list = []
    for comment in user_comments:
        comments_list.append({
            'attraction_name': get_attraction_name(comment.attraction_id),  # Функция для получения названия достопримечательности
            'text': comment.comment,
           
        })

    return render_template('lk.html', name=current_user.name, favorites=favorite_attractions, user_comments=comments_list)

def get_attraction_name(attraction_id):
    attraction = Attraction.query.get(attraction_id)
    return attraction.attraction_name if attraction else "Неизвестно"


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        password2 = request.form['password2']

         # Проверка на существование пользователя с таким email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Пользователь с такой электронной почтой уже существует. Вам необходимо войти в свой аккаунт.', 'danger')
            return render_template('register.html')

        if len(name) > 0 and len(email) > 4 and len(password) > 4 and password == password2:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            msg = Message("Уведомление о регистрации", recipients=[email])
            msg.body = f"Здравствуйте, {name}!\n\nВы успешно зарегистрировались на нашем сайте "'Золотое кольцо России'"."
            mail.send(msg)

            message = 'Регистрация прошла успешно!'
            message_type = 'success'
            return render_template('register.html', message=message, message_type=message_type)

        else:
            message = 'Пожалуйста, проверьте введенные данные.'
            message_type = 'danger'
            return render_template('register.html', message=message, message_type=message_type)

    return render_template('register.html')



@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message("Сброс пароля", recipients=[user.email])
            msg.body = f"Для сброса пароля перейдите по ссылке: {reset_url}"
            mail.send(msg)
            flash('На ваш email отправлена инструкция по сбросу пароля.', 'info')
        else:
            flash('Пользователь с таким email не найден.', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = confirm_token(token)
    if not email:
        flash('Ссылка для сброса пароля недействительна или истекла.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('login'))

    if request.method == "POST":
        password = request.form['password']
        password2 = request.form['password2']
        if password == password2:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            flash('Ваш пароль успешно обновлен.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Пароли не совпадают.', 'danger')
    return render_template('reset_password.html', token=token)


@app.route("/afisha/<int:city_id>", methods=["POST", "GET"])
def afisha(city_id):
    city = City.query.get(city_id) 
    event = Event.query.filter_by(city_id=city_id).all()
    return render_template('afisha.html', event = event, city=city)


UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'img')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/new_event/<int:city_id>", methods=["POST", "GET"])
def new_event(city_id):
    if request.method == "POST":
        event_name = request.form['event_name']
        
        date_str = request.form['date']
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        link = request.form['link']

        photo = None
        if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)  
                    photo = filename 

        if len(event_name) > 0  and len(link) > 0:
            
            new_event = Event(event_name=event_name, photo=photo, date=date, link=link, city_id=city_id)
            db.session.add(new_event)
            db.session.commit()

            city = City.query.get(city_id)
            event = Event.query.all()
            return render_template('afisha.html', event=event, city=city)

        else:
            message = 'Пожалуйста, проверьте введенные данные.'
            message_type = 'danger'
            return render_template('new_event.html', message=message, message_type=message_type, city_id=city_id)
    return render_template('new_event.html', city_id=city_id)


@app.route('/add_to_favorites/<int:attraction_id>', methods=['POST'])
@login_required
def add_to_favorites(attraction_id):
    existing_favorite = Favourite.query.filter_by(user_id=current_user.user_id, attraction_id=attraction_id).first()
    if existing_favorite:
        flash("Эта достопримечательность уже добавлена в избранное.")
        return redirect(url_for('attraction_detail', attraction_id=attraction_id))

    new_favorite = Favourite(user_id=current_user.user_id, attraction_id=attraction_id)
    db.session.add(new_favorite)
    db.session.commit()

    flash("Вы добавили достопримечательность в избранное!")
    return redirect(url_for('attraction_detail', attraction_id=attraction_id))



@app.route("/admin_page")
@login_required
def admin_page():
    if current_user.email != 'admin@mail.ru':
        return abort(403)  # Запрет доступа, если не администратор
    return render_template('admin_page.html')  


 
@app.route("/delete_feedback/<int:feedback_id>", methods=['POST'])
@login_required  
def delete_feedback(feedback_id):
    if current_user.email != 'admin@mail.ru':
        flash('У вас нет прав для удаления комментариев.', 'danger')
        return redirect(request.referrer)  # Возвращаем на предыдущую страницу

    feedback = Feedback.query.get(feedback_id)
    
    if feedback:
        try:
            db.session.delete(feedback)
            db.session.commit()
            flash('Комментарий успешно удален!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('При удалении комментария произошла ошибка: {}'.format(str(e)), 'danger')
    else:
        flash('Комментарий не найден.', 'warning')

    return redirect(request.referrer)  # Возвращаем на предыдущую страницу



def transliterate(text):
    translit_dict = {
        'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'e', 
        'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm', 
        'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u', 
        'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch', 
        'ъ': '', 'ы': 'y', 'ь': '', 'э': 'e', 'ю': 'yu', 'я': 'ya'
    }
    
    # Заменяем буквы и удаляем недопустимые символы
    result = ''.join(translit_dict.get(char, char) for char in text.lower())
    result = re.sub(r'[^a-z0-9-]', '-', result)  # Заменяем недопустимые символы на '-'
    result = re.sub(r'-+', '-', result)  # Убираем дублирующиеся '-'
    return result.strip('-')  # Убираем '-' в начале и конце




if __name__ == '__main__':
    app.run(debug=True)