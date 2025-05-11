import os
import re
import requests
from flask import Flask, jsonify, render_template, request, redirect, url_for,  flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import date, datetime, timedelta
from werkzeug.utils import secure_filename
import math 
from sqlalchemy import func  
import sqlite3
from flask import g
from ipaddress import ip_address


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///goldenring2.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)

app.config['MAIL_SERVER'] = 'smtp.mail.ru'  
app.config['MAIL_PORT'] = 465 
app.config['MAIL_USE_TLS'] = False  
app.config['MAIL_USE_SSL'] = True   
 

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
    event_type = db.Column(db.String(50), nullable=True)  #тип мероприятия

class UserPreferences(db.Model):
    preference_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    preference_type = db.Column(db.String(50), nullable=True)     

class Feedback(db.Model):
    feedback_id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    attraction_id = db.Column(db.Integer, db.ForeignKey('attraction.attraction_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
@app.context_processor
def inject_cities():
    cities = City.query.all()
    has_preferences = False
    if current_user.is_authenticated:
        has_preferences = UserPreferences.query.filter_by(user_id=current_user.user_id).count() > 0
    city_id = request.view_args.get('city_id', None)
    return dict(cities=cities, has_preferences=has_preferences, city_id=city_id)


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
    city = City.query.get(city_id)
    if not city:
        abort(404)
    category_filter = request.args.get('attraction_type')
    show_nearby = request.args.get('show_nearby') == 'true'
    attractions_query = Attraction.query.filter_by(city_id=city_id)   
    if category_filter and category_filter != "Все":
        attractions_query = attractions_query.filter_by(attraction_type=category_filter)
    show_distance = False
    location_info = None  

    attractions = attractions_query.all()

    if show_nearby:

        user_ip = request.remote_addr
        
        if user_ip in ['127.0.0.1', '::1']:
            user_ip = "94.158.118.147" 
            print(f"Локальный доступ, используем тестовый IP: {user_ip}")
        
        location_info = get_location_from_ip(user_ip)

        if location_info and isinstance(location_info, dict) and 'coordinates' in location_info:
            try:
                user_lat, user_lon = location_info['coordinates']
                print(f"Определено местоположение: {location_info.get('city', 'Неизвестно')}")
                attractions_with_coords = [
                    attr for attr in attractions 
                    if attr.latitude is not None and attr.longitude is not None
                ]
                for attr in attractions_with_coords:
                    attr.distance = calculate_distance(
                        user_lat, user_lon,
                        attr.latitude, attr.longitude
                    )
                attractions_with_coords.sort(key=lambda x: x.distance)
                attractions = attractions_with_coords[:5]
                show_distance = True
                
            except (ValueError, TypeError) as e:
                print(f"Ошибка обработки координат: {e}")
                flash("Ошибка определения местоположения. Показаны все достопримечательности.", "warning")
        else:
            error_msg = location_info if isinstance(location_info, str) else "Неизвестная ошибка"
            print(f"Ошибка определения местоположения: {error_msg}")
            flash(f"Не удалось определить ваше местоположение. {error_msg}", "warning")
    return render_template('attraction.html',
                         attractions=attractions,
                         city=city,
                         show_distance=show_distance,
                         location_info=location_info if show_nearby else None)

@app.route("/attraction_detail/<int:attraction_id>", methods=['POST', 'GET'])
def attraction_detail(attraction_id):
    attraction = Attraction.query.get(attraction_id)
    
    if request.method == 'POST':
        # Проверяем, что пользователь авторизован
        if not current_user.is_authenticated:
            flash('Вы должны быть авторизованы для добавления комментария.', 'warning')
            return redirect(f'/attraction_detail/{attraction_id}') 

        comment = request.form['comment']
        
        if comment:
            feedback = Feedback(comment=comment, user_id=current_user.user_id, attraction_id=attraction_id)

            try:
                db.session.add(feedback)
                db.session.commit()
                 # Отправка письма администратору
                user = User.query.get(current_user.user_id)
                city = City.query.get(attraction.city_id)
                msg = Message("Новый комментарий на сайте", recipients=['forsitediplom@internet.ru'])
                msg.body = f"Пользователь {user.name} ({user.email}) оставил комментарий для достопримечательности {attraction.attraction_name} в городе {city.city_name}.\n\nКомментарий: {comment}"
                mail.send(msg)
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
        if email == 'forsitediplom@internet.ru' and password == 'admin':
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
            flash("Введены неверные данные. Попробуйте снова.", 'danger')
    
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
            'attraction_name': get_attraction_name(comment.attraction_id),  # Функция для получения названия достопр.
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

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Пользователь с такой электронной почтой уже существует. Вам необходимо войти в свой аккаунт.', 'warning')
            return render_template('register.html')

        if len(name) > 0 and len(email) > 4 and len(password) > 4 and password == password2:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            msg = Message("Уведомление о регистрации", recipients=[email])
            msg.body = f"Здравствуйте, {name}!\n\nВы успешно зарегистрировались на нашем сайте "'Золотое кольцо России'"."
            mail.send(msg)

            flash('Регистрация прошла успешно!', 'success')
            return render_template('register.html')
        else:
            flash('Пожалуйста, проверьте введенные данные.', 'danger')
            return render_template('register.html')

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
            flash('На ваш email отправлена инструкция по сбросу пароля.', 'success')
        else:
            flash('Пользователь с таким email не найден.', 'warning')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = confirm_token(token)
    if not email:
        flash('Ссылка для сброса пароля недействительна или истекла.', 'warning')
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
    today = date.today()
    has_preferences = False
    if current_user.is_authenticated:
        has_preferences = UserPreferences.query.filter_by(user_id=current_user.user_id).count() > 0
        if has_preferences and request.args.get('filter') != 'all':
            preferences = [pref.preference_type for pref in 
                         UserPreferences.query.filter_by(user_id=current_user.user_id).all()]
            all_events = Event.query.filter(
                Event.city_id == city_id,
                Event.event_type.in_(preferences)
            ).all()
        else:
            all_events = Event.query.filter_by(city_id=city_id).all()
    else:
        all_events = Event.query.filter_by(city_id=city_id).all()
    
    upcoming_events = [event for event in all_events if event.date >= today]
    past_events = [event for event in all_events if event.date < today]

    upcoming_events.sort(key=lambda event: event.date)
    past_events.sort(key=lambda event: event.date, reverse=True)

    event = upcoming_events + past_events

    return render_template('afisha.html', 
                         event=event, 
                         city=city, 
                         today=today,
                         has_preferences=has_preferences)


UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'img')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

from datetime import date 

@app.route("/new_event/<int:city_id>", methods=["POST", "GET"])
def new_event(city_id):
    today = date.today()  
    
    if request.method == "POST":
        event_name = request.form['event_name']
        date_str = request.form['date']
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()  
        link = request.form['link']
        event_type = request.form['event_type']

        photo = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)  
                photo = filename 

        if len(event_name) > 0 and len(link) > 0:
            new_event = Event(event_name=event_name, photo=photo, date=date_obj, link=link, city_id=city_id,event_type=event_type)
            db.session.add(new_event)
            db.session.commit()

            city = City.query.get(city_id)
            all_events = Event.query.filter_by(city_id=city_id).all()
            upcoming_events = [event for event in all_events if event.date >= today]
            past_events = [event for event in all_events if event.date < today]
            upcoming_events.sort(key=lambda event: event.date)
            past_events.sort(key=lambda event: event.date, reverse=True)
            
            event = upcoming_events + past_events
            return render_template('afisha.html', event=event, city=city, today=today)

        else:
            message = 'Пожалуйста, проверьте введенные данные.'
            message_type = 'danger'
            return render_template('new_event.html', message=message, message_type=message_type, city_id=city_id, today=today)
        
    return render_template('new_event.html', city_id=city_id, today=today)


@app.route('/add_to_favorites/<int:attraction_id>', methods=['POST'])
@login_required
def add_to_favorites(attraction_id):
    existing_favorite = Favourite.query.filter_by(user_id=current_user.user_id, attraction_id=attraction_id).first()
    if existing_favorite:
        flash("Эта достопримечательность уже добавлена в избранное.", 'warning')
        return redirect(url_for('attraction_detail', attraction_id=attraction_id))

    new_favorite = Favourite(user_id=current_user.user_id, attraction_id=attraction_id)
    db.session.add(new_favorite)
    db.session.commit()
    attraction = Attraction.query.get(attraction_id)
    city = City.query.get(attraction.city_id)
    today = date.today()
    nearest_event = Event.query.filter(
        Event.city_id == attraction.city_id,
        Event.date >= today
    ).order_by(Event.date).first()
    
    # Отправляем письмо пользователю
    if nearest_event:
        msg = Message("Рекомендуем посетить мероприятие", recipients=[current_user.email])
        msg.body = f"""
        Советуем посетить данное мероприятие:
        
        Город: {city.city_name}
        Ближайшее мероприятие: {nearest_event.event_name}
        Дата: {nearest_event.date.strftime('%d.%m.%Y')}
        Ссылка: {nearest_event.link}
        Другие мероприятия Вы можете посмотреть на нашем сайте!
        """
        mail.send(msg)

    flash("Вы добавили достопримечательность в избранное!", 'success')
    return redirect(url_for('attraction_detail', attraction_id=attraction_id))




@app.route("/select_preferences/<int:city_id>")
@login_required
def select_preferences(city_id):
    user_preferences = [pref.preference_type for pref in 
                       UserPreferences.query.filter_by(user_id=current_user.user_id).all()]
    
    return render_template('preferences.html', 
                         user_preferences=user_preferences,
                         has_preferences=len(user_preferences) > 0,
                         city_id=city_id)

@app.route("/save_preferences/<int:city_id>", methods=["POST"])
@login_required
def save_preferences(city_id):
    UserPreferences.query.filter_by(user_id=current_user.user_id).delete()
    preferences = request.form.getlist('preferences')
    for pref in preferences:
        new_pref = UserPreferences(user_id=current_user.user_id, preference_type=pref)
        db.session.add(new_pref)
    
    db.session.commit()
    
    flash('Ваши предпочтения сохранены! Теперь афиша будет показывать только выбранные типы мероприятий.', 'success')
    return redirect(url_for('afisha', city_id=city_id))

@app.route("/recommend_events/<int:city_id>")
@login_required
def recommend_events(city_id):
    preferences = [pref.preference_type for pref in 
                  UserPreferences.query.filter_by(user_id=current_user.user_id).all()]
    
    if not preferences:
        flash('Пожалуйста, сначала выберите предпочтения', 'warning')
        return redirect(url_for('afisha', city_id=city_id))
    
    today = date.today()
    
    recommended_events = Event.query.filter(
        Event.city_id == city_id,
        Event.event_type.in_(preferences),
        Event.date >= today
    ).order_by(Event.date).all()
    
    if recommended_events:
        msg = Message("Рекомендуемые мероприятия", recipients=[current_user.email])
        msg.body = f"Рекомендуем вам следующие мероприятия в городе {City.query.get(city_id).city_name}:\n\n"
        
        for event in recommended_events:
            msg.body += f"{event.event_name} ({event.event_type})\n"
            msg.body += f"Дата: {event.date.strftime('%d.%m.%Y')}\n"
            msg.body += f"Ссылка: {event.link}\n\n"
        
        mail.send(msg)
        flash('Письмо с рекомендациями отправлено на вашу почту!', 'success')
    else:
        flash('К сожалению, сейчас нет мероприятий по вашим предпочтениям в этом городе', 'info')
    
    return redirect(url_for('afisha', city_id=city_id))




@app.route("/admin_page")
@login_required
def admin_page():
    if current_user.email != 'forsitediplom@internet.ru':
        flash('У вас нет доступа к этой странице.', 'danger')
        return redirect(url_for('lk'))

    all_comments = db.session.query(
        Feedback.comment.label('text'),
        User.name.label('user_name'),
        User.email.label('user_email'),
        Attraction.attraction_name.label('attraction_name'),
        City.city_name.label('city_name'),
        Feedback.created_at.label('created_at')
    ).join(User).join(Attraction).join(City).all()

    now = datetime.utcnow()  #текущее время
    return render_template('admin_page.html', all_comments=all_comments, now=now)


 
@app.route("/delete_feedback/<int:feedback_id>", methods=['POST'])
@login_required  
def delete_feedback(feedback_id):
    if current_user.email != 'forsitediplom@internet.ru':
        flash('У вас нет прав для удаления комментариев.', 'danger')
        return redirect(request.referrer)

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

    return redirect(request.referrer) 



def transliterate(text):
    translit_dict = {
        'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'e', 
        'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm', 
        'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u', 
        'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch', 
        'ъ': '', 'ы': 'y', 'ь': '', 'э': 'e', 'ю': 'yu', 'я': 'ya'
    }
    
    result = ''.join(translit_dict.get(char, char) for char in text.lower())
    result = re.sub(r'[^a-z0-9-]', '-', result) 
    result = re.sub(r'-+', '-', result)  
    return result.strip('-')  

def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371  # Радиус Земли 
    lat1 = math.radians(lat1)
    lon1 = math.radians(lon1)
    lat2 = math.radians(lat2)
    lon2 = math.radians(lon2)

    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    distance = R * c
    return distance 

@app.route('/get_user_city')
def get_user_city():
    user_ip = request.remote_addr
    
    if user_ip in ['127.0.0.1', '::1']:
        user_ip = "94.158.118.147" 

    location_info = get_location_from_ip(user_ip)
    
    if isinstance(location_info, dict) and 'city' in location_info:
        city = City.query.filter(func.lower(City.city_name) == func.lower(location_info['city'])).first()
        if city:
            return jsonify({
                'city': location_info['city'],
                'city_id': city.city_id
            })
    
    default_city = City.query.first()
    return jsonify({
        'city': default_city.city_name if default_city else 'Москва',
        'city_id': default_city.city_id if default_city else 1
    })

def get_ip_db():
    if 'ip_db' not in g:
        g.ip_db = sqlite3.connect('ipgeo.db')
        g.ip_db.row_factory = sqlite3.Row  
    return g.ip_db

@app.teardown_appcontext
def close_ip_db(e=None):
    db = g.pop('ip_db', None)
    if db is not None:
        db.close()

def get_location_from_ip(ip):
    if ip in ["127.0.0.1", "::1"]:
        return {
            'city': 'Владимир',
            'region': 'Владимирская область',
            'country': 'Россия',
            'coordinates': (56.1445, 40.4172),
            'isp': 'Локальный доступ'
        }
    
    try:
        db = get_ip_db()
        cursor = db.cursor()
        ip_num = int(ip_address(ip))
        
        cursor.execute('''
        SELECT city, region, lat, lon 
        FROM ip_ranges
        JOIN cities ON ip_ranges.city_id = cities.city_id
        WHERE ? BETWEEN ip_start AND ip_end
        LIMIT 1
        ''', (ip_num,))
        
        result = cursor.fetchone()
        if result:
            return {
                'city': result['city'],
                'region': result['region'],
                'country': 'Россия',  
                'coordinates': (result['lat'], result['lon']),
                'isp': 'Неизвестно'
            }
        
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp")
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'city': data.get('city', 'Неизвестно'),
                    'region': data.get('regionName', 'Неизвестно'),
                    'country': data.get('country', 'Неизвестно'),
                    'coordinates': (data.get('lat'), data.get('lon')),
                    'isp': data.get('isp', 'Неизвестно')
                }
            
    except Exception as e:
        print(f"Ошибка определения местоположения: {str(e)}")
    
    return {
        'city': 'Владимир',
        'region': 'Владимирская область',
        'country': 'Россия',
        'coordinates': (56.1445, 40.4172),
        'isp': 'Неизвестно'
    }

if __name__ == '__main__':
    app.run(debug=True)
