import os
from flask import Flask, render_template, request, redirect, url_for,  flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///goldenring.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)




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

class Favourite(db.Model):
    favourite_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    attraction_id = db.Column(db.Integer, db.ForeignKey('attraction.attraction_id'), nullable=False)

class Event(db.Model):
    event_id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(50), nullable=False)
    photo = db.Column(db.LargeBinary, nullable=False)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(40), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.city_id'), nullable=False)

class Feedback(db.Model):
    feedback_id = db.Column(db.Integer, primary_key=True)
    evaluation = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    attraction_id = db.Column(db.Integer, db.ForeignKey('attraction.attraction_id'), nullable=False)
    approved = db.Column(db.Boolean, default=False)  # Поле для отслеживания состояния модерации

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
    return render_template('city_detail.html', city=city)


@app.route("/attractions/<int:city_id>", methods=['GET'])
def attractions(city_id):
    category_filter = request.args.get('attraction_type')
    if category_filter:
        attractions = Attraction.query.filter_by(city_id=city_id, attraction_type=category_filter).all()
    else:
        attractions = Attraction.query.filter_by(city_id=city_id).all()
    city = City.query.get(city_id)  
    return render_template('attraction.html', attractions=attractions, city=city)


@app.route("/attraction_detail/<int:attraction_id>")
def attraction_detail(attraction_id):
    attraction = Attraction.query.get(attraction_id) 
    return render_template('attraction_detail.html', attraction=attraction)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
         # Проверка на админские учетные данные
        if email == 'admin@mail.ru' and password == 'admin':
            # Здесь можно создать или получить объект администратора
            # Например, если у вас есть администратор в базе данных
            admin_user = User.query.filter_by(email=email).first()
            if not admin_user:
                # Если администратор не существует, можно создать его (если необходимо)
                admin_user = User(name='Admin', email=email, password=bcrypt.generate_password_hash(password).decode('utf-8'))
                db.session.add(admin_user)
                db.session.commit()

            login_user(admin_user)
            return redirect(url_for('admin_page'))  

        # Стандартная проверка пользователя в базе данных
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
    # Получите и присоедините данные о достопримечательностях к списку избранного
    favorite_attractions = []
    for favorite in favorites:
        attraction = Attraction.query.get(favorite.attraction_id)
        if attraction:
            favorite_attractions.append(attraction)
 
    return render_template('lk.html', name=current_user.name, favorites=favorite_attractions)


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

        if len(name) > 4 and len(email) > 4 and len(password) > 4 and password == password2:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            message = 'Регистрация прошла успешно!'
            message_type = 'success'
            return render_template('register.html', message=message, message_type=message_type)

        else:
            message = 'Пожалуйста, проверьте введенные данные.'
            message_type = 'danger'
            return render_template('register.html', message=message, message_type=message_type)

    return render_template('register.html')


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






if __name__ == '__main__':
    app.run(debug=True)