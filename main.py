from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import requests
from forms import *

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Cygnuxxs'

db = SQLAlchemy(app)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(admin_id):
    return User.query.get(int(admin_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(250), unique = True, nullable = False)
    username = db.Column(db.String(50), unique = True, nullable = False)
    password = db.Column(db.String(250), nullable = False)

with app.app_context() as conn:
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/queryResults', methods = ['GET', "POST"])
def results():
    query = request.args.get('query')
    apiKey = 'ce9d991a1e37e67d2dfd5820aa08017e'
    appId = '4b2af47b'
    params = {
    'q':query,
    'app_id': appId,
    'app_key': apiKey
    }
    response = requests.get(f'https://api.edamam.com/search', params=params)
    data = response.json()
    recipes = []
    for i in data['hits']:
        nutrients = i['recipe']['totalNutrients']
        dict = {
            'dishName' : i['recipe']['label'],
            'calories' : round(i['recipe']['calories']),
            'cuisineType' : i['recipe']['cuisineType'],
            'ingredients' : i['recipe']['ingredientLines'],
            'dishName' : i['recipe']['label'],
            'totalNutrients' : [f"{nutrients[j]['label']} : {round(nutrients[j]['quantity'], 2)}{nutrients[j]['unit']}" for j in nutrients],
            'image' : i['recipe']['image']
        }
        recipes.append(dict)
    return jsonify(recipes)


@app.route('/login', methods = ['GET', "POST"])
def login():
    err = None
    form = LoginForm()
    if request.method == 'POST':
        user = User.query.filter_by(email = form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                err = "Password is Incorrect."
        else:
            err = 'Email is not found in the database. Please Register.'
    return render_template('login.html', title = 'Login', form = form, err = err)

@app.route('/signup', methods = ['GET', "POST"])
def signup():
    form = SignupForm()
    err = None
    if request.method == 'POST':
        new_user = User(
            email = form.email.data,
            username = form.username.data,
            password = generate_password_hash(form.cnfword.data, 'pbkdf2:sha256', salt_length=16)
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template("signup.html", title = 'Sign Up!', form = form, err = err)

@app.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', title = "Dashboard", user = current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
 