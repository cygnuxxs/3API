from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
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

@app.route('/login', methods = ['GET', "POST"])
def login():
    form = LoginForm()
    return render_template('login.html', title = 'Login', form = form)

@app.route('/signup', methods = ['GET', "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        new_user = User(
            email = form.email.data,
            username = form.username.data,
            password = generate_password_hash(form.cnfword.data, 'pdkdf:sha256', salt_length=16)
        )
        db.session.add(new_user)
        login_user(new_user)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template("signup.html", title = 'Sign Up!', form = form)

@app.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', title = "Dashboard")

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
 