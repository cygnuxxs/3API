from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import Length, DataRequired, EqualTo

class LoginForm(FlaskForm):
    email = EmailField("Email", [DataRequired('Please Enter Valid Email Address')])
    password = PasswordField("Password", [DataRequired("Password length should be minimum 8 letters."), Length(min=8)])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    email = EmailField("Email", [DataRequired('Please Enter Valid Email Address')])
    username = StringField("Username", [DataRequired("Username should be minimum 4 letters."), Length(min=4, max=50)])
    pword = PasswordField('Password', [DataRequired("Password should be minimum 8 letters."), Length(min=8)])
    cnfword = PasswordField("Confirm Password", [DataRequired(), EqualTo('pword', message="Password should be same.")])
    submit = SubmitField("Register")