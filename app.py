from flask import Flask, render_template_string, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize Flask app and config
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # redirect to login if not authenticated

# ---------------------- #
# Database Model: User   #
# ---------------------- #
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Create the database if it doesn't exist
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------- #
# Forms (WTForms)        #
# ---------------------- #
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please login or use a different email.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# ---------------------- #
# Routes & Views         #
# ---------------------- #

# Home page (redirect to overview if logged in, else to login)
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('overview'))
    return redirect(url_for('login'))

# Registration Endpoint
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('overview'))
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(
            username=form.username.data,
            email=form.email.data
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template_string(REGISTRATION_TEMPLATE, form=form)

# Login Endpoint
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('overview'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('overview'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template_string(LOGIN_TEMPLATE, form=form)

# Logout Endpoint
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Project Overview Page (Protected)
@app.route('/overview')
@login_required
def overview():
    return render_template_string(OVERVIEW_TEMPLATE, username=current_user.username)

# Dashboard Page (Protected)
# Instead of rendering a placeholder template, we embed the externally running Dash app.
@app.route('/dashboard')
@login_required
def dashboard():
    dashboard_iframe = '''
    <!doctype html>
    <html lang="en">
      <head>
        <title>Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
      </head>
      <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <div class="container-fluid">
            <a class="navbar-brand" href="{{ url_for('overview') }}">Project Overview</a>
            <div class="d-flex">
              <a class="btn btn-outline-light me-2" href="{{ url_for('overview') }}">Overview</a>
              <a class="btn btn-outline-light" href="{{ url_for('logout') }}">Logout</a>
            </div>
          </div>
        </nav>
        <div style="width:100%; height:100vh;">
            <iframe src="http://127.0.0.1:8050/" style="width:100%; height:100%; border:none;"></iframe>
        </div>
      </body>
    </html>
    '''
    return render_template_string(dashboard_iframe)

# ---------------------- #
# HTML Templates         #
# ---------------------- #
# Use Bootstrap for quick styling.
REGISTRATION_TEMPLATE = '''
<!doctype html>
<html lang="en">
  <head>
    <title>Register</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <div class="container mt-5">
      <h2>Register</h2>
      <form method="POST">
        {{ form.hidden_tag() }}
        <div class="mb-3">
          {{ form.username.label(class="form-label") }}
          {{ form.username(class="form-control") }}
          {% for error in form.username.errors %}
            <div class="text-danger">{{ error }}</div>
          {% endfor %}
        </div>
        <div class="mb-3">
          {{ form.email.label(class="form-label") }}
          {{ form.email(class="form-control") }}
          {% for error in form.email.errors %}
            <div class="text-danger">{{ error }}</div>
          {% endfor %}
        </div>
        <div class="mb-3">
          {{ form.password.label(class="form-label") }}
          {{ form.password(class="form-control") }}
          {% for error in form.password.errors %}
            <div class="text-danger">{{ error }}</div>
          {% endfor %}
        </div>
        <div class="mb-3">
          {{ form.confirm_password.label(class="form-label") }}
          {{ form.confirm_password(class="form-control") }}
          {% for error in form.confirm_password.errors %}
            <div class="text-danger">{{ error }}</div>
          {% endfor %}
        </div>
        {{ form.submit(class="btn btn-primary") }}
      </form>
      <p class="mt-3">Already have an account? <a href="{{ url_for('login') }}">Login Here</a></p>
    </div>
  </body>
</html>
'''

LOGIN_TEMPLATE = '''
<!doctype html>
<html lang="en">
  <head>
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <div class="container mt-5">
      <h2>Login</h2>
      <form method="POST">
        {{ form.hidden_tag() }}
        <div class="mb-3">
          {{ form.username.label(class="form-label") }}
          {{ form.username(class="form-control") }}
          {% for error in form.username.errors %}
            <div class="text-danger">{{ error }}</div>
          {% endfor %}
        </div>
        <div class="mb-3">
          {{ form.password.label(class="form-label") }}
          {{ form.password(class="form-control") }}
          {% for error in form.password.errors %}
            <div class="text-danger">{{ error }}</div>
          {% endfor %}
        </div>
        {{ form.submit(class="btn btn-primary") }}
      </form>
      <p class="mt-3">Don't have an account? <a href="{{ url_for('register') }}">Register Here</a></p>
    </div>
  </body>
</html>
'''

OVERVIEW_TEMPLATE = '''
<!doctype html>
<html lang="en">
  <head>
    <title>Project Overview</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-secondary text-white">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('overview') }}">Project Overview</a>
        <div class="d-flex">
          <a class="btn btn-outline-light me-2" href="{{ url_for('dashboard') }}">Dashboard</a>
          <a class="btn btn-outline-light" href="{{ url_for('logout') }}">Logout</a>
        </div>
      </div>
    </nav>
    <div class="container mt-5">
      <h1>Welcome {{ username }}!</h1>
      <p>This project is a network anomaly detection system that uses real-time packet capture,
         feature extraction, and predictive analytics to detect network attacks.</p>
      <h3>Overview</h3>
      <ul>
        <li><strong>Packet Capture:</strong> Uses a sniffer to capture network packets.</li>
        <li><strong>Flow Processing:</strong> Groups and processes packet flows to extract features.</li>
        <li><strong>Inference:</strong> Classifies flows as normal or attack using a machine learning model.</li>
        <li><strong>Dashboard:</strong> Provides real-time visualization and alerts.</li>
      </ul>
      <p>Click below to go to the dashboard and start detection.</p>
      <a href="{{ url_for('dashboard') }}" class="btn btn-primary">Begin Detection</a>
    </div>
  </body>
</html>
'''

# ---------------------- #
# Run the Application    #
# ---------------------- #
if __name__ == '__main__':
    app.run(debug=True, port =5010)
