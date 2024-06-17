from flask import Flask, render_template, redirect, url_for, request, flash
from flask_mysqldb import MySQL
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a2deb1b0f1750fb10ed757fc173edf77'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  # Default XAMPP MySQL user
app.config['MYSQL_PASSWORD'] = ''  # Default XAMPP MySQL password
app.config['MYSQL_DB'] = 'bucky'

mysql = MySQL(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    if user:
        return User(id=user[0], username=user[1], email=user[2], role=user[4])
    return None

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=150)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=150)])
    submit = SubmitField('Login')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[Length(min=4, max=150)])
    poin = IntegerField('Poin', validators=[InputRequired()])
    submit = SubmitField('Save')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                    (form.username.data, form.email.data, hashed_password, 'user'))
        mysql.connection.commit()
        cur.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (form.email.data,))
        user = cur.fetchone()
        cur.close()
        if user and check_password_hash(user[3], form.password.data):
            user_obj = User(id=user[0], username=user[1], email=user[2], role=user[4])
            login_user(user_obj)
            if user[4] == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('landing'))
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/landing')
@login_required
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    return render_template('dashboard.html')

@app.route('/user')
@login_required
def user():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    return render_template('user.html')

@app.route('/transaksi')
@login_required
def transaksi():
    if current_user.role != 'admin':
        return redirect(url_for('landing'))
    return render_template('transaksi.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)