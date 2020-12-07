from flask import Flask, render_template, request, redirect, url_for
from database import init_app
from models import *
from flask_user import UserManager

app = Flask(__name__)

app.config['SQLALCHEMY_URI'] = 'sqlite:///database.db'
app.config['USER_EMAIL_SENDER_EMAIL'] = "forgeteatmeds@gmail.com"
app.config['SECRET_KEY'] = "thisissecret"

init_app(app)

user_manager = UserManager(app, db, User)


@app.errorhandler(500)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username')
        password = request.form.get('password')
        return 'YOU ARE LOGGED IN'
    else:
        return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get("first-name")
        last_name = request.form.get("last-name")
        username = request.form.get("username")
        email = request.form.get("email")
        address_1 = request.form.get("address-1")
        address_2 = request.form.get("address-2")
        state = request.form.get("state")
        postcode = request.form.get("postcode")
        password = request.form.get("password")
        print(username, email)
        return redirect(url_for('login'))
    else:
        return render_template('register.html')


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)

