from datetime import date, datetime
from flask import Flask, render_template, request, redirect, url_for, session
import database
from models import *
import commands
from flask_login import login_user, logout_user, current_user, LoginManager, login_required
from passlib.hash import pbkdf2_sha256
import os
from firestore import *


app = Flask(__name__)

login_manager = LoginManager()

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['USER_EMAIL_SENDER_EMAIL'] = "forgeteatmeds@gmail.com"
app.config['SECRET_KEY'] = "thisissecret3050hellosecretjasddafkjsdalfjlksd"

database.init_app(app)
commands.init_app(app)
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


@app.errorhandler(500)
def page_not_found(e):
    return render_template('404.html', user=current_user), 404


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and pbkdf2_sha256.verify(password, user.password):
            login_user(user)
            session['username'] = user.username
            return redirect(url_for('user_home'))
        else:
            return 'YOU ARE NOT REGISTERED'
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
        hashed = pbkdf2_sha256.hash(password)
        print(username, email)

        user_role = Role.query.filter_by(name='User').first()
        new_address = Address(
            address_1=address_1,
            address_2=address_2,
            state=state,
            postcode=postcode
        )

        new_user = User(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=hashed,
            address=[new_address],
            roles=[user_role]
        )

        db.session.add(new_user)

        db.session.commit()
        return redirect(url_for('login'))
    else:
        return render_template('register.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/admin')
def admin_home():
    return "Admin page"


@app.route('/user')
@login_required
def user_home():
    return render_template('user/user_home.html', user=current_user)


@app.route('/partner')
def partner_home():
    return "Hello partner"


@app.route('/profile')
@login_required
def profile():
    return render_template('user/user_home.html', user=current_user)


@app.route('/schedule', methods=['POST', 'GET'])
@login_required
def schedule():
    if request.method == 'POST':
        med_name = request.form.get("medicine-name")
        expiry_date = request.form.get("expiry-date")
        addr_1 = request.form.get("addr-1")
        addr_2 = request.form.get("addr-2")
        state = request.form.get("state")
        postcode = request.form.get("postcode")
        data = {
            'username': current_user.username,
            'medicine name': med_name,
            'expiry date': expiry_date,
            'address line 1': addr_1,
            'address line 2': addr_2,
            'state': state,
            'status': 'pending',
            'postcode': postcode
        }
        fdb.collection('schedule').document(str(datetime.now())).set(data)
        return redirect(url_for('ongoing'))
    else:
        address_obj = current_user.address[0]
        data = {
            'addr-1': address_obj.address_1,
            'addr-2': address_obj.address_2,
            'state': address_obj.state,
            'postcode': address_obj.postcode
        }
        return render_template('user/schedule.html', address=data)


@app.route('/ongoing')
@login_required
def ongoing():
    docs = fdb.collection('schedule').where('username', '==', current_user.username).stream()
    records = list()
    for doc in docs:
        doc_dict = doc.to_dict()
        doc_dict['timestamp'] = doc.id
        records.append(doc_dict)
    return render_template('user/ongoing.html', records=records)


@app.route('/unschedule')
@login_required
def unschedule():
    id = request.args.get('id')
    fdb.collection('schedule').document(id).delete()
    return redirect(url_for('ongoing'))


@app.route('/detail')
@login_required
def detail():
    return render_template('user/detail.html')


@app.route('/history')
@login_required
def history():
    return render_template('user/history.html')


@app.route('/logout')
@login_required
def logout():
    if current_user:
        logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=False)
