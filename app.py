from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session
from flask.ctx import copy_current_request_context
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
app.config['SECRET_KEY'] = "thisissecret3050hellosecretjasddafkjsdalfjlksd"

database.init_app(app)
commands.init_app(app)
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def role_required(role_name):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if session['username']:
                user = User.query.filter_by(username=session['username']).first()
                role_str = [r.name for r in user.roles]
                print(role_str)
                if role_name in role_str:
                    return func(*args, **kwargs)
            return redirect('/login')
        return wrapper
    return decorator


@app.errorhandler(500)
def page_not_found(e):
    return render_template('404.html'), 500


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
            role_str = [r.name for r in current_user.roles]
            if 'Admin' in role_str:
                return redirect(url_for('admin_home'))
            elif 'Partner' in role_str:
                return redirect(url_for('partner_home'))
            else:
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
@role_required('Admin')
@login_required
def admin_home():
    return "Admin page"


@app.route('/user')
@role_required('User')
@login_required
def user_home():
    return render_template('user/user_home.html', user=current_user)


@app.route('/partner')
@role_required('Partner')
@login_required
def partner_home():
    return render_template('partner/partner_home.html', user=current_user)


@app.route('/profile')
@login_required
def profile():
    return render_template('user/user_home.html', user=current_user)


@app.route('/schedule', methods=['POST', 'GET'])
@role_required('User')
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
            'email': current_user.email,
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
@role_required('User')
@login_required
def ongoing():
    docs = fdb.collection('schedule').where('email', '==', current_user.email).where('status', '==', 'pending').stream()
    records = list()
    for doc in docs:
        doc_dict = doc.to_dict()
        doc_dict['timestamp'] = doc.id
        records.append(doc_dict)
    return render_template('user/ongoing.html', records=records)


@app.route('/unschedule')
@role_required('User')
@login_required
def unschedule():
    id = request.args.get('id')
    fdb.collection('schedule').document(id).delete()
    return redirect(url_for('ongoing'))


@app.route('/detail')
@role_required('User')
@login_required
def detail():
    return render_template('user/detail.html')


@app.route('/history')
@role_required('User')
@login_required
def history():
    returns = fdb.collection('schedule').where('email', '==', current_user.email).where('status', '==', 'Completed').stream()
    returns_dict = list()
    for r in returns:
        temp = r.to_dict()
        temp['timestamp'] = r.id
        returns_dict.append(temp)
    return render_template('user/history.html', records=returns_dict)


@app.route('/logout')
@login_required
def logout():
    if current_user:
        logout_user()
    return redirect(url_for('index'))


@app.route('/partner-profile')
@role_required('Partner')
@login_required
def partner_profile():
    return render_template('partner/partner_home.html', user=current_user)


@app.route('/partner-ongoing')
@role_required('Partner')
@login_required
def partner_ongoing():
    
    return render_template('partner/ongoing.html')


@app.route('/partner-complete')
@role_required('Partner')
@login_required
def partner_complete():
    doc_id = request.args.get('id')
    doc = fdb.collection('schedule').document(doc_id)
    doc.update({'status': 'Completed'})

    current_user.reward += 1
    user = User.query.filter_by(username=doc.get().to_dict()['username']).first()
    user.reward += 1
    db.session.commit()
    return redirect(url_for('partner_ongoing'))


@app.route('/partner-history')
@role_required('Partner')
@login_required
def partner_history():
    returns = fdb.collection('schedule').where('status', '==', 'Completed').stream()
    returns_dict = list()
    for r in returns:
        temp = r.to_dict()
        temp['timestamp'] = r.id
        returns_dict.append(temp)
    return render_template('partner/history.html', records=returns_dict)


@app.route('/reward/history')
def reward_history():
    rewards = fdb.collection('reward').where('email', '==', current_user.email).stream()
    reward_dict = list()
    for reward in rewards:
        temp = reward.to_dict()
        query = Reward.query.filter_by(id=int(temp['reward id'])).first()
        temp['timestamp'] = reward.id
        temp['title'] = query.title
        temp['organization'] = query.collab.org_name
        temp['cost'] = query.cost
        reward_dict.append(temp)

    return render_template('user/reward.html', rewards=reward_dict)


@app.route('/reward/collab')
def list_collab():
    collabs = Collab.query.all()
    return render_template('collab/list.html', collabs=collabs)


@app.route('/reward/<int:id>/option')
def list_reward(id):
    collab = Collab.query.filter_by(id=id).first()
    rewards = collab.rewards
    return render_template('collab/select_reward.html', reward_opt=rewards)


@app.route('/reward/<int:id>/claim')
def claim_reward(id):
    reward = Reward.query.filter_by(id=id).first()
    current_user.reward -= reward.cost
    db.session.commit()

    data = {
        'email': current_user.email,
        'reward id': id,
        'before reward': current_user.reward + reward.cost, 
        'after reward': current_user.reward,
    }

    fdb.collection('reward').document(str(datetime.now())).set(data)

    return redirect(url_for('profile'))


if __name__ == '__main__':
    app.run(debug=True)
