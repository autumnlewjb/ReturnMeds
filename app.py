from datetime import datetime
from functools import wraps
from threading import currentThread
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask.ctx import copy_current_request_context
import database
from models import *
import commands
from flask_login import login_user, logout_user, current_user, LoginManager, login_required
from passlib.hash import pbkdf2_sha256
import os
from firestore import *
import pyqrcode
from base64 import b64encode


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
            elif 'Collab' in role_str:
                return redirect(url_for('collab_home'))
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
    print(current_user.address)
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
    print(current_user.address)
    return render_template('partner/partner_home.html', user=current_user)


@app.route('/collab')
@role_required('Collab')
@login_required
def collab_home():
    print(current_user.address[0])
    return render_template('collab/collab_home.html', user=current_user)


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
            'status': 'Pending',
            'pic': None,
            'postcode': postcode, 
            'time created': firestore.SERVER_TIMESTAMP
        }
        fdb.collection('schedule').document(str(datetime.now())).set(data)
        return redirect(url_for('ongoing'))
    else:
        print('address: ', current_user.address)
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
    docs = fdb.collection('schedule').where('email', '==', current_user.email).where('status', 'in', ['Pending', 'Accepted']).stream()
    records = list()
    for doc in docs:
        doc_dict = doc.to_dict()
        doc_dict['timestamp'] = doc.id
        records.append(doc_dict)
    return render_template('user/ongoing.html', records=records[::-1])


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
    
    return render_template('partner/ongoing.html', user=current_user)


@app.route('/partner-complete', methods=['POST', 'GET'])
@role_required('Partner')
@login_required
def partner_complete():
    if (request.method == 'POST'):
        email = request.form['email']
        print(email)
        current_user.reward += 1
        user = User.query.filter_by(email=email).first()
        user.reward += 1
        db.session.commit()
        
        return jsonify({'status': 'done'})
    else:
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
@role_required('User')
@login_required
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
@role_required('User')
@login_required
def list_collab():
    collabs = Collab.query.all()
    return render_template('user/list.html', collabs=collabs)


@app.route('/reward/<int:id>/option')
@role_required('User')
@login_required
def list_reward(id):
    collab = Collab.query.filter_by(id=id).first()
    rewards = [reward for reward in collab.rewards if reward.cost <= current_user.reward]
    return render_template('user/select_reward.html', reward_opt=rewards)


@app.route('/reward/<int:reward_id>/qr-claim')
@role_required('User')
@login_required
def qr_claim(reward_id):
    url = request.base_url
    url = url.replace('qr-claim', 'claim')
    url = url + f'/{current_user.id}'
    qr = pyqrcode.create(url)
    encoded = qr.png_as_base64_str(scale=20)
    mime = "image/jpeg"
    uri = "data:%s;base64,%s" % (mime, encoded)
    return render_template('user/qr.html', uri=uri)


@app.route('/reward/<int:reward_id>/claim/<int:user_id>')
@role_required('Collab')
@login_required
def claim_reward(reward_id, user_id):
    user = User.query.filter_by(id=user_id).first()
    reward = Reward.query.filter_by(id=reward_id).first()
    if (user.reward >= reward.cost):
        user.reward -= reward.cost
        db.session.commit()

        data = {
            'email': user.email,
            'reward id': user.id,
            'before reward': user.reward + reward.cost, 
            'after reward': user.reward,
        }

        fdb.collection('reward').document(str(datetime.now())).set(data)

    else:
        return "Claim reward failed!"

    return redirect('/collab')


@app.route('/collab/services')
@role_required('Collab')
@login_required
def service():
    collab = current_user.link_account[0]
    rewards = collab.rewards
    return render_template('collab/service.html', rewards=rewards)


@app.route('/collab/add-services', methods=['GET', 'POST'])
@role_required('Collab')
@login_required
def add_service():
    if request.method == 'POST':
        new_reward = Reward(
            title=request.form.get('name'),
            description=request.form.get('description'),
            cost=request.form.get('cost'),
        )

        collab_account = current_user.link_account[0]
        collab_account.rewards.append(new_reward)

        db.session.add(new_reward)
        db.session.commit()

        return redirect(url_for('service'))
    else:
        return render_template('collab/add_service.html')


def address_query(line1, line2, postcode, state):

    query = (line1 + line2 + postcode + state).replace(" ", "+").replace(",", "%2C")

    return "https://www.google.com/maps/search/?api=1&query=" + query
    

if __name__ == '__main__':
    app.run(debug=True)
