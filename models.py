from database import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    reward = db.Column(db.Integer(), primary_key=False, default=0)
    address = db.relationship('Address', backref='user', lazy=True)
    roles = db.relationship('Role', secondary='user_roles')


class Address(db.Model):
    __tablename__ = 'addresses'
    id = db.Column(db.Integer, primary_key=True)
    address_1 = db.Column(db.String(500), nullable=False)
    address_2 = db.Column(db.String(500), nullable=False)
    state = db.Column(db.String(20), nullable=False)
    postcode = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=True)


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)


class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey(User.id))
    role_id = db.Column(db.Integer(), db.ForeignKey(Role.id))


class Collab(db.Model):
    __tablename__ = 'collabs'
    id = db.Column(db.Integer(), primary_key=True)
    org_name = db.Column(db.String(200), nullable=False)
    rewards = db.relationship('Reward', backref='collab', lazy=True)


class Reward(db.Model):
    __tablename__ = 'rewards'
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    cost = db.Column(db.Integer())
    collab_id = db.Column(db.Integer, db.ForeignKey(Collab.id))
