from database import db
from models import *
from passlib.hash import pbkdf2_sha256
import copy


def create_tables():
    db.create_all()


def start_debug():
    db.create_all()

    admin_role = Role(name='Admin')
    user_role = Role(name='User')
    partner_role = Role(name='Partner')
    collab_role = Role(name='Collab')

    new_address = Address(
        address_1='taman admin',
        address_2='jalan admin',
        state='Kedah',
        postcode='05400'
    )

    new_admin = User(
        first_name='the',
        last_name='admin',
        username='admin',
        email='admin@returnmed.com',
        password=pbkdf2_sha256.hash('adminhehe'),
        address=[copy.deepcopy(new_address)],
        roles=[admin_role, user_role, partner_role]
    )

    new_partner = User(
        first_name='the',
        last_name='partner',
        username='partner',
        email='partner@returnmed.com',
        password=pbkdf2_sha256.hash('partnerhuhu'),
        address=[copy.deepcopy(new_address)],
        roles=[partner_role]
    )

    new_user = User(
        first_name='the',
        last_name='user',
        username='user',
        email='user@returnmed.com',
        password=pbkdf2_sha256.hash('userhaha'),
        address=[copy.deepcopy(new_address)],
        roles=[user_role]
    )

    new_collab = User(
        first_name='the',
        last_name='collab',
        username='collab',
        email='collab@returnmed.com',
        password=pbkdf2_sha256.hash('collabgg'),
        address=[copy.deepcopy(new_address)],
        roles=[collab_role]
    )

    body_check = Reward(
        title='Body Check',
        description='Free body check',
        cost=2,
    )

    consult = Reward(
        title="Free consultation",
        description="Free session with out physician",
        cost=3,
    )

    org_collab = Collab(
        org_name='Hospital AA',
        rewards=[body_check, consult],
    )
    
    db.session.add(new_admin)
    db.session.add(new_user)
    db.session.add(new_collab)
    db.session.add(new_partner)

    db.session.add(admin_role)
    db.session.add(user_role)
    db.session.add(partner_role)
    db.session.add(collab_role)

    db.session.commit()

    db.session.add(body_check)
    db.session.add(consult)
    db.session.add(org_collab)

    db.session.commit()


def init_app(app):
    # add multiple commands in a bulk
    for command in [create_tables, start_debug]:
        app.cli.add_command(app.cli.command()(command))