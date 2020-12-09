from database import db
from models import *
from passlib.hash import pbkdf2_sha256


def create_tables():
    db.create_all()


def start_debug():
    db.create_all()

    admin_role = Role(name='Admin')
    user_role = Role(name='User')
    partner_role = Role(name='Partner')

    new_address = Address(
        address_1='taman admin',
        address_2='jalan admin',
        state='Kedah',
        postcode='05400'
    )

    new_user = User(
        first_name='the',
        last_name='admin',
        username='admin',
        email='admin@returnmed.com',
        password=pbkdf2_sha256.hash('adminhehe'),
        address=[new_address],
        roles=[admin_role]
    )

    db.session.add(new_user)

    db.session.add(admin_role)
    db.session.add(user_role)
    db.session.add(partner_role)

    db.session.commit()



def init_app(app):
    # add multiple commands in a bulk
    for command in [create_tables, start_debug]:
        app.cli.add_command(app.cli.command()(command))