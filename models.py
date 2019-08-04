from datetime import datetime

from passlib.hash import pbkdf2_sha256 as sha256

from application import db
from settings import PASSWORD_STATUS


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    # в качестве логина используется MSISDN (11 цифр)
    msisdn = db.Column(db.String(11), unique=True, index=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    password_status = db.Column(db.Integer, default=PASSWORD_STATUS['NEW'])

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_data(self):
        db.session.commit()

    @classmethod
    def find_by_msisdn(cls, msisdn):
        return cls.query.filter_by(msisdn=msisdn).first()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)


class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    msisdn = db.Column(db.String(11))
    jti = db.Column(db.String(120), index=True)
    date_revoked = db.Column(db.DateTime, default=datetime.utcnow)

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)


class PasswordHistoryModel(db.Model):
    __tablename__ = 'passwords_history'
    id = db.Column(db.Integer, primary_key=True)
    msisdn = db.Column(db.String(11), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def add(self):
        db.session.add(self)
        db.session.commit()
