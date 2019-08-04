import os
basedir = os.path.abspath(os.path.dirname(__file__))


# задает кол-во цифр в пароле
PASSWORD_COMPLEXITY = 6
MSISDN_LENGTH = 11

SEND_SMS_SERVICE_URL = 'http://xx.xx.xx.xxx:xxxxx/cgi-bin/sendsms'

PASSWORD_STATUS = {
        'NEW': 0,
        'USED': 1
    }


class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    APP_SECRET_KEY = 'some-secret-string'
    JWT_SECRET_KEY = 'jwt-secret-string'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'


class ProductionConfig(Config):
    pass


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
