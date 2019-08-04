from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

from settings import config

db = SQLAlchemy()
jwt = JWTManager()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    db.init_app(app)

    @app.before_first_request
    def create_tables():
        db.create_all()

    jwt.init_app(app)

    @jwt.token_in_blacklist_loader
    def check_if_token_in_blacklist(decrypted_token):
        jti = decrypted_token['jti']
        return models.RevokedTokenModel.is_jti_blacklisted(jti)

    import models, resources

    api = Api()

    api.add_resource(resources.UserRegistration, '/registration')
    api.add_resource(resources.UserLogin, '/login')
    api.add_resource(resources.UserLogoutAccessRefresh, '/logout')
    api.add_resource(resources.TokenRefresh, '/refresh-token')
    # api.add_resource(resources.AllUsers, '/users') # for test purposes
    api.add_resource(resources.SecretResource, '/secret')
    api.add_resource(resources.IsAccessTokenValidResource, '/validate-token')

    api.init_app(app)

    return app
