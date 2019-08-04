from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    jwt_refresh_token_required,
    get_jwt_identity,
    get_raw_jwt,
    get_jti,
)

from models import UserModel, RevokedTokenModel, PasswordHistoryModel
from utils import gen_password, send_password_sms_to_user, is_msisdn_valid
from settings import PASSWORD_STATUS


registration_parser = reqparse.RequestParser()
registration_parser.add_argument('msisdn', help='This field cannot be blank', required=True)

login_parser = reqparse.RequestParser()
login_parser.add_argument('msisdn', help='This field cannot be blank', required=True)
login_parser.add_argument('password', help='This field cannot be blank', required=True)

logout_parser = reqparse.RequestParser()
logout_parser.add_argument('refresh_token', help='This field cannot be blank', required=True)


class UserRegistration(Resource):
    def post(self):
        data = registration_parser.parse_args()
        msisdn = data['msisdn']
        if is_msisdn_valid(msisdn):

            current_user = UserModel.find_by_msisdn(msisdn)
            if current_user:
                if current_user.password_status == PASSWORD_STATUS['USED']:
                    password = gen_password()
                    current_user.password = UserModel.generate_hash(password)
                    current_user.password_status = PASSWORD_STATUS['NEW']
                    current_user.update_data()

                    password_history_note = PasswordHistoryModel(
                        msisdn=current_user.msisdn,
                        password=current_user.password
                    )
                    password_history_note.add()

                    send_password_sms_to_user(password, msisdn)
                    return {
                        'message': 'New password for MSISDN {} was created'.format(msisdn)
                    }, 200

                if current_user.password_status == PASSWORD_STATUS['NEW']:
                    password = gen_password()
                    current_user.password = UserModel.generate_hash(password)
                    current_user.update_data()

                    password_history_note = PasswordHistoryModel(
                        msisdn=current_user.msisdn,
                        password=current_user.password
                    )
                    password_history_note.add()

                    send_password_sms_to_user(password, msisdn)
                    return {
                               'message': 'New password for MSISDN {} was created'.format(msisdn)
                           }, 200

            else:
                password = gen_password()

                new_user = UserModel(
                    msisdn=msisdn,
                    password=UserModel.generate_hash(password)
                )
                password_history_note = PasswordHistoryModel(
                    msisdn=new_user.msisdn,
                    password=new_user.password
                )

                try:
                    new_user.save_to_db()
                    password_history_note.add()
                    send_password_sms_to_user(password, msisdn)
                    return {
                               'message': 'New password for MSISDN {} was created'.format(msisdn)
                           }, 200
                except:
                    return {'message': 'Internal error'}, 500
        else:
            return {'message': 'Wrong format for MSISDN'}, 400


class UserLogin(Resource):
    def post(self):
        data = login_parser.parse_args()
        msisdn = data['msisdn']
        current_user = UserModel.find_by_msisdn(msisdn)

        if not current_user:
            return {'message': 'User with MSISDN {} doesn\'t exist. Please register'.format(msisdn)}, 401

        if current_user.password_status == PASSWORD_STATUS['USED']:
            return {'message': 'Your password is not valid. Please register again'}, 401

        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity=msisdn)
            refresh_token = create_refresh_token(identity=msisdn)
            current_user.password_status = PASSWORD_STATUS['USED']
            current_user.update_data()
            return {
                'message': 'Logged in as {}'.format(current_user.msisdn),
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200
        else:
            return {'message': 'Wrong credentials'}, 401


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}, 200


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all(), 200


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'message': 'Secret resource is available'
        }, 200


class UserLogoutAccessRefresh(Resource):
    @jwt_required
    def post(self):
        jti_access = get_raw_jwt()['jti']
        data = logout_parser.parse_args()
        jti_refresh = get_jti(data['refresh_token'])
        current_user = get_jwt_identity()

        try:
            [RevokedTokenModel(jti=jti, msisdn=current_user).add() for jti in [jti_access, jti_refresh]]
            return {'message': 'Access and refresh tokens have been revoked'}, 200
        except:
            return {'message': 'Internal error'}, 500


class IsAccessTokenValidResource(Resource):
    @jwt_required
    def get(self):
        current_user = get_jwt_identity()
        return {
            'msisdn': current_user
        }, 200
