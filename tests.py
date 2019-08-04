import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

import unittest
import json

from flask import current_app

from application import create_app, db
from models import UserModel
from settings import PASSWORD_STATUS


class BasicsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_app_exists(self):
        self.assertFalse(current_app is None)

    def test_app_is_testing(self):
        self.assertTrue(current_app.config['TESTING'])

    def user_dict(self):
        return dict(
            msisdn='79262925356'
        )

    def wrong_user_dict(self):
        return dict(
            msisdn='79261112233',
            password='123456'
        )

    def get_api_headers(self, token=None):
        return {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {}'.format(token),
        }

    def test_register_user(self):

        # registration with wrong format for MSISDN
        new_user = {'msisdn': '7926292535'}
        response = self.client.post(
            '/registration',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 400)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['message'], 'Wrong format for MSISDN')

        # new user registration
        new_user = self.user_dict()
        response = self.client.post(
            '/registration',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        # password length - 6 characters:
        self.assertEqual(len(json_response['password']), 6)
        self.assertEqual(json_response['message'], 'New password for MSISDN {} was created'
                         .format(new_user['msisdn']))
        password_1 = json_response['password']

        # user already exists, but password not activated
        user = UserModel.query.filter_by(msisdn=new_user['msisdn']).first()
        assert user.password_status == PASSWORD_STATUS['NEW']
        # user ask for new password
        response = self.client.post(
            '/registration',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(len(json_response['password']), 6)

        password_2 = json_response['password']
        # check for new password was created
        assert password_2 != password_1

        # user login and activate password
        new_user.update(password=password_2)
        response = self.client.post(
            '/login',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))

        # password activated
        assert user.password_status == PASSWORD_STATUS['USED']
        # user ask for new password
        response = self.client.post(
            '/registration',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(len(json_response['password']), 6)

        password_3 = json_response['password']
        # check for new password was created
        assert password_3 != password_2

    def test_login_user(self):

        # user registration
        new_user = self.user_dict()
        response = self.client.post(
            '/registration',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        password = json_response['password']

        # login user that not exists in db
        wrong_user = self.wrong_user_dict()
        response = self.client.post(
            '/login',
            headers=self.get_api_headers(),
            data=json.dumps(wrong_user))
        self.assertEqual(response.status_code, 401)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['message'], 'User with MSISDN {} doesn\'t exist. Please register'
                         .format(wrong_user['msisdn']))

        # login user with wrong password
        new_user.update(password='111111')
        response = self.client.post(
            '/login',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 401)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['message'], 'Wrong credentials')

        # login user with correct password
        new_user.update(password=password)
        response = self.client.post(
            '/login',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['message'], 'Logged in as {}'.format(new_user['msisdn']))
        # in response there should be a dictionary with 3 keys:
        self.assertEqual(len(json_response), 3)

        # login user with used password
        response = self.client.post(
            '/login',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 401)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['message'], 'Your password is not valid. Please register again')

    def test_access_to_secret_resource(self):

        # user registration and login
        new_user = self.user_dict()
        response = self.client.post(
            '/registration',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        json_response = json.loads(response.get_data(as_text=True))
        new_user.update(password=json_response['password'])
        response = self.client.post(
            '/login',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))

        # access to secret resource with correct access token
        access_token = json.loads(response.get_data(as_text=True))['access_token']
        response = self.client.get(
            '/secret',
            headers=self.get_api_headers(token=access_token)
        )
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['message'], 'Secret resource is available')

        # access to secret resource with not correct access token
        response = self.client.get(
            '/secret',
            headers=self.get_api_headers())
        self.assertEqual(response.status_code, 422)

        # access to secret resource without access token
        headers = self.get_api_headers()
        del headers['Authorization']
        response = self.client.get(
            '/secret',
            headers=headers)
        self.assertEqual(response.status_code, 401)

    def test_refresh_token(self):

        # user registration and login
        new_user = self.user_dict()
        response = self.client.post(
            '/registration',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        json_response = json.loads(response.get_data(as_text=True))
        new_user.update(password=json_response['password'])
        response = self.client.post(
            '/login',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))

        # get access and refresh tokens
        access_token = json.loads(response.get_data(as_text=True))['access_token']
        refresh_token = json.loads(response.get_data(as_text=True))['refresh_token']

        # try to refresh access token with wrong refresh token
        wrong_refresh_token = refresh_token.replace(refresh_token[-3:], '111')
        response = self.client.post(
            '/refresh-token',
            headers=self.get_api_headers(token=wrong_refresh_token)
        )
        self.assertEqual(response.status_code, 422)

        # refresh access token
        response = self.client.post(
            '/refresh-token',
            headers=self.get_api_headers(token=refresh_token)
        )
        self.assertEqual(response.status_code, 200)
        new_access_token = json.loads(response.get_data(as_text=True))['access_token']
        # check we got new access token
        assert new_access_token != access_token

        # access to secret resource with new access token
        response = self.client.get(
            '/secret',
            headers=self.get_api_headers(token=new_access_token)
        )
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['message'], 'Secret resource is available')

    def test_logout(self):

        # user registration and login
        new_user = self.user_dict()
        response = self.client.post(
            '/registration',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))
        json_response = json.loads(response.get_data(as_text=True))
        new_user.update(password=json_response['password'])
        response = self.client.post(
            '/login',
            headers=self.get_api_headers(),
            data=json.dumps(new_user))

        # get access and refresh tokens
        access_token = json.loads(response.get_data(as_text=True))['access_token']
        refresh_token = json.loads(response.get_data(as_text=True))['refresh_token']

        # try to logout with wrong refresh token
        wrong_refresh_token = refresh_token.replace(refresh_token[-3:], '111')
        new_user.update(refresh_token=wrong_refresh_token)
        response = self.client.post(
            '/logout',
            headers=self.get_api_headers(token=access_token),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 422)

        # try to logout with wrong access token
        wrong_access_token = access_token.replace(access_token[-3:], '111')
        response = self.client.post(
            '/logout',
            headers=self.get_api_headers(token=wrong_access_token),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 422)

        # user logout
        new_user.update(refresh_token=refresh_token)
        response = self.client.post(
            '/logout',
            headers=self.get_api_headers(token=access_token),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['message'], 'Access and refresh tokens have been revoked')

        # user logout again
        response = self.client.post(
            '/logout',
            headers=self.get_api_headers(token=access_token),
            data=json.dumps(new_user))
        self.assertEqual(response.status_code, 401)

        # try to access to secret resource
        response = self.client.get(
            '/secret',
            headers=self.get_api_headers(token=access_token)
        )
        self.assertEqual(response.status_code, 401)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['msg'], 'Token has been revoked')

        # try to refresh access token
        response = self.client.post(
            '/refresh-token',
            headers=self.get_api_headers(token=refresh_token)
        )
        self.assertEqual(response.status_code, 401)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response['msg'], 'Token has been revoked')


if __name__ == '__main__':
    unittest.main()
