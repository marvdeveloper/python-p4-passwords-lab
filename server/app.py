from flask import Flask, request, session, jsonify
from flask_restful import Api, Resource
from models import db, User
from config import app, db, api, bcrypt

# Allow credentials for session cookies
from flask_cors import CORS
CORS(app, supports_credentials=True)


class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {"error": "Username and password required"}, 400

        # Use setter to avoid hybrid property error
        new_user = User(username=username)
        new_user.password_hash = password

        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        return new_user.to_dict(), 201


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 204


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        return {}, 204


# Register resources
api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(CheckSession, '/check_session')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
