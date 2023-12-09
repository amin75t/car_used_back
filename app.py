from flask import Flask, jsonify, request
from flask_restful import Resource, Api
from pymongo import MongoClient
from bson import json_util
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from jwt.exceptions import ExpiredSignatureError

app = Flask(__name__)
api = Api(app)
CORS(app)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/car_used'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_COOKIE_SECURE'] = False
client = MongoClient(app.config['MONGO_URI'])
db = client.get_database()
jwt = JWTManager(app)


@jwt.expired_token_loader
def expired_token_callback(expired_token):
    return jsonify({"message": "Token has expired", "error": "token_expired"}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return (
        jsonify(
            {"message": "Signature verification failed", "error": "invalid_token"}
        ),
        401,
    )


@jwt.unauthorized_loader
def missing_token_callback(error):
    return (
        jsonify(
            {
                "message": "Request doesn't contain a valid token",
                "error": "authorization_header",
            }
        ),
        401,
    )


class cars_List(Resource):

    @jwt_required()
    def get(self):
        all_data_from_mongo = db.car.find()
        json_data = json_util.dumps(list(all_data_from_mongo))
        return jsonify(json.loads(json_data))


class specific_car(Resource):

    @jwt_required()
    def post(self):
        post_data = request.get_json()
        data_from_mongo = db.carProblems.find_one({'car_id': post_data["id"]})
        json_data = json_util.dumps(data_from_mongo)
        return jsonify(json.loads(json_data))


class UserLogin(Resource):

    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = db.user.find_one({'userName': username})

        if user and check_password_hash(user["pass"], password):
            access_token = create_access_token(identity=username)
            response = {
                'message': 'Login successful',
                'token': access_token
            }
            return response, 200
        else:
            return {'message': 'Invalid username or password'}, 401


class UserRegistration(Resource):

    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if db.user.find_one({'userName': username}):
            return {'message': 'Username already taken'}, 400

        hashed_password = generate_password_hash(password, method="pbkdf2")

        user_data = {'userName': username,
                     'pass': hashed_password, 'email': email}
        user_id = db.user.insert_one(user_data)
        access_token = create_access_token(identity=username)

        response = {
            'message': 'Registration successful',
            'token': access_token
        }
        return response, 201


class UserInfo(Resource):

    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        user_data = db.user.find_one({'userName': current_user})

        if user_data:
            safe_user_data = {
                'userName': user_data['userName'], 'email': user_data['email']}
            return safe_user_data, 200
        else:
            return {'message': 'User not found'}, 404


api.add_resource(UserLogin, '/login')
api.add_resource(UserRegistration, '/register')
api.add_resource(cars_List, "/getcars")
api.add_resource(specific_car, "/specificcar")
api.add_resource(UserInfo, '/userinfo')

if __name__ == "__main__":
    app.run(debug=True)
