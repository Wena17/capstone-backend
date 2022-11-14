from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import dotenv
import datetime
from flask_bcrypt import Bcrypt
import jwt

dotenv.load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{dbuser}:{dbpass}@{dbhost}/{dbname}'.format(
    dbuser=os.environ['DBUSER'],
    dbpass=os.environ['DBPASS'],
    dbhost=os.environ['DBHOST'],
    dbname=os.environ['DBNAME']
)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

db = SQLAlchemy(app)
migrate = Migrate(app, db, compare_type=True)
bcrypt = Bcrypt(app)

# TTN message types
JOIN_ACCEPT = 1

@app.route("/")
def show_homes():
    return render_template('home.html')

@app.route("/health")
def health_check():
    return "I'm fine"

@app.route('/messages')
def show_messages():
    msgs = DeviceMessage.query.order_by(DeviceMessage.ts).all()
    return render_template('messages.html', messages=msgs)

@app.route('/devices')
def show_devices():
    data = Device.query.order_by(Device.ts).all()
    return render_template('devices.html', devices=data)

@app.route('/devices/<string:dev_id>')
def show_device(dev_id):
    dev = Device.query.filter_by(dev_id=dev_id).first()
    return render_template('device.html', dev=dev)

@app.route('/registration/<string:dev_id>')
def show_registration(dev_id):
    return render_template('registration.html', dev_id=dev_id)

@app.route('/user')
def show_users():
    msgs = User.query.all()
    return render_template('user.html', users=msgs)

# IoT API

@app.route("/api/v1/register-device", methods=["POST"])
def register_device():
    data = request.json
    dev = Device(dev_id=data["dev_id"], lat=data["lat"], long=data["long"])
    db.session.add(dev)
    db.session.commit()
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/iot/uplinkMessage", methods=['POST'])
def uplinkMessage():
    msg = request.json
    print(f"---> Received uplink message: {msg}")
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/iot/normalizedUplink", methods=['POST'])
def normalizedUplink():
    msg = request.json
    print(f"---> Received normalized uplink: {msg}")
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/iot/joinAccept", methods=['POST'])
def joinAccept():
    msg = request.json
    # TODO: Only accept join requests from previouslz registered devices
    print(f"---> Received join accept: {msg}")
    if msg["end_device_ids"]["application_ids"]["application_id"] != "capstone-util-moni":
        return ("Wrong application ID", 403)
    else:
        dev_msg = DeviceMessage()
        dev_msg.dev_id = msg["end_device_ids"]["device_id"]
        dev_msg.msg_type = JOIN_ACCEPT
        db.session.add(dev_msg)
        db.session.commit()
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/iot/locationSolved", methods=['POST'])
def locationSolved():
    msg = request.json
    print(f"---> Received location solved: {msg}")
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/signup", methods=['POST'])
def signup():
    msg = request.json
    user = User.query.filter_by(email=msg.get('email')).first()
    if not user:
        try:
            user = User(msg["email"], msg["password"])
            user.accountId = msg["consumerAccountID"]
            user.firstname = msg["firstName"]
            user.lastname = msg["lastName"]
            user.phoneNo = msg["phoneNo"]
            db.session.add(user)
            db.session.commit()
            auth_token = user.encode_auth_token(user.id)
            responseObject = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token
            }
            return jsonify(responseObject), 201
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Some error occurred. Please try again.'
            }
            return jsonify(responseObject), 401
    else:
        responseObject = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return jsonify(responseObject), 202

@app.route("/api/v1/login", methods=['POST'])
def login():
    post_data = request.json
    try:
        # fetch the user data
        user = User.query.filter_by( email=post_data.get('email') ).first()
        if user and bcrypt.check_password_hash( user.password, post_data.get('password') ):
            auth_token = user.encode_auth_token(user.id)
            user_id = user.id
            if auth_token:
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token,
                    'user_id': user_id
                }
                return jsonify(responseObject), 200
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User does not exist.'
            }
            return jsonify(responseObject), 404
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return jsonify(responseObject), 500

@app.route("/api/v1/logout", methods=['POST'])
def logout():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            # mark the token as blacklisted
            blacklist_token = BlacklistToken(token=auth_token)
            try:
                # insert the token
                db.session.add(blacklist_token)
                db.session.commit()
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully logged out.'
                }
                return jsonify(responseObject), 200
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': e
                }
                return jsonify(responseObject), 200
        else:
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return jsonify(responseObject), 401
    else:
        responseObject = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return jsonify(responseObject), 403

@app.route("/api/v1/add-pinned-location", methods=['POST'])
def pinnedLocation():
    msg = request.json
    try:
        loc_msg = PinnedLocation()
        loc_msg.name = msg["name"]
        loc_msg.address = msg["address"]
        loc_msg.user_id = msg["user_id"]
        db.session.add(loc_msg)
        db.session.commit()
        responseObject = {
            'status': 'success',
            'message': 'Pinned location added successfully added.'
        }
        return jsonify(responseObject), 201
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.'
        }
        return jsonify(responseObject), 401

@app.route("/api/v1/view-pinned-location", methods=['POST'])
def viewPinnedLocation():
    post_data = request.json
    try:
        # fetch the user pinned location
        user = PinnedLocation.query.filter_by( user_id=post_data.get('user_id') ).first()
        if user:
            name = PinnedLocation.name
            address = PinnedLocation.address
            responseObject = {
                'status': 'success',
                'name': name,
                'address': address,
            }
            return jsonify(responseObject), 200
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Pinned location does not exist.'
            }
            return jsonify(responseObject), 404
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return jsonify(responseObject), 500

# Data model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    accountId = db.Column(db.Integer)
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    phoneNo = db.Column(db.String(15))
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now())
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, password, admin=False):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.admin = admin

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'), algorithms=["HS256"])
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token logged out. Please log in again.'
            else:
                print(payload)
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False

class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False

#IOT Data model

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dev_id = db.Column(db.String(32), index=True, nullable=False, unique=True)
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    ts = db.Column(db.DateTime, default=datetime.datetime.now)

class DeviceMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dev_id = db.Column(db.String(32), index=True, nullable=False)
    msg_type = db.Column(db.Integer)
    ts = db.Column(db.DateTime, default=datetime.datetime.now)

    def msg_type_name(self):
        if self.msg_type is None:
            return "No message type"
        else:
            names = ['Unknown Message', 'Join Accept']
            return names[self.msg_type]

#App Data Model

class PinnedLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    address = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
