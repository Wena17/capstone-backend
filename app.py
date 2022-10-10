from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import dotenv
import datetime

dotenv.load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{dbuser}:{dbpass}@{dbhost}/{dbname}'.format(
    dbuser=os.environ['DBUSER'],
    dbpass=os.environ['DBPASS'],
    dbhost=os.environ['DBHOST'],
    dbname=os.environ['DBNAME']
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

JOIN_ACCEPT = 1

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

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
    if msg["end_device_ids"]["application_ids"]["application_id"] != "wena-util-moni":
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

# Data model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))

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
