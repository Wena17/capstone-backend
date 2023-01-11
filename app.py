from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import select, func, desc
import os
import dotenv
import datetime
from flask_bcrypt import Bcrypt
import jwt
import base64
import struct
import geoalchemy2
import requests
import json
from geopy.geocoders import GoogleV3

import logging
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

dotenv.load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{dbuser}:{dbpass}@{dbhost}/{dbname}'.format(
    dbuser=os.environ['DBUSER'],
    dbpass=os.environ['DBPASS'],
    dbhost=os.environ['DBHOST'],
    dbname=os.environ['DBNAME']
)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['GOOGLE_KEY'] = os.environ['GOOGLE_KEY']
app.config['VCODE'] = os.environ['VCODE']


def include_object(object, name, type_, *args, **kwargs):
    return not (type_ == 'table' and name in ['spatial_ref_sys'])


db = SQLAlchemy(app)
migrate = Migrate(app, db, compare_type=True, include_object=include_object)
bcrypt = Bcrypt(app)

# TTN message types
JOIN_ACCEPT = 1


@app.route("/health")
def health_check():
    return "I'm fine"


# SITE ROUTES

@app.route("/")
def show_homes():
    return render_template('home.html')


@app.route("/landing_page")
def show_landing():
    return render_template('landing.html')


@app.route("/logout")
def show_logout():
    session.clear()
    return render_template('home.html')


@app.route("/add_admin")
def show_addAdmin():
    return render_template('addAdmin.html')


@app.route("/add-technician")
def show_add_technician():
    return render_template('addTechnician.html')

    
@app.route('/verify')
def show_verified():
    if(session['isSuperAdmin']):
        return render_template('verification.html')
    else:
        return render_template('landing.html')

        
@app.route("/price")
def show_dev_price():
    return render_template('newPrice.html')
    
# SITE RETURN DATA
    
@app.route('/messages')
def show_messages():
    msgs = DeviceMessage.query.order_by(desc(DeviceMessage.ts)).all()
    return render_template('messages.html', messages=msgs)


@app.route("/order-device")
def show_order_device():
    price = Price.query.order_by(desc(Price.ts)).first()
    return render_template('orderDevice.html', price=price)
    

@app.route("/orders")
def show_orders():
    order = Order.query.order_by(desc(Order.ts)).all()
    return render_template('orders.html', orders=order)


@app.route('/outages')
def show_outages():
    # TODO get the device owner
    out = Outage.query.order_by(desc(Outage.start_time)).all()
    return render_template('outages.html', outages=out)


@app.route('/scheduledOutages')
def show_scheduleoutages():
    # TODO display technician name
    out = ScheduleOutages.query.order_by(desc(ScheduleOutages.start)).all()
    return render_template('scheduledOutages.html', schedoutages=out)


@app.route('/client')
def show_clients():
    clients = User.query.filter_by(admin=True).order_by(desc(User.id)).all()
    return render_template('client.html', client=clients)


@app.route('/devices')
def show_devices():
    data = Device.query.order_by(Device.ts).all()
    return render_template('devices.html', devices=data)


@app.route('/devices/<string:dev_id>')
def show_device(dev_id):
    dev = Device.query.filter_by(dev_id=dev_id).first()
    return render_template('device.html', dev=dev)


@app.route('/registration/<int:dev_id>/user/<int:user_id>')
def show_registration(dev_id, user_id):
    if user_id is None:
        return 'Not logged in', 403
    return render_template('registration.html', dev_id=dev_id, user_id=user_id)


@app.route('/user')
def show_users():
    msgs = User.query.order_by(User.id).all()
    return render_template('user.html', users=msgs)


@app.route('/prices')
def show_prices():
    prc = Price.query.order_by(desc(Price.ts)).all()
    return render_template('prices.html', prices=prc)
    

@app.route('/feedback')
def show_feedback():
    data = Feedback.query.order_by(Feedback.ts).all()
    return render_template('feedback.html', feedback=data)


@app.route('/api/v1/verified-admin/<string:id>')
def verified(id):
    if(app.config.get('VCODE') == id):
        session['verified'] = True
        return render_template('landing.html')
    else:
        session.clear()
        error = 'Incorrect verification code'
        return render_template('home.html', error= error)
        

@app.route('/outage/<int:id>')
def show_outage_details(id):
    outage = Outage.query.get(id)
    if outage:
        return render_template('outage_detail.html', outage=outage)
    else:
        return '', 404

# SITE POST OR GET DATA

@app.route("/api/v1/new-price", methods=['POST'])
def price():
    msg = request.json
    try:
        price = Price()
        price.price = msg["price"]
        db.session.add(price)
        db.session.commit()
        responseObject = {
            'status': 'success'
        }
        return jsonify(responseObject), 201
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail'
        }
        return jsonify(responseObject), 401


@app.route("/api/v1/devices", methods=['GET'])
def show_devices_on_map():
    args = request.args
    lat = args.get('lat', type=float)
    long = args.get('long', type=float)
    lat_delta = args.get('lat_delta', type=float, default=0.1)
    long_delta = args.get('long_delta', type=float, default=0.1)
    if lat is not None and long is not None:
        lat1 = lat - lat_delta
        lat2 = lat + lat_delta
        long1 = long - long_delta
        long2 = long + long_delta
        poly = func.ST_SetSRID(func.ST_MakeEnvelope(
            long1, lat1, long2, lat2), 4326)
        devs = db.session.query(Device).filter(
            Device.geom.intersects(poly)).all()
        dev_ids = [d.id for d in devs]
        print(f"Devices in range: {len(devs)}")
        outages = db.session.query(Outage).filter(Outage.dev_id.in_(dev_ids), Outage.end_time == None).all()
        print(f"Related outages: {len(outages)}")
        dev_out = [o.dev_id for o in outages]
        result = {"devices": [
            {"id": dev.id, "lat": dev.lat, "lng": dev.long, "outage": (dev.id in dev_out) } for dev in devs]}
        return jsonify(result), 200
    else:
        return jsonify(message="No map region provided"), 403


@app.route("/api/v1/restoration/<int:id>", methods=['GET', 'PUT'])
def restore(id):
    res = Outage.query.filter_by(id=id).first()
    if res is not None:
        if request.method == 'GET':
            return render_template('/addOutageDetails.html', outage=res)
        else:
            msg = request.json
            end = msg["endDate"] + " " + msg["endTime"]
            end_time = datetime.datetime.strptime(end, '%Y-%m-%d %H:%M')
            try:            
                res.outage_reason = msg["reason"]
                res.est_end_time = end_time
                db.session.add(res)
                db.session.commit()
                notify_users(res, "Outage estimated restoration time")
                responseObject = {
                    'status': 'success'
                }
                return jsonify(responseObject), 201
            except Exception as e:
                print(e)
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return jsonify(responseObject), 500


@app.route("/api/v1/device_order", methods=['POST'])
def device_order():
    msg = request.json
    user_id = msg["user_id"]
    user = User.query.filter_by(id=user_id).first()
    if user:
        try:
            order = Order()
            order.quantity = msg["quantity"]
            order.price = msg["price"]
            order.total = msg["total"]
            order.user_id = user_id
            db.session.add(order)
            db.session.commit()
            responseObject = {
                'status': 'success'
            }
            return jsonify(responseObject), 201
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail'
            }
            return jsonify(responseObject), 401
    else:
            responseObject = {
                'status': 'fail',
                'message': 'User does not exist.'
            }
            return jsonify(responseObject), 404

# IoT API


@app.route("/api/v1/register-device", methods=["POST"])
def register_device():
    # TODO: Give device an owner
    data = request.json
    dev = Device.query.filter_by(dev_id=data["dev_id"]).first()
    if dev == None:
        (lat, long) = (data["lat"], data["long"])        
        dev = Device(dev_id=data["dev_id"], lat=lat,
                     long=long, geom=f"SRID=4326;POINT({long} {lat})", owner_id=data["owner_id"])
        db.session.add(dev)
        db.session.commit()
        return jsonify(success=True), 201
    else:
        return jsonify(success=False, message="Device ID already registered"), 403


@app.route("/api/v1/iot/uplinkMessage", methods=['POST'])
def uplinkMessage():
    msg = request.json
    print(f"---> Received uplink message: {msg}")
    if msg["end_device_ids"]["application_ids"]["application_id"] != "wena-util-moni":
        return ("Wrong application ID", 403)
    voltage = float(base64.b64decode(msg["uplink_message"]["frm_payload"]))
    voltage = round(voltage, 2)
    print(f"Voltage: {voltage}")
    dev = Device.query.filter_by(
        dev_id=msg["end_device_ids"]["device_id"]).first()
    if dev == None:
        return ("Unknown device ID", 404)
    out = Outage.query.filter_by(dev_id=dev.id, end_time=None).order_by(
        Outage.start_time.desc()).first()
    print(f"---> Outage found: {out}")
    
    # geocoding
    geolocator = GoogleV3(api_key=app.config.get('GOOGLE_KEY'))
    lat = float(dev.lat)
    long = float(dev.long)
    locations = geolocator.reverse(f'{lat}, {long}')
    if locations:
        print(locations)  

    if out == None and voltage < 10.0:  # New outage
        out = Outage()
        
        out.voltage = voltage
        out.dev_id = dev.id
        out.lat = dev.lat
        out.long = dev.long
        out.geom = dev.geom
        out.address = str(locations)
        out.user_id = dev.owner_id
        db.session.add(out)
        db.session.commit()
        notify_users(out, "Outage detected!")
    elif out != None and voltage > 100.0:  # Existing outage ended
        out.end_time = datetime.datetime.now()
        db.session.add(out)
        db.session.commit()
        notify_users(out, "Outage ended")
    else:  # Either outage has not ended or no new outage began
        return ('', 204)
    resp = jsonify(success=True, outage_id=out.id)  # { "success": true }
    return resp, 200


@app.route("/api/v1/iot/normalizedUplink", methods=['POST'])
def normalizedUplink():
    msg = request.json
    print(f"---> Received normalized uplink: {msg}")
    resp = jsonify(success=True)  # { "success": true }
    return resp


@app.route("/api/v1/iot/joinAccept", methods=['POST'])
def joinAccept():
    msg = request.json
    # TODO: Only accept join requests from previously registered devices
    print(f"---> Received join accept: {msg}")
    if msg["end_device_ids"]["application_ids"]["application_id"] != "wena-util-moni":
        return ("Wrong application ID", 403)
    else:
        dev_msg = DeviceMessage()
        dev_msg.dev_id = msg["end_device_ids"]["device_id"]
        dev_msg.msg_type = JOIN_ACCEPT
        db.session.add(dev_msg)
        db.session.commit()
    resp = jsonify(success=True)  # { "success": true }
    return resp


@app.route("/api/v1/iot/locationSolved", methods=['POST'])
def locationSolved():
    msg = request.json
    print(f"---> Received location solved: {msg}")
    resp = jsonify(success=True)  # { "success": true }
    return resp



@app.route("/api/v1/users/<int:id>", methods=['PUT', 'GET'])
def users(id):
    user_id = User.decode_auth_token(getAuthToken(request))
    if not user_id or user_id != id:
        return '', 403
    user = User.query.filter_by(id=id).first()
    if not user:
        return '', 404
    if request.method == 'PUT':
        msg = request.json
        try:
            user.firstname = msg["firstName"]
            user.lastname = msg["lastName"]
            user.phoneNo = msg["phoneNo"]
            db.session.add(user)
            db.session.commit()
            return '', 204
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Some error occurred. Please try again.'
            }
            return jsonify(responseObject), 500
    else:
        return jsonify({'user_id': user.id, 'password': user.password, 'firstName': user.firstname, 'lastName': user.lastname, "phoneNo": user.phoneNo}), 200




@app.route("/api/v1/signup", methods=['POST'])
def signup():
    msg = request.json
    user = User.query.filter_by(email=msg.get('email')).first()
    isAdmin = msg["admin"]
    isTechnician = msg['technician']
    if not user:
        try:
            user = User(msg["email"], msg["password"])
            user.firstname = msg["firstName"]
            user.lastname = msg["lastName"]
            user.phoneNo = msg["phoneNo"]          
            if not isAdmin and not isTechnician:
                user.accountId = msg["consumerAccountID"]
                user.lat = msg['lat']
                user.long = msg['lng']
                user.geom = f"SRID=4326;POINT({msg['lng']} {msg['lat']})"
            elif isAdmin:
                user.company = msg["company"]
                user.tinNumber = msg["tinNumber"]
                user.admin = isAdmin  
            elif isTechnician:
                user.technician = isTechnician
            db.session.add(user)
            db.session.commit()
            auth_token = user.encode_auth_token(user.id)            
            session['user_id'] = user.id
            responseObject = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token,
                'user_id': user.id
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
        ensure_super_admin()
        user = User.query.filter_by(email=post_data.get('email')).first()
        if user and bcrypt.check_password_hash(user.password, post_data.get('password')):
            auth_token = user.encode_auth_token(user.id)
            user_id = user.id
            firstname = user.firstname
            t = post_data.get('pushToken')
            if t is not None and t is not user.pushToken:
                user.pushToken = t
                db.session.add(user)
                db.session.commit()
            if auth_token:
                session['isAdmin'] = user.admin                
                session['isSuperAdmin'] = user.superadmin
                session['name'] = firstname
                session['user_id'] = user_id
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token,
                    'user_id': user_id,
                    'fname': firstname,
                    'technician': user.technician
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
    user_id = User.decode_auth_token(msg["authToken"])
    try:
        loc_msg = PinnedLocation()
        loc_msg.name = msg["name"]
        loc_msg.address = msg["address"]
        loc_msg.user_id = user_id
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


def getAuthToken(req):
    auth = request.headers.get('Authorization')
    return auth.split(" ")[1]


@app.route("/api/v1/pinned-locations", methods=['GET'])
def viewPinnedLocation():
    try:
        # fetch the user pinned location
        auth = request.headers.get('Authorization')
        token = auth.split(" ")[1]
        user_id = User.decode_auth_token(token)
        query = select(PinnedLocation.id, PinnedLocation.name,
                       PinnedLocation.address).filter_by(user_id=user_id)
        exists = db.session.execute(query).all()
        print("Exists: " + str(exists))
        # TODO return array of the response
        locs = [{'id': id, 'name': name, 'address': address}
                for (id, name, address) in exists]
        responseObject = {
            'status': 'success',
            'locations': locs
        }
        return jsonify(responseObject), 200
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return jsonify(responseObject), 500


@app.route("/api/v1/pinned-location/<id>", methods=['DELETE'])
def delete_pinned_location(id):
    user_id = User.decode_auth_token(getAuthToken(request))
    if not isinstance(user_id, int):
        return '', 403
    loc = PinnedLocation.query.filter_by(id=id, user_id=user_id).first()
    if loc:
        db.session.delete(loc)
        db.session.commit()
        return '', 204
    else:
        responseObject = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.'
        }
        return jsonify(responseObject), 404


@app.route("/api/v1/add-alternative-power-source", methods=['POST'])
def AlternativePowerSource():
    msg = request.json
    user_id = User.decode_auth_token(msg["authToken"])
    exist = AlternativePowerSource.query.filter_by(user_id=user_id).first()
    try:
        if not exist:
            src_msg = AlternativePowerSource()
            src_msg.name = msg["name"]
            src_msg.address = msg["address"]
            src_msg.payment = msg["payment"]
            src_msg.geom = f"SRID=4326;POINT({msg['lng']} {msg['lat']})"
            src_msg.user_id = user_id
            db.session.add(src_msg)
            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'Alternative power source added successfully added.'
            }
            return jsonify(responseObject), 201
        else:
            return 'Posted alternative power source already exist ', 403
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.'
        }
        return jsonify(responseObject), 401


@app.route("/api/v1/posted-alternative-ps", methods=['GET'])
def viewPostedAlternativePS():
    try:
        auth = request.headers.get('Authorization')
        token = auth.split(" ")[1]
        user_id = User.decode_auth_token(token)
        query = select(AlternativePowerSource.id, AlternativePowerSource.name,
                       AlternativePowerSource.address, AlternativePowerSource.payment).filter_by(user_id=user_id)
        exists = db.session.execute(query).all()
        print("Exists: " + str(exists))
        # TODO return array of the response
        posted = [{'id': id, 'name': name, 'address': address, 'payment': payment}
                for (id, name, address, payment) in exists]
        responseObject = {
            'status': 'success',
            'Posted': posted
        }
        return jsonify(responseObject), 200
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return jsonify(responseObject), 500


@app.route("/api/v1/nearby-alternative-ps", methods=['GET'])
def viewNearbyAlternativePS():
    try:
        auth = request.headers.get('Authorization')
        token = auth.split(" ")[1]
        user_id = User.decode_auth_token(token)
        query = select(AlternativePowerSource.id, AlternativePowerSource.name,
                       AlternativePowerSource.address, AlternativePowerSource.payment).filter(AlternativePowerSource.user_id != user_id, func.ST_DWithin(User.geom, AlternativePowerSource.geom, 10000))
        exists = db.session.execute(query).all()
        nearby = [{'id': id, 'name': name, 'address': address, 'payment': payment}
                for (id, name, address, payment) in exists]
        responseObject = {
            'status': 'success',
            'Posted': nearby
        }
        return jsonify(responseObject), 200
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return jsonify(responseObject), 500


@app.route("/api/v1/alternative-power-source/<id>", methods=['DELETE'])
def delete_alternative_ps(id):
    user_id = User.decode_auth_token(getAuthToken(request))
    if not isinstance(user_id, int):
        return '', 403
    aps = AlternativePowerSource.query.filter_by(id=id, user_id=user_id).first()
    if aps:
        db.session.delete(aps)
        db.session.commit()
        return '', 204
    else:
        responseObject = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.'
        }
        return jsonify(responseObject), 404


@app.route("/api/v1/add-schedule-outage", methods=['POST'])
def ScheduleOutage():
    msg = request.json
    user_id = User.decode_auth_token(msg["authToken"])
    start = msg["startDate"] + " " + msg["startTime"]
    print("Start: " + start)
    start_date_time = datetime.datetime.strptime(start, '%Y-%m-%d %H:%M')
    end = msg["endDate"] + " " + msg["endTime"]
    end_date_time = datetime.datetime.strptime(end, '%Y-%m-%d %H:%M')
    try:
        sched_msg = ScheduleOutages()
        sched_msg.purpose = msg["purpose"]
        sched_msg.Location = msg["location"]
        sched_msg.start = start_date_time
        sched_msg.end = end_date_time
        sched_msg.lat = msg["lat"]
        sched_msg.long = msg["long"]
        sched_msg.user_id = user_id
        db.session.add(sched_msg)
        db.session.commit()
        responseObject = {
            'status': 'success',
            'message': 'Schedule outage added successfully added.'
        }
        return jsonify(responseObject), 201
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.'
        }
        return jsonify(responseObject), 401


@app.route("/api/v1/restoration-details/<int:dev_id>", methods=['GET'])
def restoration(dev_id):
    try:
        query = select(Outage.outage_reason, Outage.est_end_time).filter_by(dev_id=dev_id, end_time=None)
        exists = db.session.execute(query).all()
        print("Exists: " + str(exists))
        # TODO return array of the response
        details = [{'reason': outage_reason, 'est_end_time': est_end_time}
                for (outage_reason, est_end_time) in exists]
        responseObject = {
            'status': 'success',
            'Details': details
        }
        return jsonify(responseObject), 200
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return jsonify(responseObject), 500


@app.route("/api/v1/notification", methods=['GET'])
def viewNotification():
    try:
        auth = request.headers.get('Authorization')
        token = auth.split(" ")[1]
        user_id = User.decode_auth_token(token)
        query = select(Notification.id, Notification.message,
                       Notification.title, Notification.ts).filter_by(user_id=user_id, status=0).order_by(Notification.ts)
        exists = db.session.execute(query).all()
        print("Exists: " + str(exists))
        notif = [{'id': id, 'message': message, 'title': title, 'ts': ts}
                for (id, message, title, ts) in exists]
        responseObject = {
            'status': 'success',
            'Notif': notif
        }
        return jsonify(responseObject), 200
    except Exception as e:
        print(e)
        responseObject = {
            'status': 'fail',
            'message': 'Try again'
        }
        return jsonify(responseObject), 500


@app.route("/api/v1/notifications/<int:id>", methods=['PUT'])
def notif(id):
    notif = Notification.query.filter_by(id=id).first()
    if notif is not None:
        try:
            notif.status = 1
            db.session.add(notif)
            db.session.commit()
            responseObject = {
                'status': 'success'
            }
            return jsonify(responseObject), 201
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Some error occurred. Please try again.'
            }
            return jsonify(responseObject), 500


@app.route("/api/v1/outage-manual-reporting", methods=['POST'])
def outageManualReporting():
    auth = request.headers.get('Authorization')
    token = auth.split(" ")[1]
    user_id = User.decode_auth_token(token)
    user = User.query.filter_by(id=user_id).first()
    if user:
        try:
            out = Outage()
            out.lat = user.lat
            out.long = user.long
            out.geom = user.geom
            out.outage_type = 1
            out.user_id = user_id
            db.session.add(out)
            db.session.commit()
            notify_users(out, "Outage reported by user")
            responseObject = {
                'status': 'success',
                'message': 'Reporting outage succesfully sent'
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
                'message': 'User not found.'
            }
        return jsonify(responseObject), 404



@app.route("/api/v1/feedback", methods=['POST'])
def feedback():
    msg = request.json
    auth = request.headers.get('Authorization')
    token = auth.split(" ")[1]
    user_id = User.decode_auth_token(token)
    user = User.query.filter_by(id=user_id).first()
    if user:
        try:
            feed = Feedback()
            feed.message = msg["message"]
            feed.user_id = user_id
            db.session.add(feed)
            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'Thank you for the feedback.'
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
                'message': 'Some error occurred. Please try again.'
            }
        return jsonify(responseObject), 404


@app.route("/api/v1/outage-history", methods=['GET'])
def history():    
    auth = request.headers.get('Authorization')
    token = auth.split(" ")[1]
    user_id = User.decode_auth_token(token)
    dev_query = select(Device.id).filter_by(owner_id=user_id)
    dev_id = db.session.execute(dev_query).first()
    print("-----> Device ID: " + str(dev_id))
    if dev_id:
        try:
            query = select(Outage.id, Outage.start_time, Outage.end_time, Outage.address, Outage.outage_reason, Outage.outage_type).filter_by(dev_id=dev_id.id)
            exists = db.session.execute(query).all()
            print("Exists: " + str(exists))
            # TODO return array of the response
            history = [{'id': id, 'start': start_time, 'end': end_time, 'address': address, 'reason': outage_reason, 'type': outage_type}
                    for (id, start_time, end_time, address, outage_reason, outage_type) in exists]
            responseObject = {
                'status': 'success',
                'History': history
            }
            return jsonify(responseObject), 200
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return jsonify(responseObject), 500
    else:
        responseObject = {
                'status': 'fail',
                'message': 'Device not found'
            }
        return jsonify(responseObject), 404

# Data model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    accountId = db.Column(db.String(100))
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    company = db.Column(db.String(100))
    tinNumber = db.Column(db.String(100))
    phoneNo = db.Column(db.String(15))
    pushToken = db.Column(db.String(100))
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    geom = db.Column(geoalchemy2.types.Geometry(
        geometry_type="POINT", srid=4326, spatial_index=True))
    registered_on = db.Column(
        db.DateTime, nullable=False, default=datetime.datetime.now())
    technician = db.Column(db.Boolean, nullable=False, default=False)
    superadmin = db.Column(db.Boolean, nullable=False, default=False)
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
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=150000),
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
            payload = jwt.decode(auth_token, app.config.get(
                'SECRET_KEY'), algorithms=["HS256"])
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

# IOT Data model

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dev_id = db.Column(db.String(32), index=True, nullable=False, unique=True)
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    geom = db.Column(geoalchemy2.types.Geometry(
        geometry_type="POINT", srid=4326, spatial_index=True))
    ts = db.Column(db.DateTime, default=datetime.datetime.now)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))


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


class Outage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.datetime.now)
    end_time = db.Column(db.DateTime)
    est_end_time = db.Column(db.DateTime)
    outage_type = db.Column(db.Integer, default=0)
    outage_reason = db.Column(db.String(255))
    voltage = db.Column(db.Float)
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    geom = db.Column(geoalchemy2.types.Geometry(
        geometry_type="POINT", srid=4326, spatial_index=True))
    address = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dev_id = db.Column(db.Integer, db.ForeignKey('device.id'))


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer)
    price = db.Column(db.Integer)
    total = db.Column(db.Integer)
    status = db.Column(db.Integer, default=0)
    ts = db.Column(db.DateTime, default=datetime.datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Price(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.Integer)
    ts = db.Column(db.DateTime, default=datetime.datetime.now)

# App Data Model


class PinnedLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    address = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class AlternativePowerSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    address = db.Column(db.String(255))
    payment = db.Column(db.String(50))
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    geom = db.Column(geoalchemy2.types.Geometry(
        geometry_type="POINT", srid=4326, spatial_index=True))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class ScheduleOutages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    purpose = db.Column(db.String(255))
    Location = db.Column(db.String(255))
    start = db.Column(db.DateTime, default=datetime.datetime.now)
    end = db.Column(db.DateTime)
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    geom = db.Column(geoalchemy2.types.Geometry(
        geometry_type="POINT", srid=4326, spatial_index=True))
    status = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255))
    title = db.Column(db.String(255))
    status = db.Column(db.Integer, default=0)
    ts = db.Column(db.DateTime, default=datetime.datetime.now)
    out_id = db.Column(db.Integer, db.ForeignKey('outage.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255))    
    ts = db.Column(db.DateTime, default=datetime.datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



def ensure_super_admin():
    s = User.query.filter_by(email=os.getenv("SUPER_ADMIN")).first()
    if s is None:
        print("Creating super admin")
        user = User(os.getenv("SUPER_ADMIN"), os.getenv("SUPER_PW"))
        user.geom = f"SRID=4326;POINT(0 0)"
        user.superadmin = True
        db.session.add(user)
        db.session.commit()

def notify_users(outage, msg):
    users = User.query.filter(User.pushToken.isnot(None)).filter(func.ST_DWithin(User.geom, outage.geom, 10000)).all() 
    title = "UtilityTracker"
    print(f"Found {len(users)} users in range.")
    for u in users:
        print(f"Sending notification to {u.email}")
        notif = Notification()
        notif.message = msg
        notif.title = title
        notif.out_id = outage.id
        notif.user_id = u.id
        db.session.add(notif)
        db.session.commit()
        print("Notif save!")
        requests.post("https://exp.host/--/api/v2/push/send",  json={"to": u.pushToken, "title": title, "body": msg} )