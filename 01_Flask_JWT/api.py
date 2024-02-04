'''

https://flask-httpauth.readthedocs.io/en/latest/

'''



from flask import Flask, request, jsonify , make_response , session, Response
import jwt   # pip install PyJWT
import datetime
from functools import wraps

from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
auth = HTTPBasicAuth()


users = {
    "paco": generate_password_hash("123123"),
    "perico": generate_password_hash("contraseña")
}


@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username



app.config['SECRET_KEY'] = 'this_is_secret'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') # http://127.0.0.1:5000/route?token=your_token

        if not token:
            return jsonify({'message': 'Token is missing! Use http://127.0.0.1:5000/route?token=<your_token>'}), 403

        try:
            
            print( 'This is your API_KEY: {}'.format(app.config['SECRET_KEY']) )
            print( 'This is your token: {}'.format(token) )
           
            data = jwt.decode(token, app.config['SECRET_KEY'] , algorithms=["HS256"])

            print('Hello: {}!'.format(data['user']))

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired, log in again'}), 403
        
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token. Please log in again.'}), 403


        return f(*args, **kwargs)
    
    return decorated
    




@app.route('/unprotected')
def unprotected():
    return jsonify({'message': 'Anyone can view this!'})

@app.route('/protected')
@token_required
def protected():
    return jsonify({'message': 'Success! This is only available for people with valid tokens.'})



@app.route('/')
@auth.login_required
def index():
            
    token = jwt.encode(
                {
                    'user': auth.current_user(),
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
                }, 

                app.config['SECRET_KEY'],
                algorithm="HS256"

            )
    

    return jsonify({'token' : token , 
                     'message': 'Hello, {}!'.format(auth.current_user())})

    #return "Hello, {}!".format(auth.current_user())



@app.route('/logout')
@auth.login_required
def logout():
    return Response('Logout', 401)






'''
@app.route('/login')
def login():

    auth = request.authorization

    if auth and auth.password == '123123':
        token = jwt.encode(
                {
                    'user': auth.username,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
                }, 

                app.config['SECRET_KEY'],
                algorithm="HS256"

            )
        
        
        return jsonify({'token' : token })
        
        # go to https://jwt.io/ to check your token
                
        # return "Hello, {}!".format(auth.username)
    
    else:
        return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

'''


if __name__ == '__main__':
    app.run(debug=True)
    