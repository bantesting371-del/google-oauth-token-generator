# app.py
import os
from flask import Flask, request, redirect, session, url_for, render_template, jsonify, make_response
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv

load_dotenv()

os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_NAME'] = 'session'
Session(app)

SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/drive.readonly'
]

def get_flow():
    creds_json = os.getenv('CREDENTIALS_JSON')
    if not creds_json:
        raise ValueError("CREDENTIALS_JSON environment variable not set")
    
    with open('/tmp/credentials.json', 'w') as f:
        f.write(creds_json)
    
    return Flow.from_client_secrets_file(
        '/tmp/credentials.json',
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    try:
        flow = get_flow()
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        session['state'] = state
        return redirect(auth_url)
    except Exception as e:
        return f"Login error: {str(e)}", 500

@app.route('/oauth2callback')
def oauth2callback():
    try:
        state = session.get('state')
        if not state:
            return "Session expired. Please login again.", 400
        
        flow = get_flow()
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        jwt_token = getattr(credentials, 'id_token', None)
        
        if jwt_token:
            try:
                request_session = google_requests.Request()
                id_token.verify_oauth2_token(
                    jwt_token, 
                    request_session, 
                    credentials.client_id
                )
            except Exception as e:
                return f"Token verification failed: {str(e)}", 400

        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        session['user_info'] = user_info
        session['jwt_token'] = jwt_token
        
        return render_template('token.html',
                             user_info=user_info,
                             jwt_token=jwt_token,
                             email=user_info.get('email'),
                             name=user_info.get('name'),
                             picture=user_info.get('picture'))
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/download/jwt')
def download_jwt():
    if 'jwt_token' not in session or not session['jwt_token']:
        return "No JWT token found. Please login again.", 400
    
    response = make_response(session['jwt_token'])
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = 'attachment; filename=token.jwt'
    return response

@app.route('/api/jwt')
def get_jwt_json():
    if 'jwt_token' not in session or not session['jwt_token']:
        return jsonify({'error': 'No JWT token found'}), 401
    
    return jsonify({
        'status': 'success',
        'jwt_token': session['jwt_token']
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
