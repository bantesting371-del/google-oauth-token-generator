import os
import json
import pickle
import base64
from datetime import datetime
from flask import Flask, request, redirect, session, url_for, render_template, jsonify, make_response
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from dotenv import load_dotenv

load_dotenv()

# Google sometimes returns scopes in a different order, or silently adds
# 'openid' when email/profile scopes are requested. Without this, the
# oauthlib library raises a hard error on any such mismatch and the whole
# callback crashes with "Scope has changed from X to Y".
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
    """Create OAuth flow with credentials from env"""
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
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        creds_dict = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'expiry': credentials.expiry.isoformat() if credentials.expiry else None
        }
        
        session['credentials'] = creds_dict
        session['user_info'] = user_info
        
        token_data = {
            'credentials': creds_dict,
            'user_info': user_info,
            'generated_at': datetime.utcnow().isoformat()
        }
        
        pickle_bytes = pickle.dumps(token_data)
        token_b64 = base64.b64encode(pickle_bytes).decode('utf-8')
        
        return render_template('token.html',
                             user_info=user_info,
                             token_b64=token_b64,
                             email=user_info.get('email'),
                             name=user_info.get('name'),
                             picture=user_info.get('picture'))
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/download/pickle')
def download_pickle():
    if 'credentials' not in session:
        return redirect('/')
    
    token_data = {
        'credentials': session['credentials'],
        'user_info': session.get('user_info', {})
    }
    
    pickle_data = pickle.dumps(token_data)
    response = make_response(pickle_data)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Disposition'] = 'attachment; filename=token.pickle'
    return response

@app.route('/api/token')
def get_token_json():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'status': 'success',
        'user': session.get('user_info', {}),
        'credentials': session.get('credentials', {})
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
