import os
import json
import pickle
import base64
from datetime import datetime
from flask import Flask, request, redirect, session, url_for, render_template, jsonify, make_response
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
Session(app)

# OAuth Configuration
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/drive.readonly'
]

def get_flow():
    """Create OAuth flow with credentials from file or env"""
    if os.getenv('CREDENTIALS_JSON'):
        creds_data = json.loads(os.getenv('CREDENTIALS_JSON'))
        with open('/tmp/credentials.json', 'w') as f:
            json.dump(creds_data, f)
        creds_file = '/tmp/credentials.json'
    else:
        creds_file = 'credentials.json'
    
    return Flow.from_client_secrets_file(
        creds_file,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login')
def login():
    """Start OAuth flow"""
    flow = get_flow()
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth callback and generate token"""
    try:
        state = session.get('state')
        flow = get_flow()
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        
        # Get user info
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        # Store credentials in session
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
        
        # Generate token.pickle (base64 encoded)
        token_data = {
            'credentials': creds_dict,
            'user_info': user_info,
            'generated_at': datetime.utcnow().isoformat()
        }
        
        pickle_bytes = pickle.dumps(token_data)
        token_b64 = base64.b64encode(pickle_bytes).decode('utf-8')
        
        # Generate JWT-style token (like in your example)
        jwt_token = generate_jwt_style_token(user_info, creds_dict)
        
        return render_template('token.html',
                             user_info=user_info,
                             token_b64=token_b64,
                             jwt_token=jwt_token,
                             email=user_info.get('email'),
                             name=user_info.get('name'),
                             picture=user_info.get('picture'))
    
    except Exception as e:
        return render_template('error.html', error=str(e)), 400

@app.route('/download/pickle')
def download_pickle():
    """Download token.pickle file"""
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

@app.route('/download/jwt')
def download_jwt():
    """Download JWT token as text file"""
    if 'credentials' not in session:
        return redirect('/')
    
    jwt_token = generate_jwt_style_token(
        session.get('user_info', {}),
        session.get('credentials', {})
    )
    
    response = make_response(jwt_token)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = 'attachment; filename=token.jwt'
    return response

@app.route('/api/token')
def get_token_json():
    """Get token as JSON API"""
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated', 'status': 401}), 401
    
    return jsonify({
        'status': 'success',
        'user': session.get('user_info', {}),
        'credentials': session.get('credentials', {}),
        'token_type': 'OAuth 2.0',
        'generated_at': datetime.utcnow().isoformat()
    })

@app.route('/api/jwt')
def get_jwt():
    """Get JWT-style token as JSON"""
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    jwt_token = generate_jwt_style_token(
        session.get('user_info', {}),
        session.get('credentials', {})
    )
    
    return jsonify({
        'token': jwt_token,
        'type': 'JWT-style',
        'user': session.get('user_info', {}).get('email')
    })

@app.route('/logout')
def logout():
    """Clear session and logout"""
    session.clear()
    return redirect('/')

def generate_jwt_style_token(user_info, credentials):
    """Generate a JWT-style token similar to your example"""
    import hashlib
    import time
    
    # Create header (base64)
    header = {
        "alg": "RS256",
        "kid": hashlib.md5(f"{user_info.get('email')}".encode()).hexdigest()[:16],
        "typ": "JWT"
    }
    
    # Create payload
    payload = {
        "iss": "https://accounts.google.com",
        "azp": credentials.get('client_id', ''),
        "aud": credentials.get('client_id', ''),
        "sub": user_info.get('id', ''),
        "email": user_info.get('email', ''),
        "email_verified": True,
        "name": user_info.get('name', ''),
        "picture": user_info.get('picture', ''),
        "given_name": user_info.get('given_name', ''),
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    
    # Encode header and payload to base64url
    import base64
    import json
    
    def b64url_encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
    
    header_b64 = b64url_encode(header)
    payload_b64 = b64url_encode(payload)
    
    # Since we don't have private key, we'll use a placeholder signature
    # This is just for display - real Google JWT uses RS256 with Google's private key
    signature = hashlib.sha256(f"{header_b64}.{payload_b64}".encode()).hexdigest()
    signature_b64 = base64.urlsafe_b64encode(signature.encode()).decode().rstrip('=')
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
