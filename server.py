from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO, emit, disconnect
from datetime import datetime
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app)

# Store data in memory (in production, use a database)
users = {
    'alice': generate_password_hash('password123'),  # Test user 1
    'bob': generate_password_hash('password456')     # Test user 2
}
messages = []
online_users = set()
typing_users = set()

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password or not confirm_password:
            return render_template('register.html', error="Please fill all fields")
            
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")
            
        if username in users:
            return render_template('register.html', error="Username already exists")
            
        users[username] = generate_password_hash(password)
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error="Please fill all fields")
        
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        session.pop('username', None)
        online_users.discard(username)
        emit('user_status', {'user': username, 'status': 'offline'}, broadcast=True, namespace='/')
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        disconnect()
        return
    
    online_users.add(session['username'])
    emit('user_status', {'user': session['username'], 'status': 'online'}, broadcast=True)
    emit('online_users', list(online_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        online_users.discard(session['username'])
        typing_users.discard(session['username'])
        emit('user_status', {'user': session['username'], 'status': 'offline'}, broadcast=True)
        emit('online_users', list(online_users), broadcast=True)

@socketio.on('typing')
def handle_typing(data):
    username = session.get('username')
    if username:
        if data['typing']:
            typing_users.add(username)
        else:
            typing_users.discard(username)
        emit('typing_status', {'user': username, 'typing': data['typing']}, broadcast=True)

@socketio.on('message')
def handle_message(data):
    if 'username' not in session:
        return
    
    message_text = data.get('message', '').strip()
    
    # Message validation
    if not message_text or len(message_text) > 500:  # limit message length
        emit('error', {'message': 'Invalid message'})
        return
    
    message = {
        'text': message_text,
        'user': session['username'],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': 'user'
    }
    
    messages.append(message)
    emit('message', message, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)