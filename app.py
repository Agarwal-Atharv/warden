from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'guardianx_secret_key'
socketio = SocketIO(app, cors_allowed_origins='*')

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('alert')
def handle_alert(msg):
    print(f"[DASHBOARD] Alert received: {msg}")
    emit('alert', msg, broadcast=True)

if __name__ == '__main__':
    print("🚀 GuardianX Flask Dashboard running on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000)
