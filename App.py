from flask import Flask, render_template, request, redirect, session
import Diffie_hellman as dh
import Totp as totp

app = Flask(__name__)
app.secret_key = "super_secure_bifrost_key"

# In a real app, this would be a real SQL Database
users_db = {} 

@app.route('/')
def home():
    return redirect('/signup')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        bob_public_key = int(request.form.get('bob_public_key'))
        
        # 1. Get Alice's Private/Public info from session
        alice_private = session.get('alice_private')
        
        # 2. Compute the Shared Secret
        shared_secret = dh.compute_shared_secret(bob_public_key, alice_private, dh.P)
        
        # 3. Save User to "Database"
        users_db[username] = {
            'password': password,
            'shared_secret': shared_secret
        }
        return "Signup Successful! Now go to /login"

    # For GET: Generate Alice's keys for the exchange
    alice_private, alice_public = dh.generate_keys()
    session['alice_private'] = alice_private
    return render_template('signup.html', alice_public=alice_public)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_otp = request.form.get('otp')

        if username in users_db and users_db[username]['password'] == password:
            # Verify the TOTP code
            expected_otp = totp.generate_totp(users_db[username]['shared_secret'])
            if user_otp == expected_otp:
                return f"<h1>Welcome, {username}! Access Granted.</h1>"
            return "Invalid TOTP Code!"
        return "Invalid Credentials!"
        
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)