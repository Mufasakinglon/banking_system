from flask import Flask, render_template, request, redirect, url_for, flash, session
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from functools import wraps
from functions import Bank  # Ensure this imports your Bank class correctly

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'banking'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)

class User:
    def __init__(self, user_data):
        self.name = user_data['name']
        self.balance = user_data['balance']
        self.username = user_data['username']

    def show_details(self):
        details = [
            'Personal details',
            f'Name: {self.name}',
            f'Account balance is now Ksh {self.balance}'
        ]
        return details

class Bank(User):
    def __init__(self, user_data):
        super().__init__(user_data)

    def deposit(self, amount):
        self.amount = float(amount)
        self.balance += self.amount
        self.update_balance_in_db()
        return f'Account balance is now Ksh {self.balance}'

    def withdraw(self, amount):
        self.amount = float(amount)
        if self.amount > self.balance:
            return f"Insufficient funds Ksh {self.balance}"
        else:
            self.balance -= self.amount
            self.update_balance_in_db()
            return f'Account balance is now Ksh {self.balance}'

    def update_balance_in_db(self):
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET balance = %s WHERE username = %s", (self.balance, self.username))
        mysql.connection.commit()
        cur.close()

    def view_money(self):
        return str(self.balance)

@app.route("/")
def home():
    return render_template("home.html")

# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template("signup.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                # Create user instance and store it in session
                session['user'] = data
                user = Bank(session['user'])
                return redirect(url_for('account'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route("/account")
@is_logged_in
def account():
    user_data = session['user']
    return render_template("account.html", user=user_data)


@app.route("/deposit", methods=["GET", "POST"])
@is_logged_in
def deposit():
    user_data = session['user']
    user = Bank(user_data)
    if request.method == 'POST':
        amount = request.form['deposit']
        user.deposit(amount)
        session['user']['balance'] = user.balance  # Update session balance
        flash(f'Deposited {amount} successfully', 'success')
        return redirect(url_for('account'))
    return render_template('deposit.html', user=user_data)

@app.route("/withdraw", methods=["GET", "POST"])
@is_logged_in
def withdraw():
    user_data = session['user']
    user = Bank(user_data)
    if request.method == 'POST':
        amount = request.form['withdraw']
        message = user.withdraw(amount)
        session['user']['balance'] = user.balance  # Update session balance
        if "Insufficient funds" in message:
            flash(message, 'danger')
        else:
            flash(f'Withdrew {amount} successfully', 'success')
        return redirect(url_for('account'))
    return render_template('withdraw.html', user=user_data)

if __name__ == "__main__":
    app.secret_key = "secret denis"
    app.run(debug=True)
