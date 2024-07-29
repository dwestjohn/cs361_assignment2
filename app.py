from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg2
from psycopg2 import sql
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')


def get_db_connection():
    conn = psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST")
    )
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create-account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        first_name = request.form['first-name']
        last_name = request.form['last-name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        birth_date = request.form['birth-date']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(sql.SQL("SELECT * FROM public.user WHERE username = %s"), [username])
        existing_user = cur.fetchone()

        if existing_user:
            flash("Username already exists. Try again.")
            cur.close()
            conn.close()
            return redirect(url_for('create_account'))
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            cur.execute(sql.SQL("""
                INSERT INTO public.user (first_name, last_name, email, username, password, birth_date)
                VALUES (%s, %s, %s, %s, %s, %s)
            """), (first_name, last_name, email, username, hashed_password, birth_date))
            cur.execute(sql.SQL("""
                INSERT INTO public.monthly_income (username, amount)
                VALUES (%s, %s)
            """), (username, 0)) 
            conn.commit()
            cur.close()
            conn.close()
            flash("Account created successfully!")
            return redirect(url_for('index'))

    return render_template('create-account.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(sql.SQL("SELECT * FROM public.user WHERE username = %s"), [username])
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[5], password): 
            session['user'] = {'first_name': user[1], 'username': user[4]}
            return redirect(url_for('account_page'))
        else:
            flash("Invalid username and/or password. Please try again!")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/account-page', methods=['GET', 'POST'])
def account_page():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']['username']
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        new_amount = request.form['amount']
        try:
            cur.execute(sql.SQL("""
                INSERT INTO public.monthly_income (username, amount)
                VALUES (%s, %s)
                ON CONFLICT (username) 
                DO UPDATE SET amount = EXCLUDED.amount
            """), (username, new_amount))
            conn.commit()
        except Exception as e:
            flash(f"An error occurred: {e}")
        finally:
            cur.close()
            conn.close()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(sql.SQL("SELECT amount FROM public.monthly_income WHERE username = %s"), [username])
    result = cur.fetchone()
    cur.close()
    conn.close()

    if result:
        monthly_income = result[0]
    else:
        monthly_income = 0

    return render_template('account-page.html', first_name=session['user']['first_name'], monthly_income=monthly_income)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)