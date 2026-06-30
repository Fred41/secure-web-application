from flask import Flask, render_template, request, session, redirect
from config import mysql
import bcrypt
import re

app = Flask(__name__)
app.secret_key = "my_secret_key_123"

# Secure Session Settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# MySQL Configuration
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "Fredfrango@24122005"
app.config["MYSQL_DB"] = "secure_web"

mysql.init_app(app)


# ===========================
# Home Page
# ===========================
@app.route("/")
def home():
    return redirect("/login")


# ===========================
# Sign Up
# ===========================
@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        # Username Validation
        if len(username) < 3:
            return render_template(
                "signup.html",
                error="Username must be at least 3 characters."
            )

        # Strong Password Validation
        if len(password) < 8:
            return render_template(
                "signup.html",
                error="Password must be at least 8 characters."
            )

        if not re.search(r"[A-Z]", password):
            return render_template(
                "signup.html",
                error="Password must contain at least one uppercase letter."
            )

        if not re.search(r"[a-z]", password):
            return render_template(
                "signup.html",
                error="Password must contain at least one lowercase letter."
            )

        if not re.search(r"[0-9]", password):
            return render_template(
                "signup.html",
                error="Password must contain at least one number."
            )

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return render_template(
                "signup.html",
                error="Password must contain at least one special character."
            )

        cursor = mysql.connection.cursor()

        # Check if email already exists
        cursor.execute(
            "SELECT id FROM users WHERE email=%s",
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            return render_template(
                "signup.html",
                error="Email already registered. Please login."
            )

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        cursor.execute(
            """
            INSERT INTO users(username, email, password)
            VALUES(%s, %s, %s)
            """,
            (
                username,
                email,
                hashed_password.decode("utf-8")
            )
        )

        mysql.connection.commit()
        cursor.close()

        return render_template(
            "signup.html",
            error="Registration Successful! You can now login."
        )

    return render_template("signup.html")


# ===========================
# Login
# ===========================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip()
        password = request.form["password"]

        cursor = mysql.connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()

        if user:

            stored_password = user[3]

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password.encode("utf-8")
            ):
                session["user"] = user[1]
                return redirect("/dashboard")

        return render_template(
            "login.html",
            error="Invalid Email or Password"
        )

    return render_template("login.html")


# ===========================
# Dashboard
# ===========================
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["user"]
    )


# ===========================
# Logout
# ===========================
@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect("/login")


# ===========================
# Run App
# ===========================
if __name__ == "__main__":
    app.run(debug=True)