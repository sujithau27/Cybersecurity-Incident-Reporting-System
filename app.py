from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for session
app.secret_key = "cybersecurity_secret_key"


# ---------------- DATABASE CONNECTION ----------------
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="cybersecurity_db"
)


# ---------------- HOME ----------------
@app.route("/")
def home():
    return redirect(url_for("login"))


# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        # Hash password
        hashed_password = generate_password_hash(password)

        cursor = db.cursor()

        try:

            sql = """
                INSERT INTO users (username, password)
                VALUES (%s, %s)
            """

            cursor.execute(sql, (username, hashed_password))

            db.commit()

            return redirect(url_for("login"))

        except mysql.connector.Error as error:

            return f"Registration failed: {error}"

        finally:

            cursor.close()

    return render_template("register.html")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        cursor = db.cursor(dictionary=True)

        sql = """
            SELECT * FROM users
            WHERE username = %s
        """

        cursor.execute(sql, (username,))

        user = cursor.fetchone()

        cursor.close()

        # Check login details
        if user and check_password_hash(
            user["password"],
            password
        ):

            session["username"] = username

            return redirect(url_for("dashboard"))

        else:

            return "Invalid username or password!"

    return render_template("login.html")


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():

    # Check whether user is logged in
    if "username" not in session:

        return redirect(url_for("login"))

    cursor = db.cursor(dictionary=True)

    sql = """
        SELECT * FROM incidents
        ORDER BY id DESC
    """

    cursor.execute(sql)

    incidents = cursor.fetchall()

    cursor.close()

    return render_template(
        "dashboard.html",
        incidents=incidents
    )


# ---------------- ADD INCIDENT ----------------
@app.route("/add_incident", methods=["GET", "POST"])
def add_incident():

    # Check login
    if "username" not in session:

        return redirect(url_for("login"))

    if request.method == "POST":

        title = request.form["title"]
        incident_type = request.form["incident_type"]
        description = request.form["description"]
        severity = request.form["severity"]

        reported_by = session["username"]

        cursor = db.cursor()

        sql = """
            INSERT INTO incidents
            (title, incident_type, description, severity, reported_by)
            VALUES (%s, %s, %s, %s, %s)
        """

        values = (
            title,
            incident_type,
            description,
            severity,
            reported_by
        )

        cursor.execute(sql, values)

        db.commit()

        cursor.close()

        return redirect(url_for("dashboard"))

    return render_template("add_incident.html")


# ---------------- EDIT INCIDENT ----------------
@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_incident(id):

    # Check login
    if "username" not in session:

        return redirect(url_for("login"))

    cursor = db.cursor(dictionary=True)

    # Update incident
    if request.method == "POST":

        title = request.form["title"]
        incident_type = request.form["incident_type"]
        description = request.form["description"]
        severity = request.form["severity"]

        sql = """
            UPDATE incidents
            SET title=%s,
                incident_type=%s,
                description=%s,
                severity=%s
            WHERE id=%s
        """

        values = (
            title,
            incident_type,
            description,
            severity,
            id
        )

        cursor.execute(sql, values)

        db.commit()

        cursor.close()

        return redirect(url_for("dashboard"))

    # Get existing incident
    sql = """
        SELECT * FROM incidents
        WHERE id=%s
    """

    cursor.execute(sql, (id,))

    incident = cursor.fetchone()

    cursor.close()

    return render_template(
        "edit_incident.html",
        incident=incident
    )


# ---------------- DELETE INCIDENT ----------------
@app.route("/delete/<int:id>", methods=["POST"])
def delete_incident(id):

    # Check login
    if "username" not in session:

        return redirect(url_for("login"))

    cursor = db.cursor()

    sql = """
        DELETE FROM incidents
        WHERE id=%s
    """

    cursor.execute(sql, (id,))

    db.commit()

    cursor.close()

    return redirect(url_for("dashboard"))


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():

    session.pop("username", None)

    return redirect(url_for("login"))


# ---------------- RUN APPLICATION ----------------
if __name__ == "__main__":

    app.run(debug=True)