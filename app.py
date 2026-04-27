from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
import jwt
import datetime
import json
import os
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)

SECRET_KEY = "secure-shield-secret-key"
USERS_FILE = "users.json"
SECURITY_LOG = "security.log"

blacklisted_tokens = set()


# ---------------- FILE HELPERS ----------------

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}

    with open(USERS_FILE, "r") as file:
        return json.load(file)


def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)


def log_unauthorized(action):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(SECURITY_LOG, "a") as file:
        file.write(f"[{timestamp}] Unauthorized attempt: {action}\n")


# ---------------- JWT DECORATOR ----------------

def token_required(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization")

            if not token:
                log_unauthorized("Missing token")
                return jsonify({"error": "Token is missing"}), 401

            if token.startswith("Bearer "):
                token = token.split(" ")[1]

            if token in blacklisted_tokens:
                log_unauthorized("Blacklisted token used")
                return jsonify({"error": "Token has been revoked"}), 401

            try:
                decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                username = decoded_token["username"]
                role = decoded_token["role"]

                if allowed_roles and role not in allowed_roles:
                    log_unauthorized(f"User '{username}' tried to access forbidden route")
                    return jsonify({"error": "Forbidden: insufficient role"}), 403

                request.current_user = {
                    "username": username,
                    "role": role,
                    "token": token
                }

            except jwt.ExpiredSignatureError:
                log_unauthorized("Expired token used")
                return jsonify({"error": "Token expired"}), 401

            except jwt.InvalidTokenError:
                log_unauthorized("Invalid token used")
                return jsonify({"error": "Invalid token"}), 401

            return f(*args, **kwargs)

        return wrapper
    return decorator


# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return jsonify({
        "message": "SecureShield API is running"
    })


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if role not in ["user", "admin"]:
        return jsonify({"error": "Role must be either user or admin"}), 400

    users = load_users()

    if username in users:
        return jsonify({"error": "User already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    users[username] = {
        "password": hashed_password,
        "role": role
    }

    save_users(users)

    return jsonify({
        "message": "User registered successfully",
        "username": username,
        "role": role
    }), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    users = load_users()

    if username not in users:
        return jsonify({"error": "Invalid username or password"}), 401

    stored_password = users[username]["password"]

    if not bcrypt.check_password_hash(stored_password, password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = jwt.encode({
        "username": username,
        "role": users[username]["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "message": "Login successful",
        "token": token
    }), 200


@app.route("/profile", methods=["GET"])
@token_required(allowed_roles=["user", "admin"])
def profile():
    current_user = request.current_user

    return jsonify({
        "message": "Profile accessed successfully",
        "username": current_user["username"],
        "role": current_user["role"]
    }), 200


@app.route("/user/<username>", methods=["DELETE"])
@token_required(allowed_roles=["admin"])
def delete_user(username):
    users = load_users()

    if username not in users:
        return jsonify({"error": "User not found"}), 404

    del users[username]
    save_users(users)

    return jsonify({
        "message": f"User '{username}' deleted successfully"
    }), 200


@app.route("/logout", methods=["POST"])
@token_required(allowed_roles=["user", "admin"])
def logout():
    token = request.current_user["token"]
    blacklisted_tokens.add(token)

    return jsonify({
        "message": "Logout successful. Token has been revoked."
    }), 200


if __name__ == "__main__":
    app.run(debug=True)