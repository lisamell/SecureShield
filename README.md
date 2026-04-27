# SecureShield

SecureShield is a Python-based API that demonstrates **authentication** and **role-based access control (RBAC)** using modern security practices.

---

## Project Objective

The goal of this project is to build a secure backend system that:

- Authenticates users using **JWT (JSON Web Tokens)**
- Protects endpoints based on user roles (**Admin vs User**)
- Stores passwords securely using **bcrypt hashing**
- Prevents unauthorized access and logs suspicious activities

---

## Technologies Used

- Python
- Flask
- Flask-Bcrypt
- PyJWT
- Thunder Client (for API testing)

---

## Features

### 1. Secure Password Storage
- Passwords are never stored in plain text
- They are hashed using **bcrypt**

---

### 2. Authentication (JWT)
- Users log in with username and password
- The system generates a **JWT token**
- The token contains:
  - Username
  - Role (user/admin)

---

### 3. Protected Routes
- Some endpoints require a valid token
- Token must be sent in the header:

```text
Authorization: Bearer YOUR_TOKEN
```
### 4. Role-Based Access Control (RBAC)
- `/profile` → accessible by all authenticated users
- `/user/<username>` → accessible only by admin

### 5. Logout & Token Blacklisting
When a user logs out:
- Token is added to a blacklist
- Token becomes unusable

### 6. Security Logging
Unauthorized access attempts are recorded in:
`security.log`

## How to Run
1. Install dependencies
pip install flask flask-bcrypt pyjwt
2. Run the application
python app.py
3. API will run at
http://127.0.0.1:5000

## API Endpoints
Register
POST /register

Body:
```json
{
  "username": "user",
  "password": "1234",
  "role": "user"
}
``` 
Login
POST /login
Profile (Protected)
GET /profile

Header:

Authorization: Bearer TOKEN
Delete User (Admin Only)
DELETE /user/<username>
Logout
POST /logout

## Testing

We used Thunder Client inside VS Code to:

Send HTTP requests
Add headers
Test authentication and authorization

## Security Concepts
Password hashing (bcrypt)
JWT authentication
Token validation
Role-based authorization
Token blacklisting
Security logging

## Conclusion

SecureShield demonstrates how to build a secure backend system using:

Authentication
Authorization
Secure password handling
Access control
Logging mechanisms

## Team
- Member 1 → Registration & Hashing
- Member 2 → Authentication & JWT
- Member 3 → Authorization & Security
