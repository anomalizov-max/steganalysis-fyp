"""
make_admin.py — Create a new admin account OR promote an existing user to admin.

Usage:
    python make_admin.py

Follow the prompts to enter username, email and password.
"""
from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    print("=" * 45)
    print("  StegDetect — Admin Account Setup")
    print("=" * 45)

    username = input("Enter admin username : ").strip()
    email    = input("Enter admin email    : ").strip()
    password = input("Enter admin password : ").strip()

    if not username or not password or not email:
        print("\nError: All fields are required.")
        exit(1)

    # Check if user already exists
    existing = User.query.filter_by(username=username).first()
    if existing:
        existing.is_admin = True
        existing.set_password(password)
        db.session.commit()
        print(f"\nSuccess! Existing user '{username}' updated to admin with new password.")
    else:
        user = User(username=username, email=email)
        user.set_password(password)
        user.is_admin = True
        db.session.add(user)
        db.session.commit()
        print(f"\nSuccess! New admin account '{username}' created.")

    print(f"  → Log in at: http://127.0.0.1:5000/login")
    print(f"  → Admin panel: http://127.0.0.1:5000/admin/")
    print("=" * 45)

