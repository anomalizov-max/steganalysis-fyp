"""
Run this script once to add the hidden_filename column to the database.
Usage:  python add_hidden_filename_col.py
"""
from app import create_app, db

app = create_app()
with app.app_context():
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text(
                "ALTER TABLE analysis ADD COLUMN hidden_filename VARCHAR(255)"
            ))
            conn.commit()
        print("✅  Column 'hidden_filename' added successfully.")
    except Exception as e:
        if 'duplicate column' in str(e).lower() or 'already exists' in str(e).lower():
            print("ℹ️  Column 'hidden_filename' already exists — nothing to do.")
        else:
            print(f"❌  Error: {e}")
