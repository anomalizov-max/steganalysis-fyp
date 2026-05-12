"""
One-time migration: add 'carved_files' column to the analysis table.
Run once: python add_carved_files_col.py
"""
from app import create_app, db
import sqlalchemy as sa

app = create_app()

with app.app_context():
    conn = db.engine.connect()

    # Check if the column already exists
    result = conn.execute(sa.text("PRAGMA table_info(analysis)")).fetchall()
    columns = [row[1] for row in result]

    if 'carved_files' not in columns:
        conn.execute(sa.text("ALTER TABLE analysis ADD COLUMN carved_files TEXT"))
        conn.commit()
        print("✅  Column 'carved_files' added to 'analysis' table.")
    else:
        print("ℹ️   Column 'carved_files' already exists — nothing to do.")

    conn.close()
