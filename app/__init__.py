from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from config import Config
import os

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['ANALYSIS_MODELS_PATH'], exist_ok=True)

    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)

    # Auto-migrate: add any missing columns to existing tables
    with app.app_context():
        _auto_migrate_db()
    
    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    return app

from app import models


def _auto_migrate_db():
    """
    Automatically add any columns that exist in the SQLAlchemy models
    but are missing from the actual database table.
    Safe to run on every startup — skips columns that already exist.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)

    # Map: table_name -> list of new (column_name, column_def_sql) to add
    migrations = {
        'analysis': [
            ('hidden_filename', 'VARCHAR(255)'),
        ],
    }

    try:
        with db.engine.connect() as conn:
            for table, columns in migrations.items():
                try:
                    existing = {c['name'] for c in inspector.get_columns(table)}
                except Exception:
                    existing = set()

                for col_name, col_type in columns:
                    if col_name not in existing:
                        conn.execute(text(
                            f'ALTER TABLE {table} ADD COLUMN {col_name} {col_type}'
                        ))
                        conn.commit()
                        print(f'[auto-migrate] Added column: {table}.{col_name}')
    except Exception as e:
        print(f'[auto-migrate] Warning: {e}')
