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

    from app.admin_routes import admin
    app.register_blueprint(admin)

    # Auto-migrate: add any missing columns to existing tables
    with app.app_context():
        _auto_migrate_db()
        _seed_default_admin()
    
    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    # Inject current datetime into all templates
    @app.context_processor
    def inject_now():
        from datetime import datetime
        return {'now': datetime.utcnow()}

    return app

from app import models


def _seed_default_admin():
    """
    Ensures that a default admin account exists in the database.
    This is especially useful for cloud deployments where the SQLite DB is empty.
    """
    from app.models import User
    
    # Check if any admin exists
    admin_exists = User.query.filter_by(is_admin=True).first()
    if not admin_exists:
        try:
            # Create default admin account
            default_admin = User(username='admin', email='admin@stegdetect.local')
            default_admin.set_password('admin123')
            default_admin.is_admin = True
            db.session.add(default_admin)
            db.session.commit()
            print("[seed] Created default admin account: username='admin', password='admin123'")
        except Exception as e:
            db.session.rollback()
            print(f"[seed] Warning: Failed to create default admin account: {e}")

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
            ('carved_files',    'TEXT'),
        ],
        'user': [
            ('failed_login_attempts', 'INTEGER DEFAULT 0 NOT NULL'),
            ('locked_until',          'DATETIME'),
            ('is_admin',              'BOOLEAN DEFAULT 0 NOT NULL'),
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
