"""
Database Migration Script
Adds new fields for extracted data preview to Analysis table
"""

from app import create_app, db
from sqlalchemy import text

def migrate_database():
    """Add new columns to Analysis table"""
    app = create_app()
    
    with app.app_context():
        print("Starting database migration...")
        
        try:
            # Add new columns
            with db.engine.connect() as conn:
                # Check if columns exist before adding
                print("Adding extracted_data_preview column...")
                try:
                    conn.execute(text(
                        "ALTER TABLE analysis ADD COLUMN extracted_data_preview TEXT"
                   ))
                    conn.commit()
                    print("✓ Added extracted_data_preview")
                except Exception as e:
                    print(f"Column extracted_data_preview may already exist: {e}")
                
                print("Adding extracted_data_type column...")
                try:
                    conn.execute(text(
                        "ALTER TABLE analysis ADD COLUMN extracted_data_type VARCHAR(50)"
                    ))
                    conn.commit()
                    print("✓ Added extracted_data_type")
                except Exception as e:
                    print(f"Column extracted_data_type may already exist: {e}")
                
                print("Adding extracted_data_size column...")
                try:
                    conn.execute(text(
                        "ALTER TABLE analysis ADD COLUMN extracted_data_size INTEGER"
                    ))
                    conn.commit()
                    print("✓ Added extracted_data_size")
                except Exception as e:
                    print(f"Column extracted_data_size may already exist: {e}")
            
            print("\n✅ Database migration completed successfully!")
            print("The application is ready to display extracted data previews.")
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            print("You may need to manually add the columns or recreate the database.")

if __name__ == '__main__':
    migrate_database()
