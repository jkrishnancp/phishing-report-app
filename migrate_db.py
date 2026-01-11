from db import init_db, ensure_columns

if __name__ == "__main__":
    init_db()
    ensure_columns()
    print("DB migration/ensure complete.")
