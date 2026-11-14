"""
ساخت ادمین اولیه پنل. توسط اسکریپت نصب فراخوانی می‌شود:
python3 -m app.init_admin <username> <password>
"""
import sys
from app.database import SessionLocal, Base, engine
from app.models import Admin, AdminRole
from app.security import hash_password


def main():
    if len(sys.argv) != 3:
        print("usage: python3 -m app.init_admin <username> <password>")
        sys.exit(1)

    username, password = sys.argv[1], sys.argv[2]

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(Admin).filter(Admin.username == username).first()
        if existing:
            existing.password_hash = hash_password(password)
            existing.is_active = True
            db.commit()
            print(f"ادمین '{username}' به‌روزرسانی شد.")
            return

        admin = Admin(
            username=username,
            password_hash=hash_password(password),
            role=AdminRole.superadmin,
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print(f"ادمین '{username}' ساخته شد.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
