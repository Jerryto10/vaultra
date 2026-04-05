web: python -c "from admin.app import init_db; init_db()" && gunicorn admin.app:app --bind 0.0.0.0:$PORT --workers 2
