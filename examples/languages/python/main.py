def normalize_user(user):
    name = user.get("name", "").strip().lower()
    email = user.get("email", "").strip().lower()
    active = bool(user.get("active", False))
    return {"name": name, "email": email, "active": active}
