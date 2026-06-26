def normalize_order(order):
    name = order.get("name", "").strip().lower()
    email = order.get("email", "").strip().lower()
    active = bool(order.get("active", False))
    return {"name": name, "email": email, "active": active}
