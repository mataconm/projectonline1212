import os
import json
import bcrypt
import time
from datetime import datetime, timedelta
import calendar
from functools import wraps
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

# ===== FILES =====
USERS_FILE = "users.json"
NOTES_FILE = "notes.json"
NEWS_FILE = "news.json"
GUIDES_FILE = "guides.json"
SETTINGS_FILE = "settings.json"
RESULTS_FILE = "results.json"
TESTS_FILE = "tests.json"
ANALYTICS_FILE = "analytics.json"
NOTIFICATIONS_FILE = "notifications.json"
GROUPS_FILE = "groups.json"
EVENTS_FILE = "events.json"

# ===== RATE LIMITING =====
request_counts = defaultdict(lambda: {"count": 0, "reset_time": time.time()})
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60


def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        current_time = time.time()
        
        if current_time > request_counts[ip]["reset_time"] + RATE_LIMIT_WINDOW:
            request_counts[ip] = {"count": 0, "reset_time": current_time}
        
        request_counts[ip]["count"] += 1
        
        if request_counts[ip]["count"] > RATE_LIMIT_REQUESTS:
            return jsonify({"error": "rate limit exceeded"}), 429
        
        return f(*args, **kwargs)
    return decorated


def load_json(path, default):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, ensure_ascii=False, indent=2)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def normalize_users(raw):
    if not isinstance(raw, dict):
        return {}
    new = {}
    for k, v in raw.items():
        if isinstance(v, dict):
            pwd = v.get("password", "")
            role = v.get("role", "student")
            group = v.get("group", None)
            new[k] = {"password": pwd, "role": role, "group": group}
        else:
            new[k] = {"password": v, "role": "student", "group": None}
    return new


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if isinstance(stored, str) and stored.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored.encode('utf-8'))
        except Exception:
            return False
    return password == stored


_raw_users = load_json(USERS_FILE, {})
users = normalize_users(_raw_users)
if any(not isinstance(_raw_users.get(k), dict) for k in _raw_users):
    save_json(USERS_FILE, users)

if not users:
    users = {
        "admin": {"password": hash_password("admin123"), "role": "admin", "group": None},
        "ivan": {"password": hash_password("ivanpass"), "role": "student", "group": "10A"},
        "masha": {"password": hash_password("mashapass"), "role": "student", "group": "10A"}
    }
    save_json(USERS_FILE, users)

notes = load_json(NOTES_FILE, [])
news = load_json(NEWS_FILE, [])
guides = load_json(GUIDES_FILE, [])
settings = load_json(SETTINGS_FILE, {"theme": "light", "language": "ru", "version": "4.0.0"})
tests = load_json(TESTS_FILE, [])
results = load_json(RESULTS_FILE, [])
analytics = load_json(ANALYTICS_FILE, {"version": "4.0.0", "stats": {}})
notifications = load_json(NOTIFICATIONS_FILE, [])
groups = load_json(GROUPS_FILE, {})
events = load_json(EVENTS_FILE, [])


def check_admin_payload(payload):
    if not payload:
        return False
    admin_login = payload.get("admin_login")
    admin_password = payload.get("admin_password")
    if not admin_login or not admin_password:
        return False
    u = users.get(admin_login)
    return bool(u and check_password(admin_password, u.get("password")) and u.get("role") == "admin")


def add_notification(user, title, message, type="info"):
    notification = {
        "user": user,
        "title": title,
        "message": message,
        "type": type,
        "timestamp": datetime.now().isoformat(),
        "read": False
    }
    notifications.append(notification)
    save_json(NOTIFICATIONS_FILE, notifications)
    return notification


def track_analytics(event_type, user, details=None):
    if "events" not in analytics:
        analytics["events"] = []
    
    event = {
        "type": event_type,
        "user": user,
        "timestamp": datetime.now().isoformat(),
        "details": details or {}
    }
    analytics["events"].append(event)
    save_json(ANALYTICS_FILE, analytics)


def get_user_group(username):
    u = users.get(username)
    return u.get("group") if u else None


def notify_group(group_name, title, message, type="info"):
    for username, user_data in users.items():
        if user_data.get("group") == group_name:
            add_notification(username, title, message, type)


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path and os.path.exists(path):
        return send_from_directory(".", path)
    return send_from_directory(".", "index.html")


@app.post("/login")
@rate_limit
def login():
    data = request.json or {}
    login_username = data.get("login")
    login_password = data.get("password")
    if not login_username or not login_password:
        return jsonify({"ok": False, "error": "login and password required"}), 400
    u = users.get(login_username)
    if not u or not check_password(login_password, u.get("password", "")):
        track_analytics("login_failed", login_username)
        return jsonify({"ok": False, "error": "invalid credentials"}), 401
    
    track_analytics("login_success", login_username)
    return jsonify({
        "ok": True,
        "role": u.get("role", "student"),
        "group": u.get("group"),
        "version": "4.0.0"
    })


# ===== ГРУППЫ/КЛАССЫ =====
@app.post("/admin/groups/list")
@rate_limit
def list_groups():
    payload = request.json or {}
    if not check_admin_payload(payload):
        return jsonify({"error": "admin auth required"}), 403
    return jsonify(groups)


@app.post("/admin/groups/create")
@rate_limit
def create_group():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    group_name = data.get("name")
    if not group_name or group_name in groups:
        return jsonify({"error": "invalid group name"}), 400
    
    groups[group_name] = {
        "name": group_name,
        "members": [],
        "created_at": datetime.now().isoformat()
    }
    save_json(GROUPS_FILE, groups)
    track_analytics("group_created", data.get("admin_login"), {"group": group_name})
    return jsonify({"ok": True})


@app.post("/admin/groups/add_member")
@rate_limit
def add_group_member():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    group_name = data.get("group")
    username = data.get("username")
    
    if group_name not in groups or username not in users:
        return jsonify({"error": "invalid group or user"}), 400
    
    if username not in groups[group_name]["members"]:
        groups[group_name]["members"].append(username)
        users[username]["group"] = group_name
        save_json(GROUPS_FILE, groups)
        save_json(USERS_FILE, users)
        track_analytics("user_added_to_group", data.get("admin_login"), {"group": group_name, "user": username})
    
    return jsonify({"ok": True})


@app.post("/admin/groups/remove_member")
@rate_limit
def remove_group_member():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    group_name = data.get("group")
    username = data.get("username")
    
    if group_name not in groups or username not in users:
        return jsonify({"error": "invalid group or user"}), 400
    
    if username in groups[group_name]["members"]:
        groups[group_name]["members"].remove(username)
        users[username]["group"] = None
        save_json(GROUPS_FILE, groups)
        save_json(USERS_FILE, users)
        track_analytics("user_removed_from_group", data.get("admin_login"), {"group": group_name, "user": username})
    
    return jsonify({"ok": True})


@app.post("/admin/groups/delete")
@rate_limit
def delete_group():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    group_name = data.get("group")
    if group_name not in groups:
        return jsonify({"error": "group not found"}), 404
    
    for username in groups[group_name]["members"]:
        users[username]["group"] = None
    
    del groups[group_name]
    save_json(GROUPS_FILE, groups)
    save_json(USERS_FILE, users)
    track_analytics("group_deleted", data.get("admin_login"), {"group": group_name})
    return jsonify({"ok": True})


# ===== NOTIFICATIONS =====
@app.get("/notifications/<username>")
@rate_limit
def get_notifications(username):
    user_notifications = [n for n in notifications if n.get("user") == username]
    return jsonify(user_notifications)


@app.post("/notifications/read/<int:idx>")
@rate_limit
def mark_notification_read(idx):
    if 0 <= idx < len(notifications):
        notifications[idx]["read"] = True
        save_json(NOTIFICATIONS_FILE, notifications)
        return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404


# ===== NOTES (Materials) =====
@app.get("/notes")
@rate_limit
def list_notes():
    return jsonify(notes)


@app.get("/notes/<username>")
@rate_limit
def list_notes_for_user(username):
    user_group = get_user_group(username)
    filtered = [n for n in notes if n.get("assigned_to") is None or 
                n.get("assigned_to") == username or 
                n.get("assigned_to") == user_group]
    return jsonify(filtered)


@app.post("/notes")
@rate_limit
def add_note():
    data = request.json or {}
    user = data.get("user", "")
    note = {
        "title": data.get("title", ""),
        "desc": data.get("desc", ""),
        "user": user,
        "image": data.get("image", ""),
        "assigned_to": None,
        "created_at": datetime.now().isoformat(),
        "time_spent": 0,
        "id": int(time.time() * 1000)
    }
    notes.append(note)
    save_json(NOTES_FILE, notes)
    track_analytics("material_added", user, {"title": note["title"]})
    add_notification(user, "Материал добавлен", f"Вы добавили материал: {note['title']}")
    return jsonify({"ok": True})


@app.post("/admin/notes/delete")
@rate_limit
def admin_delete_note():
    """Админ удаляет любой материал"""
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    try:
        idx = int(data.get("index"))
    except:
        return jsonify({"error": "invalid index"}), 400
    if idx < 0 or idx >= len(notes):
        return jsonify({"error": "invalid index"}), 400
    
    deleted_title = notes[idx].get("title", "")
    notes.pop(idx)
    save_json(NOTES_FILE, notes)
    track_analytics("material_deleted_admin", data.get("admin_login"), {"index": idx, "title": deleted_title})
    return jsonify({"ok": True})


@app.post("/materials/delete")
@rate_limit
def delete_own_material():
    """Ученик удаляет только СВОЙ материал"""
    data = request.json or {}
    username = data.get("username")
    
    if not username:
        return jsonify({"error": "username required"}), 400
    
    try:
        idx = int(data.get("index"))
    except:
        return jsonify({"error": "invalid index"}), 400
    
    if idx < 0 or idx >= len(notes):
        return jsonify({"error": "invalid index"}), 400
    
    # ПРОВЕРКА: материал должен принадлежать этому ученику
    if notes[idx].get("user") != username:
        return jsonify({"error": "can only delete your own materials"}), 403
    
    deleted_title = notes[idx].get("title", "")
    notes.pop(idx)
    save_json(NOTES_FILE, notes)
    track_analytics("material_deleted_self", username, {"title": deleted_title})
    add_notification(username, "Материал удален", f"Вы удалили: {deleted_title}")
    return jsonify({"ok": True})


@app.post("/admin/materials/assign_group")
@rate_limit
def admin_assign_material_to_group():
    """Админ назначает материал ученику или группе"""
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403

    try:
        idx = int(data.get("index"))
    except:
        return jsonify({"error": "invalid index"}), 400

    if idx < 0 or idx >= len(notes):
        return jsonify({"error": "invalid index"}), 400

    assigned_to = data.get("assigned_to", "")
    notes[idx]["assigned_to"] = assigned_to if assigned_to else None
    save_json(NOTES_FILE, notes)
    
    material_title = notes[idx].get("title", "Без названия")
    track_analytics("material_assigned_admin", data.get("admin_login"), {"to": assigned_to, "title": material_title})
    
    if assigned_to:
        # Уведомление для группы
        if assigned_to in groups:
            notify_group(assigned_to, "Новый материал", 
                        f"Материал назначен вашему классу: {material_title}", "assignment")
        # Уведомление для ученика
        elif assigned_to in users:
            add_notification(assigned_to, "Новый материал", 
                           f"Вам назначен материал: {material_title}")
    
    return jsonify({"ok": True})


@app.post("/materials/assign")
@rate_limit
def assign_own_material():
    """Ученик назначает только СВОЙ материал другому ученику"""
    data = request.json or {}
    username = data.get("username")
    assigned_to = data.get("assigned_to", "")
    
    if not username or not assigned_to:
        return jsonify({"error": "username and assigned_to required"}), 400
    
    try:
        idx = int(data.get("index"))
    except:
        return jsonify({"error": "invalid index"}), 400
    
    if idx < 0 or idx >= len(notes):
        return jsonify({"error": "invalid index"}), 400
    
    # ПРОВЕРКА: материал должен принадлежать этому ученику
    if notes[idx].get("user") != username:
        return jsonify({"error": "can only assign your own materials"}), 403
    
    # ПРОВЕРКА: назначаемый ученик должен существовать
    if assigned_to not in users and assigned_to not in groups:
        return jsonify({"error": "invalid student or group"}), 400
    
    notes[idx]["assigned_to"] = assigned_to
    save_json(NOTES_FILE, notes)
    
    material_title = notes[idx].get("title", "Без названия")
    track_analytics("material_assigned_self", username, {"to": assigned_to, "title": material_title})
    
    # Уведомление
    if assigned_to in users:
        add_notification(assigned_to, "Новый материал от ученика", 
                       f"{username} поделился материалом: {material_title}")
    elif assigned_to in groups:
        notify_group(assigned_to, "Новый материал", 
                    f"{username} поделился материалом: {material_title}")
    
    return jsonify({"ok": True})


@app.post("/admin/materials/edit")
@rate_limit
def admin_edit_material():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403

    try:
        idx = int(data.get("index"))
    except:
        return jsonify({"error": "invalid index"}), 400

    if idx < 0 or idx >= len(notes):
        return jsonify({"error": "invalid index"}), 400

    if "title" in data:
        notes[idx]["title"] = data.get("title", "")
    if "desc" in data:
        notes[idx]["desc"] = data.get("desc", "")
    if "image" in data:
        notes[idx]["image"] = data.get("image", "")

    save_json(NOTES_FILE, notes)
    track_analytics("material_edited_admin", data.get("admin_login"), {"index": idx})
    return jsonify({"ok": True})


@app.post("/materials/edit")
@rate_limit
def edit_own_material():
    data = request.json or {}

    username = data.get("username")
    try:
        idx = int(data.get("index"))
    except:
        return jsonify({"error": "invalid index"}), 400

    if not username:
        return jsonify({"error": "username required"}), 400

    if idx < 0 or idx >= len(notes):
        return jsonify({"error": "invalid index"}), 400

    if notes[idx].get("user") != username:
        return jsonify({"error": "can only edit your own materials"}), 403

    if "title" in data:
        notes[idx]["title"] = data.get("title", "")
    if "desc" in data:
        notes[idx]["desc"] = data.get("desc", "")
    if "image" in data:
        notes[idx]["image"] = data.get("image", "")

    save_json(NOTES_FILE, notes)
    track_analytics("material_edited_self", username, {"index": idx})
    return jsonify({"ok": True})


# ===== NEWS =====
@app.get("/news")
@rate_limit
def list_news():
    return jsonify(news)


@app.get("/news/<username>")
@rate_limit
def list_news_for_user(username):
    user_group = get_user_group(username)
    filtered = [n for n in news if n.get("assigned_to") is None or 
                n.get("assigned_to") == username or 
                n.get("assigned_to") == user_group]
    return jsonify(filtered)


@app.post("/news")
@rate_limit
def add_news():
    data = request.json or {}
    user = data.get("user", "")
    news_item = {
        "title": data.get("title", ""),
        "desc": data.get("desc", ""),
        "user": user,
        "image": data.get("image", ""),
        "assigned_to": None,
        "created_at": datetime.now().isoformat(),
        "id": int(time.time() * 1000)
    }
    news.append(news_item)
    save_json(NEWS_FILE, news)
    track_analytics("news_added", user, {"title": news_item["title"]})
    return jsonify({"ok": True})


@app.post("/admin/news/delete")
@rate_limit
def admin_delete_news():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    try:
        idx = int(data.get("index"))
    except:
        return jsonify({"error": "invalid index"}), 400
    if idx < 0 or idx >= len(news):
        return jsonify({"error": "invalid index"}), 400
    news.pop(idx)
    save_json(NEWS_FILE, news)
    track_analytics("news_deleted", data.get("admin_login"))
    return jsonify({"ok": True})


# ===== GUIDES =====
@app.get("/guides")
@rate_limit
def list_guides():
    return jsonify(guides)


@app.get("/guides/<username>")
@rate_limit
def list_guides_for_user(username):
    user_group = get_user_group(username)
    filtered = [g for g in guides if g.get("assigned_to") is None or 
                g.get("assigned_to") == username or 
                g.get("assigned_to") == user_group]
    return jsonify(filtered)


@app.post("/guides")
@rate_limit
def add_guide():
    data = request.json or {}
    user = data.get("user", "")
    guide = {
        "title": data.get("title", ""),
        "desc": data.get("desc", ""),
        "user": user,
        "image": data.get("image", ""),
        "assigned_to": None,
        "created_at": datetime.now().isoformat(),
        "id": int(time.time() * 1000)
    }
    guides.append(guide)
    save_json(GUIDES_FILE, guides)
    track_analytics("guide_added", user, {"title": guide["title"]})
    return jsonify({"ok": True})


@app.post("/admin/guides/delete")
@rate_limit
def admin_delete_guide():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    try:
        idx = int(data.get("index"))
    except:
        return jsonify({"error": "invalid index"}), 400
    if idx < 0 or idx >= len(guides):
        return jsonify({"error": "invalid index"}), 400
    guides.pop(idx)
    save_json(GUIDES_FILE, guides)
    track_analytics("guide_deleted", data.get("admin_login"))
    return jsonify({"ok": True})


# ===== TESTS =====
@app.get("/tests")
@rate_limit
def list_tests():
    return jsonify(tests)


@app.post("/tests/submit")
@rate_limit
def submit_test():
    data = request.json or {}
    user = data.get("user", "")
    test_id = data.get("test_id", "")
    answers = data.get("answers", [])
    time_spent = data.get("time_spent", 0)
    
    test = next((t for t in tests if t.get("id") == test_id), None)
    if not test:
        return jsonify({"error": "test not found"}), 404
    
    score = 0
    total = len(test.get("questions", []))
    
    for i, q in enumerate(test.get("questions", [])):
        if i < len(answers):
            user_answer = answers[i]
            correct = q.get("answers", [])
            
            if q.get("type") == "multiple":
                if isinstance(user_answer, list) and set(user_answer) == set(correct):
                    score += 1
            else:
                if user_answer == correct[0]:
                    score += 1
    
    percentage = int((score / total * 100) if total > 0 else 0)
    
    result = {
        "user": user,
        "test_id": test_id,
        "score": score,
        "total": total,
        "percentage": percentage,
        "time_spent": time_spent,
        "timestamp": datetime.now().isoformat()
    }
    results.append(result)
    save_json(RESULTS_FILE, results)
    track_analytics("test_completed", user, {"score": score, "total": total})
    
    return jsonify(result)


@app.post("/admin/tests/add_or_update")
@rate_limit
def admin_add_update_test():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    test = data.get("test", {})
    test_id = test.get("id") or int(time.time() * 1000)
    
    existing = next((t for t in tests if t.get("id") == test_id), None)
    if existing:
        existing.update(test)
    else:
        test["id"] = test_id
        test["created_at"] = datetime.now().isoformat()
        tests.append(test)
    
    save_json(TESTS_FILE, tests)
    track_analytics("test_created_or_updated", data.get("admin_login"), {"title": test.get("title")})
    return jsonify({"ok": True})


@app.post("/admin/tests/delete")
@rate_limit
def admin_delete_test():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    test_id = data.get("id")
    global tests
    tests = [t for t in tests if t.get("id") != test_id]
    save_json(TESTS_FILE, tests)
    track_analytics("test_deleted", data.get("admin_login"))
    return jsonify({"ok": True})


# ===== USERS =====
@app.post("/admin/users/list")
@rate_limit
def admin_list_users():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    return jsonify(users)


@app.post("/admin/users/add_or_update")
@rate_limit
def admin_add_update_user():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    login = data.get("login", "")
    password = data.get("password", "")
    role = data.get("role", "student")
    
    if not login:
        return jsonify({"error": "login required"}), 400
    
    if login not in users and not password:
        return jsonify({"error": "password required for new user"}), 400
    
    if login not in users:
        users[login] = {
            "password": hash_password(password),
            "role": role,
            "group": None
        }
    else:
        if password:
            users[login]["password"] = hash_password(password)
        users[login]["role"] = role
    
    save_json(USERS_FILE, users)
    track_analytics("user_updated", data.get("admin_login"), {"user": login})
    return jsonify({"ok": True})


@app.post("/admin/users/delete")
@rate_limit
def admin_delete_user():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    login = data.get("login", "")
    if login not in users:
        return jsonify({"error": "user not found"}), 404
    
    del users[login]
    save_json(USERS_FILE, users)
    track_analytics("user_deleted", data.get("admin_login"), {"user": login})
    return jsonify({"ok": True})


# ===== ADMIN ANALYTICS =====
@app.post("/admin/analytics/stats")
@rate_limit
def get_admin_stats():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    stats = {
        "users": len([u for u in users.values() if u.get("role") == "student"]),
        "tests": len(tests),
        "completed_tests": len(results),
        "materials": len(notes),
        "average_score": int(sum(r.get("percentage", 0) for r in results) / len(results)) if results else 0
    }
    return jsonify(stats)


@app.post("/admin/results")
@rate_limit
def get_admin_results():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    return jsonify(results)


@app.post("/admin/settings/theme")
@rate_limit
def admin_set_theme():
    data = request.json or {}
    if not check_admin_payload(data):
        return jsonify({"error": "admin auth required"}), 403
    
    theme = data.get("theme", "light")
    settings["theme"] = theme
    save_json(SETTINGS_FILE, settings)
    track_analytics("theme_changed", data.get("admin_login"), {"theme": theme})
    return jsonify({"ok": True})


@app.get("/settings")
@rate_limit
def get_settings():
    return jsonify(settings)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
