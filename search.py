# -*- coding: utf-8 -*-
"""
search.py
=========
جزء "مساعدة صاحب الداشبورد ببناء نظام البحث والفلترة بالتاريخ" (التاسك المشتركة).

هاد الملف Flask Blueprint مستقل - ما بيعدّل ولا بيلمس app.py أو models.py.
صاحب الداشبورد بس بيستورده ويسجّله (register) بـ app.py بسطرين، وخلص.

بيوفر endpoint واحد:
    GET /api/search

بيدعم الفلترة حسب:
    - hash          : جزء أو كل الـ md5/sha1/sha256 (بحث جزئي، مش لازم يكون كامل)
    - family        : نوع/عائلة الفايروس (بحث جزئي - مثلاً "Trojan" بيلاقي "Trojan.GenKD")
    - risk_level    : تصفية دقيقة (مثلاً Malicious / Suspicious / Clean)
    - date_from     : تاريخ الفحص من (YYYY-MM-DD)
    - date_to       : تاريخ الفحص إلى (YYYY-MM-DD)
    - q             : بحث عام بيدور باسم الملف أو أي هاش دفعة وحدة

كل الفلاتر اختيارية ومركّبة مع بعض (AND) - يعني ممكن تدمج أكتر من واحد بنفس
الوقت. لو ما انبعث أي فلتر، بيرجع كل السجلات (بحد أقصى `limit`).

الاستخدام (من المتصفح أو الفرونت):
    GET /api/search?family=Trojan
    GET /api/search?hash=b4a7ddf6
    GET /api/search?date_from=2026-08-01&date_to=2026-08-31
    GET /api/search?family=Trojan&risk_level=Malicious&date_from=2026-08-01
    GET /api/search?q=cpu-z

الرد بيرجع JSON:
    {
      "count": <عدد النتائج>,
      "results": [ {id, filename, sha256, family, risk_score, risk_level,
                     status, created_at, ...}, ... ]
    }
"""

import sqlite3
from datetime import datetime

from flask import Blueprint, jsonify, request

# بياخد مسار قاعدة البيانات من config.py الموجود أصلاً بمشروع الداشبورد -
# ما في أي مسار مكتوب يدوي (hardcoded) هون.
try:
    from config import DATABASE_PATH
except ImportError:
    # احتياطي بس لو ملف config ما فيه هيك متغير أو الاسم مختلف - عدّل هون
    # لو احتجت.
    DATABASE_PATH = "instance/database.db"

search_bp = Blueprint("search_bp", __name__)


def _get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # يخلي كل صف قابل نحوله لـ dict مباشرة
    return conn


def _is_valid_date(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except (ValueError, TypeError):
        return False


@search_bp.route("/api/search", methods=["GET"])
def search_analyses():
    """
    بيبني استعلام SQL ديناميكي حسب الفلاتر المرسلة بالـ query string،
    باستخدام placeholders (?) عشان يمنع SQL injection.
    """
    hash_query = request.args.get("hash", "").strip()
    family = request.args.get("family", "").strip()
    risk_level = request.args.get("risk_level", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    general_q = request.args.get("q", "").strip()
    limit = request.args.get("limit", default=100, type=int)

    # تحقق بسيط من صيغة التواريخ (لو انبعثت) قبل ما نبنيها بالاستعلام
    if date_from and not _is_valid_date(date_from):
        return jsonify({"error": "date_from must be in YYYY-MM-DD format"}), 400
    if date_to and not _is_valid_date(date_to):
        return jsonify({"error": "date_to must be in YYYY-MM-DD format"}), 400

    conditions = []
    params = []

    if hash_query:
        conditions.append("(md5 LIKE ? OR sha1 LIKE ? OR sha256 LIKE ?)")
        like_val = f"%{hash_query}%"
        params.extend([like_val, like_val, like_val])

    if family:
        conditions.append("family LIKE ?")
        params.append(f"%{family}%")

    if risk_level:
        conditions.append("risk_level = ?")
        params.append(risk_level)

    if date_from:
        conditions.append("date(created_at) >= date(?)")
        params.append(date_from)

    if date_to:
        conditions.append("date(created_at) <= date(?)")
        params.append(date_to)

    if general_q:
        conditions.append("(filename LIKE ? OR md5 LIKE ? OR sha1 LIKE ? OR sha256 LIKE ?)")
        like_val = f"%{general_q}%"
        params.extend([like_val, like_val, like_val, like_val])

    query = "SELECT * FROM analysis"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    conn = _get_connection()
    try:
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()

    results = [dict(row) for row in rows]
    return jsonify({"count": len(results), "results": results})
