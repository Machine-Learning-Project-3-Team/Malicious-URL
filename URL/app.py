from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from DB.db_conn import db_conn
from datetime import datetime, timedelta
import pymysql
import secrets
import os
import joblib
from predict_model import predict_url_label  # ✅ 예측 함수 분리된 파일에서 불러오기

app = Flask(__name__)
app.secret_key = "1234"

@app.route('/')
def check_db_connection():
    return redirect(url_for('login'))

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json()
        user_id = data.get("id")
        user_pw = data.get("pw")

        conn = db_conn()
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT id, name FROM users WHERE id = %s AND pw = %s", (user_id, user_pw))
            user = cursor.fetchone()

        if user:
            session["userid"] = user["id"]
            session["username"] = user["name"]
            return jsonify({"success": True, "message": f"환영합니다, {user['name']}님!"})
        else:
            return jsonify({"success": False, "message": "아이디 또는 비밀번호가 틀렸습니다."})

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/index')
def index():
    if "userid" not in session:
        return "로그인이 필요합니다.", 403

    conn = db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT idx, id, name, api_key, datetime FROM users ORDER BY datetime DESC")
    board_list = cursor.fetchall()
    conn.close()

    return render_template("index.html", username=session.get("username"), board_list=board_list)

@app.route('/regist')
def regist():
    return render_template('regist.html')

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    name = data.get("name")
    regist_id = data.get("id")
    regist_pw = data.get("pw")

    if not all([name, regist_id, regist_pw]):
        return jsonify({"success": False, "message": "모든 필드를 입력해주세요."})

    conn = db_conn()
    try:
        with conn.cursor() as cursor:
            sql = "INSERT INTO users (id, pw, name) VALUES (%s, %s, %s)"
            cursor.execute(sql, (regist_id, regist_pw, name))
            conn.commit()
        return jsonify({"success": True, "message": "회원가입 성공!"})
    except Exception as e:
        print("회원가입 오류:", e)
        return jsonify({"success": False, "message": "회원가입 실패!"})
    finally:
        conn.close()

@app.route('/check_id', methods=['POST'])
def check_id():
    try:
        data = request.get_json()
        regist_id = data.get("regist_id")

        conn = db_conn()
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE id = %s", (regist_id,))
            result = cursor.fetchone()

            if result["count"] > 0:
                return jsonify({"success": False})
            else:
                return jsonify({"success": True})

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"success": False, "message": "아이디 중복 검사 중 오류가 발생했습니다."})
    finally:
        if conn:
            conn.close()

@app.route('/predict_url', methods=['POST'])
def predict_url():
    try:
        data = request.get_json()
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"message": "URL이 제공되지 않았습니다."}), 400

        result = predict_url_label(url)
        return jsonify({"prediction": result})

    except Exception as e:
        print("예측 오류:", e)
        return jsonify({"message": "예측 중 오류 발생"}), 500

@app.route('/issue_api_key')
def issue_api_key():
    if "userid" not in session:
        return jsonify({"message": "로그인이 필요합니다."}), 401

    user_id = session["userid"]
    conn = db_conn()
    now = datetime.utcnow()

    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT api_key, api_expiration FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()

            if result["api_key"] and result["api_expiration"]:
                exp_time = result["api_expiration"]
                if exp_time > now:
                    return jsonify({
                        "api_key": result["api_key"],
                        "api_expiration": exp_time.strftime("%Y.%m.%d %H:%M"),
                        "message": "기존 API 키가 아직 유효합니다."
                    })
                else:
                    cursor.execute("UPDATE users SET api_key = NULL, api_expiration = NULL WHERE id = %s", (user_id,))
                    conn.commit()

            new_key = secrets.token_hex(32)
            expiration = now + timedelta(days=30)

            cursor.execute("UPDATE users SET api_key = %s, api_expiration = %s WHERE id = %s", (new_key, expiration, user_id))
            conn.commit()

            return jsonify({
                "api_key": new_key,
                "api_expiration": expiration.strftime("%Y.%m.%d %H:%M"),
                "message": "새로운 API 키가 발급되었습니다."
            })

    except Exception as e:
        print("API Key 발급 오류:", e)
        return jsonify({"message": "API Key 발급 중 오류가 발생했습니다."}), 500
    finally:
        conn.close()

@app.route('/reissue_api_key', methods=['POST'])
def reissue_api_key():
    if "userid" not in session:
        return jsonify({"message": "로그인이 필요합니다."}), 401

    user_id = session["userid"]
    now = datetime.utcnow()
    conn = db_conn()

    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT api_key FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            current_key = user_data["api_key"] if user_data else None

            def generate_unique_key():
                while True:
                    new_key = secrets.token_hex(32)
                    cursor.execute("SELECT COUNT(*) AS count FROM users WHERE api_key = %s", (new_key,))
                    result = cursor.fetchone()
                    if result["count"] == 0 and new_key != current_key:
                        return new_key

            new_api_key = generate_unique_key()
            expiration = now + timedelta(days=30)

            cursor.execute(
                "UPDATE users SET api_key = %s, api_expiration = %s WHERE id = %s",
                (new_api_key, expiration, user_id)
            )
            conn.commit()

            return jsonify({
                "api_key": new_api_key,
                "api_expiration": expiration.strftime("%Y.%m.%d %H:%M"),
                "message": "API Key가 재발급되었습니다."
            })

    except Exception as e:
        print("API Key 재발급 오류:", e)
        return jsonify({"message": "API Key 재발급 중 오류가 발생했습니다."}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)