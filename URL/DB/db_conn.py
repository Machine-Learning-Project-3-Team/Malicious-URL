import pymysql
import os
from dotenv import load_dotenv

def db_conn():
    conn = pymysql.connect(
        host = "localhost",
        user = "root",
        password= "1234",
        database = "malicious_url",
        charset = "utf8mb4",  # 문자 인코딩 설정
        cursorclass = pymysql.cursors.DictCursor
    )
    return conn
