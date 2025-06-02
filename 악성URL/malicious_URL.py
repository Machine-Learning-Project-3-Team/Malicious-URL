import os
import pandas as pd
import requests
from bs4 import BeautifulSoup

# ✅ 현재 스크립트 기준 경로에서 CSV 파일 절대 경로 설정
base_dir = os.path.dirname(__file__)
file_path = os.path.join(base_dir, 'fast_malicious_analysis.csv')

# ✅ CSV 파일에서 URL 읽기
df = pd.read_csv(file_path)
urls = df['url'].dropna().unique()

html_count = 0  # HTML 응답 URL 개수 카운트
headers = {'User-Agent': 'Mozilla/5.0'}
timeout = 5

for url in urls:
    try:
        # HEAD 요청으로 HTML 응답 여부 확인
        resp = requests.head(url, headers=headers, timeout=timeout, allow_redirects=False)
        if 'text/html' not in resp.headers.get('Content-Type', '').lower():
            continue

        # 실제 HTML 페이지인지 확인
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        if soup.find('html') or soup.find('script'):
            html_count += 1

    except:
        pass  # 예외 발생 시 조용히 건너뜀

# ✅ 결과 출력
print(f"✅ HTML/JS 응답이 있는 악성 URL 개수: {html_count}")
