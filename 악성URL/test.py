import requests
from bs4 import BeautifulSoup
import pandas as pd
import time

# CSV 파일 로드
df = pd.read_csv("C:/Users/user/Desktop/25-1/기계학습/언더샘플링/malicious_only.csv")
urls = df['url'].dropna().tolist()  # 결측치 제거

# 실제 브라우저처럼 위장된 User-Agent
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

# 위험 확장자 리스트
dangerous_ext = ('.zip', '.exe', '.apk', '.rar', '.bat', '.js')

for idx, url in enumerate(urls):
    print(f"\n🔗 [{idx + 1}] {url}")

    # 자동 다운로드 가능한 URL 사전 필터링
    if url.lower().endswith(dangerous_ext):
        print("⚠️ 다운로드 위험 확장자 URL → 분석 제외됨.")
        continue

    try:
        # 요청: 리다이렉트 및 실행 방지
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        html = response.text

        # HTML 파싱
        soup = BeautifulSoup(html, "html.parser")

        print("\n📄 HTML 구조:")
        print(soup.prettify()[:2000])  # 최대 2000자 출력

        print("\n📜 JavaScript 코드:")
        scripts = soup.find_all("script")
        for i, script in enumerate(scripts):
            if script.string:
                print(f"\n[Script {i + 1}]\n{script.string[:1000]}")  # 최대 1000자 출력
            else:
                print(f"\n[Script {i + 1}] 외부 JS 또는 비어 있음")

    except requests.exceptions.RequestException as e:
        print(f"❌ 요청 오류 발생: {e}")
    except Exception as e:
        print(f"❌ 기타 오류 발생: {e}")

    # 요청 간 시간 간격 설정 (Rate Limit 방지)
    time.sleep(1)

    try:
        input("\n⏎ Enter를 누르면 다음 URL로 넘어갑니다...")
    except KeyboardInterrupt:
        print("\n⛔ 사용자 중단으로 분석 종료")
        break
