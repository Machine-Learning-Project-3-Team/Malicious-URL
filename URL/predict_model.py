import joblib
import pandas as pd
import numpy as np
import re

# ✅ 모델 및 기타 자원 로드
model_A = joblib.load('model/best_model_A.pkl')
model_B = joblib.load('model/best_model_B.pkl')
selector = joblib.load('model/selector.pkl')
encoder = joblib.load('model/encoder.pkl')  # save_encoder.py에서 저장한 확장자 인코더
base_features = joblib.load('model/base_features.pkl')
selected_html_features = joblib.load('model/selected_html_features.pkl')

# ✅ URL에서 피처 계산
def calculate_features(url: str) -> dict:
    return {
        'url_length': len(url),
        'count_dots': url.count('.'),
        'count_digits': sum(c.isdigit() for c in url),
        'count_special': len(re.findall(r'[-_%=]', url)),
        'url_entropy': -sum(p * np.log2(p) for p in [
            count / len(url) for count in np.bincount([ord(c) for c in url]) if count > 0
        ]) if url else 0,
        'count_slash': url.count('/'),
        'path_depth': url.count('/') - 2 if url.count('/') > 2 else 0,
    }

# ✅ 최종 예측 수행 함수
def predict_url_label(url: str) -> str:
    url = str(url).strip()
    features = calculate_features(url)

    # 확장자 추출 및 인코딩
    file_ext = url.split('.')[-1] if '.' in url else 'none'
    if file_ext not in encoder.classes_:
        file_ext = 'none'
    features['file_ext'] = encoder.transform([file_ext])[0]

    # A 모델용 입력 생성
    X_a = pd.DataFrame([{key: features.get(key, 0) for key in base_features}])
    proba_a = model_A.predict_proba(X_a)

    # B 모델용 입력 생성 (HTML 피처 포함)
    X_b = pd.DataFrame([{key: features.get(key, 0) for key in base_features + selected_html_features}])
    proba_b = model_B.predict_proba(X_b)

    # Soft Voting 앙상블
    alpha, beta = 0.3, 0.7
    final_proba = alpha * proba_a + beta * proba_b
    y_pred = int(np.argmax(final_proba))

    label_map = {0: "정상", 1: "멀웨어", 2: "피싱"}
    return label_map.get(y_pred, "알 수 없음")
