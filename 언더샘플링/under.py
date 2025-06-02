import pandas as pd
from sklearn.utils import resample
from collections import Counter

# 1. CSV 파일 불러오기
df = pd.read_csv('cleaned_url_dataset.csv')

print("🧾 전체 데이터 클래스 분포:")
for label, count in df['label'].value_counts().items():
    print(f"  클래스 {label}: {count}개")

# 2. 클래스별 데이터 분리
df_normal = df[df['label'] == 0]
df_malicious = df[df['label'].isin([1, 2])]

# 3. 악성 데이터 개수 확인
n_malicious = len(df_malicious)

# 4. 정상 데이터를 악성 데이터 수만큼 언더샘플링
df_normal_undersampled = resample(df_normal,
                                  replace=False,       # 복원 없이
                                  n_samples=n_malicious, # 악성 수만큼만 뽑기
                                  random_state=42)     # 재현 가능성

# 🔍 언더샘플링 결과 확인
y_resampled = pd.concat([df_normal_undersampled, df_malicious])['label']
print(Counter(y_resampled))  # ✅ 여기서 클래스별 개수 확인

# 5. 언더샘플된 정상 데이터와 악성 데이터 합치기 
df_balanced = pd.concat([df_normal_undersampled, df_malicious])

# 6. 셔플 (행 순서를 섞기 위해해)
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

# 7. 최종 확인
print(df_balanced['label'].value_counts())

# 8. ✅ 파일로 저장
df_balanced.to_csv('balanced_data.csv', index=False)

# 제대로 들어갔나 확인 
df = pd.read_csv('balanced_data.csv')  # 경로는 상황에 맞게 수정
print("📊 balanced_data.csv 내 클래스별 분포:")
print(df['label'].value_counts())
