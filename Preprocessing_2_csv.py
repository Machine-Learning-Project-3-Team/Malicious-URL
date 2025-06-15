import warnings
warnings.filterwarnings('ignore')
warnings.filterwarnings("ignore", category=UserWarning)
import os, re, zipfile, glob, time, gc, math, subprocess, random
import pandas as pd
import numpy as np
import requests
import tldextract

from io import BytesIO, StringIO
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample
from collections import Counter
from scipy.stats import zscore
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

os.environ['KAGGLE_CONFIG_DIR'] = "/home/ubuntu"
download_dir = "/home/ubuntu"

# 다운 파트
kaggle_files = [
    ("sid321axn/malicious-urls-dataset", "malicious-urls-dataset.zip"),
    ("taruntiwarihp/phishing-site-urls", "phishing-site-urls.zip"),
    ("antonyj453/urldataset", "urldataset.zip"),
    ("pilarpieiro/tabular-dataset-ready-for-malicious-url-detection", "tabular-dataset-ready-for-malicious-url-detection.zip")
]

for dataset, zipname in kaggle_files:
    os.system(f"kaggle datasets download -d {dataset} -p {download_dir}")
    zip_path = os.path.join(download_dir, zipname)
    if os.path.exists(zip_path):
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(download_dir)
        os.remove(zip_path)


# 악성 url 데이터 수집
#malicious_url = "https://urlhaus.abuse.ch/downloads/text/"
#malicious_df = pd.read_csv(malicious_url, comment='#', header=None, names=['url'])
urlhaus_url = "https://urlhaus.abuse.ch/downloads/csv/"
response = requests.get(urlhaus_url)
response.raise_for_status()

# 압축 해제 + CSV 읽기
with zipfile.ZipFile(BytesIO(response.content)) as z:
    name = z.namelist()[0]
    with z.open(name) as f:
        df = pd.read_csv(f, encoding='latin1', header=None, comment='#', on_bad_lines='skip')

# 열 이름 수동 지정
df.columns = ['id', 'dateadded', 'url', 'url_status', 'unused1', 'threat', 'unused2', 'urlhaus_link', 'signature']

# URL만 추출
malicious_df = df[['url']].dropna()


openphish_url = "https://openphish.com/feed.txt"
openphish_df = pd.read_csv(openphish_url, header=None, names=['url'])

# 캐글 데이터 읽기
kaggle_1_df = pd.read_csv(f"{download_dir}/malicious_phish.csv")

kaggle_1_df.rename(columns={'type': 'label'}, inplace=True)

kaggle_1_df['label'] = kaggle_1_df['label'].map({'benign': 0, 'malware': 1, 'phishing': 2})


# kaggle_1_df['label'].value_counts()
# kaggle_3_df.columns

kaggle_2_df = pd.read_csv(f"{download_dir}/phishing_site_urls.csv")
kaggle_2_df.rename(columns={'URL': 'url', 'Label': 'label'}, inplace=True)
kaggle_2_df['label'] = kaggle_2_df['label'].map({'bad': 2, 'good': 0})

kaggle_3_df = pd.read_csv(f"{download_dir}/data.csv")
kaggle_3_df.rename(columns={'URL': 'url', 'Label': 'label'}, inplace=True)
kaggle_3_df['label'] = kaggle_3_df['label'].map({'bad': 2, 'good': 0})
kaggle_3_df = kaggle_3_df[kaggle_3_df['label'] != 2]

kaggle_4_df_1 = pd.read_csv(f"{download_dir}/train_dataset.csv", usecols=['url', 'label'])
kaggle_4_df_2 = pd.read_csv(f"{download_dir}/test_dataset.csv", usecols=['url', 'label'])

kaggle_4_df_1.rename(columns={'URL': 'url', 'Label': 'label'}, inplace=True)
kaggle_4_df_1['label'] = kaggle_4_df_1['label'].map({1: 2, 0: 0})
kaggle_4_df_1 = kaggle_4_df_1[kaggle_4_df_1['label'] != 2]

kaggle_4_df_2.rename(columns={'URL': 'url', 'Label': 'label'}, inplace=True)
kaggle_4_df_2['label'] = kaggle_4_df_2['label'].map({1: 2, 0: 0})
kaggle_4_df_2 = kaggle_4_df_2[kaggle_4_df_2['label'] != 2]

# 통합
kaggle_df = pd.concat([kaggle_1_df, kaggle_2_df, kaggle_3_df, kaggle_4_df_1, kaggle_4_df_2], ignore_index=True)
kaggle_df['label'].value_counts()

# 악성 url 데이터
malicious_df['label'] = 1 # 멀웨어
openphish_df['label'] = 2 # 피싱

# 데이터 합치기 (정상, 악성)
df = pd.concat([malicious_df, openphish_df, kaggle_df], ignore_index=True)

print(df['label'].value_counts())

# 언더샘플링 진행
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

# 5. 언더샘플된 정상 데이터와 악성 데이터 합치기
df = pd.concat([df_normal_undersampled, df_malicious])

# 6. 셔플 (행 순서를 섞기 위해)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)



# 중복 URL 제거
df = df.drop_duplicates(subset=['url'])
print(df['label'].value_counts())


# === 사용할 HTML 태그 목록
tags = ['script', 'iframe', 'form', 'input', 'meta', 'link', 'object', 'embed']
event_handlers = ['onclick', 'onmouseover', 'onload', 'onerror', 'onfocus', 'onblur']

redirect_patterns = [re.compile(p, re.IGNORECASE) for p in [
    r'window\.location', 
    r'location\.href', 
    r'location\.replace', 
    r'document\.location'
]]

# === 새 피처 추가 (기존 컬럼 유지)
df['url_available'] = 0
for tag in tags:
    df[f'html_{tag}_num'] = 0
for handler in event_handlers:
    df[f'html_event_{handler}_num'] = 0
    df[f'html_event_{handler}_elem'] = 0 # 이벤트에 연결된 요소 개수
df['html_external_resource_num'] = 0
df['html_same_domain_ratio'] = 0
df['html_js_redirect_count'] = 0
df['html_redirected'] = 0
df['html_redirected_domain_changed'] = 0
if 'html_processed' not in df.columns:
    df['html_processed'] = 0
if 'url_checked' not in df.columns:
    df['url_checked'] = 0

# 테스트용 나중에 삭제
total_urls = len(df)
# df = df.head(1000)
start = time.time()
batch_size = 1000

# 중간저장 다시시작 부분
files = glob.glob('intermediate_1_*.csv')
if files:
    latest = max(files, key=lambda x: int(x.split('_')[2].split('.')[0]))
    print(f'▶ 중간 결과 불러오는 중: {latest}')
    df = pd.read_csv(latest)
    start_i = int(latest.split('_')[2].split('.')[0]) + batch_size
else:
    start_i = 0



# 이동된 url 수정
headers = {
    'User-Agent': 'Mozilla/5.0 (compatible; URLChecker/1.0)'
}

session = requests.Session()
session.headers.update(headers)
adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount('http://', adapter)
session.mount('https://', adapter)

existing = set(df['url'])
new_rows = []
redirect_sources = set()
REDIRECT_STATUS = {301, 302, 307, 308}

alive_idxs = []
#max_workers = min(32, os.cpu_count() * 2)
max_workers = min(64, os.cpu_count() * 8)

for i in range(start_i, len(df), batch_size):
    batch = df.iloc[i:i+batch_size]
    batch = batch[batch['url_checked'] == 0]
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(
                lambda url=(row['url'].strip() if row['url'].strip().startswith('http')
                             else 'http://' + row['url'].strip()):
                    session.head(url, timeout=0.8, allow_redirects=False)
            ): idx
            for idx, row in batch.iterrows()
        }
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                r = fut.result()
                code = r.status_code
                df.loc[idx, 'url_checked'] = 1

                if code == 405:
                    r = session.get(r.url, timeout=0.8, allow_redirects=False)
                    code = r.status_code
                if code < 400:
                    df.loc[idx, 'url_available'] = 1
                    alive_idxs.append(idx)
            except Exception as e:
                df.loc[idx, 'url_checked'] = 1
                print(f"[HEAD ERROR][{idx}] {e}", flush=True)
    offset = start_i + i
    if i % (batch_size * 5) == 0:
        df.drop_duplicates(subset='url', inplace=True)
        done = df['url_checked'].sum()
        df.to_csv(f'intermediate_1_{int(done)}.csv', index=False)

# html 피처 추가

# 중간저장
files_html = glob.glob('intermediate_html_*.csv')
if files_html:
    latest_html  = max(files_html, key=lambda x: int(x.split('_')[2].split('.')[0]))
    print(f'▶ 중간 결과 불러오는 중: {latest_html }')
    df = pd.read_csv(latest_html )
else:
    df['html_processed'] = 0

alive_idxs = df.index[df['url_available'] == 1].tolist()

# === 병렬 요청 및 파싱
for offset in range(0, len(alive_idxs), batch_size):
    idxs = alive_idxs[offset:offset+batch_size]
    to_proc = [idx for idx in idxs if df.at[idx, 'html_processed'] == 0]
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            (idx, executor.submit(
                lambda u=(df.at[idx,'url'].strip()
                           if df.at[idx,'url'].strip().startswith('http')
                           else 'http://' + df.at[idx,'url'].strip()):
                    session.get(u, timeout=0.6, allow_redirects=True)
            ))
            for idx in to_proc
        ]

        for idx, fut in futures:
            try:
                r = fut.result()
            except Exception as e:
                print(f"[HTML ERROR][{idx}] {e}", flush=True)
                continue

            if 300 <= r.status_code < 400 and 'Location' in r.headers:
                new_url = urljoin(r.url, r.headers['Location'])
                r = session.get(new_url, timeout=0.6, allow_redirects=True)
            
            # 리다이렉트 코드 감지
            soup_tmp  = BeautifulSoup(r.text, 'lxml')
            meta = soup_tmp.find('meta', attrs={'http-equiv': lambda v: v and v.lower()=='refresh'})
            if meta and 'url=' in meta.get('content','').lower():
                part = meta['content'].split('url=')[-1].strip().strip("'\"")
                new_url = urljoin(r.url, part)
                try:
                    r = session.get(new_url, timeout=0.6, allow_redirects=True)
                except:
                    pass

            soup = BeautifulSoup(r.text, 'lxml')
            text = r.text.lower()
            if 'moved' in text:
                link = soup.find('a', href=True)   
                if link:
                    new_url = urljoin(r.url, link['href'])
                    try:
                        r = session.get(urljoin(r.url, link['href']), timeout=0.6, allow_redirects=True)
                        soup = BeautifulSoup(r.text, 'lxml')
                    except:
                        pass

            # 리다이렉트 여부 및 도메인 변경
            redirected   = int(bool(r.history))
            dom_changed  = int(
                urlparse(df.at[idx,'url']).netloc.replace('www.','')
                != urlparse(r.url).netloc.replace('www.','')
            )

            
            html = str(soup)
            tag_counts   = [html.count(f'<{t}') for t in tags]
            event_counts = [html.count(h+'=') for h in event_handlers]
            event_elems  = [len(soup.find_all(attrs={h:True})) for h in event_handlers]

            origin = urlparse(df.at[idx,'url']).netloc.replace('www.','')
            ext = same = tot = 0
            for tag, attr in [('a','href'),('script','src'),('img','src'),('link','href')]:
                for e in soup.find_all(tag):
                    u2 = e.get(attr)
                    if not u2: continue
                    p2 = urlparse(u2); tot += 1
                    if not p2.netloc or origin in p2.netloc:
                        same += 1
                    else:
                        ext += 1
            js_redirects = sum(len(p.findall(html)) for p in redirect_patterns)

            results.append((
                idx, redirected, dom_changed,
                *tag_counts, *event_counts, *event_elems,
                ext, (same/tot if tot else 0), js_redirects
            ))
            del r, soup, html, soup_tmp
    gc.collect()  
    cols = (
        [f'html_{t}_num' for t in tags] +
        [f'html_event_{h}_num'  for h in event_handlers] +
        [f'html_event_{h}_elem' for h in event_handlers] +
        ['html_external_resource_num','html_same_domain_ratio','html_js_redirect_count']
    )
    processed = []
    for res in results:
        idx = res[0]
        processed.append(idx)
        df.at[idx, 'html_redirected']                = res[1]
        df.at[idx, 'html_redirected_domain_changed'] = res[2]
        for col, val in zip(cols, res[3:3+len(cols)]):
            df.at[idx, col] = val
        df.at[idx, 'html_processed'] = 1

    if i % (batch_size * 5) == 0: # 수정: 처리된 행 제거로 메모리 절약
        done = df['html_processed'].sum()
        df.to_csv(f'intermediate_html_{int(done)}.csv', index=False)
    

end = time.time()
elapsed = end - start
print(elapsed)
print(elapsed/1000 * total_urls / 3600)

# url 길이 컬럼 추가
df['url_length'] = df['url'].apply(len)

# 점(.) 개수 컬럼 추가
df['count_dots'] = df['url'].apply(lambda x: x.count('.'))

# 숫자 개수 컬럼 추가
df['count_digits'] = df['url'].apply(lambda x: sum(c.isdigit() for c in x))

# 특수문자 개수 컬럼 추가
special_chars = "-_=+&%$#@!*"
df['count_special'] = df['url'].apply(lambda x: sum(c in special_chars for c in x))

# 슬래시(/) 개수
df['count_slash'] = df['url'].apply(lambda x: x.count('/'))

# 물음표(?) 포함 여부
df['count_question'] = df['url'].apply(lambda x: x.count('?'))

# 등호(=) 개수
df['count_equal'] = df['url'].apply(lambda x: x.count('='))

# 퍼센트(%) 개수
df['count_percent'] = df['url'].apply(lambda x: x.count('%'))

# 인코딩 여부 (%3f 같은거)
df['is_encoded'] = df['url'].apply(lambda x: 1 if re.search(r'%[0-9a-fA-F]{2}', x) else 0)

# 의심 TLD 포함 여부  TLD ex) .com
suspicious_tlds = ['zip', 'top', 'xyz', 'tk', 'ml']
df['suspicious_tld'] = df['url'].apply(lambda x: 1 if x.split('.')[-1].lower() in suspicious_tlds else 0)

# 확장자 여부 (exe php sh 등등)

# IP 주소 포함 여부
df['has_ip'] = df['url'].apply(lambda x: 1 if re.search(r'://\d+\.\d+\.\d+\.\d+', x) else 0)

# tldextract 기반 도메인 정보 길이 (각 도메인 정보)
ext = df['url'].apply(lambda x: tldextract.extract(x, include_psl_private_domains=True))

df['subdomain_len'] = ext.apply(lambda x: len(x.subdomain))
df['domain_len'] = ext.apply(lambda x: len(x.domain))
df['suffix_len'] = ext.apply(lambda x: len(x.suffix))

# 서브 도메인 구성 개수
df['count_subdomain_parts'] = ext.apply(lambda x: len(x.subdomain.split('.')) if x.subdomain else 0)

# https 포함 여부
df['has_https'] = df['url'].apply(lambda x: 1 if 'https://' in x else 0)

# 확장자 여부 (exe php sh 등등)
df['file_ext'] = df['url'].apply(
    lambda x: re.findall(r'\.([a-zA-Z0-9]{1,6})(?:[/?#]|$)', x)
)
df['file_ext'] = df['file_ext'].apply(lambda ext: ext[-1].lower() if ext else 'none')

dangerous_exts = ['exe', 'php', 'asp', 'aspx', 'jsp', 'scr', 'bat', 'sh']
df['suspicious_ext'] = df['file_ext'].apply(lambda x: 1 if x in dangerous_exts else 0)
df.drop(columns='file_ext', inplace=True)
# 경로 깊이(path depth)
df['path_depth'] = df['url'].apply(lambda x: len([p for p in urlparse(x).path.split('/') if p]))

# URL 문자 엔트로피 (복잡도) 낮을수록 복잡한 url이 아님
df['url_entropy'] = df['url'].apply(
    lambda s: -sum(
        (s.count(c) / len(s)) * math.log2(s.count(c) / len(s))
        for c in dict.fromkeys(s)
    ) if len(s) > 0 else 0
)

# url 단축 여부
shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'buff.ly', 'rebrand.ly', 'is.gd', 'u.to', 'shorte.st']
df['html_is_shortened'] = df['url'].apply(lambda x: 1 if any(s in x for s in shorteners) else 0)

# 여기부터 데이터 품질 향상 코드

# 라벨 분리 (label 데이터 변형 방지)
url = df['url']
y = df['label']
X = df.drop(columns=['url', 'label'])

# 결측치 처리
null_ratio = X.isnull().mean()

# 10% ~ 50% → 평균 대치
#fill_cols = null_ratio[(null_ratio >= 0.1) & (null_ratio < 0.5)].index.tolist()
#for col in fill_cols:
#    X[col].fillna(X[col].mean(), inplace=True)

# 결측치 처리 - 0인 것으로 예상되어 제거하지 않고 -1 로 대체함
# 결측치와 이상치도 의미있는 feature 일 수 있음
X = X.fillna(-1)
url = url.loc[X.index]
y = y.loc[X.index]


# 표준화(정규화) : 학습 모델이 정규화된 값을 더 잘 사용해서 사용함
#scaler = StandardScaler()
#X_scaled = scaler.fit_transform(X)

# 복원
#df_cleaned = pd.DataFrame(X_scaled, columns=X.columns)
df_cleaned = X.copy()
df_cleaned['label'] = y.reset_index(drop=True)
df_cleaned['url'] = url.reset_index(drop=True)

# 최종 데이터 저장
# df_cleaned.to_csv('cleaned_url_dataset.csv', index=False)

# 확장자 포함
# (논문에서 악성 url feature가 있을 수 있음)
#
print(df_cleaned['label'].value_counts())
print(df.dtypes)


df = df_cleaned
#df = df_balanced


# 8. ✅ 파일로 저장
df.to_csv('balanced_data.csv', index=False)

# 제대로 들어갔나 확인
df = pd.read_csv('balanced_data.csv')  # 경로는 상황에 맞게 수정
print("📊 balanced_data.csv 내 클래스별 분포:")
print(df['label'].value_counts())