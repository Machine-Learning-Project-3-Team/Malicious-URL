// ✅ API Key 발급 버튼 클릭 시 모달 열기
async function openModal() {
  try {
    const response = await fetch('/issue_api_key'); // Flask 라우터 호출
    const result = await response.json();

    if (response.ok && result.api_key) {
      // API 키 및 유효기간 표시
      document.querySelector('.modal-input').value = result.api_key;
      document.querySelector('.expiration').innerText = result.api_expiration;

      // 모달 열기
      document.getElementById('apiModal').style.display = 'block';
    } else {
      alert(result.message || 'API Key 발급에 실패했습니다.');
    }
  } catch (err) {
    console.error('API 요청 실패:', err);
    alert('서버와의 통신 중 오류가 발생했습니다.');
  }
}

// ✅ 모달 닫기 버튼 클릭 시
function closeModal() {
  document.getElementById('apiModal').style.display = 'none';
}

// ✅ 복사 버튼 클릭 시 클립보드 복사
function copyAPIKey() {
  const input = document.querySelector('.modal-input');
  if (!input.value) {
    alert('API Key가 없습니다.');
    return;
  }

  navigator.clipboard.writeText(input.value)
    .then(() => {
      alert('API Key가 복사되었습니다.');
    })
    .catch(err => {
      console.error('복사 실패:', err);
      alert('복사에 실패했습니다.');
    });
}

// ✅ 재발급 버튼 클릭 시 새 API Key 발급
async function reissueAPIKey() {
  try {
    const response = await fetch('/reissue_api_key', {
      method: 'POST'
    });
    const result = await response.json();

    if (response.ok && result.api_key) {
      // 새 키 표시
      document.querySelector('.modal-input').value = result.api_key;
      document.querySelector('.expiration').innerText = result.api_expiration;
      alert('새 API Key가 발급되었습니다.');
    } else {
      alert(result.message || 'API Key 재발급에 실패했습니다.');
    }
  } catch (err) {
    console.error('재발급 요청 실패:', err);
    alert('서버와의 통신 중 오류가 발생했습니다.');
  }
}
