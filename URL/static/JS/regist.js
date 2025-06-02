document.addEventListener("DOMContentLoaded", function () {
    // ✅ 아이디 중복 체크
    const checkIdButton = document.getElementById("id_check");
    if (checkIdButton) {
        checkIdButton.addEventListener("click", function () {
            const id = document.getElementById("id").value;

            if (id) {
                fetch("/check_id", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ id })
                })
                .then(response => response.json())
                .then(data => {
                    const messageElement = document.getElementById("idCheckMessage");

                    if (messageElement) {
                        if (data.success) {
                            messageElement.innerText = "사용 가능한 아이디입니다.";
                            messageElement.style.color = "green";
                        } else {
                            messageElement.innerText = "이미 사용 중인 아이디입니다.";
                            messageElement.style.color = "red";
                        }
                    }
                })
                .catch(error => console.error("중복 검사 오류:", error));
            } else {
                alert("아이디를 입력해주세요.");
            }
        });
    }

    // ✅ 회원가입 폼 제출 처리
    const registerForm = document.getElementById("registerForm");
    if (registerForm) {
        registerForm.addEventListener("submit", function (event) {
            event.preventDefault();

            const name = document.getElementById("name").value;
            const id = document.getElementById("id").value;
            const pw = document.getElementById("pw").value;

            if (!name || !id || !pw) {
                alert("모든 필드를 입력해주세요.");
                return;
            }

            fetch("/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ name, id, pw })
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                if (data.success) {
                    window.location.href = '/login';
                }
            })
            .catch(error => {
                console.error("회원가입 오류:", error);
                alert("회원가입 중 오류가 발생했습니다.");
            });
        });
    }
});
