document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.querySelector("form");

    loginForm.addEventListener("submit", async function (event) {
        event.preventDefault(); // 기본 폼 제출 동작 방지

        const id = document.getElementById("insert_id").value;
        const pw = document.getElementById("insert_pw").value;

        // 로그인 요청 전송
        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ id, pw }),
        });

        const data = await response.json();

        if (data.success) {
            alert(data.message);
            window.location.href = "/index"; // 로그인 성공 후 리디렉션
        } else {
            alert(data.message); // 실패 시 알림
        }
    });
});
