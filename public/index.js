
  fetch("/profile")
    .then(res => res.json())
    .then(user => {
      document.getElementById("name").textContent = user.name;
      document.getElementById("email").textContent = user.email;
    })


const modal = document.getElementById("videoModal");
const modal2 = document.getElementById("videoModal2");

const btn = document.getElementById("playVideoBtn");
const btn2 = document.getElementById("playVideoBtn2");

const closeBtn = modal.querySelector(".close");
const closeBtn2 = modal2.querySelector(".close");

const video = document.getElementById("popupVideo");
const video2 = document.getElementById("popupVideo2");


// فتح البوب أب وتشغيل الفيديو
btn.addEventListener("click", (e) => {
  e.preventDefault();
  modal.style.display = "flex";
  video.play();
});

// إغلاق عند الضغط على ×
closeBtn.addEventListener("click", () => {
  modal.style.display = "none";
  video.pause();
  video.currentTime = 0;
});

// إغلاق عند الضغط خارج الفيديو
modal.addEventListener("click", (e) => {
  if (e.target === modal) {
    modal.style.display = "none";
    video.pause();
    video.currentTime = 0;
  }
});

btn2.addEventListener("click", (e) => {
  e.preventDefault();
  modal2.style.display = "flex";
  video2.play();
});
closeBtn2.addEventListener("click", () => {
  modal2.style.display = "none";
  video2.pause();
  video2.currentTime = 0;
});
modal2.addEventListener("click", (e) => {
  if (e.target === modal2) {
    modal2.style.display = "none";
    video2.pause();
    video2.currentTime = 0;
  }
});


(async () => {
  try {
    const res = await fetch('/api/user', { credentials:'include' });
    const el = document.getElementById('auth-link');
    if (res.ok) {
      el.textContent = 'Logout';
      el.href = '/logout';
      el.className = 'hpt-logout-btn-1';
    } else {
      el.textContent = 'Login';
      el.href = '/login';
      el.className = 'hpt-login-btn-1';
    }
  } catch (_) {}
})();

