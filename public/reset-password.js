/* public/js/login.js */

  const errBox = document.getElementById('error-message');

document.addEventListener('DOMContentLoaded', () => {
  const form   = document.getElementById('resetForm');

  /* عرض الخطأ القادم من السيرفر */
  const params = new URLSearchParams(window.location.search);
  if (params.has('error')) {
    errBox.textContent = decodeURIComponent(params.get('error'));
  }

  /* تحقّق بسيط قبل الإرسال */
  form.addEventListener('submit', e => {
    const pass  = sanitizeInput(document.getElementById('password').value);
    errBox.textContent = '';

    if (!isValidPassword(pass)) {
      e.preventDefault();
      errorBox.textContent =
        "Password must be at least 8 characters and include:\n• One uppercase letter\n• One lowercase letter\n• One special character";
    }
  });
   const queryParams = new URLSearchParams(window.location.search);
  const serverError = queryParams.get("error");
  if (serverError) {
    errorBox.textContent = decodeURIComponent(serverError.replace(/\+/g, " "));
  }
});

document.getElementById('resetForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const password = e.target.password.value;
  const token = window.location.pathname.split('/').pop();
  document.getElementById('token').value = token;
  
  try {
    const res = await fetch('/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, token })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      alert(data.message);
      window.location.href = '/login';
    } else {
        errBox.textContent = data.message || 'An error occurred ❌';
    }
  } catch (err) {
    console.error(err);
    errBox.textContent = 'There was an error connecting to the server ❌';
  }
});

