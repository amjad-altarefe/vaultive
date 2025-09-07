/*
Vaultive - Copyright (C) 2025 Amjad Qandeel
This file is part of Vaultive, licensed under GNU GPL v3.
For full license text, see LICENSE file.
*/
 const errBox = document.getElementById('error-message');

  document.addEventListener('DOMContentLoaded', () => {
  const form   = document.getElementById('forgot-form');

  /* عرض الخطأ القادم من السيرفر */
  const params = new URLSearchParams(window.location.search);
  if (params.has('error')) {
    errBox.textContent = decodeURIComponent(params.get('error'));
  }

  /* تحقّق بسيط قبل الإرسال */
  form.addEventListener('submit', e => {
    const email = sanitizeInput(document.getElementById('email').value);
    errBox.textContent = '';

    if (!isValidEmail(email)) {
      e.preventDefault();
      errBox.textContent = 'Invalid email format.';
    }
  });
});


    document.getElementById('forgot-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      errBox.textContent = '';

      try {
        const res = await fetch('/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type':'application/json' },
          body: JSON.stringify({ email })
        });
        const data = await res.json();
        errBox.textContent = data.message || (data.success ? 'Sent successfully' : 'An error occurred.');
      } catch {
        errBox.textContent = 'Could not connect to the server.';
      }
    });
