// لو CSP يمنع inline scripts، انقل هذا لملف JS خارجي وأضف nonce أو عدّل helmet.
document.getElementById('contactForm').addEventListener('submit', async function (e) {
  e.preventDefault();

  const form = e.target;
  const payload = {
    name: form.name.value.trim(),
    phone: form.phone.value.trim(),
    email: form.email.value.trim(),
    message: form.message.value.trim(),
  };

  const msgEl = document.getElementById('responseMsg');
  msgEl.textContent = "Sending...";

  try {
    const res = await fetch('/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.message || 'Failed');
    }

    msgEl.textContent = "✅ Message sent successfully!";
    form.reset();
  } catch (err) {
    msgEl.textContent = "❌ Something went wrong. Please try again later.";
  }
});



























/*
document.getElementById('contactForm').addEventListener('submit', function(e) {
    e.preventDefault(); // منع إعادة تحميل الصفحة

    const form = e.target;
    const formData = new FormData();
    for (let [key, value] of formData.entries()) {
        formData.append(key, DOMPurify.sanitize(value));
    }

    fetch('http://localhost:8080/web%20agency/assets/php/sendmail.php', {
    method: 'POST',
    body: formData
})
.then(response => {
    console.log('Status:', response.status);
    if (!response.ok) {
        throw new Error('Status code: ' + response.status);
    }
    return response.text();
})
.then(data => {
    console.log('Response data:', data);
    document.getElementById('responseMsg').textContent = "✅ Message sent successfully!";
    form.reset();
})
.catch(error => {
    document.getElementById('responseMsg').textContent = "❌ Something went wrong. Please try again later.";
});
});*/



