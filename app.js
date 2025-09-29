const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const User = require('./models/User');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
require('dotenv').config();
const {checkAdmin, checkSession } = require('./authentication');
const { encrypt, decrypt } = require('./encryption');
const rateLimit = require('express-rate-limit');
const nodemailer = require("nodemailer");
const bodyParser = require("body-parser");
const lusca = require("lusca");
const crypto = require('crypto'); // ستحتاجه لتوليد التوكِن

// index.js (CommonJS)
//app.use(express.urlencoded({ extended: false }));

//////////////////////////////////////////////////////////////////


const app = express();

// حل مشكلة proxy على Vercel
app.set("trust proxy", 1); 

// إعداد مرسل البريد
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// فحص الإعدادات عند الإقلاع
transporter.verify((err, success) => {
  if (err) {
    console.error('❌ SMTP verify error:', err);
  } else {
    console.log('✅ SMTP is ready to send emails');
  }
});


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use('/assets', express.static('assets')); // هذا يرسل الفيديوهات مع MIME type صحيح

const helmet = require('helmet');
app.use(helmet());
const cors = require('cors');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", 'trusted-cdn.com'],
        styleSrc:   ["'self'", "'unsafe-inline'"], // ← هنا المفتاح!
    fontSrc: ["'self'", 'fonts.gstatic.com'],
    imgSrc: ["'self'", 'data:'],
  }
}));


const corsOptions = {
  origin: 'http://localhost:5000',      //    <--------------- ` http://localhost:${PORT} ` رح يطلع ايرور في عملية ال(run)
  methods: ['GET', 'POST'],
  credentials: true,
};

app.use(cors(corsOptions));
const PORT=process.env.PORT;
const EMAIL = process.env.EMAIL
const SALT = Number(process.env.SALT);
const secret = process.env.JWT_SECRET;
const MONGO_DB = process.env.MONGODB_URI || process.env.MONGO_DB;

mongoose.connect(MONGO_DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("✅ Connected to MongoDB");
}).catch(err => {
    console.error("❌ Failed to connect to MongoDB", err);
});


app.use(express.urlencoded({ extended: true }));
app.use(express.json());


// حد: 3 محاولات تسجيل دخول كل 15 دقيقة
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 15 دقيقة
  max: 10, // عدد المحاولات المسموح بها
  message: { message: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const contactLimiter = rateLimit({
  windowMs: 60 * 1000, // دقيقة
  max: 5,              // 5 رسائل بالدقيقة
  message: { message: "Too many requests. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(session({
  secret: process.env.JWT_SECRET, 
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',  // فعّلها في الإنتاج فقط
    sameSite: 'strict',  // أو 'lax' حسب احتياجك
    maxAge: 1000 * 60 * 15 // 15 دقيقة = 1000 ملي ثانية * 60 ثانية * 15  
    }
}));


app.post('/login', [
  body('email').matches( /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/i)
  .withMessage('Invalid email format').normalizeEmail(),
  body('password')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/)
  .withMessage('Incorrect password'),
], loginLimiter,
  async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const message = errors.array().map(e => e.msg).join(', ');
    return res.redirect('/login?error=' + encodeURIComponent(message));
  }

  const { email, password } = req.body;

  try {
    const encryptedEmail = encrypt(email);
    const user = await User.findOne({ email: encryptedEmail });

    if (!user) {
      return res.redirect('/login?error=' + encodeURIComponent('User not found'));
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.redirect('/login?error=' + encodeURIComponent('Invalid credentials'));
    }

    req.session.regenerate(function(err) {
      if (err) return res.redirect('/login?error=' + encodeURIComponent('Session error'));

      req.session.userId = user._id;
      req.session.role = user.role;

      if (user.role === 'admin') {
        req.session.isAdmin = true;
        return res.redirect('/admin');
      }

      return res.redirect('/index1');
    });

  } catch (err) {
    console.error("Login error:", err);
    return res.redirect('/login?error=' + encodeURIComponent('Server error'));
  }
});
app.post('/register',[ body('name').matches(/^[A-Za-z\s]{2,}$/).withMessage('Invalid Name format'),
  body('email').matches( /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/i)
  .withMessage('Invalid email format').normalizeEmail(),
  body('password')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/)
  .withMessage('Password must be at least 8 characters and include:\n• One uppercase letter\n• One lowercase letter\n• One special character')
,], 
  async (req, res) => {
  
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // إذا في أخطاء، رجعها للمستخدم
     const msg = errors.array()[0].msg;
      return res.redirect('/register.html?error=' + encodeURIComponent(msg));
    }

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.redirect(
        '/register.html?error=' + encodeURIComponent('All fields are required')
      );
    }

    try {
        const hashedPassword = await bcrypt.hash(password, SALT); // <-- تشفير الباسورد
        const encryptedEmail = encrypt(email);
        const user = new User({ name, email: encryptedEmail, password: hashedPassword, role: 'user' }); // <-- حفظ المشفّر
        await user.save();

        return res.redirect(
        '/login.html?success=' + encodeURIComponent('User registered successfully. Please log in.')
      );
    } catch (err) {
        if (err.code === 11000) {
            return res.redirect(
          '/register.html?error=' + encodeURIComponent('Email already exists.')
        );
      }
      console.error('Registration error:', err);
      return res.redirect(
        '/register.html?error=' + encodeURIComponent('Something went wrong.')
      );
    }
});

// تحديد معدل للطلبات (اختياري لكن مُستحسن)
const forgotLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 دقائق
  max: 5,
  message: { message: 'Too many requests. Try again later.' }
});

app.post('/forgot-password', forgotLimiter , [
    // التحقق من صيغة البريد
    body('email').matches( /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/i)
  .withMessage('Invalid email format').normalizeEmail(),
  ], async (req, res) => {
  try {
    const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const msg = errors.array()[0].msg;
        return res.json({ success: false, message: msg });
      }

    const { email } = req.body;
    if (!email) return res.json({ success: false, message: 'Please enter your email.' });

    // ابحث عن المستخدم بالإيميل المُشفّر
    const encryptedEmail = encrypt(email);
    const user = await User.findOne({ email: encryptedEmail });
    if (!user) {
      // لأسباب أمنية، لا تفصح إن الإيميل غير موجود؛ لكن إن أردتها صريحة اتركها
      return res.json({ success: true, message: 'If there is an account with this email, you will receive a message.' });
    }

    // أنشئ توكِن يحوي 32 بايت
    const token = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // ساعة
    await user.save();

    const resetURL = `${process.env.BASE_URL}/reset-password/${token}`;
    console.log('🔗 Reset link: ', resetURL);

    await transporter.sendMail({
      from: `"Vaultive" <${process.env.EMAIL_USER}>`,
      to: email, // نرسل على البريد بصيغته العادية
      subject: 'Reset password',
      html: `
        <p>You have been asked to reset your Vaultive account password.</p>
        <p>If you didn't request this, you can ignore this message.</p>
        <p>To reset, click the following link (valid for one hour):</p>
        <p><a href="${resetURL}">${resetURL}</a></p>
      `
    });

    return res.json({ success: true, message: 'The link has been sent to your email.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    return res.json({ success: false, message: 'A server error occurred.' });
  }
});


app.post("/api/contact",contactLimiter,
  [body("name").trim().isLength({ min: 3, max: 25 }).withMessage("Invalid name"),
    body("email").isEmail().withMessage("Invalid email").normalizeEmail(),
    body("phone").matches(/^\+?[0-9]{8,15}$/).withMessage("Invalid phone"),
    body("message").trim().isLength({ min: 10, max: 2000 }).withMessage("Message too short"),],
  async (req, res) => {
    // تحقّق الفالديشن
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ ok: false, errors: errors.array() });
    }

    const { name, email, phone, message } = req.body;

    // مُرسِل SMTP (Gmail)
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // نص الرسالة
    const subject = `New message from ${name}`;
    const text = `Name: ${name}
                  Phone: ${phone}
                  Email: ${email}

                  Message:
                  ${message}`;

                  const html = `
                    <h3>You have a new message from Vaultive</h3>
                    <p><strong>Name:</strong> ${escapeHtml(name)}</p>
                    <p><strong>Email:</strong> ${escapeHtml(email)}</p>
                    <p><strong>Phone:</strong> ${escapeHtml(phone)}</p>
                    <p><strong>Message:</strong><br>${escapeHtml(message).replace(/\n/g, "<br>")}</p>
                  `;

    try {
      await transporter.sendMail({
        from: `"Vaultive" <${process.env.EMAIL_USER}>`, // من بريدك (التزام DMARC)
        to: process.env.CONTACT_TO,                     // بريد الاستقبال
        replyTo: email,                                 // زرّ الرد يروح لمرسل الرسالة
        subject,
        text,
        html,
      });

      return res.json({ ok: true, message: "Message sent successfully!" });
    } catch (err) {
      console.error("Mail error:", err);
      return res.status(500).json({ ok: false, message: "Failed to send message." });
    }
  });

// دالة بسيطة لتفادي إدخال HTML
function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ملفات static مثل html, css, js
app.use(express.static(path.join(__dirname, 'public')));

// الراوت الرئيسي يفتح login.html
app.get('/',loginLimiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// راوت login
app.get('/login',loginLimiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// راوت register
app.get('/register',loginLimiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid'); // ← مهم لمسح الكوكي
    res.redirect('/login');
  });
});

app.get("/profile", loginLimiter, async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: "Not logged in" });
    }

    const user = await User.findById(req.session.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    let decryptedEmail;
    try {
      decryptedEmail = decrypt(user.email);  // فك تشفير الإيميل
    } catch (err) {
      console.error("Error decrypting email:", err);
      return res.status(500).json({ message: "Error decrypting email" });
    }

    // عدل الكائن بحيث يرجع الإيميل المفكوك
    const userData = {
      _id: user._id,
      name: user.name,
      email: decryptedEmail
    };

    res.json(userData);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Route لعرض صفحة إعادة التعيين
app.get('/reset-password/:token', loginLimiter, async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() }
  });

  if (!user) {
    return res.redirect('/reset-password?error=' + encodeURIComponent('The link is invalid or expired ❌'));
  }

  // لو صالح اعرض صفحة HTML
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});



app.post('/reset-password', [
  body('token').isLength({ min: 64, max: 64 })
   .withMessage('Invalid or expired reset token'),
  body('password')
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/)
  .withMessage('Password must be at least 8 characters and include:\n• One uppercase letter\n• One lowercase letter\n• One special character')
,], loginLimiter,
  async (req, res) => {
     try {
      const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const msg = errors.array()[0].msg;
      return res.status(400).json({ success: false, message: msg }); // ✅
    }

  const { password, token } = req.body;

  if (!token || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' }); // ✅

    }

  const user = await User.findOne({ resetPasswordToken: { $eq: token }, resetPasswordExpires: { $gt: Date.now() } });

    if (!user) {
      return res.status(400).json({ success: false, message: 'The link is invalid or expired ❌' }); // ✅
    }

    // تحديث كلمة المرور
    user.password = await bcrypt.hash(password, SALT);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

        return res.json({ success: true, message: 'Password changed successfully ✅' }); // ✅

  } catch (err) {
    console.error(err);
     return res.status(500).json({ success: false, message: 'Something went wrong ❌' }); // ✅

    }
});


app.get('/admin',loginLimiter, checkAdmin,checkSession, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
//✅ عرض جميع المستخدمين:
app.get('/admin/users',loginLimiter, checkAdmin,checkSession, async (req, res) => {
  try {
    const users = await User.find();
    const decryptedUsers = users.map(user => ({
      _id: user._id,
      name: user.name,  
      email: decrypt(user.email), // ← فك التشفير
      role: user.role
    }));  
    res.json(decryptedUsers); // ترسل البيانات كـ JSON
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.get('/index1',loginLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index1.html'));
});
app.get('/service',loginLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'service.html'));
});


//✅ حذف مستخدم:
app.delete('/admin/users/:id', loginLimiter, checkAdmin,checkSession, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.send('User deleted');
  } catch (err) {
    res.status(500).send('Server error');
  } 
});

// استخدامها في المسارات

app.get('/api/user',loginLimiter, (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

  User.findById(req.session.userId)
    .then(user => {
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json({ name: user.name, email: decrypt(user.email), role: user.role });
    })
    .catch(() => res.status(500).json({ error: 'Server error' }));
});

// صدّر الـ app — Vercel يتعرف على الملف ويشغّله كـ Function أو App
module.exports = app;

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
