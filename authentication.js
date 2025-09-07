/*
Vaultive - Copyright (C) 2025 Amjad Qandeel
This file is part of Vaultive, licensed under GNU GPL v3.
For full license text, see LICENSE file.
*/
const User = require('./models/User');
require('dotenv').config();

const checkSession = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).send('Unauthorized');
    }
    next();
};

function checkAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    next();
  } else {
    res.status(403).send('Access denied');
  }
}

module.exports = {
    checkSession,
    checkAdmin
};
