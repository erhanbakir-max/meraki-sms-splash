'use strict';

// SMS şimdilik kapalı.
// Anlaşma bitince burayı gerçek provider ile dolduracağız.

async function sendSms(/* phone, text */) {
  return { ok: false, disabled: true };
}

module.exports = { sendSms };
