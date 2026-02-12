// smsService.js (şimdilik kullanılmıyor)
// Firma onayı gelince burayı gerçek SMS servisine bağlarız.

export async function sendOtpSms(_args) {
  return { ok: false, error: "SMS_DISABLED" };
}
