import os
import httpx
import logging

logger = logging.getLogger(__name__)

# Çevre değişkenlerinden dinamik olarak çekilen yapılandırmalar
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

SMS_ACCOUNT_SID = os.getenv("SMS_ACCOUNT_SID", "")
SMS_AUTH_TOKEN = os.getenv("SMS_AUTH_TOKEN", "")
SMS_FROM_NUMBER = os.getenv("SMS_FROM_NUMBER", "")
TARGET_PHONE = os.getenv("TARGET_PHONE", "+905458967685")

def send_webhook(message: str):
    if not WEBHOOK_URL:
        logger.info("Webhook URL tanımlı değil, bildirim atlanıyor.")
        return
    try:
        # Discord 'content', Slack 'text' parametresi bekler
        payload = {"text": message, "content": message}
        httpx.post(WEBHOOK_URL, json=payload, timeout=15.0)
    except Exception as e:
        logger.error(f"Webhook gönderilemedi: {e}")

def send_sms(short_message: str):
    if not SMS_ACCOUNT_SID or not SMS_AUTH_TOKEN:
        logger.info("SMS API bilgileri eksik, SMS atlanıyor.")
        return

    url = f"https://api.twilio.com/2010-04-01/Accounts/{SMS_ACCOUNT_SID}/Messages.json"
    data = {
        "To": TARGET_PHONE,
        "From": SMS_FROM_NUMBER,
        "Body": short_message
    }
    
    try:
        httpx.post(url, data=data, auth=(SMS_ACCOUNT_SID, SMS_AUTH_TOKEN), timeout=15.0)
        logger.info(f"{TARGET_PHONE} numarasina SMS iletildi.")
    except Exception as e:
        logger.error(f"SMS gonderilemedi: {e}")

def trigger_audit_alert_if_needed(diff_data: dict):
    summary = diff_data.get("summary", {})
    new_ports = summary.get("new_ports_count", 0)
    mod_ports = summary.get("modified_ports_count", 0)

    if new_ports > 0 or mod_ports > 0:
        target = diff_data.get("target", "Bilinmeyen")
        
        # 1. DISCORD İÇİN DETAYLI MESAJ
        webhook_msg = f"🚨 *GÜVENLİK UYARISI: Ağ Değişikliği Tespit Edildi!*\n📍 **Hedef:** `{target}`\n"
        if new_ports > 0:
            webhook_msg += f"⚠️ **YENİ PORTLAR ({new_ports}):**\n"
            for p in diff_data["changes"]["new_open_ports"]:
                webhook_msg += f"   - Port {p.get('portid')} ({p.get('service')})\n"
        if mod_ports > 0:
            webhook_msg += f"🔄 **DEĞİŞEN SERVİSLER ({mod_ports})**\n"
        
        send_webhook(webhook_msg)

        # 2. TELEFON İÇİN KISA SMS MESAJI
        sms_msg = f"ALARM! Hedef: {target}\nYeni Port: {new_ports} | Degisen: {mod_ports}\nAginda yetkisiz degisiklik tespit edildi. Sisteme giris yapip kontrol et."
        send_sms(sms_msg)