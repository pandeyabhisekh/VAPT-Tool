import requests
from bs4 import BeautifulSoup

url = "http://localhost:8081/Login"

session = requests.Session()

# Helper function
def get_value(soup, field_id):
    tag = soup.find(id=field_id)
    return tag["value"] if tag and "value" in tag.attrs else ""

print("\n🔍 Starting Smart Login Test...\n")

# STEP 1: Get login page
res = session.get(url)
soup = BeautifulSoup(res.text, "html.parser")

page_text = res.text.lower()

# 🔐 Detect protections
captcha_present = "captcha" in page_text
viewstate_present = "__viewstate" in page_text
encryption_detected = "process(" in page_text  # JS encryption

print("[+] Protection Detection:")
print(f"    CAPTCHA Present: {captcha_present}")
print(f"    ASP.NET Tokens Present: {viewstate_present}")
print(f"    JS Password Encryption: {encryption_detected}")

# 🚫 If CAPTCHA present → skip brute force
if captcha_present:
    print("\n🚫 CAPTCHA detected → Skipping brute-force test (Correct Behavior)")
    print("✅ System is protected against automated attacks")
else:
    print("\n⚠️ No CAPTCHA → Proceeding with brute-force test")

    for i in range(5):
        print(f"\n================ Attempt {i+1} ================")

        # Get fresh tokens every time
        res = session.get(url)
        soup = BeautifulSoup(res.text, "html.parser")

        viewstate = get_value(soup, "__VIEWSTATE")
        eventvalidation = get_value(soup, "__EVENTVALIDATION")
        viewstategen = get_value(soup, "__VIEWSTATEGENERATOR")

        data = {
            "__VIEWSTATE": viewstate,
            "__EVENTVALIDATION": eventvalidation,
            "__VIEWSTATEGENERATOR": viewstategen,
            "txtUser": "wronguser",
            "txtPassword": "wrongpass",
            "btnLogin": "Log In"
        }

        res = session.post(url, data=data)

        print("[+] Status:", res.status_code)
        print("[+] Response Length:", len(res.text))

        response_text = res.text.lower()

        if "locked" in response_text:
            print("🔒 Account LOCKED → Rate limiting working")
            break
        elif "invalid" in response_text:
            print("❌ Login failed")
        else:
            print("⚠️ Unknown response")

print("\n✅ Test Completed")