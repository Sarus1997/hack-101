import requests
import subprocess
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# ปิดคำเตือน SSL warning (ใช้เฉพาะตอนทดสอบเท่านั้น)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# fallback ด้วย curl ถ้า requests ใช้ไม่ได้
def fallback_curl_request(url, required_headers):
    try:
        print(f"\n🌐 Using curl fallback for: {url}\n")
        result = subprocess.run(
            ['curl', '-I', '--insecure', url],  # -I = HEAD request
            capture_output=True,
            text=True
        )
        headers = result.stdout
        for header in required_headers:
            if any(header.lower() in line.lower() for line in headers.splitlines()):
                print(f"✅ {header}: Found")
            else:
                print(f"❌ {header}: Not Found")
    except Exception as e:
        print(f"\n❗ Curl error: {e}")

# ฟังก์ชันหลักสำหรับตรวจสอบ Security Headers
def check_security_web(url):
    required_headers = [
        # Core security headers
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",

        # Additional useful headers
        "Access-Control-Allow-Origin",
        "Cache-Control",
        "Pragma",
        "Expires",
        "Content-Disposition",

        # Server info (should be hidden or removed)
        "Server",
        "X-Powered-By"
    ]

    try:
        print(f"\n🔍 Checking security headers for: {url}\n")
        response = requests.get(url, verify=False, timeout=30)
        headers = response.headers

        for header in required_headers:
            if header in headers:
                if header in ["Server", "X-Powered-By"]:
                    print(f"⚠️  {header}: Found → Consider removing or obfuscating this")
                else:
                    print(f"✅ {header}: Found")
            else:
                if header in ["Server", "X-Powered-By"]:
                    print(f"✅ {header}: Not Found → Good (Information not exposed)")
                else:
                    print(f"❌ {header}: Not Found")

        # เช็ค Set-Cookie แยก (เพราะเป็น list และมี attribute หลายค่า)
        cookies = response.headers.get("Set-Cookie")
        if cookies:
            print("\n🍪 Set-Cookie:")
            secure = "Secure" in cookies
            httponly = "HttpOnly" in cookies
            samesite = "SameSite" in cookies

            print(f"   {'✅' if secure else '❌'} Secure")
            print(f"   {'✅' if httponly else '❌'} HttpOnly")
            print(f"   {'✅' if samesite else '❌'} SameSite")
        else:
            print("\n🍪 Set-Cookie: Not Found")

    except (requests.exceptions.SSLError, requests.exceptions.ReadTimeout) as err:
        print(f"\n⚠ Connection issue with {url}: {err}")
        fallback_curl_request(url, required_headers)

    except Exception as e:
        print(f"\n❗ Error checking {url}: {e}")

# ✅ ตัวอย่างการใช้งาน
if __name__ == "__main__":
    check_security_web("https://chatgpt.com/")  # เปลี่ยน URL ตามต้องการ
