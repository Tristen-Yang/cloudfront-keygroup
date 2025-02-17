import json
import base64
from datetime import datetime, timedelta
import rsa
from urllib.parse import quote

def generate_signed_cookies():
    # 配置参数
    cloudfront_domain = "***.cloudfront.net"  # CloudFront 分配域名
    resource_path = "files/*"             # 允许访问的路径（支持通配符）
    private_key_path = "private_key.pem"      # 本地私钥文件路径
    key_pair_id = "***7JGJNHLC3PB"          # CloudFront Key Pair ID

    # 过期时间（例如1小时后）
    expire_time = datetime.utcnow() + timedelta(hours=1)
    expire_timestamp = int(expire_time.timestamp())

    # 1. 创建策略（允许访问 protected/ 下的所有文件）
    policy = {
        "Statement": [{
            "Resource": f"https://{cloudfront_domain}/{resource_path}",
            "Condition": {
                "DateLessThan": {"AWS:EpochTime": expire_timestamp}
            }
        }]
    }
    policy_json = json.dumps(policy, separators=(",", ":")).encode("utf-8")

    # 2. 对策略进行 Base64 编码
    policy_b64 = base64.b64encode(policy_json).decode("utf-8")

    # 3. 使用私钥对策略签名
    with open(private_key_path, "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign(policy_json, private_key, "SHA-1")
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    # 4. 生成 Signed Cookies
    cookies = {
        "CloudFront-Policy": policy_b64,
        "CloudFront-Signature": signature_b64,
        "CloudFront-Key-Pair-Id": key_pair_id
    }

    return cookies

if __name__ == "__main__":
    signed_cookies = generate_signed_cookies()
    print("Set-Cookie Headers:")
    for name, value in signed_cookies.items():
        # 注意：Cookie 的 Path 和 Domain 需根据实际情况设置
        print(f"Set-Cookie: {name}={value}; Path=/; Domain=.example.com; Secure; HttpOnly")
