import sys
from datetime import datetime, timedelta
import base64
import hashlib
import rsa
from urllib.parse import quote
import json

def generate_signed_url():
    # 配置参数
    cloudfront_domain = "***.cloudfront.net"  # CloudFront 分配域名
    s3_object_key = "file"               # 要访问的文件路径
    private_key_path = "private_key.pem"      # 本地私钥文件路径
    key_pair_id = "***7JGJNHLC3PB"          # CloudFront Key Pair ID（不是密钥组名！）

    # 过期时间（例如1小时后）
    expire_time = datetime.utcnow() + timedelta(hours=1)
    expire_timestamp = int(expire_time.timestamp())

    # 1. 创建签名策略（Canned Policy）
    policy = {
        "Statement": [{
            "Resource": f"https://{cloudfront_domain}/{s3_object_key}",
            "Condition": {"DateLessThan": {"AWS:EpochTime": expire_timestamp}}
        }]
    }
    policy_json = bytes(json.dumps(policy).replace(" ", ""), 'utf-8')

    # 2. 对策略进行 Base64 编码
    policy_b64 = base64.b64encode(policy_json).decode('utf-8')

    # 3. 使用私钥对策略签名
    with open(private_key_path, 'rb') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign(policy_json, private_key, 'SHA-1')
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    # 4. 生成签名 URL
    signed_url = (
        f"https://{cloudfront_domain}/{s3_object_key}"
        f"?Policy={quote(policy_b64)}"
        f"&Signature={quote(signature_b64)}"
        f"&Key-Pair-Id={key_pair_id}"
    )

    return signed_url

if __name__ == "__main__":
    signed_url = generate_signed_url()
    print("Signed URL:", signed_url)
