1.生成密钥对
openssl genrsa -out private_key.pem 2048
openssl rsa -pubout -in private_key.pem -out public_key.pem

2.将公钥上传至AWS CloudFront Public Key

3.创建Key Groups

4.关联Key Groups 和 Distribution
