import datetime, json, requests, base64, hashlib, re, time, uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from . import utils

class Telebirr:
    api = "http://196.188.120.3:10443/service-openup/toTradeWebPay"

    def __init__(self, app_id, app_key, public_key, notify_url, receive_name, return_url, short_code, subject,
                 timeout_express, total_amount, nonce, out_trade_no,
                 api="http://196.188.120.3:10443/service-openup/toTradeWebPay"):

        self.api = api
        self.app_id = app_id
        ussd = {
            "appId": self.app_id,
            "notifyUrl": notify_url,
            "outTradeNo": out_trade_no,
            "receiveName": receive_name,
            "returnUrl": return_url,
            "shortCode": short_code,
            "subject": subject,
            "timeoutExpress": timeout_express,
            "totalAmount": total_amount, "nonce": nonce,
            "timestamp": str(int(datetime.datetime.now().timestamp() * 1000))
        }
        self.ussd = self.__encrypt_ussd(ussd=ussd, public_key=public_key)
        self.sign = self.__sign(ussd=ussd, app_key=app_key)

    @staticmethod
    def __encrypt_ussd(ussd, public_key):
        public_key = re.sub("(.{64})", "\\1\n", public_key.replace("\n", ""), 0, re.DOTALL)
        public_key = '-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----'.format(public_key)
        ussd_json = json.dumps(ussd)
        encrypt = Telebirr.encrypt(public_key=public_key, msg=ussd_json)
        return encrypt

    @staticmethod
    def encrypt(public_key, msg):
        rsa = RSA.importKey(public_key)
        cipher = PKCS1_v1_5.new(rsa)
        ciphertext = b''
        for i in range(0, len(msg) // 117):
            ciphertext += cipher.encrypt(msg[i * 117:(i + 1) * 117].encode('utf8'))
        ciphertext += cipher.encrypt(msg[(len(msg) // 117) * 117: len(msg)].encode('utf8'))
        return base64.b64encode(ciphertext).decode('ascii')

    @staticmethod
    def __sign(ussd, app_key):
        ussd_for_string_a = ussd.copy()
        ussd_for_string_a["appKey"] = app_key
        string_b = utils.sign_sha256(ussd_for_string_a)
        return str(string_b).upper()

    def request_params(self):
        return {
            "appid": self.app_id,
            "sign": self.sign,
            "ussd": self.ussd
        }

    def send_request(self):
        response = requests.post(url=self.api, json=self.request_params())
        return json.loads(response.text)


    @staticmethod
    def decrypt(public_key, payload):
        public_key = re.sub("(.{64})", "\\1\n", public_key.replace("\n", ""), 0, re.DOTALL)
        public_key = '-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n'.format(public_key)
        b64data = '\n'.join(public_key.splitlines()[1:-1])
        key = load_der_public_key(base64.b64decode(b64data), default_backend())

        signature = base64.b64decode(payload)
        decrypted = b''
        for i in range(0, len(signature), 256):
            partial = key.recover_data_from_signature(
                signature[i:i + 256 if i + 256 < len(signature) else len(signature)], PKCS1v15(), None)
            decrypted += partial

        return json.loads(decrypted)



class TelebirrSuperApp:
    def __init__(self, short_code, app_key, app_secret, merchant_id, private_key, url):
        self.short_code = short_code
        self.app_key = app_key
        self.app_secret = app_secret
        self.merchant_id = merchant_id
        self.private_key = private_key
        self.url = url


    def apply_fabric_token(self):
        response = requests.post(url=self.url+"/apiaccess/payment/gateway/payment/v1/token", headers={"X-App-key": self.app_key}, json={"appSecret": self.app_secret}, verify=False)
        return json.loads(response.content)

    def auth(self, token):
        fabric_token = self.apply_fabric_token()
        url = self.url + "/apiaccess/payment/gateway/payment/v1/auth/authToken"

        payload = {
            "timestamp": "{}".format(int(time.time())),
            "method": "payment.authtoken",
            "nonce_str": str(uuid.uuid4().hex),
            "biz_content": {
                access_token: token,
                trade_type: "InApp",
                appid: self.merchant_id,
                resource_type: "OpenId",
            },
            "version": "1.0",
            "sign_type": "SHA256WithRSA",
        }
        signature = utils.sign(payload, self.private_key)
        payload['sign'] = signature

        response = requests.post(
            url=url,
            headers={
                "X-App-key": self.app_key,
                "Authorization": fabric_token.get("token")
            },
            json=payload,
            verify=False
        )
        return json.loads(response.content)

    def request_create_order(self, nonce_str, amount, notify_url, redirect_url, merch_order_id, timeout_express, title, business_type, payee_identifier_type):
        fabric_token = self.apply_fabric_token()
        url = self.url+"/apiaccess/payment/gateway/payment/v1/merchant/preOrder"

        payload = {
                "nonce_str": nonce_str,
                "biz_content": {
                     "notify_url": notify_url,
                     "redirect_url": redirect_url,
                     "trans_currency": "ETB",
                     "total_amount": amount,
                     "merch_order_id": merch_order_id,
                     "appid": self.merchant_id,
                     "merch_code": self.short_code,
                     "timeout_express": timeout_express,
                     "trade_type": "InApp",
                     "title": title,
                     "business_type": business_type,
                     "payee_identifier": self.short_code,
                     "payee_identifier_type": payee_identifier_type,
                     "payee_type": "5000"
                 },
                 "method": "payment.preorder",
                 "version": "1.0",
                 "sign_type": "SHA256WithRSA",
                 "timestamp": "{}".format(int(time.time()))
            }
        signature = utils.sign(payload, self.private_key)
        payload['sign'] = signature
        print(payload)
        response = requests.post(
            url= url,
            headers={
                "X-App-key": self.app_key,
                "Authorization": fabric_token.get("token")
            },
            json=payload,
            verify=False
        )
        return json.loads(response.content)

    def queryOrder(self, nonce_str, sign, merch_order_id, version="1.0", method="payment.queryorder", sign_type="SHA256WithRSA"):
        fabric_token = self.apply_fabric_token()

        response = requests.post(
            url=self.url,
            headers={
                "X-App-key": self.app_key,
                "Authorization": fabric_token.get("token")
            },
            json={
                 "timestamp": "{}".format(time.time()),
                 "nonce_str": nonce_str,
                 "method": method,
                 "sign_type": sign_type,
                 "sign": sign,
                "version": version,
                "biz_content": {
                    "appid": self.merchant_id,
                    "merch_code": self.short_code,
                    "merch_order_id": merch_order_id
                }
            }, verify=False
        )
        return json.loads(response.content)

    @staticmethod
    def __sign(data, private_key):
        excludeFields = [
            "sign",
            "sign_type",
            "header",
            "refund_info",
            "openType",
            "raw_request",
            "biz_cont"]
        to_sign_data = data.copy()
        flat_signa_data = {}
        for key, value in to_sign_data.items():
            if isinstance(value, dict):
                for k, v in value.items():
                    if k not in excludeFields:
                        flat_signa_data[k] = v
            else:
                if key not in excludeFields:
                    flat_signa_data[key] = value
        string_b = utils.sign_sha256(flat_signa_data, private_key)
        return string_b

