import datetime, json, requests, base64, collections, hashlib, re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

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
        ordered_items = collections.OrderedDict(sorted(ussd_for_string_a.items()))
        string_a = ''
        for key, value in ordered_items.items():
            if string_a == '':
                string_a = key + '=' + value
            else:
                string_a += '&' + key + '=' + value
        string_b = hashlib.sha256(str.encode(string_a)).hexdigest()
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