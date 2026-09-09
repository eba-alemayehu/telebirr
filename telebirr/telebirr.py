import datetime, json, requests, base64, hashlib, re, time, uuid, urllib3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from . import utils
from . import utils as tools

urllib3.disable_warnings()


class ApplyFabricTokenService:
    BASE_URL = None;
    fabricAppId = None
    appSecret = None
    merchantAppId = None

    def __init__(self, BASE_URL, fabricAppId, appSecret, merchantAppId):
        self.BASE_URL = BASE_URL
        self.fabricAppId = fabricAppId
        self.appSecret = appSecret
        self.merchantAppId = merchantAppId

    def applyFabricToken(self):
        headers = {
            "Content-Type": "application/json",
            "X-APP-Key": self.fabricAppId
        }
        payload = {
            "appSecret": self.appSecret
        }
        data = json.dumps(payload)
        authToken = requests.post(url=self.BASE_URL + "/payment/v1/token", headers=headers, data=data, verify=False)
        return authToken.json()


class Telebirr:
    req = None;
    BASE_URL = None
    fabricAppId = None
    appSecret = None
    merchantAppId = None
    merchantCode = None
    notify_path = None

    # def __init__(self, app_id, app_key, public_key, notify_url, receive_name, return_url, short_code, subject,
    #              timeout_express, total_amount, nonce, out_trade_no,
    #              api="http://196.188.120.3:10443/service-openup/toTradeWebPay"):
    def __init__(self, req, BASE_URL, fabricAppId, appSecret, merchantAppId, merchantCode, private_key):
        self.req = req
        self.BASE_URL = BASE_URL
        self.webBaseUrl = "https://developerportal.ethiotelebirr.et:38443/payment/web/paygate?"
        self.fabricAppId = fabricAppId
        self.appSecret = appSecret
        self.merchantAppId = merchantAppId
        self.merchantCode = merchantCode
        self.notify_path = "http://www.google.com"
        self.private_key = private_key

    # @Purpose: Creating Order
    #  *
    #  * @Param: all optional; title and amount fall back to the constructor's req,
    #  *         the rest override the otherwise static payload fields
    #  * @Return: rawRequest|String
    def createOrder(self, title=None, amount=None, nonce_str=None, notify_url=None,
                    redirect_url="https://www.bing.com/",
                    trade_type="Checkout", trans_currency="ETB", timeout_express="120m",
                    business_type="BuyGoods", payee_identifier_type="04", payee_type="5000",
                    callback_info="From web", method="payment.preorder", version="1.0",
                    sign_type="SHA256withRSA"):
        title = title if title is not None else self.req["title"]
        amount = amount if amount is not None else self.req["amount"]
        applyFabricTokenResult = ApplyFabricTokenService(self.BASE_URL, self.fabricAppId,
                                                                                 self.appSecret, self.merchantAppId)
        result = applyFabricTokenResult.applyFabricToken()
        fabricToken = result["token"]
        createOrderResult = self.requestCreateOrder(fabricToken, title, amount, nonce_str=nonce_str,
                                                    notify_url=notify_url,
                                                    redirect_url=redirect_url, trade_type=trade_type,
                                                    trans_currency=trans_currency, timeout_express=timeout_express,
                                                    business_type=business_type,
                                                    payee_identifier_type=payee_identifier_type,
                                                    payee_type=payee_type, callback_info=callback_info,
                                                    method=method, version=version, sign_type=sign_type)
        prepayId = createOrderResult["biz_content"]["prepay_id"]
        rawRequest = self.createRawRequest(prepayId, nonce_str=nonce_str)
        rawRequest = self.webBaseUrl + rawRequest + "&version=" + version + "&trade_type=" + trade_type
        print("URL: ", rawRequest)
        return rawRequest

    #  * @Purpose: Requests CreateOrder
    #  *
    #  * @Param: fabricToken|String title|string amount|string, plus optional
    #  *         overrides forwarded to createRequestObject
    #  * @Return: String | Boolean
    def requestCreateOrder(self, fabricToken, title, amount, **payload_params):
        headers = {
            "Content-Type": "application/json",
            "X-APP-Key": self.fabricAppId,
            "Authorization": fabricToken
        }
        # Body parameters
        payload = self.createRequestObject(title, amount, **payload_params)
        server_output = requests.post(url=self.BASE_URL + "/payment/v1/merchant/preOrder", headers=headers,
                                      data=payload, verify=False)
        print("Server output: ", server_output.content)
        return server_output.json()

    #  * @Purpose: Creating Request Object
    #  *
    #  * @Param: title|String and amount|String, plus optional overrides for the
    #  *         otherwise static payload fields
    #  * @Return: Json encoded string
    def createRequestObject(self, title, amount, nonce_str=None, notify_url=None,
                            redirect_url="https://www.bing.com/",
                            trade_type="Checkout", trans_currency="ETB", timeout_express="120m",
                            business_type="BuyGoods", payee_identifier_type="04", payee_type="5000",
                            callback_info="From web", method="payment.preorder", version="1.0",
                            sign_type="SHA256withRSA"):
        req = {
            "nonce_str": nonce_str if nonce_str is not None else tools.createNonceStr(),
            "method": method,
            "timestamp": tools.createTimeStamp(),
            "version": version,
            "biz_content": {},
        }
        biz = {
            "notify_url": notify_url if notify_url is not None else self.notify_path,
            "appid": self.merchantAppId,
            "merch_code": self.merchantCode,
            "merch_order_id": tools.createMerchantOrderId(),
            "trade_type": trade_type,
            "title": title,
            "total_amount": amount,
            "trans_currency": trans_currency,
            "timeout_express": timeout_express,
            "business_type": business_type,
            "payee_identifier": self.merchantCode,
            "payee_identifier_type": payee_identifier_type,
            "payee_type": payee_type,
            "redirect_url": redirect_url,
            "callback_info": callback_info,
        }
        req["biz_content"] = biz
        req["sign_type"] = sign_type
        sign = tools.sign(req, privateKey=self.private_key)
        req["sign"] = sign
        print(json.dumps(req))
        return json.dumps(req)

    #  * @Purpose: Create a rawRequest string for H5 page to start pay
    #  *
    #  * @Param: prepayId returned from the createRequestObject
    #  * @Return: rawRequest|string
    def createRawRequest(self, prepayId, nonce_str=None):
        maps = {
            "appid": self.merchantAppId,
            "merch_code": self.merchantCode,
            "nonce_str": nonce_str if nonce_str is not None else tools.createNonceStr(),
            "prepay_id": prepayId,
            "timestamp": tools.createTimeStamp(),
            "sign_type": "SHA256WithRSA"
        }
        rawRequest = ""
        for key in maps:
            value = maps[key]
            rawRequest = rawRequest + key + "=" + value + "&"
        sign = tools.sign(maps, privateKey=self.private_key)
        rawRequest = rawRequest + "sign=" + sign
        return rawRequest


class TelebirrSuperApp:
    def __init__(self, short_code, app_key, app_secret, merchant_id, private_key, url):
        self.short_code = short_code
        self.app_key = app_key
        self.app_secret = app_secret
        self.merchant_id = merchant_id
        self.private_key = private_key
        self.url = url

    def apply_fabric_token(self):
        response = requests.post(url=self.url + "/apiaccess/payment/gateway/payment/v1/token",
                                 headers={"X-App-key": self.app_key}, json={"appSecret": self.app_secret}, verify=False)
        return json.loads(response.content)

    def auth(self, token):
        fabric_token = self.apply_fabric_token()
        url = self.url + "/apiaccess/payment/gateway/payment/v1/auth/authToken"

        payload = {
            "timestamp": "{}".format(int(time.time())),
            "method": "payment.authtoken",
            "nonce_str": str(uuid.uuid4().hex),
            "biz_content": {
                "access_token": token,
                "trade_type": "InApp",
                "appid": self.merchant_id,
                "resource_type": "OpenId",
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

    def request_create_order(self, nonce_str, amount, notify_url, redirect_url, merch_order_id, timeout_express, title,
                             business_type, payee_identifier_type):
        fabric_token = self.apply_fabric_token()
        url = self.url + "/apiaccess/payment/gateway/payment/v1/merchant/preOrder"
        SIGN_TYPE = "SHA256WithRSA"
        timestamp = "{}".format(int(time.time()))
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
            "sign_type": SIGN_TYPE,
            "timestamp": timestamp
        }
        signature = utils.sign(payload, self.private_key)
        payload['sign'] = signature
        print(payload)
        response = requests.post(
            url=url,
            headers={
                "X-App-key": self.app_key,
                "Authorization": fabric_token.get("token")
            },
            json=payload,
            verify=False
        )
        response = json.loads(response.content)
        payload = {
            "appid": self.merchant_id,
            "merch_code": self.short_code,
            "nonce_str": nonce_str,
            "prepay_id": response.get('biz_content').get('prepay_id'),
            "timestamp": timestamp,
            "sign_type": SIGN_TYPE
        }
        pay_signature = utils.sign(payload, self.private_key)
        payload["sign"] = pay_signature
        return response, payload

    def queryOrder(self, nonce_str, merch_order_id, version="1.0", method="payment.queryorder",
                   sign_type="SHA256WithRSA"):
        fabric_token = self.apply_fabric_token()

        url = self.url + "/apiaccess/payment/gateway/payment/v1/merchant/queryOrder"
        payload = {
            "timestamp": "{}".format(int(time.time())),
            "nonce_str": nonce_str,
            "method": "payment.queryorder",
            "sign_type": sign_type,
            "version": version,
            "biz_content": {
                "appid": self.merchant_id,
                "merch_code": self.short_code,
                "merch_order_id": merch_order_id
            }
        }
        print(payload)
        print(url)
        pay_signature = utils.sign(payload, self.private_key)
        payload["sign"] = pay_signature
        print(payload)
        response = requests.post(
            url=url,
            headers={
                "X-App-key": self.app_key,
                "Authorization": fabric_token.get("token")
            },
            json=payload,
            verify=False
        )
        print(response.text)
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
