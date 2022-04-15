# Telebirr

This is a python helper package for Telebirr H5 Web payment integration helper. The use case for this interface is
payment via web. Third party system will invoke the interface upon payment issue by the customer and a redirect page
will be return to the third party system from telebirr platform.

## Logical specification

![Logical specification](img/logical_design.png)

## Platform Authentication Rule

1. Telebirr platform allocate appId and appKey to the corresponding third party client. Each third party will have a
   unique appId and appKey.
2. Third party source IP addresses should be added on the trust list. Those IP addresses of clients that are not in the
   trust list will not access telebirr system.
3. The time of the timestamp is consistent with that of the server (within one minute). If they are inconsistent, the
   access is considered illegal.
4. Check whether the signature entered by the client is consistent with the signature generated by the system. If they
   are inconsistent, the access is considered illegal.

## Request Interface Description

|Parameter |Data Type | Mandatory or Optional |Description| Example|
|----------|----------|-----------------------|-----------|--------|
|appId |String |M |Indicates the appID provided from telebirr platform. It uniquely identify the third party.| ce83aaa3dedd42 ab88bd017ce1ca|
|appKey| String |M |Indicates the appKey provided by telebirr platform| a8955b02b5df475882038616d5448d43|
|nonce| String |M |Indicates a unique random string generated by third party system. The value of nonce for each request should be unique.| ER33419df678o8bb|
|notifyUrl| String |O |Indicates the end point URL from third party which will be used by telebirr platform to respond the Payment result. Telebirr platform uses this third party end point to proactively notify third party server for payment request result. If this parameter is empty, payment result  notification will not be sent.| <https://mmpay.trade.pay/notifyUrl/>|
|outTradeNo| String |M |Indicates the third party payment transaction order number that will be generated by third party system and it shall be unique. Supported contents for outTradeNo parameter value is  digits, letters, and underscores.| T0533111222S001114129|
|returnUrl| String |M |Indicates third party redirect page URL after the payment completed.| <https://mmpay.trade.pay/T0533111222S001114129>|
|shortCode| String |M |Indicates third party  Short Code provided from telebirr.| 8000001|
|subject| String |M |Indicates the item or any other name for the payment that is being issued by the customer.
Note: Special characters such as /, =, & are not allowed.| Book|
|timeoutExpress| String |M |Indicates the payment Order request timeout from third party, which indicates the time for payment process to be ended. After this time the payment will not be processed and third party system can reinitiate again. Note: the parameter value unit is Minutes| 30|
|timestamp| String |M |Indicates the time stamp on the request message. The timestamp should be in milliseconds. Python code：`str(int(datetime.datetime.now().timestamp() * 1000))` Note: Use unix timestamp| 1624546517701|
|totalAmount| String |M |Indicates the order amount in ETB. The value ranges from 0.01 to 100000000.00 and is accurate to two decimal places. Note: The value will be authenticated by telebirr platform depending on the limit rule assigned to the customer. For instance, if the allowed daily limit transaction for a customer is 10,000 ETB then those transactions against this rule will be failed.| 9.00|
|receiveName| String |O |Indicates the transaction receiver name. | Ethiopian airlines|

## Response Interface Description

Response message element is described below

|Parameter |Data Type | Mandatory or Optional |Description| Example|
|----------|----------|-----------------------|-----------|--------|
|code |String |M |Indicates the Status Code for payment request| 0|
|msg |String |M |Indicates the Status Code Description for payment request|  success|
|data |Object |M |Indicates the Data Object that consists the toPayURL| |
|toPayUrl |String |M |Indicates telebirr payment landing page URL to redirect the customer to H5 Web Payment. | <https://h5pay.trade.pay/payId=RE9879T0972S>|

## Getting started

` pip install telebirr `

```python
from telebirr import Telebirr
private_key = "YOUR PUBLIC KEY FORM TELEBIRR ADMIN"
telebirr = Telebirr(
    app_id="YOUR APP ID FROM TELEBIRR ADMIN",
    app_key="YOUR APP KEY FROM TELEBIRR ADMIN",
    public_key=private_key,
    notify_url="https://example.com/telebirr/121232",
    receive_name="Your company name",
    return_url="https://example.com/",
    short_code="SHORT CODE FROM TELEBIRR ADMIN",
    subject="Test",
    timeout_express="30",
    total_amount="10",
    nonce="UNIQUE",
    out_trade_no="UNIQUE"
)
response = telebirr.send_request()
```
