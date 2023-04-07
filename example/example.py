from telebirr import TelebirrSuperApp
import random, uuid

def main():
    t = TelebirrSuperApp(
        short_code='202333',
        app_key="ada42afe807a43759c99f5e0ef54b573",
        app_secret="0dd307bc81a3605f750b3ae38725f828",
        merchant_id="978274019430402",
        private_key="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChuoLgHVngrJflKXd2cHJyAicyBkL1HDmWZS4hITWaDKvMjCHZKlR8iKCgHVn6wVTEOv2UWPsBiUEdhtZ41xCsSvK/Y2PF12lzqueHebrlKygdztCCz/uQWFpQdKIX4jBMYTLbfowalaZ9fKfUN68+zlDmi/eDOtYSOf9EqVT1ws5UrfYrojiFewaNjsg5um2i9aAfW8Zx7Q2RLHl1mtaMeT1Dyvlk9XOzRnuis8/R4PtO/MO68TNXMD/G+YO7ybX3BqR4lkDv/tOHA0IJ45fmd4Dp/e2vuJRgfmtxNqUI2442p8WzSoUbFkn5Awda8Os+XlNUrFFTmDrwFYdC5jrVAgMBAAECggEAD7TiJHtdQPNqHgygqD1D9BwO6+4NPypCUn+ZkwibYM5luewLFoDkqyKGvP4UwMRZY+RZv7hDilLm4sP3XM2ANkdiG2G+7RYeTOg2a6MQGlUOZJSzDd0+kHZwMPueyWSDbcuLyaLY3vUVMf8y+mp9B8O4OieyPkmuxB7jUmsCkAp3gjpBqBqYsgDFVaKIm8zMIbDWq4eo4Iur1jEdV89SGXEhqzGt8H3M86H4ydovEgC8rNQ9RlEx1LUtFC4GindBeJKeAO2Y/WSat35ja0oLwg/8ckw9A84R44Qa1SY1+0+0ZwHOCjBI0OjH9dL0qq2FXRf9HQZO5bpP2x/TARjtYQKBgQDIySodkysk+EHqt2tEf2MmmWTneCbtdEMKiBonBB/oi0kQIoVUhLseW7NuyWq3QNHugxoa2kIPB2bV9jDojxx9fBssL/xUScMKo0ZPRlzlL/wqlR+6SeGRG0a1sKXhhmmAhw0QvBwT9XrDZcGtFi5frMBSm9zVV9NqbbLC58YtoQKBgQDOM8+1YyGah/cpebHhAiFNjcEsefGmtzv4cUwt57HbGZp6M5GjI7W+0NCz8jbEowuqCjO41VKi7ESzb9NOZuphSCBjZZEWyrXu3/kfixYyUkKQbh6iFfJLmGVgp0EcGLnM0fmwK12pcG+PCaFxNajFhf/F5bslOWPL+haAdxT4tQKBgBfvArorxMTPYuwbmQm9NZBwUHrW86zyYttqhdOIxlTt5XOq6cG9YKCpxaW7FKFrdJq9verdgWpRM4zln8bY6Eh89rA5uBZEBJ/L/qGMfZ5ELgbVZ8bI775gRfl6aQuM/h53+rK3+ZDXfh60jnWXY0e8S+CM+7HimizhjqF1B0aBAoGBALyxZO2T3XhP27m0hzZkgJ07jv5oSN5K5zIeW5vWXkclUttovWkQkIwhAhrpF30xxsa/tzz42ToGA4hAWJlyTCDho+HRW8gDkCEcDBj1akZ6SDdqzdV9R9AtkPe1ljtj1QK9U0QHKxqWrT+zjGzQsbSvPrOV2n/h2JUcMeM1FZfRAoGAa5e2uey+653fcxP+0eGD/D2FDAs0q8ig2yKaJBhGyUG16c5oh0yxf+E93EPayOWMi4Tx7ylJcv7L0foDCMDWhbI5riAfztMnPKmmrEkvG1UOVo4QWYK2QmcOYau+W6pLM8yv4F0xVfAyfum7RJtaIYMQj1oaWQwuTaw22jFcsCc=",
        url="https://196.188.120.3:38443"
    )

    order_id = random.randint(99999, 1000000)
    nonce_str = str(uuid.uuid4().hex)

    response = t.auth('InApp:e0d4dc0978b4eaaba17d2f99aea93a36fbe4a4e5fed9c075')
    print(response)

if __name__ == "__main__":
    main()