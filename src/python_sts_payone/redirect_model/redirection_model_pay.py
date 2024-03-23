import requests
from requests.models import Response
from ..secure_hash.secure_hash_generator import get_secure_hash
from decimal import Decimal
from typing import Tuple

SR_URL: str = 'https://smartroute-test.payone.io/SmartRoutePaymentWeb/SRPayMsgHandler'
REDIRECT_MESSAGE_ID: str = '1'

def redirect_model_pay(merchant_id: str, auth_token: str, transaction_id: str, amount: Decimal, currency_iso_code: str, response_back_url: str) -> Tuple[str, int]:
    params: dict = {
        'MessageID': REDIRECT_MESSAGE_ID,
        'TransactionID': transaction_id,
        'MerchantID': merchant_id,
        'Amount': str(amount),
        'CurrencyISOCode': currency_iso_code,
        'ResponseBackURL': response_back_url,
    }

    params['SecureHash'] = get_secure_hash(auth_token, params)
    
    res: Response = requests.post(SR_URL, params)

    redirection_html_str: str = res.text
    """Due to a bug in SmartRoute, we need to manually set the action to the full SR_URL"""
    redirection_html_str = redirection_html_str.replace('action=\'SRPayMsgHandler\'', 'action={}'.format(SR_URL))

    return redirection_html_str, res.status_code