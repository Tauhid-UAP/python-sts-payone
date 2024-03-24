from requests.models import Response
from typing import Tuple
from ..base.request_handler import SmartRouteRequestHandler

SR_URL_TEST: str = 'https://smartroute-test.payone.io/SmartRoutePaymentWeb/SRPayMsgHandler'
SR_URL_LIVE: str = 'https://smartroute-test.payone.io/SmartRoutePaymentWeb/SRPayMsgHandler'
REDIRECT_MESSAGE_ID: str = '1'

def redirect_model_pay(merchant_id: str, auth_token: str, transaction_id: str, amount: int, currency_iso_code: str,
                       response_back_url: str, generate_token: bool=False, payment_method_token: str=None,
                       payment_description: str=None, live_mode: bool=True, version: float=None) -> Tuple[str, int]:
    params: dict = {
        'MessageID': REDIRECT_MESSAGE_ID,
        'TransactionID': transaction_id,
        'MerchantID': merchant_id,
        'Amount': str(amount),
        'CurrencyISOCode': currency_iso_code,
        'ResponseBackURL': response_back_url,
        'GenerateToken': 'Yes' if generate_token else 'No',
    }

    if payment_method_token is not None:
        params['Token'] = payment_method_token

    if payment_description is not None:
        params['PaymentDescription'] = payment_description

    if version is not None:
        params['Version'] = str(version)
    
    sr_url: str = SR_URL_LIVE if live_mode else SR_URL_TEST
    res: Response = SmartRouteRequestHandler(sr_url, auth_token, params).send_request()

    redirection_html_str: str = res.text
    """Due to a bug in SmartRoute, we need to manually set the action to the full SR_URL"""
    redirection_html_str = redirection_html_str.replace('action=\'SRPayMsgHandler\'', 'action={}'.format(sr_url))

    return redirection_html_str, res.status_code