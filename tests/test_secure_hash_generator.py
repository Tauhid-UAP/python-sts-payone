import unittest

from src.python_sts_payone.secure_hash.secure_hash_generator import (
    SecureHashGenerator,
    get_secure_hash,
    is_secure_hash_valid_for_parameters,
    is_secure_hash_valid_for_response_payload
)


class BaseSecureHashTest(unittest.TestCase):
    def setUp(self) -> None:
        print('{}SETTING UP{}'.format('-' * 10, '-' * 10))

        self.auth_token_1: str = '5555bbb7-3402-4bac-91bb-c875f81723d1'
        self.auth_token_2: str = '5150ce90-ec9f-4004-9d87-c9fc9295bbee'

        self.MESSAGE_ID: str = '1'
        self.MERCHANT_ID: str = 'MID0001'
        self.AMOUNT: str = '100'
        self.CURRENCY_ISO_CODE: str = '840'
        self.BASE_PARAMS: dict = {
            'MessageID': self.MESSAGE_ID,
            'MerchantID': self.MERCHANT_ID,
            'Amount': self.AMOUNT,
            'CurrencyISOCode': self.CURRENCY_ISO_CODE
        }


        self.TRANSACTION_ID_1: str = '4d5eedd6-f119-4b21-b16e-4a39d34841a8'
        self.params_1: dict = self.BASE_PARAMS.copy()
        self.params_1['TransactionID'] = self.TRANSACTION_ID_1

        self.secure_hash_1: str = '081cfe52dc0062a154ffb8af966a5ce97e64078912ea87ac875fc3c91883c310'


        self.TRANSACTION_ID_2: str = 'c0b12a81-8e80-4bc1-901f-f0d8cb28b70e'
        self.params_2: dict = self.BASE_PARAMS.copy()
        self.params_2['TransactionID'] = self.TRANSACTION_ID_2

        self.secure_hash_2: str = 'b9449c3809925fb833b7de57e1f5135fde0764f53eef8dd55a2fa76ca8cb5e39'

        print('{}SET-UP COMPLETE{}'.format('-' * 10, '-' * 10))


class TestSecureHashGenerator(BaseSecureHashTest):
    def test_generate_secure_hash(self):
        auth_token_1: str = self.auth_token_1
        auth_token_2: str = self.auth_token_2

        generated_secure_hash_1: str = SecureHashGenerator(auth_token_1, self.params_1).generate_secure_hash()
        self.assertEqual(generated_secure_hash_1, self.secure_hash_1)

        generated_secure_hash_2: str = SecureHashGenerator(auth_token_2, self.params_2).generate_secure_hash()
        self.assertEqual(generated_secure_hash_2, self.secure_hash_2)


class TestGetSecureHash(BaseSecureHashTest):
    def test_get_secure_hash(self):
        auth_token_1: str = self.auth_token_1
        auth_token_2: str = self.auth_token_2

        generated_secure_hash_1: str = get_secure_hash(auth_token_1, self.params_1)
        self.assertEqual(generated_secure_hash_1, self.secure_hash_1)

        generated_secure_hash_2: str = get_secure_hash(auth_token_2, self.params_2)
        self.assertEqual(generated_secure_hash_2, self.secure_hash_2)

class TestIsSecureHashValidForParameters(BaseSecureHashTest):
    def test_is_secure_hash_valid_for_parameters(self):
        auth_token_1: str = self.auth_token_1
        auth_token_2: str = self.auth_token_2
        params_1: dict = self.params_1
        secure_hash_1: str = self.secure_hash_1
        params_2: dict = self.params_2
        secure_hash_2: str = self.secure_hash_2

        self.assertTrue(is_secure_hash_valid_for_parameters(secure_hash_1, auth_token_1, params_1))
        self.assertFalse(is_secure_hash_valid_for_parameters(secure_hash_1, auth_token_1, params_2))
        self.assertFalse(is_secure_hash_valid_for_parameters(secure_hash_1, auth_token_2, params_1))
        self.assertFalse(is_secure_hash_valid_for_parameters(secure_hash_1, auth_token_2, params_2))
        self.assertFalse(is_secure_hash_valid_for_parameters(secure_hash_2, auth_token_1, params_1))
        self.assertFalse(is_secure_hash_valid_for_parameters(secure_hash_2, auth_token_1, params_2))
        self.assertFalse(is_secure_hash_valid_for_parameters(secure_hash_2, auth_token_2, params_1))
        self.assertTrue(is_secure_hash_valid_for_parameters(secure_hash_2, auth_token_2, params_2))

class TestIsSecureHashValidForResponsePayload(BaseSecureHashTest):
    def test_is_secure_hash_valid_for_response_payload(self):
        auth_token_1: str = self.auth_token_1
        auth_token_2: str = self.auth_token_2
        params_1: dict = self.params_1
        secure_hash_1: str = self.secure_hash_1
        params_2: dict = self.params_2
        secure_hash_2: str = self.secure_hash_2

        response_secure_hash_1_injection_payload: dict = {
            'Response.SecureHash': secure_hash_1
        }

        response_secure_hash_2_injection_payload: dict = {
            'Response.SecureHash': secure_hash_2
        }

        self.assertTrue(is_secure_hash_valid_for_response_payload(auth_token_1, {**response_secure_hash_1_injection_payload, **params_1}))
        self.assertFalse(is_secure_hash_valid_for_response_payload(auth_token_1, {**response_secure_hash_1_injection_payload, **params_2}))
        self.assertFalse(is_secure_hash_valid_for_response_payload(auth_token_1, {**response_secure_hash_2_injection_payload, **params_1}))
        self.assertFalse(is_secure_hash_valid_for_response_payload(auth_token_1, {**response_secure_hash_2_injection_payload, **params_2}))
        self.assertFalse(is_secure_hash_valid_for_response_payload(auth_token_2, {**response_secure_hash_1_injection_payload, **params_1}))
        self.assertFalse(is_secure_hash_valid_for_response_payload(auth_token_2, {**response_secure_hash_1_injection_payload, **params_2}))
        self.assertFalse(is_secure_hash_valid_for_response_payload(auth_token_2, {**response_secure_hash_2_injection_payload, **params_1}))
        self.assertTrue(is_secure_hash_valid_for_response_payload(auth_token_2, {**response_secure_hash_2_injection_payload, **params_2}))


if __name__ == '__main__':
    unittest.main()