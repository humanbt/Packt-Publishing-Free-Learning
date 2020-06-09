"""Module with Packt API client handling API's authentication."""
import sys

import logging

import requests

from utils.logger import get_logger

logger = get_logger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)  # downgrading logging level for requests

PACKT_API_LOGIN_URL = 'https://services.packtpub.com/auth-v1/users/tokens'
PACKT_API_REFRESH_URL = 'https://services.packtpub.com/auth-v1/users/me/tokens'
PACKT_API_PRODUCTS_URL = 'https://services.packtpub.com/entitlements-v1/users/me/products'
PACKT_PRODUCT_SUMMARY_URL = 'https://static.packt-cdn.com/products/{product_id}/summary'
PACKT_API_PRODUCT_FILE_TYPES_URL = 'https://services.packtpub.com/products-v1/products/{product_id}/types'
PACKT_API_PRODUCT_FILE_DOWNLOAD_URL =\
    'https://services.packtpub.com/products-v1/products/{product_id}/files/{file_type}'
PACKT_API_FREE_LEARNING_OFFERS_URL = 'https://services.packtpub.com/free-learning-v1/offers'
PACKT_API_USER_URL = 'https://services.packtpub.com/users-v1/users/me'
PACKT_API_FREE_LEARNING_CLAIM_URL = 'https://services.packtpub.com/free-learning-v1/users/{user_id}/claims/{offer_id}'
DEFAULT_PAGINATION_SIZE = 25


class PacktAPIClient:
    """Packt API client making API requests on script's behalf."""

    def __init__(self, credentials, cookie):
        self.session = requests.Session()
        self.credentials = credentials
        self.cookie = cookie
        self.refresh_token = ''
        self.bearer_token = ''
        self.header = {
           "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 " +
           "(KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
           "Authorization": ""
        }
        self.fetch_jwt()

    def fetch_jwt(self):
        """Fetch user's JWT to be used when making Packt API requests."""
        try:
            if self.cookie is not None:
                for cookie in self.cookie:
                    if (cookie.name == 'access_token_live' and cookie.domain == '.packtpub.com'):
                        self.bearer_token = cookie.value
                    if (cookie.name == 'refresh_token_live' and cookie.domain == '.packtpub.com'):
                        self.refresh_token = cookie.value
                    if (self.bearer_token != '' and self.refresh_token != ''):
                        break
                logger.info('access: {}'.format(self.bearer_token))
                logger.info('refresh: {}'.format(self.refresh_token))
            if self.refresh_token == '':
                if self.credentials['recaptcha'] == '':
                    self.bearer_token = input('Enter your access token: ')
                    self.refresh_token = input('Enter your refresh token: ')
                else:
                    response = requests.post(PACKT_API_LOGIN_URL, json=self.credentials)
                    self.bearer_token = response.json().get('data').get('access')
                    self.refresh_token = response.json().get('data').get('refresh')
                self.session.headers.update({'authorization': 'Bearer {}'.format(self.bearer_token)})
                logger.info('JWT token has been fetched successfully!')
            else:
                self.refresh_jwt()
        except Exception:
            logger.error('Fetching JWT token failed!')
            sys.exit(2)

    def refresh_jwt(self):
        try:
            logger.info('Refreshing JWT token...')
            self.header["Authorization"] = 'Bearer ' + self.bearer_token
            response = requests.post(PACKT_API_REFRESH_URL, json={'refresh': self.refresh_token}, headers=self.header)
            self.bearer_token = response.json().get('data').get('access')
            self.refresh_token = response.json().get('data').get('refresh')
            self.session.headers.update({'authorization': 'Bearer {}'.format(self.bearer_token)})
            logger.info('JWT token has been refreshed successfully!')
        except Exception as e:
            logger.error(e)
            logger.error('Refreshing JWT token failed!')
            sys.exit(2)

    def request(self, method, url, **kwargs):
        """Make a request to a Packt API."""
        response = self.session.request(method, url, **kwargs)
        if response.status_code == 401:
            # Fetch a new JWT as the old one has expired and update session headers
            self.fetch_jwt()
            return self.session.request(method, url, **kwargs)
        else:
            return response

    def get(self, url, **kwargs):
        """Make a GET request to a Packt API."""
        return self.request('get', url, **kwargs)

    def post(self, url, **kwargs):
        """Make a POST request to a Packt API."""
        return self.request('post', url, **kwargs)

    def put(self, url, **kwargs):
        """Make a PUT request to a Packt API."""
        return self.request('put', url, **kwargs)

    def patch(self, url, **kwargs):
        """Make a PATCH request to a Packt API."""
        return self.request('patch', url, **kwargs)

    def delete(self, url, **kwargs):
        """Make a DELETE request to a Packt API."""
        return self.request('delete', url, **kwargs)
