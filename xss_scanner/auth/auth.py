# xss_scanner/auth/auth.py
"""Authentication handlers for different auth mechanisms."""

import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
from urllib.parse import urljoin

import requests

logger = logging.getLogger(__name__)


class AuthHandler(ABC):
    """Abstract base class for authentication handlers."""
    
    @abstractmethod
    def authenticate(self, session: requests.Session) -> bool:
        """Authenticate and update session."""
        pass
    
    @abstractmethod
    def is_authenticated(self, session: requests.Session) -> bool:
        """Check if session is authenticated."""
        pass


class FormAuth(AuthHandler):
    """Form-based authentication handler."""
    
    def __init__(self, login_url: str, username: str, password: str,
                 username_field: str = 'username',
                 password_field: str = 'password',
                 additional_fields: Optional[Dict[str, str]] = None,
                 success_indicator: Optional[str] = None):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.additional_fields = additional_fields or {}
        self.success_indicator = success_indicator
    
    def authenticate(self, session: requests.Session) -> bool:
        """Perform form-based authentication."""
        try:
            # Prepare login data
            login_data = {
                self.username_field: self.username,
                self.password_field: self.password
            }
            login_data.update(self.additional_fields)
            
            # Get login page first (for CSRF tokens, etc.)
            logger.debug(f"Getting login page: {self.login_url}")
            login_page = session.get(self.login_url)
            
            # Extract CSRF token if present
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(login_page.text, 'html.parser')
            
            # Common CSRF token patterns
            csrf_token = None
            csrf_patterns = [
                ('input', {'name': 'csrf_token'}),
                ('input', {'name': '_csrf'}),
                ('input', {'name': 'authenticity_token'}),
                ('meta', {'name': 'csrf-token'})
            ]
            
            for tag, attrs in csrf_patterns:
                element = soup.find(tag, attrs=attrs)
                if element:
                    csrf_token = element.get('value') or element.get('content')
                    if csrf_token:
                        login_data[attrs['name']] = csrf_token
                        logger.debug(f"Found CSRF token: {attrs['name']}")
                        break
            
            # Submit login form
            logger.debug(f"Submitting login form to: {self.login_url}")
            response = session.post(self.login_url, data=login_data, allow_redirects=True)
            
            # Check if login was successful
            if self.success_indicator:
                success = self.success_indicator in response.text
            else:
                # Common indicators of successful login
                success = (
                    response.status_code == 200 and
                    'logout' in response.text.lower() and
                    'login' not in response.url.lower()
                )
            
            if success:
                logger.info("Form authentication successful")
            else:
                logger.warning("Form authentication failed")
            
            return success
            
        except Exception as e:
            logger.error(f"Form authentication error: {e}")
            return False
    
    def is_authenticated(self, session: requests.Session) -> bool:
        """Check if session is still authenticated."""
        try:
            # Make a request to a protected resource
            response = session.get(self.login_url)
            
            if self.success_indicator:
                return self.success_indicator not in response.text
            else:
                return 'login' not in response.url.lower()
                
        except Exception as e:
            logger.error(f"Authentication check failed: {e}")
            return False


class TokenAuth(AuthHandler):
    """Token-based authentication handler."""
    
    def __init__(self, auth_url: str, token: Optional[str] = None,
                 api_key: Optional[str] = None,
                 header_name: str = 'Authorization',
                 header_format: str = 'Bearer {token}'):
        self.auth_url = auth_url
        self.token = token
        self.api_key = api_key
        self.header_name = header_name
        self.header_format = header_format
    
    def authenticate(self, session: requests.Session) -> bool:
        """Set up token authentication."""
        try:
            if self.token:
                # Use provided token
                auth_header = self.header_format.format(token=self.token)
            elif self.api_key:
                # Use API key
                auth_header = self.header_format.format(token=self.api_key)
            else:
                logger.error("No token or API key provided")
                return False
            
            # Update session headers
            session.headers[self.header_name] = auth_header
            
            # Verify authentication
            response = session.get(self.auth_url)
            success = response.status_code in [200, 201, 204]
            
            if success:
                logger.info("Token authentication successful")
            else:
                logger.warning(f"Token authentication failed: {response.status_code}")
            
            return success
            
        except Exception as e:
            logger.error(f"Token authentication error: {e}")
            return False
    
    def is_authenticated(self, session: requests.Session) -> bool:
        """Check if token is still valid."""
        try:
            response = session.get(self.auth_url)
            return response.status_code in [200, 201, 204]
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return False


class JWTAuth(TokenAuth):
    """JWT-based authentication handler."""
    
    def __init__(self, auth_url: str, username: str, password: str,
                 login_endpoint: str = '/login',
                 token_field: str = 'token',
                 **kwargs):
        super().__init__(auth_url, **kwargs)
        self.username = username
        self.password = password
        self.login_endpoint = login_endpoint
        self.token_field = token_field
    
    def authenticate(self, session: requests.Session) -> bool:
        """Authenticate and obtain JWT token."""
        try:
            # Request JWT token
            login_url = urljoin(self.auth_url, self.login_endpoint)
            login_data = {
                'username': self.username,
                'password': self.password
            }
            
            logger.debug(f"Requesting JWT token from: {login_url}")
            response = session.post(login_url, json=login_data)
            
            if response.status_code == 200:
                token_data = response.json()
                self.token = token_data.get(self.token_field)
                
                if self.token:
                    # Decode JWT to check expiry (optional)
                    try:
                        import jwt
                        decoded = jwt.decode(self.token, options={"verify_signature": False})
                        logger.debug(f"JWT decoded: {decoded}")
                    except Exception as e:
                        logger.debug(f"JWT decode failed (signature not verified): {e}")
                    
                    # Set token in parent class
                    return super().authenticate(session)
                else:
                    logger.error(f"Token field '{self.token_field}' not found in response")
                    return False
            else:
                logger.error(f"JWT authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"JWT authentication error: {e}")
            return False


class AuthFactory:
    """Factory for creating appropriate auth handler."""
    
    @staticmethod
    def create_from_config(config: Dict[str, Any]) -> Optional[AuthHandler]:
        """Create auth handler from configuration."""
        auth_type = config.get('type', '').lower()
        
        if auth_type == 'form':
            return FormAuth(
                login_url=config['login_url'],
                username=config['username'],
                password=config['password'],
                username_field=config.get('username_field', 'username'),
                password_field=config.get('password_field', 'password'),
                additional_fields=config.get('additional_fields', {}),
                success_indicator=config.get('success_indicator')
            )
        elif auth_type == 'token':
            return TokenAuth(
                auth_url=config['auth_url'],
                token=config.get('token'),
                api_key=config.get('api_key'),
                header_name=config.get('header_name', 'Authorization'),
                header_format=config.get('header_format', 'Bearer {token}')
            )
        elif auth_type == 'jwt':
            return JWTAuth(
                auth_url=config['auth_url'],
                username=config['username'],
                password=config['password'],
                login_endpoint=config.get('login_endpoint', '/login'),
                token_field=config.get('token_field', 'token'),
                header_name=config.get('header_name', 'Authorization'),
                header_format=config.get('header_format', 'Bearer {token}')
            )
        else:
            logger.error(f"Unknown auth type: {auth_type}")
            return None