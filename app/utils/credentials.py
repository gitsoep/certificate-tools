"""
Azure credential classes for authentication
"""
import datetime
from azure.core.credentials import AccessToken


class UserCredential:
    """Custom credential using the user's access token for Azure Key Vault."""
    
    def __init__(self, access_token: str):
        self.token = access_token
    
    def get_token(self, *scopes, **kwargs) -> AccessToken:
        return AccessToken(self.token, int(datetime.datetime.now().timestamp()) + 3600)


class StorageCredential:
    """Custom credential using the user's access token for Azure Blob Storage."""
    
    def __init__(self, access_token: str):
        self.token = access_token
    
    def get_token(self, *scopes, **kwargs) -> AccessToken:
        return AccessToken(self.token, int(datetime.datetime.now().timestamp()) + 3600)
