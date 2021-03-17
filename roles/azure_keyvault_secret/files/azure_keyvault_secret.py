from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
import requests

display = Display()

TOKEN_ACQUIRED = False

token_params = {
    'api-version': '2018-02-01',
    'resource': 'https://vault.azure.net'
}
token_headers = {
    'Metadata': 'true'
}
token = None
try:
    token_res = requests.get('http://169.254.169.254/metadata/identity/oauth2/token', params=token_params, headers=token_headers)
    token = token_res.json().get("access_token")
    if token is not None:
        TOKEN_ACQUIRED = True
    else:
        display.v('Successfully called MSI endpoint, but no token was available. Will use service principal if provided.')
except requests.exceptions.RequestException:
    display.v('Unable to fetch MSI token. Will use service principal if provided.')
    TOKEN_ACQUIRED = False
	
class LookupModule(LookupBase):

    def run(self, terms, variables, **kwargs):

        ret = []
        vault_name = kwargs.pop('vault_name', None)
        if vault_name is None:
            raise AnsibleError('Failed to get valid vault.')
        if TOKEN_ACQUIRED:
            secret_params = {'api-version': '2016-10-01'}
            secret_headers = {'Authorization': 'Bearer ' + token}
            for term in terms:
                try:
                    vault_url = "https://" + vault_name + ".vault.azure.net"
                    secret_res = requests.get(vault_url + '/secrets/' + term, params=secret_params, headers=secret_headers)
                    ret.append(secret_res.json()["value"])
                except requests.exceptions.RequestException:
                    raise AnsibleError('Failed to fetch secret: ' + term + ' via MSI endpoint.')
                except KeyError:
                    raise AnsibleError('Failed to fetch secret ' + term + '.')
            return ret
        else:
            return lookup_secret_non_msi(terms, vault_url, kwargs)

