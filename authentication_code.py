import webbrowser
import os
import base64
import hashlib
import urllib.parse
import requests
import json
# Define your Azure AD B2C tenant values
tenant_name = "droopelonline"
policy = "B2C_1_signin"
client_id = "bf17c8fb-38bc-42de-a4f4-f8317b0c3560"
nonce = "defaultNonce"  # Replace with your nonce logic
redirect_uri = "https://oauth.pstmn.io/v1/callback"
scopes = "openid"
response_type = "code"
prompt = "login"

# Generate a random code_verifier
code_verifier = "dr_MQKoQxvtvN4f6iBntcSM9EHXvUfGDMtqVUsVTIT8" #base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')

# Hash the code_verifier using SHA-256
code_challenge = hashlib.sha256(code_verifier.encode()).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode('utf-8')

# Define the original authorization request URL
authorization_request_url = f"https://{tenant_name}.b2clogin.com/{tenant_name}.onmicrosoft.com/{policy}/oauth2/v2.0/authorize"
authorization_request_url += f"?client_id={client_id}"
authorization_request_url += f"&nonce={nonce}"
authorization_request_url += f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
authorization_request_url += f"&scope={scopes}"
authorization_request_url += f"&response_type={response_type}"
authorization_request_url += f"&prompt={prompt}"
authorization_request_url += f"&code_challenge={urllib.parse.quote(code_challenge)}"
authorization_request_url += "&code_challenge_method=S256"

# Print the final authorization request URL
print("Authorization Request URL with code_challenge:")
print(authorization_request_url)

# Open the authorization URL in a web browser
webbrowser.open(authorization_request_url)

# Wait for the user to complete the authorization in the browser
code = input("Give me the code")

# Now you can proceed with obtaining an access token using the returned authorization code.

# OAuth 2.0 token endpoint URL
token_url = "https://droopelonline.b2clogin.com/droopelonline.onmicrosoft.com/oauth2/v2.0/token?p=b2c_1_signin"
# Your application's client ID
client_id = "bf17c8fb-38bc-42de-a4f4-f8317b0c3560"

# Redirect URI registered with your OAuth provider
redirect_uri = "https://oauth.pstmn.io/v1/callback"


#GET https://<tenant-name>.b2clogin.com/<tenant-name>.onmicrosoft.com/<policy-name>/oauth2/v2.0/authorize?
#client_id=<application-ID>
#&nonce=anyRandomValue
#&redirect_uri=https://jwt.ms
#&scope=<application-ID-URI>/<scope-name>
#&response_type=code

# Parameters for the token request
token_params = {
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "code": code,  # Replace with the obtained authorization code
    "grant_type": "authorization_code",
    "code_verifier": code_verifier 
}

# Send the token request
token_response = requests.post(token_url, data=token_params)

# Check for a successful response (status code 200)
if token_response.status_code == 200:
    # Parse the JSON response
    token_data = token_response.json()

    # Print the entire JSON response as JSON format
    print("\nToken Response JSON:")
    print(json.dumps(token_data, indent=4))
else:
    print("Token request failed.")
