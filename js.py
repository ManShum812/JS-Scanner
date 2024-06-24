import requests
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(filename='scan_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Headers for the HTTP request
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Regular expressions to match various types of sensitive data
SENSITIVE_PATTERNS = [
    (r'password\s*=\s*[\'"](.+?)[\'"]', "Password"),
    (r'token\s*:\s*[\'"](.+?)[\'"]', "Token"),
    (r'key\s*:\s*[\'"](.+?)[\'"]', "Key"),
    (r'secret\s*:\s*[\'"](.+?)[\'"]', "Secret"),
    (r'apikey\s*=\s*[\'"](.+?)[\'"]', "API Key"),
    (r'password\s*:\s*[\'"](.+?)[\'"]', "Password"),
    (r'auth\s*:\s*[\'"](.+?)[\'"]', "Auth"),
    (r'jwt_token\s*[:=]\s*[\'"](.+?)[\'"]', "JWT Token"),
    (r'bearer_token\s*[:=]\s*[\'"](.+?)[\'"]', "Bearer Token"),
    (r'db_password\s*[:=]\s*[\'"](.+?)[\'"]', "Database Password"),
    (r'ssh_key\s*[:=]\s*[\'"](.+?)[\'"]', "SSH Key"),
    (r'rsa_private_key\s*[:=]\s*[\'"](.+?)[\'"]', "RSA Private Key"),
    (r'api_url\s*[:=]\s*[\'"](.+?)[\'"]', "API URL"),
    (r'oauth2_access_token\s*[:=]\s*[\'"](.+?)[\'"]', "OAuth2 Access Token"),
    (r'oauth2_refresh_token\s*[:=]\s*[\'"](.+?)[\'"]', "OAuth2 Refresh Token"),
    (r'cookie\s*[:=]\s*[\'"](.+?)[\'"]', "Cookie"),
    (r'application_secret\s*[:=]\s*[\'"](.+?)[\'"]', "Application Secret"),
    (r'env_var\s*[:=]\s*[\'"](.+?)[\'"]', "Environment Variable"),
    (r'server\s*[:=]\s*[\'"](.+?)[\'"]', "Server"),
    (r'internal_url\s*[:=]\s*[\'"](.+?)[\'"]', "Internal URL"),
    (r'file_path\s*[:=]\s*[\'"](.+?)[\'"]', "File Path"),
    (r'file_name\s*[:=]\s*[\'"](.+?)[\'"]', "File Name"),
    (r'api_version\s*[:=]\s*[\'"](.+?)[\'"]', "API Version"),
    (r'encryption_key\s*[:=]\s*[\'"](.+?)[\'"]', "Encryption Key"),
    (r'email\s*[:=]\s*[\'"](.+?)[\'"]', "Email"),
    (r'password\s*[:=]\s*[\'"](.+?)[\'"]', "Password"),
    (r'username\s*[:=]\s*[\'"](.+?)[\'"]', "Username"),
    (r'api_key\s*[:=]\s*[\'"](.+?)[\'"]', "API Key"),
    (r'client_secret\s*[:=]\s*[\'"](.+?)[\'"]', "Client Secret"),
    (r'access_token\s*[:=]\s*[\'"](.+?)[\'"]', "Access Token"),
    (r'secret_key\s*[:=]\s*[\'"](.+?)[\'"]', "Secret Key"),
    (r'access_key\s*[:=]\s*[\'"](.+?)[\'"]', "Access Key"),
    (r'refresh_token\s*[:=]\s*[\'"](.+?)[\'"]', "Refresh Token"),
    (r'api_secret_key\s*[:=]\s*[\'"](.+?)[\'"]', "Api Secret Key"),
    (r'application_token\s*[:=]\s*[\'"](.+?)[\'"]', "Application Token"),
    (r'endpoint\s*[:=]\s*[\'"](.+?)[\'"]', "Endpoint"),
    (r'port\s*[:=]\s*[\'"](.+?)[\'"]', "Port"),
    (r'query\s*[:=]\s*[\'"](.+?)[\'"]', "Query"),
    (r'authentication\s*[:=]\s*[\'"](.+?)[\'"]', "Authentication"),
    (r'file\s*[:=]\s*[\'"](.+?)[\'"]', "File"),
    (r'path\s*[:=]\s*[\'"](.+?)[\'"]', "Path"),
    (r'command\s*[:=]\s*[\'"](.+?)[\'"]', "Command"),
    (r'license\s*[:=]\s*[\'"](.+?)[\'"]', "License"),
    (r'credential\s*[:=]\s*[\'"](.+?)[\'"]', "Credential"),
    (r'credentials\s*[:=]\s*[\'"](.+?)[\'"]', "Credentials"),
    (r'signature\s*[:=]\s*[\'"](.+?)[\'"]', "Signature"),
    (r'number\s*[:=]\s*[\'"](.+?)[\'"]', "Number"),
    (r'license_key\s*[:=]\s*[\'"](.+?)[\'"]', "License Key"),
    (r'url\s*[:=]\s*[\'"](.+?)[\'"]', "URL"),
    (r'uri\s*[:=]\s*[\'"](.+?)[\'"]', "URI"),
    (r'endpoint\s*[:=]\s*[\'"](.+?)[\'"]', "Endpoint"),
    (r'database_url\s*[:=]\s*[\'"](.+?)[\'"]', "Database URL"),
    (r'db_url\s*[:=]\s*[\'"](.+?)[\'"]', "DB URL"),
    (r'jdbc_url\s*[:=]\s*[\'"](.+?)[\'"]', "JDBC URL"),
    (r'api_token\s*[:=]\s*[\'"](.+?)[\'"]', "API Token"),
    (r'api_key\s*[:=]\s*[\'"](.+?)[\'"]', "API Key"),
    (r'api_secret\s*[:=]\s*[\'"](.+?)[\'"]', "API Secret"),
    (r'auth_token\s*[:=]\s*[\'"](.+?)[\'"]', "Auth Token"),
    (r'auth_key\s*[:=]\s*[\'"](.+?)[\'"]', "Auth Key"),
    (r'auth_secret\s*[:=]\s*[\'"](.+?)[\'"]', "Auth Secret"),
    (r'session_token\s*[:=]\s*[\'"](.+?)[\'"]', "Session Token"),
    (r'session_id\s*[:=]\s*[\'"](.+?)[\'"]', "Session ID"),
    (r'aws_access_key_id\s*[:=]\s*[\'"](.+?)[\'"]', "AWS Access Key ID"),
    (r'aws_secret_access_key\s*[:=]\s*[\'"](.+?)[\'"]', "AWS Secret Access Key"),
    (r'slack_api_token\s*[:=]\s*[\'"](.+?)[\'"]', "Slack API Token"),
    (r'github_token\s*[:=]\s*[\'"](.+?)[\'"]', "GitHub Token"),
    (r'gitlab_token\s*[:=]\s*[\'"](.+?)[\'"]', "GitLab Token"),
    (r'azure_token\s*[:=]\s*[\'"](.+?)[\'"]', "Azure Token"),
    (r'heroku_api_key\s*[:=]\s*[\'"](.+?)[\'"]', "Heroku API Key"),
    (r'facebook_access_token\s*[:=]\s*[\'"](.+?)[\'"]', "Facebook Access Token"),
    (r'google_api_key\s*[:=]\s*[\'"](.+?)[\'"]', "Google API Key"),
    (r'twitter_api_key\s*[:=]\s*[\'"](.+?)[\'"]', "Twitter API Key"),
    (r'linkedin_access_token\s*[:=]\s*[\'"](.+?)[\'"]', "LinkedIn Access Token"),
    (r'dropbox_api_key\s*[:=]\s*[\'"](.+?)[\'"]', "Dropbox API Key"),
    (r'stripe_api_key\s*[:=]\s*[\'"](.+?)[\'"]', "Stripe API Key"),
    (r'paypal_api_key\s*[:=]\s*[\'"](.+?)[\'"]', "PayPal API Key"),
    (r'gh_oauth\s*[:=]\s*[\'"](.+?)[\'"]', "GitHub OAuth"),
    (r'secret_token\s*[:=]\s*[\'"](.+?)[\'"]', "Secret Token"),
    (r'secret_key\s*[:=]\s*[\'"](.+?)[\'"]', "Secret Key"),
    (r'client_id\s*[:=]\s*[\'"](.+?)[\'"]', "Client ID"),
    (r'client_secret\s*[:=]\s*[\'"](.+?)[\'"]', "Client Secret"),
]

def create_session():
    session = requests.Session()
    return session

def fetch_and_search(url):
    session = create_session()
    try:
        # First, make a HEAD request
        head_response = session.head(url, headers=HEADERS, allow_redirects=False)
        if not (200 <= head_response.status_code < 300):
            logging.warning(f"Skipping URL due to status code: {url} - Status code: {head_response.status_code}")
            return None, []

        # If the HEAD request is successful, proceed with the GET request
        response = session.get(url, headers=HEADERS)
        response.raise_for_status()

        content = response.text
        findings = []

        for pattern, description in SENSITIVE_PATTERNS:
            for match in re.findall(pattern, content, re.IGNORECASE):
                findings.append((description, match))

        return url, findings

    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return url, []

def scan_urls(url_list, output_file):
    with open(output_file, 'w') as f_out:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_and_search, url): url for url in url_list}

            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    if result[0] is None:
                        continue
                    if result[1]:  # If findings are not empty
                        f_out.write(f"Sensitive data found in {url}:\n")
                        for description, match in result[1]:
                            f_out.write(f"- {description}: {match}\n")
                        f_out.write("\n")
                        logging.info(f"Sensitive data found in {url}")
                    else:
                        f_out.write(f"No sensitive data found in {url}\n\n")
                        logging.info(f"No sensitive data found in {url}")
                except Exception as e:
                    logging.error(f"Error processing {url}: {e}")
                    f_out.write(f"Error scanning URL: {url}\n\n")

def scan_js_urls_from_file(input_file, output_file):
    with open(input_file, 'r') as f_in:
        urls = [line.strip() for line in f_in]

    scan_urls(urls, output_file)

if __name__ == "__main__":
    input_file = 'input_urls.txt'
    output_file = 'output_results.txt'
    scan_js_urls_from_file(input_file, output_file)
