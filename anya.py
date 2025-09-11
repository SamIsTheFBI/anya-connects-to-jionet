import requests
import urllib.parse
import json
import os
from dotenv import load_dotenv

load_dotenv()

def find_csrf_token(node):
    """Recursively search for csrf_token in JSON tree."""
    if isinstance(node, dict):
        # check if this node is the csrf_token field
        if node.get("data", {}).get("name") == "csrf_token":
            return node["data"].get("value")
        # search inside children
        if "children" in node:
            for child in node["children"]:
                result = find_csrf_token(child)
                if result:
                    return result
    elif isinstance(node, list):
        for item in node:
            result = find_csrf_token(item)
            if result:
                return result
    return None

def jionet_login(jio_id, password, account):
    """
    Complete JioNet authentication flow
    
    Args:
        jio_id (str): JioNet username
        password (str): JioNet password  
        account (str): Account identifier for connection
    
    Returns:
        dict: Final response from connect request
    """
    
    # Common headers for all requests
    headers = {
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9,hi;q=0.8",
        "connection": "keep-alive",
        "content-type": "application/x-www-form-urlencoded",  # Fixed content-type
        "cookie": "ROUTEID=balancer.node1; route=c84631e43c097b078a5a00b708d0a736; PHPSESSID=bsjfs70f4k1racpud57f1hodm2; NSC_kjpofu2.kjp.jo_WT*8443=ffffffff099cd98045525d5f4f58455e445a4a4229c5",
        "dnt": "1",
        "host": "jionet2.jio.in:8443",
        "referer": "https://jionet2.jio.in:8443/",
        "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Linux\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest"
    }
    
    url = "https://jionet2.jio.in:8443/portal/auth/login"
    
    try:
        # Step 1: GET request to obtain initial CSRF token
        print("Step 1: Getting initial CSRF token...")
        get_headers = headers.copy()
        get_headers["content-type"] = "application/json"  # GET request uses JSON content-type
        
        response1 = requests.get(url, headers=get_headers, params={"auth": "auth1"})
        response1.raise_for_status()
        
        first_response = response1.json()
        # print(f"GET Response: {first_response}")
        
        # Extract first CSRF token
        first_csrf_token = find_csrf_token(first_response["result"]["raw"]["children"]) #first_response.get('csrf_token')
        print(f"First CSRF token: {first_csrf_token}")
        
        # Step 2: POST login with credentials and first CSRF token
        print("\nStep 2: Posting login credentials...")
        
        # Properly encode the password for URL
        encoded_password = urllib.parse.quote(password, safe='')
        
        login_payload = f"jioId={jio_id}&password={encoded_password}&terms=true&csrf_token={first_csrf_token}&auth=auth1&action=login"
        
        response2 = requests.post(url, data=login_payload, headers=headers)
        response2.raise_for_status()
        
        second_response = response2.json()
        # print(f"POST Login Response: {second_response}")
        
        # Extract second CSRF token using recursive search
        second_csrf_token = find_csrf_token(second_response["result"]["raw"]["children"])
        if not second_csrf_token:
            print("Searching for alternative token keys in second response...")
            # Try alternative common keys
            alternative_keys = ['csrfToken', 'token', '_token', 'authenticity_token']
            for alt_key in alternative_keys:
                second_csrf_token = find_csrf_token(second_response, alt_key)
                if second_csrf_token:
                    print(f"Found token with key '{alt_key}': {second_csrf_token}")
                    break
        
        if not second_csrf_token:
            print("Full response structure for debugging:")
            import json
            print(json.dumps(second_response, indent=2))
            raise ValueError("Second CSRF token not found in response")
        
        print(f"Second CSRF token: {second_csrf_token}")
        
        # Step 3: POST connect with account and second CSRF token
        print("\nStep 3: Connecting with account...")
        
        connect_payload = f"account={account}&csrf_token={second_csrf_token}&auth=auth1&action=connect"
        
        response3 = requests.post(url, data=connect_payload, headers=headers)
        response3.raise_for_status()
        
        final_response = response3.json()
        print(f"POST Connect Response: {final_response}")
        
        return final_response
        
    except requests.RequestException as e:
        print(f"HTTP Error: {e}")
        return None
    except ValueError as e:
        print(f"Value Error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected Error: {e}")
        return None

def main():
    # Get credentials from environment variables
    JIO_ID = os.getenv("JIO_ID")
    PASSWORD = os.getenv("PASSWORD")
    ACCOUNT = os.getenv("ACCOUNT")

    if not JIO_ID or not PASSWORD or not ACCOUNT:
        print("❌ Missing required environment variables: JIO_ID, PASSWORD, ACCOUNT")
        return

    # Perform authentication
    result = jionet_login(JIO_ID, PASSWORD, ACCOUNT)

    if result:
        print("\n✅ Authentication completed successfully!")
        print(f"Final result: {result}")
    else:
        print("\n❌ Authentication failed!")

# Example usage
if __name__ == "__main__":
    main()
