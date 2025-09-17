import requests
import json
import time
import hashlib
import os # Import os for file size check

class VirusTotalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3/"

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def _make_request(self, endpoint, method="GET", data=None, files=None, custom_headers=None):
        url = self.BASE_URL + endpoint
        headers = custom_headers if custom_headers is not None else self.headers
        try:
            if method == "POST":
                response = requests.post(url, headers=headers, data=data, files=files)
            else:
                response = requests.get(url, headers=headers)

            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_message = f"HTTP Error: {e.response.status_code} - {e.response.text}"
            print(error_message)
            return {"error": error_message} # Return error dict instead of None
        except requests.exceptions.ConnectionError as e:
            error_message = f"Connection Error: {e}"
            print(error_message)
            return {"error": error_message}
        except requests.exceptions.Timeout:
            error_message = "Request timed out."
            print(error_message)
            return {"error": error_message}
        except requests.exceptions.RequestException as e:
            error_message = f"An unexpected request error occurred: {e}"
            print(error_message)
            return {"error": error_message}
        except json.JSONDecodeError:
            error_message = f"Failed to decode JSON from response: {response.text}"
            print(error_message)
            return {"error": error_message}

    def scan_file(self, file_path):
        try:
            file_size = os.path.getsize(file_path)
            # VirusTotal API v3 direct upload limit is 32MB.
            if file_size > 32 * 1024 * 1024:
                print(f"File '{os.path.basename(file_path)}' is larger than 32MB. Using large file upload method.")
                return self._scan_large_file(file_path)
            
            # Standard upload for files <= 32MB
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                print(f"Uploading '{os.path.basename(file_path)}' to VirusTotal...")
                response = self._make_request("files", method="POST", files=files)
                return response
        except FileNotFoundError:
            error_message = f"File not found: {file_path}"
            print(error_message)
            return {"error": error_message}
        except Exception as e:
            error_message = f"Error scanning file {file_path}: {e}"
            print(error_message)
            return {"error": error_message}

    def _scan_large_file(self, file_path):
        # 1. Get a special URL for large file uploads
        upload_url_response = self._make_request("files/upload_url")
        if not upload_url_response or 'data' not in upload_url_response:
            return {"error": "Failed to get large file upload URL from VirusTotal."}
        
        upload_url = upload_url_response['data']

        # 2. Upload the file to the obtained URL
        print(f"Uploading large file to special URL...")
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                # This request uses the special URL and does not need the API key in the header
                response = requests.post(upload_url, files=files)
                response.raise_for_status()
                return response.json()
        except Exception as e:
            error_message = f"Failed to upload large file: {e}"
            print(error_message)
            return {"error": error_message}

    def get_file_analysis_report(self, analysis_id):
        print(f"Fetching file analysis report for ID: {analysis_id}...")
        return self._make_request(f"analyses/{analysis_id}")

    def scan_url(self, url):
        data = {"url": url}
        print(f"Submitting URL {url} to VirusTotal...")
        # URLs need to be base64 encoded for the analysis endpoint, but for submission
        # the API takes the raw URL. However, the documentation for /urls endpoint
        # usually suggests sending a POST request with 'url' as form data.
        # For public API, direct URL submission is often handled by /urls or /url_files endpoint.
        # Let's use `multi_scan_urls` for consistency or modify for `/urls`
        # Using `/urls` endpoint for simplicity of POST submission.
        response = self._make_request("urls", method="POST", data=data)
        return response

    def get_url_analysis_report(self, analysis_id):
        print(f"Fetching URL analysis report for ID: {analysis_id}...")
        return self._make_request(f"analyses/{analysis_id}")

    def get_file_report_by_hash(self, file_hash):
        # file_hash can be MD5, SHA-1, or SHA-256
        print(f"Fetching file report for hash: {file_hash}...")
        return self._make_request(f"files/{file_hash}")

    def get_url_report_by_id(self, url_id):
        # url_id is the URL identifier (SHA256 hash of the URL)
        print(f"Fetching URL report for ID: {url_id}...")
        return self._make_request(f"urls/{url_id}")

    @staticmethod
    def calculate_file_hash(file_path, algorithm='sha256'):
        hash_func = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
        }.get(algorithm.lower())

        if not hash_func:
            raise ValueError("Unsupported hash algorithm. Choose from 'md5', 'sha1', 'sha256'.")

        try:
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(65536) # Read in 64k chunks
                    if not data:
                        break
                    hash_func.update(data)
            return hash_func.hexdigest()
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {e}")
            return None