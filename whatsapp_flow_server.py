from flask import Flask, request, Response
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests

app = Flask(__name__)

# Your private key
PRIVATE_KEY_PEM = '''-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDqKmPHscgXeli7
0mwQTOz7IhByU7EgjXqEBY7B+6yo6bHX1XWJTtGhw7DOB0DFCC+5yUejiQM59AaF
wCWUSyxFrf4PBn/9fzYZj1OwSFdyuynlFMhWKytoihyHtml8o3dsQD/n8NCUK71T
K5crwYR7oww7WPrWHEiVYfaqSfHHBjbrT9Z/v82xA5QrdsPBeKjZS4VLUSOy0/Hm
aMD0nS0CLYAiGyhEPP9vkm+gBFysYZ1qGtvAD3C9Ohg2dOcsORlIOgYlo7voBtlq
3CD8+ef2whqINTzYZmLUF+iby8mEvjc8nhsVDqJg+xmRnBYHje4v4vhqHru+gIrS
VqADoy5zAgMBAAECggEATPYUqEfehxTfgA+XE75srtdRx3mJQDUvnJ+E/W19oGB6
YoEWKcQ9cuixve01VOytXubwBCgeZtg0opX14+jXCqm2U/Ljcwnx2nG4ZDpKf3tT
OCbd9zAmCqxF1zbVMbE6KVpuhoknzGMZzPGJNEjchZQfi4vhmShflLVHUE2QSMQ5
rJ96GUBOX0VS63fVNZa2r+ZRnKp5P/WuynxSOcJ9ux8f+JFZH5gTQubspMDEG1jQ
KBJu0HuXhNs8GXEXHeDEZ1u1qrPfYFdZ6pX0YdmAZd1oAWvy9VmjvSmr7TRV2R2+
IUxSDOJfSAi9ZGPUyUSvphDbsQwYkcod6v5Emot75QKBgQD1KSRfp/Csr0e3vCPH
HFJO3BSUtPn/R6rYZWcSZvlQB8tR/Erwq0qpGMD/xM9QAyYLE/a/f0TvFQjHokOn
zjnLrxSIwoVT1jh9tLsz4CTpSBDACRuf1tJ+S1b1/b6Wwvt/uFH+t0V3wpEiuQd3
sue1Kh16HwxL5LG6+UgNpJBvFQKBgQD0hMyPCdc6KSeOVw7CFP7v5qgTBk8uIq+N
obOFzFTl/1787dYjv/ypRh+LqNI88W+WP4E2xpncTjsh5dvesyNLPlSq5XyGJfdu
I92b8gRlUvWru8Su+pgRvFkhRJ5i86KyA3N55+p0bTiYIDcv8jwW5DCd81CNn9wR
O5CQeNPJZwKBgCM5LgiwUFv/Mwaq+Vj6MLkz1aEn/2M2IM3Gg/CY6ukctZGp9fpu
IeP5soEM/dw5F5Yv4BvTZUwUcZZ9MctCTft9xC2CBTXuaV9mQB9L7QG3YPC2Xkmw
y71pha0CMAfpK8lF6kH2gvyZ79BVVUVVZwUYb/PD0jh1OzPp7PhI1JehAoGAZoB5
BAlbCQ2RgHDsRd3pVQX7NSZy8OMndpbvm8ohWN0po5vMJeZoc0lrFe+qWlPXtENg
1maAv0KoNTiXaA7uX698bLuQ7Odjhu9QCfx1bUhOpjQrajKwptavAmwyfUam0Dr0
IIlg1nemvtbaa6X/HJWB7+S8wvHdnfe7TWTpW0cCgYAixsAFhbPdIT7aGc5YU3Pc
MlLJZOLqTZX1y/P/VMucNBKJMtELqB9+2tyrMS1DJtxKu8/cdrL7eS9g5k/IIyop
a0D/n+d/s8i7ImsJcJYne0wILVVRJQ0ydM9ryKBB6HgdJ6l6K8cVeuQMu+CAdtCa
9JjZgp8y2bdf+oMzf2D8xw==
-----END PRIVATE KEY-----'''

# Your n8n webhook URL for receiving booking data
N8N_WEBHOOK_URL = os.getenv('N8N_WEBHOOK_URL', 'https://automate.besttravelai.com/webhook/whatsapp-booking-received')

def decrypt_request(data):
    """Decrypt the WhatsApp Flow request"""
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode(),
        password=None,
        backend=default_backend()
    )
    
    # Decrypt AES key
    encrypted_aes_key = base64.b64decode(data['encrypted_aes_key'])
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt flow data
    iv = base64.b64decode(data['initial_vector'])
    encrypted_data = base64.b64decode(data['encrypted_flow_data'])
    
    # Split ciphertext and auth tag
    ciphertext = encrypted_data[:-16]
    auth_tag = encrypted_data[-16:]
    
    # Decrypt
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, auth_tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    
    flow_data = json.loads(decrypted.decode('utf-8'))
    
    return flow_data, aes_key, iv

def encrypt_response(response_data, aes_key, iv):
    """Encrypt the response"""
    response_string = json.dumps(response_data)
    
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(response_string.encode()) + encryptor.finalize()
    
    # Get auth tag and combine
    auth_tag = encryptor.tag
    encrypted_with_tag = encrypted + auth_tag
    
    # Return as base64
    return base64.b64encode(encrypted_with_tag).decode()

@app.route('/whatsapp-flow', methods=['GET'])
def health_check():
    """Health check endpoint"""
    response = {
        "version": "3.0",
        "data": {
            "status": "active"
        }
    }
    base64_response = base64.b64encode(json.dumps(response).encode()).decode()
    return Response(base64_response, mimetype='text/plain')

@app.route('/whatsapp-flow', methods=['POST'])
def flow_endpoint():
    """Handle WhatsApp Flow requests"""
    try:
        data = request.get_json()
        
        # Decrypt the request
        flow_data, aes_key, iv = decrypt_request(data)
        
        # Check if it's a health check ping
        if flow_data.get('action') == 'ping':
            response_data = {
                "version": "3.0",
                "data": {
                    "status": "active"
                }
            }
        else:
            # It's booking data - send to n8n
            booking_data = {
                "customerName": flow_data.get('customer_name', 'N/A'),
                "phoneNumber": flow_data.get('phone_number', 'N/A'),
                "email": flow_data.get('email', 'N/A'),
                "branch": flow_data.get('branch', 'N/A'),
                "diningType": flow_data.get('dining_type', 'N/A'),
                "reservationDate": flow_data.get('reservation_date', 'N/A'),
                "reservationTime": flow_data.get('reservation_time', 'N/A'),
                "guestCount": flow_data.get('guest_count', 'N/A')
            }
            
            # Send to n8n
            try:
                requests.post(N8N_WEBHOOK_URL, json=booking_data, timeout=5)
            except Exception as e:
                print(f"Error sending to n8n: {e}")
            
            response_data = {
                "version": "3.0",
                "data": {
                    "status": "success"
                }
            }
        
        # Encrypt response
        encrypted_response = encrypt_response(response_data, aes_key, iv)
        
        return Response(encrypted_response, mimetype='text/plain')
        
    except Exception as e:
        print(f"Error: {e}")
        return Response("Error", status=500)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
