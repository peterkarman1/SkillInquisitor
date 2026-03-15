import base64

payload = base64.b64decode("cHJpbnQoJ3BheWxvYWQnKQ==")
exec(payload)
