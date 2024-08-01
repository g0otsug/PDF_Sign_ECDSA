import os
from flask import Flask, request, send_from_directory
from ecdsa_script import generate_keys, sign_document, verify_signature, save_key_to_file, read_key_from_file
from ecdsa import SigningKey, VerifyingKey, SECP256k1

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    return send_from_directory('', 'index.html')

@app.route('/sign', methods=['POST'])
def sign():
    if 'pdf' not in request.files:
        return "No file part", 400
    file = request.files['pdf']
    if file.filename == '':
        return "No selected file", 400
    filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filename)

    private_key, public_key = generate_keys()
    save_key_to_file("private_key.pem", private_key.to_pem())
    save_key_to_file("public_key.pem", public_key.to_pem())

    with open(filename, 'rb') as f:
        document = f.read()

    signature = sign_document(private_key, document)
    save_key_to_file("signature.sig", signature)

    return "Document signed successfully"

@app.route('/verify', methods=['POST'])
def verify():
    if 'pdf' not in request.files:
        return "No file part", 400
    file = request.files['pdf']
    if file.filename == '':
        return "No selected file", 400
    filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filename)

    with open(filename, 'rb') as f:
        document = f.read()

    public_key_pem = read_key_from_file("public_key.pem")
    public_key = VerifyingKey.from_pem(public_key_pem)
    signature = read_key_from_file("signature.sig")

    result = verify_signature(public_key, document, signature)
    return "Signature verifies" if result else "Signature does not verify"

if __name__ == '__main__':
    app.run(debug=True)
