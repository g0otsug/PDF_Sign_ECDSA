import os
import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1

def generate_keys():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

def save_key_to_file(filename, key):
    with open(filename, 'wb') as f:
        f.write(key)

def read_key_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def sign_document(private_key, document):
    digest = hashlib.sha256(document).digest()
    signature = private_key.sign(digest)
    return signature

def verify_signature(public_key, document, signature):
    digest = hashlib.sha256(document).digest()
    return public_key.verify(signature, digest)

def main():
    while True:
        print("Menu:")
        print("1. Key Generation")
        print("2. Sign Document")
        print("3. Verify Document")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            private_key, public_key = generate_keys()
            save_key_to_file("private_key.pem", private_key.to_pem())
            save_key_to_file("public_key.pem", public_key.to_pem())

            with open("key_generation_output.txt", "w") as f:
                f.write("Private Key:\n")
                f.write(private_key.to_pem().decode() + "\n")
                f.write("Public Key:\n")
                f.write(public_key.to_pem().decode() + "\n")

            print("Keys generated and saved to files")

        elif choice == '2':
            filename = input("Enter the PDF document filename: ")
            if not os.path.exists(filename):
                print("File not found")
                continue

            with open(filename, 'rb') as f:
                document = f.read()

            try:
                private_key_pem = read_key_from_file("private_key.pem")
                private_key = SigningKey.from_pem(private_key_pem)
            except Exception as e:
                print("Error reading private key:", e)
                continue

            signature = sign_document(private_key, document)
            save_key_to_file("signature.sig", signature)

            with open("signing_output.txt", "w") as f:
                f.write("Signature:\n")
                f.write(signature.hex() + "\n")

            print("Document signed and signature saved to file")

        elif choice == '3':
            filename = input("Enter the PDF document filename: ")
            if not os.path.exists(filename):
                print("File not found")
                continue

            with open(filename, 'rb') as f:
                document = f.read()

            try:
                public_key_pem = read_key_from_file("public_key.pem")
                public_key = VerifyingKey.from_pem(public_key_pem)
            except Exception as e:
                print("Error reading public key:", e)
                continue

            try:
                signature = read_key_from_file("signature.sig")
            except Exception as e:
                print("Error reading signature:", e)
                continue

            result = verify_signature(public_key, document, signature)

            with open("verification_output.txt", "w") as f:
                f.write("Verification Result:\n")
                f.write("Signature verifies" if result else "Signature does not verify")

            if result:
                print("Signature verifies")
            else:
                print("Signature does not verify")

        elif choice == '4':
            print("Exiting...")
            break

        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
