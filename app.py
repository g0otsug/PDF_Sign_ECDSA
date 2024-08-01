import os
import streamlit as st
from ecdsa_script import generate_keys, sign_document, verify_signature, save_key_to_file, read_key_from_file
from ecdsa import SigningKey, VerifyingKey, SECP256k1

def main():
    st.title("ECDSA Document Signing")

    choice = st.sidebar.selectbox("Menu", ["Key Generation", "Sign Document", "Verify Document"])

    if choice == "Key Generation":
        if st.button("Generate Keys"):
            private_key, public_key = generate_keys()
            private_pem = private_key.to_pem()
            public_pem = public_key.to_pem()

            save_key_to_file("private_key.pem", private_pem)
            save_key_to_file("public_key.pem", public_pem)

            with open("private_key.txt", "w") as f:
                f.write(private_pem.decode())

            with open("public_key.txt", "w") as f:
                f.write(public_pem.decode())

            st.write("Keys generated and saved to files")
            st.download_button("Download Private Key (.pem)", private_pem, file_name="private_key.pem")
            st.download_button("Download Private Key (.txt)", private_pem.decode(), file_name="private_key.txt")
            st.download_button("Download Public Key (.pem)", public_pem, file_name="public_key.pem")
            st.download_button("Download Public Key (.txt)", public_pem.decode(), file_name="public_key.txt")

    elif choice == "Sign Document":
        pdf_file = st.file_uploader("Upload PDF Document", type=["pdf"])
        private_key_file = st.file_uploader("Upload Private Key (.pem)", type=["pem"])
        if pdf_file and private_key_file:
            document = pdf_file.read()
            private_key_pem = private_key_file.read()
            private_key = SigningKey.from_pem(private_key_pem)
            signature = sign_document(private_key, document)
            save_key_to_file("signature.sig", signature)
            st.write("Document signed and signature saved to file")
            st.download_button("Download Signature", signature, file_name="signature.sig")

    elif choice == "Verify Document":
        pdf_file = st.file_uploader("Upload PDF Document", type=["pdf"])
        public_key_file = st.file_uploader("Upload Public Key (.pem)", type=["pem"])
        signature_file = st.file_uploader("Upload Signature File", type=["sig"])
        if pdf_file and public_key_file and signature_file:
            document = pdf_file.read()
            public_key_pem = public_key_file.read()
            public_key = VerifyingKey.from_pem(public_key_pem)
            signature = signature_file.read()
            result = verify_signature(public_key, document, signature)
            st.write("Signature verifies" if result else "Signature does not verify")

if __name__ == '__main__':
    main()
