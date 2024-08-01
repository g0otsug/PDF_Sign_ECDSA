import streamlit as st
from scripts.ecdsa_script import generate_keys, sign_document, verify_signature, save_key_to_file, read_key_from_file
from ecdsa import SigningKey, VerifyingKey, SECP256k1

def main():
    st.title("ECDSA Document Signing")

    choice = st.sidebar.selectbox("Menu", ["Key Generation", "Sign Document", "Verify Document"])

    if choice == "Key Generation":
        if st.button("Generate Keys"):
            private_key, public_key = generate_keys()
            save_key_to_file("private_key.pem", private_key.to_pem())
            save_key_to_file("public_key.pem", public_key.to_pem())
            st.write("Keys generated and saved to files")
            st.download_button("Download Private Key", private_key.to_pem(), file_name="private_key.pem")
            st.download_button("Download Public Key", public_key.to_pem(), file_name="public_key.pem")

    elif choice == "Sign Document":
        pdf_file = st.file_uploader("Upload PDF Document", type=["pdf"])
        if pdf_file:
            document = pdf_file.read()
            private_key_pem = read_key_from_file("private_key.pem")
            private_key = SigningKey.from_pem(private_key_pem)
            signature = sign_document(private_key, document)
            save_key_to_file("signature.sig", signature)
            st.write("Document signed and signature saved to file")
            st.download_button("Download Signature", signature, file_name="signature.sig")

    elif choice == "Verify Document":
        pdf_file = st.file_uploader("Upload PDF Document", type=["pdf"])
        if pdf_file:
            document = pdf_file.read()
            public_key_pem = read_key_from_file("public_key.pem")
            public_key = VerifyingKey.from_pem(public_key_pem)
            signature = read_key_from_file("signature.sig")
            result = verify_signature(public_key, document, signature)
            st.write("Signature verifies" if result else "Signature does not verify")

if __name__ == '__main__':
    main()
