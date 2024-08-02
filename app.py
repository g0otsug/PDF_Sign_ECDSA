import streamlit as st
import firebase_admin
from firebase_admin import auth
from firebase_config import cred
from ecdsa import SigningKey, VerifyingKey
from ecdsa_script import generate_keys, sign_document, verify_signature, save_key_to_file, read_key_from_file

# Initialize Firebase
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

def sign_up(email, password):
    try:
        user = auth.create_user(email=email, password=password)
        return user.uid
    except firebase_admin._auth_utils.EmailAlreadyExistsError:
        st.error("Email already exists")
    except Exception as e:
        st.error(f"Sign up failed: {str(e)}")
    return None

def sign_in(email, password):
    try:
        user = auth.get_user_by_email(email)
        # Note: In a real application, you would use Firebase Authentication SDK to verify the password
        # Firebase Admin SDK doesn't support password verification directly
        return user.uid
    except firebase_admin._auth_utils.UserNotFoundError:
        st.error("User not found")
    except Exception as e:
        st.error(f"Sign in failed: {str(e)}")
    return None

def main():
    st.title("ECDSA Document Signing")

    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        menu = ["Home", "SignUp", "Login"]
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "Home":
            st.subheader("Home")

        elif choice == "SignUp":
            st.subheader("Create New Account")
            email = st.text_input("User Email")
            password = st.text_input("Password", type='password')
            if st.button("SignUp"):
                user_uid = sign_up(email, password)
                if user_uid:
                    st.success(f"Account created for {email}")

        elif choice == "Login":
            st.subheader("Login")
            email = st.text_input("User Email")
            password = st.text_input("Password", type='password')
            if st.button("Login"):
                user_uid = sign_in(email, password)
                if user_uid:
                    st.success(f"Welcome {email}")
                    st.session_state.logged_in = True
                    st.session_state.user_uid = user_uid
                    st.experimental_rerun()  # Reload the page to show the app menu

    else:
        menu = ["Key Generation", "Sign Document", "Verify Document", "Logout"]
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "Logout":
            st.session_state.logged_in = False
            st.success("You have been logged out")
            st.experimental_rerun()  # Reload the page to show the login menu

        elif choice == "Key Generation":
            st.subheader("Key Generation")
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
            st.subheader("Sign Document")
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
            st.subheader("Verify Document")
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
