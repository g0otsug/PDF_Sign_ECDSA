import streamlit as st
import firebase_admin
from firebase_admin import auth, db
from firebase_config import cred
from ecdsa import SigningKey, VerifyingKey
from ecdsa_script import generate_keys, sign_document, verify_signature, save_key_to_file, read_key_from_file
import hashlib
from datetime import datetime, timedelta

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
        return user.uid
    except firebase_admin._auth_utils.UserNotFoundError:
        st.error("User not found")
    except Exception as e:
        st.error(f"Sign in failed: {str(e)}")
    return None

def verify_password(stored_password, entered_password):
    return stored_password == entered_password

def get_file_name(email, key_type):
    user_name = email.split('@')[0]
    file_name = f"{key_type}_key_{user_name}.pem"
    return file_name

def save_key_to_database(uid, key_type, key_pem, key_period):
    ref = db.reference(f'keys/{uid}')
    new_key_ref = ref.push()
    new_key_ref.set({
        'type': key_type,
        'pem': key_pem.decode(),
        'period': key_period,
        'actions': {
            'download': True,
            'view': True,
            'delete': True
        }
    })
def save_key_to_database(uid, key_type, key_pem, key_period):
    # Current date (date of key generation)
    creation_date = datetime.now()
    # Expiration date is one year from creation date
    expiration_date = creation_date + timedelta(days=365)
    
    ref = db.reference(f'keys/{uid}')
    new_key_ref = ref.push()
    new_key_ref.set({
        'type': key_type,
        'pem': key_pem.decode(),
        'period': key_period,
        'creation_date': creation_date.strftime('%Y-%m-%d'),
        'expiration_date': expiration_date.strftime('%Y-%m-%d'),
        'actions': {
            'download': True,
            'view': True,
            'delete': True
        }
    })

def get_keys_from_database(uid):
    ref = db.reference(f'keys/{uid}')
    return ref.get()
def get_keys_from_database(uid):
    ref = db.reference(f'keys/{uid}')
    return ref.get()

def delete_key_from_database(uid, key_id):
    ref = db.reference(f'keys/{uid}/{key_id}')
    ref.delete()

def main():
    st.set_page_config(page_title="Sandi Berkas", page_icon=":lock:", layout="wide")

    if 'page' not in st.session_state:
        st.session_state.page = "landing"

    if st.session_state.page == "landing":
        st.title("Welcome to Sandi Berkas")
        st.write("Securely sign and verify your PDF documents.")
        if st.button("Get Started"):
            st.session_state.page = "home"
            if st.button("Let's Go"):
                st.experimental_rerun()

    elif st.session_state.page == "home":
        st.title("Sandi Berkas - Home")

        menu = ["SignUp", "Login", "Tutorial", "About"]
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "SignUp":
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
                    st.session_state.email = email
                    st.session_state.password = password
                    st.session_state.page = "app"
                    if st.button("Next"):
                        st.experimental_rerun()

        elif choice == "Tutorial":
            st.subheader("Tutorial")
            st.write("### Steps to use Sandi Berkas")
            st.markdown("""
            1. **Sign Up**: Create a new account using your email and password.
            2. **Login**: Use your credentials to log in.
            3. **Generate Keys**: Create a pair of public and private keys for signing documents.
            4. **Sign Document**: Upload a PDF and sign it with your private key.
            5. **Verify Document**: Verify a signed PDF using the public key.
            6. **Logout**: Log out of your account securely.
            """)

        elif choice == "About":
            st.subheader("About Sandi Berkas")
            st.write("Sandi Berkas is a secure web application designed to help you sign and verify PDF documents using ECDSA.")
            st.write("Features include:")
            st.write("- User authentication")
            st.write("- Key generation")
            st.write("- Document signing")
            st.write("- Document verification")
    
    elif st.session_state.page == "app":
        st.title(f"Welcome, {st.session_state.email}")
        menu = ["Key Generation", "Key Storage", "Sign Document", "Verify Document", "Users", "Logout"]
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "Logout":
            st.session_state.logged_in = False
            st.session_state.page = "home"
            st.success("You have been logged out.")
            if st.button("Quit"):
                st.experimental_rerun()

        elif choice == "Key Generation":
            st.subheader("Key Generation")
            if st.button("Generate Keys") or ('private_pem' in st.session_state and 'public_pem' in st.session_state):
                if 'private_pem' not in st.session_state or 'public_pem' not in st.session_state:
                    private_key, public_key = generate_keys()
                    st.session_state.private_pem = private_key.to_pem()
                    st.session_state.public_pem = public_key.to_pem()

                st.write("Keys generated and saved to files")

            

            entered_password = st.text_input("Enter your password to download keys", type="password")
            if st.button("Download Private Key (.pem)") and verify_password(st.session_state.password, entered_password):
                file_name = get_file_name(st.session_state.email, 'private')
                st.download_button("Download Private Key (.pem)", st.session_state.private_pem, file_name=file_name)
            if st.button("Download Public Key (.pem)") and verify_password(st.session_state.password, entered_password):
                file_name = get_file_name(st.session_state.email, 'public')
                st.download_button("Download Public Key (.pem)", st.session_state.public_pem, file_name=file_name)

            if st.button("Save Keys to Database"):
                save_key_to_database(st.session_state.user_uid, 'private', st.session_state.private_pem, '1 year')
                save_key_to_database(st.session_state.user_uid, 'public', st.session_state.public_pem, '1 year')
                st.success("Keys saved to database")

        elif choice == "Key Storage":
            st.subheader("Key Storage")
            keys = get_keys_from_database(st.session_state.user_uid)
            if keys:
                for key_id, key_data in keys.items():
                    st.write(f"Key ID: {key_id}")
                    st.write(f"Key Type: {key_data['type']}")
                    st.write(f"Key Period: {key_data['period']}")
                    st.write(f"Creation Date: {key_data['creation_date']}")
                    st.write(f"Expiration Date: {key_data['expiration_date']}")
                    if st.button(f"Download {key_data['type']} Key"):
                        st.download_button("Download Key", key_data['pem'], file_name=f"{key_data['type']}_key_{st.session_state.email}.pem")
                    if st.button(f"View {key_data['type']} Key"):
                        st.code(key_data['pem'], language="text")
                    if st.button(f"Delete {key_data['type']} Key"):
                        delete_key_from_database(st.session_state.user_uid, key_id)
                        st.success(f"{key_data['type']} Key deleted")

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

        elif choice == "Users":
            st.subheader("Users")
            users = auth.list_users().users
            for i, user in enumerate(users, 1):
                st.write(f"{i}. {user.email}")
                public_keys = get_keys_from_database(user.uid)
                for key_id, key_data in public_keys.items():
                    if key_data['type'] == 'public':
                        if st.button(f"Download Public Key for {user.email}"):
                            st.download_button("Download Public Key", key_data['pem'], file_name=f"public_key_{user.email}.pem")

if __name__ == '__main__':
    main()






