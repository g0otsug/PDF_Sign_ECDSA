import streamlit as st
import firebase_admin
from firebase_admin import auth
from firebase_config import cred
from ecdsa import SigningKey, VerifyingKey
from ecdsa_script import generate_keys, sign_document, verify_signature, save_key_to_file, read_key_from_file
from PyPDF2 import PdfFileWriter, PdfFileReader
from PIL import Image
import io

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

def add_signature_to_pdf(pdf_bytes, signature_bytes, page_number, x, y):
    pdf_reader = PdfFileReader(io.BytesIO(pdf_bytes))
    pdf_writer = PdfFileWriter()

    for i in range(pdf_reader.numPages):
        page = pdf_reader.getPage(i)
        if i == page_number:
            signature_image = Image.open(io.BytesIO(signature_bytes))
            img_buffer = io.BytesIO()
            signature_image.save(img_buffer, format="PNG")
            page.mergePage(PdfFileReader(io.BytesIO(img_buffer.getvalue())).getPage(0))
        pdf_writer.addPage(page)

    output = io.BytesIO()
    pdf_writer.write(output)
    return output.getvalue()

def verify_password(stored_password, entered_password):
    # In a real application, passwords should be hashed and checked securely
    return stored_password == entered_password

def main():
    st.set_page_config(page_title="Sandi Berkas", page_icon=":lock:", layout="wide")

    if 'page' not in st.session_state:
        st.session_state.page = "landing"

    if st.session_state.page == "landing":
        st.title("Welcome to Sandi Berkas")
        st.write("Securely sign and verify your PDF documents.")
        if st.button("Get Started"):
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
        menu = ["Key Generation", "Sign Document", "Verify Document", "Logout"]
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

            with st.expander("Lihat Private Key"):
                entered_password = st.text_input("Enter your password to view the Private Key", type="password")
                if st.button("View Private Key") and verify_password(st.session_state.password, entered_password):
                    st.code(st.session_state.private_pem.decode(), language="text")
                
            with st.expander("Lihat Public Key"):
                entered_password = st.text_input("Enter your password to view the Public Key", type="password")
                if st.button("View Public Key") and verify_password(st.session_state.password, entered_password):
                    st.code(st.session_state.public_pem.decode(), language="text")

            entered_password = st.text_input("Enter your password to download keys", type="password")
            if st.button("Download Private Key (.pem)") and verify_password(st.session_state.password, entered_password):
                st.download_button("Download Private Key (.pem)", st.session_state.private_pem, file_name="private_key.pem")
            if st.button("Download Public Key (.pem)") and verify_password(st.session_state.password, entered_password):
                st.download_button("Download Public Key (.pem)", st.session_state.public_pem, file_name="public_key.pem")

        elif choice == "Sign Document":
            st.subheader("Sign Document")
            pdf_file = st.file_uploader("Upload PDF Document", type=["pdf"])
            private_key_file = st.file_uploader("Upload Private Key (.pem)", type=["pem"])
            signature_image = st.file_uploader("Upload Signature Image (.png or .jpg)", type=["png", "jpg"])
            page_number = st.number_input("Page Number", min_value=0, step=1)
            x = st.number_input("X Position", min_value=0, step=1)
            y = st.number_input("Y Position", min_value=0, step=1)

            if pdf_file and private_key_file and signature_image:
                document = pdf_file.read()
                private_key_pem = private_key_file.read()
                private_key = SigningKey.from_pem(private_key_pem)
                signature = sign_document(private_key, document)
                signed_pdf = add_signature_to_pdf(document, signature_image.read(), page_number, x, y)
                entered_password = st.text_input("Enter your password to download signed PDF", type="password")
                if st.button("Download Signed PDF") and verify_password(st.session_state.password, entered_password):
                    st.download_button("Download Signed PDF", signed_pdf, file_name="signed_document.pdf")
                st.write("Document signed and signature saved to file")

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
