import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet
import json
import os
import time

DATA_FILE = "data_store1.json"
LOCKOUT_TIME = 30

if "login_info" not in st.session_state:
    st.session_state.login_info = {}

# Load or initialize stored data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Load into session state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()

# if "failed_attempts" not in st.session_state:
#     st.session_state.failed_attempts = 0

# Get cipher from passkey
def get_cipher(passkey: str, salt: bytes) -> Fernet:
    key = hashlib.pbkdf2_hmac(
        'sha256',                # Algorithm
        passkey.encode(),        # Password
        salt,                    # Salt
        100_000                  # Iterations (more = stronger)
    )
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key)

def register_user(username, password):
    st.session_state.stored_data = load_data()
    # if username in st.session_state.stored_data:
    #     return False, "Username already exists..."
    
    st.session_state.stored_data[username] = {"password": password, "data": []}
    save_data(st.session_state.stored_data)
    return True

def login_user(username, password):
    st.session_state.stored_data = load_data()
    user = st.session_state.stored_data.get(username)

    if not user:
        return False, "User not found! Please register first..."

    if "lockout" in st.session_state and time.time() < st.session_state["lockout"]:
        return False, f"🔒 Locked out. Try again in {int(st.session_state['lockout'] - time.time())}s"

    if password == user["password"]:
        st.session_state["user"] = username
        st.session_state["failures"] = 0
        return True, "Logged in"
    else:
        st.session_state["failures"] = st.session_state.get("failures", 0) + 1
        if st.session_state["failures"] >= 3:
            st.session_state["lockout"] = time.time() + LOCKOUT_TIME
            return False, "🚫 Too many failed attempts...Locked for 30 seconds."
        return False, "Incorrect Username and password!"



# Encrypt data
def encrypt_data(username, passkey, salt, text ):
    st.session_state.stored_data = load_data()
    username = st.session_state["user"]
    cipher = get_cipher(passkey,salt)
    encrypted = cipher.encrypt(text.encode()).decode()
    return encrypted
    

# Decrypt data
def decrypt_data(username, passkey,salt, encrypted_text):
    st.session_state.stored_data = load_data()
    username = st.session_state["user"]
    cipher = get_cipher(passkey, salt)
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
        # return cipher.decrypt(item.encode()).decode() for item in st.session_state.stored_data[username]["data"]]
    except:
        return None
    

# UI starts here
st.set_page_config(page_title="🔐 SecureVault", layout="wide")

st.markdown(
    """
    <style>
    /* Set default font color for the entire app */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: white;
        color: black!important;
    }

     /* Optional: Label text for input fields */
    label, .stTextInput > div > label {
        color: black!important;
    }

    div.stButton > button {
        background-color: #1E3A8A;/*blue-900*/ ;
        color: white!important;
        font-weight: bold;
    }
    div.stButton > button:hover {
    background-color: #047857;/*green-700*/
    color: white!important;
    }
    </style>
    """,
    unsafe_allow_html=True)

def styled_message(message, type="success", font_color="#FFFFFF"):
    if type == "success":
        bg_color = "#25BF6F"  
        icon = "✅"
    elif type == "error":
        bg_color = "#FEF9C3"; 
        icon = "❌"
    elif type == "warning":
        bg_color = "red"
        icon = "⚠️"
    st.markdown(f"""
            <div style="background-color: {bg_color}; 
                padding: 10px; 
                border-radius: 6px;
                color: {font_color}; 
                font-size: 16px;">
                {icon}
                {message}
            </div>
            """, unsafe_allow_html=True)
    
st.title("🔐 Secure Data Vault")

menu = ["Home", "Register", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if st.session_state.get("redirect_to"):
    choice = st.session_state["redirect_to"]
    del st.session_state["redirect_to"]

if choice == "Home":
    
    st.subheader("🏠 Welcome")
    st.write("Use this app to **store and retrieve encrypted data** securely using unique passkeys and a data ID.")

elif choice == "Register":
    st.subheader("📝 Register Here")
    user_name = st.text_input("Enter a Username:")
    password = st.text_input("Enter a password:", type= "password")
    if st.button("Register"):
        if user_name and password:
            if user_name in st.session_state.stored_data:
                styled_message("Username already exists...","error","black")
            else:
                cnfrm_registration = register_user(user_name, password)
                styled_message("You are registered! Please Login","success","#FFFFFF")
        else:
            styled_message("You must enter Username and password...","error","black")

elif choice == "Login":
    st.subheader("🔑 Login")
    user_name = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        success, msg = login_user(user_name, password)
        if success:
            styled_message(msg,"success","#FFFFFF")
            st.session_state["redirect_to"] = "Store Data"
            # st.rerun()
        else:
            styled_message(msg,"error","black")
            

elif choice == "Store Data":
    if "user" in st.session_state:
        username = st.session_state["user"]
        st.subheader("🔐 Store Your Secret")
        user_data = st.text_area("Enter your text")
        passkey = st.text_input("Encryption Passkey", type="password")
        if st.button("Encrypt and Store"):
            salt = os.urandom(16)
            encrypted = encrypt_data(username, passkey, salt, user_data)

            # Save under existing user's list
            user_record = st.session_state.stored_data.get(username)
            if user_record:
                user_record["data"].append({"encrypted_text": encrypted, "salt": base64.b64encode(salt).decode()})
                save_data(st.session_state.stored_data)
                styled_message("Data stored securely!","success","#FFFFFF")
                # st.code(encrypted)

    else:
        styled_message("Please login first.","warning","#FFFFFF")

elif choice == "Retrieve Data":
    if "user" in st.session_state:
        username = st.session_state["user"]
        user_record = st.session_state.stored_data.get(username)
        if user_record:
            passkey = st.text_input("Enter your passkey", type="password")
            if st.button("Decrypt"):
                decrypted_list = []
                for entry in user_record["data"]:
                    salt = base64.b64decode(entry["salt"])
                    decrypted = decrypt_data(username, passkey, salt, entry["encrypted_text"])
                    if decrypted:
                        decrypted_list.append(decrypted)
                if decrypted_list:
                        styled_message("Decrypted data:","success","#FFFFFF") 
                        for i, item in enumerate(decrypted_list, 1):
                                st.write(f"{i}. {item}")
                else:
                    styled_message("Incorrect passkey or data error.","error","black")
    else:
        styled_message("Please login first.","warning","#FFFFFF")

        

                    
                    