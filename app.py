import streamlit as st
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

# Load trained model
model = joblib.load("phishing_model.pkl")


def having_ip_address(url):
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    return 1 if re.search(ip_pattern, url) else -1


def url_length(url):
    if len(url) < 54:
        return 1
    elif 54 <= len(url) <= 75:
        return 0
    else:
        return -1


def https_token(url):
    return 1 if "https" in url.lower() else -1


def prefix_suffix(url):
    domain = urlparse(url).netloc
    return -1 if "-" in domain else 1


def extract_features(url):
    return {
        'having_IP_Address': having_ip_address(url),
        'URL_Length': url_length(url),
        'Shortining_Service': 0,
        'having_At_Symbol': 0,
        'double_slash_redirecting': 0,
        'Prefix_Suffix': prefix_suffix(url),
        'having_Sub_Domain': 0,
        'SSLfinal_State': 0,
        'Domain_registeration_length': 0,
        'Favicon': 0,
        'port': 0,
        'HTTPS_token': https_token(url),
        'Request_URL': 0,
        'URL_of_Anchor': 0,
        'Links_in_tags': 0,
        'SFH': 0,
        'Submitting_to_email': 0,
        'Abnormal_URL': 0,
        'Redirect': 0,
        'on_mouseover': 0,
        'RightClick': 0,
        'popUpWidnow': 0,
        'Iframe': 0,
        'age_of_domain': 0,
        'DNSRecord': 0,
        'web_traffic': 0,
        'Page_Rank': 0,
        'Google_Index': 0,
        'Links_pointing_to_page': 0,
        'Statistical_report': 0
    }


st.title("PhishGuard AI")
st.subheader("AI-Powered Phishing Website Detector")

url = st.text_input("Enter website URL")

if st.button("Check URL"):
    features = extract_features(url)
    feature_df = pd.DataFrame([features])

    prediction = model.predict(feature_df)

    if prediction[0] == -1:
        st.error("⚠️ Phishing Website Detected")
    else:
        st.success("✅ Legitimate Website")