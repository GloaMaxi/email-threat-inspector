import streamlit as st
from analyzer import check_email

st.set_page_config(
    page_title="Email Threat Inspector",
    layout="wide"
)

st.title("Email Threat Inspector")
st.write("Small SOC-style tool for checking suspicious .eml email files.")

uploaded_email = st.file_uploader("Choose an email file", type=["eml"])

if uploaded_email:
    saved_file = "uploaded_email.eml"

    with open(saved_file, "wb") as file:
        file.write(uploaded_email.getbuffer())

    result = check_email(saved_file)

    st.subheader("Email Details")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.caption("Sender")
        st.info(result["sender"])

    with col2:
        st.caption("Reply-To")
        st.info(result["reply_to"] if result["reply_to"] else "Not available")

    with col3:
        st.caption("Subject")
        st.info(result["subject"])

    st.subheader("Risk Overview")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Score", result["score"])

    with col2:
        if result["risk"] == "High":
            st.error(f"Risk: {result['risk']}")
        elif result["risk"] == "Medium":
            st.warning(f"Risk: {result['risk']}")
        else:
            st.success(f"Risk: {result['risk']}")

    st.subheader("Links Found")

    if result["links"]:
        for link in result["links"]:
            st.code(link)
    else:
        st.success("No links were found.")

    st.subheader("Indicators")

    if result["indicators"]:
        for item in result["indicators"]:
            st.code(item)
    else:
        st.success("No indicators were extracted.")

    st.subheader("Analysis Notes")

    if result["notes"]:
        for note in result["notes"]:
            st.warning(note)
    else:
        st.success("No obvious phishing indicators found.")

    st.subheader("Analyst Summary")
    st.info(result["analyst_note"])

    with st.expander("Show email body"):
        st.text(result["body"])