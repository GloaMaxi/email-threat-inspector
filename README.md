    Email Threat Inspector

Email Threat Inspector is a small SOC-style project built in Python.  
The goal of this project is to analyze suspicious `.eml` email files and identify basic phishing indicators.

    Features

- Reads `.eml` email files
- Extracts sender, Reply-To, subject and body
- Detects suspicious phishing wording
- Extracts links from the email body
- Checks for risky domain patterns
- Detects mismatched Reply-To addresses
- Detects risky attachment references
- Calculates a basic risk score
- Generates analyst-style investigation notes

    How to Run

1. Clone the repository:

git clone https://github.com/GloaMaxi/email-threat-inspector.git
cd email-threat-inspector

2. Create a virtual environment:

python -m venv venv

3. Activate the virtual environment (Windows PowerShell):

.\venv\Scripts\Activate.ps1

4. Install dependencies:

python -m pip install -r requirements.txt

5. Start the Streamlit application:

python -m streamlit run app.py

6. Open the local URL shown in the terminal and upload the included sample_email.eml file.


<img width="1879" height="692" alt="app" src="https://github.com/user-attachments/assets/044e8d2c-2e50-4d0f-977f-af55b5f92241" />

<img width="1871" height="657" alt="image" src="https://github.com/user-attachments/assets/06bbb00d-e13e-460c-914d-9edfb860e451" />
