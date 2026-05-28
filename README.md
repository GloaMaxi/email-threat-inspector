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

![Application Screenshot](screenshots/app.png)
