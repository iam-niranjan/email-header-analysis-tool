# Email Header Analysis Tool

This project is a comprehensive email analysis tool that examines email headers, attachments, and URLs to assess the potential risk of phishing or other malicious activities.

## Features

- Analyze email headers from EML files
- Extract and analyze sender domain information
- Perform email authentication checks (SPF, DKIM, DMARC)
- Analyze IP addresses found in the email headers
- Examine attachments for potential threats
- Analyze URLs found in the email body
- Provide a risk assessment based on various factors
- Generate a detailed analysis report

## Setup

1. Clone the repository:
   ```
   git clone https://github.com/your-username/email-header-analysis.git
   cd email-header-analysis
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up the configuration file:
   - Rename `config_example.py` to `config.py`
   - Add your API keys and other configuration settings in `config.py`

## API Keys Required

This tool uses several third-party services for analysis. You'll need to obtain API keys for the following services:

- AbuseIPDB
- AlienVault OTX
- URLScan.io
- VirusTotal

Add these API keys to the `config.py` file.

## How to Run

To analyze a single email file:

```
python main.py path/to/your/email.eml
```

To analyze multiple email files:

```
python main.py path/to/email1.eml path/to/email2.eml path/to/email3.eml
```

To save the analysis results to a file:

```
python main.py path/to/your/email.eml --output analysis_results.txt
```

## Output

The tool will provide a detailed analysis of the email, including:

- Basic information (sender, recipient, subject, etc.)
- Domain analysis
- Email authentication results
- IP address analysis
- Attachment analysis (if any)
- URL analysis
- Overall risk assessment

## Contributing

Contributions to this project are welcome. Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Always follow applicable laws and regulations when analyzing emails, and respect privacy and data protection guidelines.
