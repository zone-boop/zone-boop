import os
import base64
import msal
import requests
import dkim
import spf
import dns.resolver
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from fpdf import FPDF
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from email.utils import parsedate_tz, mktime_tz
from email import message_from_bytes
import argparse
import tkinter as tk
from tkinter import messagebox

# ===================== Gmail Authentication =====================

def authenticate_gmail():
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    service = build('gmail', 'v1', credentials=creds)
    return service

def fetch_gmail_emails(service):
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], q="is:unread").execute()
    messages = results.get('messages', [])
    email_data = []
    
    if not messages:
        print('No messages found.')
    else:
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            email_data.append(msg)
    
    return email_data


# ===================== Outlook Authentication =====================

def authenticate_outlook():
    CLIENT_ID = 'your-client-id'
    CLIENT_SECRET = 'your-client-secret'
    AUTHORITY = 'https://login.microsoftonline.com/common'
    SCOPES = ['Mail.Read']

    app = msal.ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)
    result = app.acquire_token_for_client(scopes=SCOPES)
    
    return result

def fetch_outlook_emails(token):
    url = "https://graph.microsoft.com/v1.0/me/messages"
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    response = requests.get(url, headers=headers)
    messages = response.json()
    email_data = []
    for message in messages['value']:
        email_data.append(message)
    
    return email_data


# ===================== Email Parsing and Metadata Analysis =====================

def analyze_metadata(raw_email):
    msg = message_from_bytes(raw_email)
    subject = msg['Subject']
    from_ = msg['From']
    date = msg['Date']
    timestamp = mktime_tz(parsedate_tz(date))
    
    return {
        'subject': subject,
        'from': from_,
        'date': timestamp
    }

def group_emails_by_thread(emails):
    threads = {}
    
    for email in emails:
        thread_id = email.get('In-Reply-To')
        
        if thread_id:
            if thread_id in threads:
                threads[thread_id].append(email)
            else:
                threads[thread_id] = [email]
        else:
            threads[email['Message-ID']] = [email]
    
    return threads


# ===================== Attachment Analysis =====================

def download_attachments(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id).execute()
    for part in msg['payload']['parts']:
        if part['filename']:
            attachment = service.users().messages().attachments().get(
                userId='me', messageId=msg_id, id=part['body']['attachmentId']).execute()
            file_data = base64.urlsafe_b64decode(attachment['body']['data'])
            path = os.path.join('downloads', part['filename'])
            with open(path, 'wb') as f:
                f.write(file_data)
            print(f"Downloaded attachment: {part['filename']}")


# ===================== Message Authentication (SPF, DKIM, DMARC) =====================

def check_dkim(email):
    signature = dkim.verify(email)
    return signature

def check_spf(email_sender, email_domain):
    result, explanation = spf.check2(email_sender, email_domain)
    return result

def check_dmarc(email_domain):
    try:
        dns_resolver = dns.resolver.Resolver()
        result = dns_resolver.resolve(f'_dmarc.{email_domain}', 'TXT')
        return result
    except dns.resolver.NoAnswer:
        return None


# ===================== Visualization and Reporting =====================

def visualize_email_data(email_data):
    df = pd.DataFrame(email_data)
    plt.figure(figsize=(10, 6))
    sns.countplot(data=df, x='from')
    plt.title('Email Frequency by Sender')
    plt.xticks(rotation=45)
    plt.show()


def export_to_pdf(report_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 12)

    pdf.cell(200, 10, txt="Forensic Email Report", ln=True, align="C")
    pdf.ln(10)
    
    for data in report_data:
        pdf.cell(200, 10, txt=f"{data['subject']}: {data['from']}", ln=True)

    pdf.output("forensic_report.pdf")


# ===================== CLI Interface =====================

def cli_main():
    parser = argparse.ArgumentParser(description="Email Forensic Tool")
    parser.add_argument('--fetch-gmail', action='store_true', help="Fetch Gmail emails")
    parser.add_argument('--fetch-outlook', action='store_true', help="Fetch Outlook emails")
    parser.add_argument('--generate-report', action='store_true', help="Generate forensic report")
    args = parser.parse_args()

    if args.fetch_gmail:
        service = authenticate_gmail()
        emails = fetch_gmail_emails(service)
        print(f"Fetched {len(emails)} Gmail emails.")

    if args.fetch_outlook:
        token = authenticate_outlook()
        emails = fetch_outlook_emails(token)
        print(f"Fetched {len(emails)} Outlook emails.")

    if args.generate_report:
        report_data = [{'subject': 'Test Subject', 'from': 'test@example.com'}]  # Dummy data for the report
        export_to_pdf(report_data)
        print("Forensic report exported.")


# ===================== GUI Interface =====================

class EmailForensicToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Forensic Tool")
        
        # Buttons to trigger actions
        self.gmail_button = tk.Button(root, text="Fetch Gmail Emails", command=self.fetch_gmail_emails)
        self.gmail_button.pack(pady=10)
        
        self.outlook_button = tk.Button(root, text="Fetch Outlook Emails", command=self.fetch_outlook_emails)
        self.outlook_button.pack(pady=10)

    def fetch_gmail_emails(self):
        service = authenticate_gmail()
        emails = fetch_gmail_emails(service)
        messagebox.showinfo("Info", f"Fetched {len(emails)} Gmail emails.")

    def fetch_outlook_emails(self):
        token = authenticate_outlook()
        emails = fetch_outlook_emails(token)
        messagebox.showinfo("Info", f"Fetched {len(emails)} Outlook emails.")


# ===================== Main =====================

if __name__ == '__main__':
    choice = input("Choose interface: [cli/gui]: ").strip().lower()

    if choice == 'cli':
        cli_main()
    elif choice == 'gui':
        root = tk.Tk()
        app = EmailForensicToolGUI(root)
        root.mainloop()
    else:
        print("Invalid choice. Exiting.")
