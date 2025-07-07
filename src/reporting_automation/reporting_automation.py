__version__ = "0.1.0"

# import libraries
import argparse
import os
import sys

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
from email.message import EmailMessage

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# Notes
"""
Email functionality utilizes gmail oauth2 authentication
This requires 
1) setting up a project in "Google Cloud"
2) creating a client for the project and downloading the credentials json (client id+secret)
3) adding the scope for gmail sending "../auth/gmail.send"
4) enabling the gmail api for the project
5) linking a (test) user to utilize the client

online examples for implementation in python, and google/python error messaging help navigate the outlined steps
https://developers.google.com/workspace/gmail/api/guides/sending#python
https://stackoverflow.com/questions/73256179/how-to-send-email-with-attachment-through-gmail-api
https://stackoverflow.com/questions/37201250/sending-email-via-gmail-python

a token.json and a credential.json (not tracked in repository) are needed for email functionality

if you desire a longer lasting authentication - registration/verification of the application within the google cloud api may be needed.

invitations to access reporting_automation application access can be requested from ward.chris.s@gmail.com
"""

# send email
def get_gmail_credentials():
    SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


def send_message(
    from_email: str, to_email: list, subject: str, messageBody: str, attachments: list = None
):
    """Create and send an email message
    Print the returned  message id
    Returns: Message object, including message id"""

    creds = get_gmail_credentials()
    SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
    
    try:
        service = build("gmail", "v1", credentials=creds)
        message = EmailMessage()
        message.set_content(messageBody)

        if attachments:
            for attachment in attachments:
                with open(attachment, "rb") as content_file:
                    content = content_file.read()
                    message.add_attachment(
                        content,
                        maintype="application",
                        subtype=(attachment.split(".")[1]),
                        filename=attachment,
                    )

        message["To"] = ", ".join(to_email)
        message["From"] = from_email
        message["Subject"] = subject

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {"raw": encoded_message}
        send_message = (
            service.users().messages().send(userId="me", body=create_message).execute()
        )
        print(f'Message Id: {send_message["id"]}')
    except HttpError as error:
        print(f"An error occurred: {error}")
        send_message = None
    return send_message


if __name__ == "__main__":
    # parse arguments
    parser = argparse.ArgumentParser("reporting_automation")
    parser.add_argument("--test", action="store_true")
    parser.add_argument('--to', help="semicolon delimited list of recipients")
    parser.add_argument("--sender", help="sender's email address - will use/authenticate via gmail")
    parser.add_argument("--subject",help="quoted text string for email subject")
    parser.add_argument("--message",help="quoted text string for email body text")
    parser.add_argement("--attachment",help="path to file to include as attachment")
    parsed_args = parser.parse_args()

    args = sys.argv.copy()

    print(f"From: {args.sender}")
    print(f"To: {args.to}")
    print(f"Subject: {args.subject}")
    print(f"Message: {args.message}")
    print(f"Attachment: {args.attachment}")

    print("sending email")
    send_message(
        messageBody=args.message,
        subject=args.subject,
        to_email=args.to.split(";"),
        attachments=[args.attachment],
    )
    print("!!! finished !!!")