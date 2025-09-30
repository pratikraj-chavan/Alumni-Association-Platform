from email.message import EmailMessage
import aiosmtplib

async def send_email(to_email: str, subject: str, body: str):
    message = EmailMessage()
    message["From"] = "your_email@example.com"
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    await aiosmtplib.send(
        message,
        hostname="smtp.gmail.com",
        port=587,
        start_tls=True,
        username="your_email@example.com",
        password="your_email_password"
    )
