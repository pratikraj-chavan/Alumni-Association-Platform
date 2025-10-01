from email.message import EmailMessage
import aiosmtplib

async def send_email(to_email: str, subject: str, body: str):
    message = EmailMessage()
    message["From"] = "chavanpratikpsc@gmail.com"
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    await aiosmtplib.send(
        message,
        hostname="smtp.gmail.com",
        port=587,
        start_tls=True,
        username="chavanpratikpsc@gmail.com",
        password="ettd stej eotw mahg"
        
    )
    print("email send")
