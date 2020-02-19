#!/usr/bin/python3.6

import os

def send_email(email_dest, subject, body, emailer='ends.no-reply@less-tools.enwd.co.sa.charterlab.com', html=False):
    # if only one email is supplied
    if type(email_dest) is str:
        # make it an array
        email_dest = [email_dest]
    # create email
    if html:
        email_string = f"printf \"From: {emailer}\nSubject: {subject}\nContent-Type: text/html\n{body}\n.\n\" | sendmail -v"
    else:
        email_string = f"printf \"From: {emailer}\nSubject: {subject}\n{body}\n.\n\" | sendmail -v"
    # for each email
    for email_to in email_dest:
        # send the email
        cmd = f"{email_string} {email_to} > /dev/null 2>&1 || true"
        os.system(cmd)

