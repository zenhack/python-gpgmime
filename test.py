
import gpgmime
import email

msg = '''To: Alice <alice@example.com>
From: Bob <bob@example.org>
Date: Sun, 30 Aug 2015 20:00:03 -0400
Subject: hello

This message is signed!

Isn't that cool?

-Bob
'''.replace('\n', '\r\n')

msg = email.message_from_string(msg)
gpg = gpgmime.GPG()

msg = gpg.sign_and_encrypt_email(msg, recipients='alice@example.com')
# Encrypting an already signed message isn't working yet, but we eventually
# want to be able to do this:
# msg = gpg.encrypt_email(gpg.sign_email(msg), 'alice@example.com')

print(msg.as_string())
