
import gpgmime
import email
from os.path import join, dirname

msg = '''To: Robert <bob@example.org>
From: Alice <alice@example.com>
Date: Sun, 30 Aug 2015 20:00:03 -0400
Subject: hello

This message is signed!

Isn't that cool?

-Bob
'''

msg = email.message_from_string(msg)
gpg = gpgmime.GPG(gnupghome=join(dirname(__file__), 'testing/gpghome'),
                  use_agent=False)

msg = gpg.sign_and_encrypt_email(msg,
                                 keyid='alice@example.com',
                                 passphrase='secret',
                                 recipients='bob@example.org',
                                 )
# Encrypting an already signed message isn't working yet, but we eventually
# want to be able to do this:
# msg = gpg.encrypt_email(gpg.sign_email(msg), 'alice@example.com')

print(msg.as_string())
