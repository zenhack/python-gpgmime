
from pgpmime.envelope import *
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
msg = sign(msg)

print(msg.as_string())
