# Copyright (C) 2011-2012  Patrick Totzke <patricktotzke@gmail.com>
# This file is released under the GNU GPL, version 3 or a later revision.
# For further details see the COPYING file
import re
from cStringIO import StringIO
from email.generator import Generator
from email.mime.multipart import MIMEMultipart


def RFC3156_canonicalize(text):
    """
    Canonicalizes plain text (MIME-encoded usually) according to RFC3156.

    This function works as follows (in that order):

    1. Convert all line endings to \\\\r\\\\n (DOS line endings).
    2. Ensure the text ends with a newline (\\\\r\\\\n).
    3. Encode all occurences of "From " at the beginning of a line
       to "From=20" in order to prevent other mail programs to replace
       this with "> From" (to avoid MBox conflicts) and thus invalidate
       the signature.

    :param text: text to canonicalize (already encoded as quoted-printable)
    :rtype: str
    """
    text = re.sub("\r?\n", "\r\n", text)
    if not text.endswith("\r\n"):
        text += "\r\n"
    text = re.sub("^From ", "From=20", text, flags=re.MULTILINE)
    return text


def email_as_string(mail):
    """
    Converts the given message to a string, without mangling "From" lines
    (like as_string() does).

    :param mail: email to convert to string
    :rtype: str
    """
    fp = StringIO()
    g = Generator(fp, mangle_from_=False, maxheaderlen=78)
    g.flatten(mail)
    as_string = RFC3156_canonicalize(fp.getvalue())

    if isinstance(mail, MIMEMultipart):
        # Get the boundary for later
        boundary = mail.get_boundary()

        # Workaround for http://bugs.python.org/issue14983:
        # Insert a newline before the outer mail boundary so that other mail
        # clients can verify the signature when sending an email which contains
        # attachments.
        as_string = re.sub(r'--(\r\n)--' + boundary,
                           '--\g<1>\g<1>--' + boundary,
                           as_string, flags=re.MULTILINE)

    return as_string
