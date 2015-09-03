# Copyright (C) 2011-2012  Patrick Totzke <patricktotzke@gmail.com>
# Copyright (C) 2015       Ian Denhardt <ian@zenhack.net>
# This file is released under the GNU GPL, version 3 or a later revision.
# For further details see the COPYING file
import re
from cStringIO import StringIO
from email.generator import Generator
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .errors import GPGProblem, GPGCode


def normalize_payload(payload):
    """Normalize the format of the payload.

    If payload is a string, convert it to MIMEText and return it.
    Otherwise, leave it alone.
    """
    # Build body text part. To properly sign/encrypt messages later on, we
    # convert the text to its canonical format (as per RFC 2015).
    if isinstance(payload, basestring):
        payload = payload.encode('utf-8')
        payload = payload.replace('\\t', ' ' * 4)
        payload = MIMEText(payload, 'plain', 'utf-8')

    return payload


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


def RFC3156_micalg_from_algo(hash_algo):
    """Convert hash_algo returned by python-gnupg to what RFC3156 requires.

    GPG (and by extension python-gnupg) returns hash algorithms as numbers
    (encoded as strings), but RFC3156 says that programs need to use names
    such as "pgp-sha256" instead.

    :param hash_algo: python-gnupg hash_algo
    :rtype: str
    """
    mapping = {
        '1':   'pgp-md5',
        '2':   'pgp-sha1',
        '3':   'pgp-ripemd160',
        '5':   'pgp-md2',
        '6':   'pgp-tiger192',
        '7':   'pgp-haval',
        '8':   'pgp-sha256',
        '9':   'pgp-sha384',
        '10':  'pgp-sha512',
        '301': 'pgp-md4',
        '302': 'pgp-crc32',
        '303': 'pgp-crc32rfc1510',
        '304': 'pgp-crc24rfc2440',
    }
    if hash_algo in mapping:
        return mapping[hash_algo]
    else:
        raise GPGProblem(("Invalid hash_algo passed to hash_algo_name."),
                         code=GPGCode.INVALID_HASH)


def copy_headers(src, dest):
    """Add all headers from src to dest, except those already present.

    Both src and dest should be instances of class:`email.message.Message`.
    dest will be modified in place, adding all of the headers in src which
    are not already present.
    """
    for key in src.keys():
        if key not in dest:
            dest[key] = src[key]


def clone_payload(src):
    """Return a copy of the payload.

    :param src: The email payload to copy
    """
    if isinstance(src, basestring):
        return src
    else:
        return [clone_message(m) for m in src]


def clone_message(src):
    """Return a copy of the message.

    :param src: The message to copy
    """
    dest = Message()
    copy_headers(src, dest)
    payload = src.get_payload()
    if not isinstance(payload, basestring):
        payload = clone_payload(payload)
    dest.set_payload(payload)
    return dest



def infer_recipients(msg):
    """Infer the proper recipients based on msg's headers.

    return a list of recipients including all addresses listed in the
    To, Cc, and Bcc headers.
    """
    recipients = []
    for hdr in 'To', 'Cc', 'Bcc':
        for addr in msg[hdr].split(','):
            addr = addr.strip()
            recipients.append(addr)
    return addr
