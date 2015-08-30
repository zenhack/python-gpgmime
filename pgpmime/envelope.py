# Copyright (C) 2011-2012  Patrick Totzke <patricktotzke@gmail.com>
# This file is released under the GNU GPL, version 3 or a later revision.
# For further details see the COPYING file
import os
import email
import email.charset as charset
charset.add_charset('utf-8', charset.QP, charset.QP, 'utf-8')
from email.encoders import encode_7or8bit
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

from alot import __version__
import logging
import alot.helper as helper
import alot.crypto as crypto
import gpgme
from alot.settings import settings
from alot.errors import GPGProblem, GPGCode

from .utils import encode_header


def construct_mail(self):
    """
    compiles the information contained in this envelope into a
    :class:`email.Message`.
    """
    # Build body text part. To properly sign/encrypt messages later on, we
    # convert the text to its canonical format (as per RFC 2015).
    canonical_format = self.body.encode('utf-8')
    canonical_format = canonical_format.replace('\\t', ' ' * 4)
    textpart = MIMEText(canonical_format, 'plain', 'utf-8')

    # wrap it in a multipart container if necessary
    if self.attachments:
        inner_msg = MIMEMultipart()
        inner_msg.attach(textpart)
        # add attachments
        for a in self.attachments:
            inner_msg.attach(a.get_mime_representation())
    else:
        inner_msg = textpart

    if self.sign:
        plaintext = helper.email_as_string(inner_msg)
        logging.debug('signing plaintext: ' + plaintext)

        try:
            signatures, signature_str = crypto.detached_signature_for(
                plaintext, self.sign_key)
            if len(signatures) != 1:
                raise GPGProblem("Could not sign message (GPGME "
                                    "did not return a signature)",
                                    code=GPGCode.KEY_CANNOT_SIGN)
        except gpgme.GpgmeError as e:
            if e.code == gpgme.ERR_BAD_PASSPHRASE:
                # If GPG_AGENT_INFO is unset or empty, the user just does
                # not have gpg-agent running (properly).
                if os.environ.get('GPG_AGENT_INFO', '').strip() == '':
                    msg = "Got invalid passphrase and GPG_AGENT_INFO\
                            not set. Please set up gpg-agent."
                    raise GPGProblem(msg, code=GPGCode.BAD_PASSPHRASE)
                else:
                    raise GPGProblem("Bad passphrase. Is gpg-agent "
                                        "running?",
                                        code=GPGCode.BAD_PASSPHRASE)
            raise GPGProblem(str(e), code=GPGCode.KEY_CANNOT_SIGN)

        micalg = crypto.RFC3156_micalg_from_algo(signatures[0].hash_algo)
        unencrypted_msg = MIMEMultipart('signed', micalg=micalg,
                                        protocol=
                                        'application/pgp-signature')

        # wrap signature in MIMEcontainter
        stype = 'pgp-signature; name="signature.asc"'
        signature_mime = MIMEApplication(_data=signature_str,
                                            _subtype=stype,
                                            _encoder=encode_7or8bit)
        signature_mime['Content-Description'] = 'signature'
        signature_mime.set_charset('us-ascii')

        # add signed message and signature to outer message
        unencrypted_msg.attach(inner_msg)
        unencrypted_msg.attach(signature_mime)
        unencrypted_msg['Content-Disposition'] = 'inline'
    else:
        unencrypted_msg = inner_msg

    if self.encrypt:
        plaintext = helper.email_as_string(unencrypted_msg)
        logging.debug('encrypting plaintext: ' + plaintext)

        try:
            encrypted_str = crypto.encrypt(plaintext,
                                            self.encrypt_keys.values())
        except gpgme.GpgmeError as e:
            raise GPGProblem(str(e), code=GPGCode.KEY_CANNOT_ENCRYPT)

        outer_msg = MIMEMultipart('encrypted',
                                    protocol='application/pgp-encrypted')

        version_str = 'Version: 1'
        encryption_mime = MIMEApplication(_data=version_str,
                                            _subtype='pgp-encrypted',
                                            _encoder=encode_7or8bit)
        encryption_mime.set_charset('us-ascii')

        encrypted_mime = MIMEApplication(_data=encrypted_str,
                                            _subtype='octet-stream',
                                            _encoder=encode_7or8bit)
        encrypted_mime.set_charset('us-ascii')
        outer_msg.attach(encryption_mime)
        outer_msg.attach(encrypted_mime)

    else:
        outer_msg = unencrypted_msg

    headers = self.headers.copy()
    # add Message-ID
    if 'Message-ID' not in headers:
        headers['Message-ID'] = [email.Utils.make_msgid()]

    if 'User-Agent' in headers:
        uastring_format = headers['User-Agent'][0]
    else:
        uastring_format = settings.get('user_agent').strip()
    uastring = uastring_format.format(version=__version__)
    if uastring:
        headers['User-Agent'] = [uastring]

    # copy headers from envelope to mail
    for k, vlist in headers.items():
        for v in vlist:
            outer_msg[k] = encode_header(k, v)

    return outer_msg
