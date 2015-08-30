# Copyright (C) 2011-2012  Patrick Totzke <patricktotzke@gmail.com>
# Copyright (C) 2015       Ian Denhardt <ian@zenhack.net>
# This file is released under the GNU GPL, version 3 or a later revision.
# For further details see the COPYING file
import os
import email.charset as charset
charset.add_charset('utf-8', charset.QP, charset.QP, 'utf-8')
from email.encoders import encode_7or8bit
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

import logging
from . import helper
import alot.crypto as crypto
import gpgme
from .errors import GPGProblem, GPGCode


def sign_payload(payload, key=None):
    payload = helper.normalize_payload(payload)
    plaintext = helper.email_as_string(payload)
    logging.debug('signing plaintext: ' + plaintext)

    try:
        signatures, signature_str = crypto.detached_signature_for(
            plaintext, key)
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
    unencrypted_msg = MIMEMultipart(
        'signed',
        micalg=micalg,
        protocol='application/pgp-signature'
    )

    # wrap signature in MIMEcontainter
    stype = 'pgp-signature; name="signature.asc"'
    signature_mime = MIMEApplication(_data=signature_str,
                                     _subtype=stype,
                                     _encoder=encode_7or8bit)
    signature_mime['Content-Description'] = 'signature'
    signature_mime.set_charset('us-ascii')

    # add signed message and signature to outer message
    unencrypted_msg.attach(payload)
    unencrypted_msg.attach(signature_mime)
    unencrypted_msg['Content-Disposition'] = 'inline'

    return unencrypted_msg


def encrypt_payload(unencrypted_msg, keys):

    plaintext = helper.email_as_string(unencrypted_msg)
    logging.debug('encrypting plaintext: ' + plaintext)

    try:
        encrypted_str = crypto.encrypt(plaintext,
                                       keys.values())
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

    return outer_msg
