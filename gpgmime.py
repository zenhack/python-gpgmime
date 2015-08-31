
import logging
import gnupg
from pgpmime import helper, crypto
from pgpmime.errors import GPGCode, GPGProblem

import email.charset as charset
charset.add_charset('utf-8', charset.QP, charset.QP, 'utf-8')
from email.encoders import encode_7or8bit
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication


def _(s):
    """Placeholder for gettext; we may internationalize this library later."""
    return s


def _copy_headers(src, dest):
        """Add all headers from src to dest, except those already present.

        Both src and dest should be instances of class:`email.message.Message`.
        dest will be modified in place, adding all of the headers in src which
        are not already present.
        """
        for key in src.keys():
            if key not in dest:
                dest[key] = src[key]


class GPG(gnupg.GPG):

    def sign_email(self, msg, keyid=None, passphrase=None):
        payload = self._sign_payload(msg.get_payload(),
                                     keyid=keyid,
                                     passphrase=passphrase)
        _copy_headers(msg, payload)
        return payload

    def encrypt_email(self, msg, recipients):
        payload = self._encrypt_payload(msg.get_payload(),
                                        recipients=recipients)
        _copy_headers(msg, payload)
        return payload

    def sign_and_encrypt_email(self,
                               msg,
                               recipients,
                               keyid=None,
                               passphrase=None):
        payload = self._sign_payload(msg.get_payload(),
                                     keyid=keyid,
                                     passphrase=passphrase)
        payload = self._encrypt_payload(payload,
                                        recipients=recipients)
        _copy_headers(msg, payload)
        return payload

    def _sign_payload(self, payload, keyid=None, passphrase=None):
        payload = helper.normalize_payload(payload)
        plaintext = helper.email_as_string(payload)
        logging.debug('signing plaintext: ' + plaintext)

        signature = self.sign(plaintext,
                              detach=True,
                              keyid=keyid,
                              passphrase=passphrase)
        if not signature:
            raise GPGProblem(_("Could not sign message (GnuPG "
                               "did not return a signature)"),
                             code=GPGCode.KEY_CANNOT_SIGN)

        micalg = crypto.RFC3156_micalg_from_algo(signature.hash_algo)
        unencrypted_msg = MIMEMultipart(
            'signed',
            micalg=micalg,
            protocol='application/pgp-signature'
        )

        # wrap signature in MIMEcontainter
        stype = 'pgp-signature; name="signature.asc"'
        signature_mime = MIMEApplication(_data=str(signature),
                                         _subtype=stype,
                                         _encoder=encode_7or8bit)
        signature_mime['Content-Description'] = 'signature'
        signature_mime.set_charset('us-ascii')

        # add signed message and signature to outer message
        unencrypted_msg.attach(payload)
        unencrypted_msg.attach(signature_mime)
        unencrypted_msg['Content-Disposition'] = 'inline'

        return unencrypted_msg

    def _encrypt_payload(self, unencrypted_msg, recipients):

        plaintext = helper.email_as_string(unencrypted_msg)
        logging.debug('encrypting plaintext: ' + plaintext)

        ciphertext = self.encrypt(plaintext, recipients)
        if not ciphertext:
            raise GPGProblem(ciphertext.stderr,
                             code=GPGCode.KEY_CANNOT_ENCRYPT)

        outer_msg = MIMEMultipart('encrypted',
                                  protocol='application/pgp-encrypted')

        version_str = 'Version: 1'
        encryption_mime = MIMEApplication(_data=version_str,
                                          _subtype='pgp-encrypted',
                                          _encoder=encode_7or8bit)
        encryption_mime.set_charset('us-ascii')

        encrypted_mime = MIMEApplication(_data=str(ciphertext),
                                         _subtype='octet-stream',
                                         _encoder=encode_7or8bit)
        encrypted_mime.set_charset('us-ascii')
        outer_msg.attach(encryption_mime)
        outer_msg.attach(encrypted_mime)

        return outer_msg
