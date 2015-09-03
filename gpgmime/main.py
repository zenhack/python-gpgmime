
import logging
import gnupg
from . import helper
from .errors import GPGCode, GPGProblem

import email.charset as charset
charset.add_charset('utf-8', charset.QP, charset.QP, 'utf-8')
from email.encoders import encode_7or8bit
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.message import Message


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


def _infer_recipients(msg):
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


class GPG(gnupg.GPG):

    def sign_email(self, msg, keyid=None, passphrase=None):
        """MIME-sign a message.

        keyid and passphrase are the same as the parameters for the
        superclass's sign method.
        """
        payload = self._sign_payload(msg.get_payload(),
                                     keyid=keyid,
                                     passphrase=passphrase)
        _copy_headers(msg, payload)
        return payload

    def encrypt_email(self, msg, recipients=None):
        """MIME-encrypt a message.

        :param msg: The message to encrypt (an instance of
            :class:`email.message.Message`).
        :param recipients: A list of recipients to encrypt to. If None or
            unspecified, infered from the To, Cc, and Bcc headers.
        """
        if 'MIME-Version' in msg:
            body = Message()
            body.set_payload(msg.get_payload())
            body['MIME-Version'] = msg['MIME-Version']
            body['Content-Type'] = msg['Content-Type']
        else:
            body = msg.get_payload()
        if recipients is None:
            recipients = _infer_recipients(msg)
        payload = self._encrypt_payload(body, recipients=recipients)
        _copy_headers(msg, payload)
        return payload

    def sign_and_encrypt_email(self,
                               msg,
                               recipients=None,
                               keyid=None,
                               passphrase=None):
        """MIME-sign and encrypt the message.

        The parameters are the same as with encrypt_email and sign_email.
        """
        if recipients is None:
            recipients = _infer_recipients(msg)
        payload = self._sign_payload(msg.get_payload(),
                                     keyid=keyid,
                                     passphrase=passphrase)
        payload = self._encrypt_payload(payload,
                                        recipients=recipients)
        _copy_headers(msg, payload)
        return payload

    def decrypt_email(self, msg):
        """Decrypt the MIME-encrypted message.

        :param msg: The message (a :class:`email.message.Message`) to decrypt

        Returns a tuple, (mail, decrypted), where decrypted is a
        :class:`gnupg.Crypt` indicating the success or failure of the
        decryption, and (if succesful), mail is a
        :class:`email.message.Message`, which is the same as msg but
        with the body decrypted.
        """
        assert False, "Not yet implemented"

    def verify_email(self, msg):
        """Verify the MIME-signed message.

        :param msg: The message (a :class:`email.message.Message`) to verify

        Returns a :class:`gnupg.Verify` indicating the result of the
        verification
        """
        assert False, "Not yet implemented"

    def decrypt_and_verify_email(self, msg):
        """Decrypt and verify the mime encrypted/signed message.

        Note that this is not merely a shortcut for calling decrypt_email
        followed by verify_email; RFC3156 permits signing and encrypting via a
        single PGP packet (section 6.2).

        The return value will be a tuple (mail, decrypted, verified), where (if
        successful) mail is the decrypted mail, and decrypted and verified are
        the same as in the return values for decrypt_email and verify_email.
        """
        assert False, "Not yet implemented"

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

        micalg = helper.RFC3156_micalg_from_algo(signature.hash_algo)
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
