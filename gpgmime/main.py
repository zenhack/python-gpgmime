
import logging
import os
import tempfile
import gnupg
from . import helper
from .errors import GPGCode, GPGProblem

import email.charset as charset
charset.add_charset('utf-8', charset.QP, charset.QP, 'utf-8')
import email
from email.encoders import encode_7or8bit
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.message import Message

app_pgp_sig = 'application/pgp-signature'
app_pgp_enc = 'application/pgp-encrypted'


def _(s):
    """Placeholder for gettext; we may internationalize this library later."""
    return s


def is_encrypted(msg):
    """Return whether the message is encrypted."""
    p = helper.get_params(msg)
    return (msg.is_multipart() and
            msg.get_content_subtype() == 'encrypted' and
            p.get('protocol', None) == app_pgp_enc and
            'Version: 1' in msg.get_payload(0).get_payload())


def is_signed(msg):
    """Return whether the message is signed.

    NOTE WELL: if the message is encrypted, there is no way to determine
    whether the message is signed without decrypting it. As such,
    this functionwill always return False if msg is encrypted.
    """
    p = helper.get_params(msg)
    return (msg.is_multipart() and
            msg.get_content_subtype() == 'signed' and
            p.get('protocol', None) == app_pgp_sig)


class GPG(gnupg.GPG):
    """An extended :class:`gnupg.GPG` with support for PGP MIME.

    None of the methods exposed by this class modify their arguments;
    results are always modified *copies* of the original.
    """

    def sign_email(self, msg, keyid=None, passphrase=None):
        """MIME-sign a message.

        keyid and passphrase are the same as the parameters for the
        superclass's sign method.

        Return a signed copy of the message object.
        """
        payload = self._sign_payload(msg.get_payload(),
                                     keyid=keyid,
                                     passphrase=passphrase)
        helper.copy_headers(msg, payload)
        return payload

    def encrypt_email(self, msg, recipients=None):
        """MIME-encrypt a message.

        :param msg: The message to encrypt (an instance of
            :class:`email.message.Message`).
        :param recipients: A list of recipients to encrypt to. If ``None`` or
            unspecified, this will be infered from the To, Cc, and Bcc headers.

        Return an encrypted copy of the message object.
        """
        if 'MIME-Version' in msg:
            body = Message()
            body.set_payload(msg.get_payload())
            body['MIME-Version'] = msg['MIME-Version']
            body['Content-Type'] = msg['Content-Type']
        else:
            body = MIMEText(msg.get_payload())
        if recipients is None:
            recipients = helper.infer_recipients(msg)
        payload = self._encrypt_payload(body, recipients=recipients)
        helper.copy_headers(msg, payload)
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
            recipients = helper.infer_recipients(msg)
        payload = self._sign_payload(msg.get_payload(),
                                     keyid=keyid,
                                     passphrase=passphrase)
        payload = self._encrypt_payload(payload,
                                        recipients=recipients)
        helper.copy_headers(msg, payload)
        return payload

    def decrypt_email(self, msg, passphrase=None):
        """Decrypt the MIME-encrypted message.

        :param msg: The message (an :class:`email.message.Message`) to decrypt.
            ``msg`` MUST be a mime encrypted email.
        :param passphrase: The passphrase for the secret key with which to
            decrypt the message.

        Returns a tuple, (mail, decrypted), where decrypted is a
        :class:`gnupg.Crypt` indicating the success or failure of the
        decryption, and (if succesful), mail is a
        :class:`email.message.Message`, which is the same as msg but
        with the body decrypted.
        """
        if not is_encrypted(msg):
            raise TypeError(_('%r is not a mime-encrypted email.') % msg)

        # Second mime part is the ciphertext:
        ciphertext = msg.get_payload(1).get_payload()
        plaintext = self.decrypt(ciphertext)
        if plaintext:
            payload = email.message_from_string(str(plaintext))
            ret = helper.clone_message(msg)

            # Copy the headers/body from decrypted payload to the main message:
            for k in payload.keys():
                if k in ret:
                    ret.replace_header(k, payload[k])
                else:
                    ret[k] = payload[k]
                ret.set_payload(payload.get_payload())

            return ret, plaintext
        else:
            return None, plaintext

    def verify_email(self, msg):
        """Verify the MIME-signed message.

        :param msg: The message (a :class:`email.message.Message`) to verify

        Returns a :class:`gnupg.Verify` indicating the result of the
        verification
        """
        if not is_signed(msg):
            raise TypeError(_('%r is not a mime-signed email.') % msg)

        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(msg.get_payload(1).get_payload())
        filename = tmp.name
        tmp.close()
        verified = self.verify_data(filename, msg.get_payload(0).get_payload())
        os.remove(filename)
        return verified

##   The below hasn't actually been implemented yet, so we're leaving it out
##   of the releases for the time being. The docstring is complete enough to
##   leave it here in the source:
#
#    def decrypt_and_verify_email(self, msg, passphrase=None):
#        """Decrypt and verify the mime encrypted/signed message.
#
#        :param msg: The message (a :class:`email.message.Message`) to decrypt.
#            msg MUST be a mime encrypted email.
#        :param passphrase: The passphrase for the secret key with which to
#            decrypt the message.
#
#        Note that this is not merely a shortcut for calling decrypt_email
#        followed by verify_email; RFC3156 permits signing and encrypting via a
#        single PGP packet (section 6.2).
#
#        The return value will be a tuple (mail, decrypted, verified), where (if
#        successful) mail is the decrypted mail, and decrypted and verified are
#        the same as in the return values for decrypt_email and verify_email.
#        """
#        assert False, "Not yet implemented"

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
        logging.debug(_('encrypting plaintext %r') % plaintext)

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
