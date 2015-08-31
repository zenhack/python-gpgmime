
import logging
import gnupg
from pgpmime import helper, crypto
from pgpmime.errors import GPGCode, GPGProblem

import email.charset as charset
charset.add_charset('utf-8', charset.QP, charset.QP, 'utf-8')
from email.encoders import encode_7or8bit
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication


class GPG(gnupg.GPG):

    def sign_email(self, msg, keyid=None, passphrase=None):
        payload = self._sign_payload(msg.get_payload(),
                                     keyid=keyid,
                                     passphrase=passphrase)
        for key in msg.keys():
            if key not in payload:
                payload[key] = msg[key]
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
            raise GPGProblem("Could not sign message (GnuPG "
                             "did not return a signature)",
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
