
import pytest
import logging
import gpgmime

# These are pytest fixtures; while we don't use them explicitly in the module
# below, they're used implicitly due to the parameter names of the tests. This
# may throw off some static analysis tools (e.g. python-mode throws an error
# about an unused import).
from testing.utils import msg, gpg

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestSignAndEncrypt:
    """Each of these tests verifies a few things:

    1. The operation in question doesn't blow up.
    2. The operation doesn't modify the original message.
    3. The result is consistent with is_signed and is_encrypted.
    """

    def test_sign_encrypt_onestep(self, gpg, msg):
        msg_text = msg.as_string()
        ret = gpg.sign_and_encrypt_email(msg,
                                         keyid='alice@example.com',
                                         passphrase='secret',
                                         recipients='bob@example.org')

        assert gpgmime.is_encrypted(ret)
        assert not gpgmime.is_signed(ret)  # Per is_signed's docstring, there
                                           # is no way to tell if the message
                                           # is also encrypted.
        assert msg.as_string() == msg_text
        logger.debug("one-step output: %r", ret.as_string())

    def test_sign_then_encrypt(self, gpg, msg):
        msg_text = msg.as_string()

        signed = gpg.sign_email(msg,
                                keyid='alice@example.com',
                                passphrase='secret')
        assert gpgmime.is_signed(signed)

        assert msg.as_string() == msg_text
        signed_text = signed.as_string()

        encrypted = gpg.encrypt_email(signed, recipients='bob@example.org')
        assert gpgmime.is_encrypted(encrypted)
        assert not gpgmime.is_signed(encrypted)

        assert signed.as_string() == signed_text

        logger.debug("two-step output: %r", encrypted.as_string())


@pytest.mark.xfail()
def test_encrypt_decrypt(gpg, msg):
    orig_text = msg.as_string()

    msg = gpg.encrypt_email(msg, recipients='bob@example.org')
    msg, decrypted = gpg.decrypt_email(msg)
    assert decrypted

    assert msg.as_string() == orig_text


@pytest.mark.xfail()
def test_sign_verify(gpg, msg):
    orig_text = msg.as_string()

    ret = gpg.sign_email(msg, keyid='alice@example.com', passphrase='secret')
    ret, verified = gpg.verify_email(msg)
    assert verified

    assert msg.as_string() == orig_text
