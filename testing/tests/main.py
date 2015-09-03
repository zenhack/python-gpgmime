
import pytest
import logging

# These are pytest fixtures; while we don't use them explicitly in the module
# below, they're used implicitly due to the parameter names of the tests. This
# may throw off some static analysis tools (e.g. python-mode throws an error
# about an unused import).
from testing.utils import msg, gpg

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# So far, the two tests below just verify that things don't throw exceptions.
# We should add more extensive tests in the future.

def test_sign_encrypt_onestep(gpg, msg):
    msg = gpg.sign_and_encrypt_email(msg,
                                     keyid='alice@example.com',
                                     passphrase='secret',
                                     recipients='bob@example.org')
    logger.debug("one-step output: %r", msg.as_string())


def test_sign_then_encrypt(gpg, msg):
    msg = gpg.encrypt_email(gpg.sign_email(msg,
                                           keyid='alice@example.com',
                                           passphrase='secret'),
                            recipients='bob@example.org')
    logger.debug("two-step output: %r", msg.as_string())


@pytest.mark.xfail()
def test_encrypt_decrypt(gpg, msg):
    msg = gpg.encrypt_email(msg, recipients='bob@example.org')
    msg, decrypted = gpg.decrypt_email(msg)
    assert decrypted


@pytest.mark.xfail()
def test_sign_verify(gpg, msg):
    msg = gpg.sign_email(msg, keyid='alice@example.com', passphrase='secret')
    msg, verified = gpg.verify_email(msg)
    assert verified
