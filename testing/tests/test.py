
import pytest
import gpgmime
import email
import logging
from os.path import join, dirname

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@pytest.fixture()
def msg():
    result = email.message_from_string('\r\n'.join([
        "To: Robert <bob@example.org>",
        "From: Alice <alice@example.com>",
        "Date: Sun, 30 Aug 2015 20:00:03 -0400",
        "Subject: hello",
        "",
        "This message is signed!",
        "",
        "Isn't that cool?",
        "",
        "-Alice",
        "",
    ]))
    logger.debug("Using message: %r", result.as_string())
    return result


@pytest.fixture()
def gpg():
    return gpgmime.GPG(gnupghome=join(dirname(__file__), '../gpghome'),
                       use_agent=False)


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
