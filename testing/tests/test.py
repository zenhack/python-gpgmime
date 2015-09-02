
import pytest
import gpgmime
import email
from os.path import join, dirname


@pytest.fixture()
def msg():
    return email.message_from_string('\r\n'.join([
        "To: Robert <bob@example.org>",
        "From: Alice <alice@example.com>",
        "Date: Sun, 30 Aug 2015 20:00:03 -0400",
        "Subject: hello",
        "",
        "This message is signed!",
        "",
        "Isn't that cool?",
        "",
        "-Bob",
        "",
    ]))


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


@pytest.mark.xfail()
def test_sign_then_encrypt(gpg, msg):
    msg = gpg.encrypt_email(gpg.sign_email(msg,
                                           keyid='alice@example.com',
                                           passphrase='secret'),
                            recipients='bob@example.org')
