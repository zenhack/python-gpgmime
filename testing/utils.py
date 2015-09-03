
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
    return gpgmime.GPG(gnupghome=join(dirname(__file__), 'gpghome'),
                       use_agent=False)
