
import pytest
import gpgmime
import email
import logging
from os.path import join, dirname

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

_msg = '\r\n'.join([
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
    ])


@pytest.fixture()
def msg():
    """Pytest fixture which returns a sample message.

    Tests *are* allowed to rely on the specific message returned;
    it is not considered an implementation detail.
    """
    # TODO: find a way to stick the message in the docstring; pydoc doesn't
    # seem to pick it up if we try to make the docstring a non-literal
    # expression.
    result = email.message_from_string(_msg)
    logger.debug("Using message: %r", result.as_string())
    return result


@pytest.fixture()
def gpg():
    return gpgmime.GPG(gnupghome=join(dirname(__file__), 'gpghome'),
                       use_agent=False)
