from gpgmime import helper
from testing.utils import msg


class Test_clone_message:

    def test_modify(self, msg):
        """Verify that modifying a copy doesn't change the original."""
        test_subject = 'Unit testing'
        test_payload = 'This is a test payload'

        copy = helper.clone_message(msg)
        copy.replace_header('Subject', test_subject)
        assert msg['Subject'] != test_subject
        copy.set_payload(test_payload)
        assert msg.get_payload() != test_payload
