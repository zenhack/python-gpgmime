`python-gpgmime` is a library for manipulating PGP mime messages.

It provides support for encrypting, decrypting, signing, and verifying
PGP mime email messages (RFC 3156). It's based partly on the
corresponding functionality in [alot][1], but the interface is built on
top of [python-gnupg][2]; It provides a subclass of that library's
`GPG`, with some additional mime-related methods.

This is in a very early stage of development; not everything works yet,
and what does may still be rough around the edges.

# LICENSE

GPL, version 3 or later.

# HACKING

Get set up:

    virtualenv .venv
    source .venv/bin/activate
    python setup.py develop
    pip install -r test-requirements.txt

Running the test suite:

    py.test

Notes on tests:

* The folder `testing/gpghome` contains a keyring used by the test
  suite, and there's a fixture defined in `testing/utils.py` that
  sets up the library to use this keyring. Obviously, don't rely on
  these keys for security; the private keys are published in a public
  git repository! The passphrases for the secret keys are as follows:
    * Alice: `secret`
    * Bob has no passphrase on his key (tsk tsk).
    * Mallory: `god`
* Tests themselves go in `testing/tests`. Support code for tests goes
  in other modules under `testing/`.

[1]: https://github.com/pazz/alot
[2]: https://pythonhosted.org/python-gnupg/
