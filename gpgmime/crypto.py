# Copyright (C) 2011-2012  Patrick Totzke <patricktotzke@gmail.com>
# Copyright (C) 2015       Ian Denhardt <ian@zenhack.net>
# This file is released under the GNU GPL, version 3 or a later revision.
# For further details see the COPYING file
from .errors import GPGProblem, GPGCode


def RFC3156_micalg_from_algo(hash_algo):
    """
    Converts a GPGME hash algorithm name to one conforming to RFC3156.

    GPGME returns hash algorithm names such as "SHA256", but RFC3156 says that
    programs need to use names such as "pgp-sha256" instead.

    :param hash_algo: GPGME hash_algo
    :rtype: str
    """
    mapping = {
        '1':   'pgp-md5',
        '2':   'pgp-sha1',
        '3':   'pgp-ripemd160',
        '5':   'pgp-md2',
        '6':   'pgp-tiger192',
        '7':   'pgp-haval',
        '8':   'pgp-sha256',
        '9':   'pgp-sha384',
        '10':  'pgp-sha512',
        '301': 'pgp-md4',
        '302': 'pgp-crc32',
        '303': 'pgp-crc32rfc1510',
        '304': 'pgp-crc24rfc2440',
    }
    if hash_algo in mapping:
        return mapping[hash_algo]
    else:
        raise GPGProblem(("Invalid hash_algo passed to hash_algo_name."
                          " Please report this as a bug in alot."),
                         code=GPGCode.INVALID_HASH)
