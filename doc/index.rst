.. GPGMime documentation master file, created by
   sphinx-quickstart2 on Mon Aug 31 20:50:12 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

###############################################################
`python-gpgmime` - a library for manipulating PGP mime messages
###############################################################


:Release: |release|
:Date: September 4, 2015

.. moduleauthor:: Ian Denhardt <ian@zenhack.net>
.. sectionauthor:: Ian Denhardt <ian@zenhack.net>

.. toctree::
   :maxdepth: 2

The ``gpgmime`` module provides support for encrypting, decrypting, signing,
and verifying PGP mime email messages (RFC 3156). The interface is built on top
of ``python-gnupg``; It provides a subclass of that library's `GPG`, with some
additional mime-related methods.

This is in a very early stage of development; not everything works yet, and what
does may still be rough around the edges.

Module Reference
----------------

.. module:: gpgmime

.. autoclass:: GPG
   :members:

.. autofunction:: is_encrypted

.. autofunction:: is_signed

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

