Installation
============

``xmlsec`` is available on PyPI:

.. code-block:: bash

   pip install xmlsec

Depending on your OS, you may need to install the required native
libraries first:

Linux (Debian)
--------------

.. code-block:: bash

   apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl

.. note:: There is no required version of LibXML2 for Ubuntu Precise,
   so you need to download and install it manually:

   .. code-block:: bash

      wget http://xmlsoft.org/sources/libxml2-2.9.1.tar.gz
      tar -xvf libxml2-2.9.1.tar.gz
      cd libxml2-2.9.1
      ./configure && make && make install


Linux (CentOS)
--------------

.. code-block:: bash

   yum install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel


Linux (Fedora)
--------------

.. code-block:: bash

   dnf install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel


Mac
---

.. code-block:: bash

   xcode-select --install
   brew upgrade
   brew install libxml2 libxmlsec1 pkg-config


Alpine
------

.. code-block:: bash

   apk add build-base openssl libffi-dev openssl-dev libxslt-dev libxml2-dev xmlsec-dev xmlsec


Troubleshooting
***************

``lxml & xmlsec libxml2 library version mismatch`` (removed)
------------------------------------------------------------

Earlier versions of ``xmlsec`` passed ``lxml`` XML nodes directly to
the underlying ``xmlsec1`` library, which meant both libraries had to
load compatible ``libxml2`` versions at runtime. Mismatches surfaced
as a hard import-time error of the form
``xmlsec.InternalError: (-1, 'lxml & xmlsec libxml2 library version mismatch')``.

That dependency is gone. Starting with the release that resolved
`issue #356 <https://github.com/xmlsec/python-xmlsec/issues/356>`_,
the C extension no longer dereferences ``lxml``-owned ``libxml2``
nodes. XML is exchanged between ``lxml`` and ``xmlsec`` as serialized
bytes, so each library can use whichever ``libxml2`` it links against
without any cross-library ABI requirement. The runtime mismatch check
has been removed.

If you encounter the historical error on an older ``xmlsec`` release,
upgrade to a release that includes the issue #356 fix.


``libxml2 version mismatch: compiled against X.Y, loaded A.B``
--------------------------------------------------------------

This different (and rarer) error means the C extension was built
against one ``libxml2`` but a *different* ``libxml2`` was loaded into
the process at runtime. ``xmlsec1``'s public API is
``libxml2``-tree-shaped — every operation takes ``xmlNodePtr`` /
``xmlDocPtr`` — so the C extension *must* link against ``libxml2``,
and the ``libxml2`` it calls must match the one ``xmlsec1`` itself
was built against. When the two diverge, ``xmlAddID`` / ``xmlGetID``
and similar calls write and read incompatible struct layouts.

Common causes:

* macOS dev with mixed prefixes: Homebrew has both ``libxml2`` and
  ``libxmlsec1``, but the system ``libxml2`` (or a stale one in
  ``/usr/local``) gets resolved first. Make sure
  ``pkg-config xmlsec1 --libs`` and ``pkg-config libxml-2.0 --libs``
  point at the same prefix.
* Linux with ``libxmlsec1-dev`` from one distro and ``libxml2-dev``
  from another channel (system + a third-party APT, conda, etc.).
* Cross-built wheel picking up a different system ``libxml2`` than
  the one bundled at build time.

The cleanest fix for local development is to bundle a matched pair
via the static-deps build, which compiles ``libxml2`` and ``xmlsec1``
together from source so they cannot drift:

.. code-block:: bash

   PYXMLSEC_STATIC_DEPS=true pip install -e .

For deployments, install ``xmlsec`` from the prebuilt wheel (which
already bundles a matched pair) or rebuild against your current
system ``libxml2``.


Mac
---

If you get any fatal errors about missing ``.h`` files, update your
``C_INCLUDE_PATH`` environment variable to include the appropriate
files from the ``libxml2`` and ``libxmlsec1`` libraries.


Windows
-------

Starting with 1.3.7, prebuilt wheels are available for Windows,
so running ``pip install xmlsec`` should suffice. If you want
to build from source:

#. Configure build environment, see `wiki.python.org <https://wiki.python.org/moin/WindowsCompilers>`_ for more details.

#. Install from source dist:

   .. code-block:: bash

      pip install xmlsec --no-binary=xmlsec
