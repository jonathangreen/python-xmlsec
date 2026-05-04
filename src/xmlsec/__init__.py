"""Python bindings for the XML Security Library.

The C extension lives at ``xmlsec._impl``; this module re-exports its public
symbols so user code can keep importing from ``xmlsec`` directly.
"""

import sys as _sys

from xmlsec import _impl
from xmlsec._impl import (
    EncryptionContext,
    Error,
    InternalError,
    Key,
    KeysManager,
    SignatureContext,
    VerificationError,
    __version__,
    base64_default_line_size,
    cleanup_callbacks,
    constants,
    enable_debug_trace,
    get_libxml_compiled_version,
    get_libxml_version,
    get_libxmlsec_version,
    init,
    register_callbacks,
    register_default_callbacks,
    shutdown,
    template,
    tree,
)

# Expose the C-extension submodules under their public dotted names so that
# ``import xmlsec.constants`` (and likewise tree/template) resolves to the same
# module object as ``xmlsec._impl.constants``.
_sys.modules.setdefault('xmlsec.constants', constants)
_sys.modules.setdefault('xmlsec.tree', tree)
_sys.modules.setdefault('xmlsec.template', template)

__all__ = [
    'EncryptionContext',
    'Error',
    'InternalError',
    'Key',
    'KeysManager',
    'SignatureContext',
    'VerificationError',
    '__version__',
    'base64_default_line_size',
    'cleanup_callbacks',
    'constants',
    'enable_debug_trace',
    'get_libxml_compiled_version',
    'get_libxml_version',
    'get_libxmlsec_version',
    'init',
    'register_callbacks',
    'register_default_callbacks',
    'shutdown',
    'template',
    'tree',
]
