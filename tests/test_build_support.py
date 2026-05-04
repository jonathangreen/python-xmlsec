import unittest
from types import SimpleNamespace

from build_support.static_build import StaticBuildHelper


class TestStaticBuildHelper(unittest.TestCase):
    def test_uses_renamed_impl_extension(self):
        ext = object()
        builder = SimpleNamespace(ext_map={'xmlsec._impl': ext}, info=lambda _message: None)

        helper = StaticBuildHelper(builder)

        self.assertIs(ext, helper.ext)
