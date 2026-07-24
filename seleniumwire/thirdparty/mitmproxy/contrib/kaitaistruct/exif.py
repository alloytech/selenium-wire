# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import array
import struct
import zlib
from enum import Enum

from kaitaistruct import BytesIO, KaitaiStream, KaitaiStruct

from .exif_be import ExifBe
from .exif_le import ExifLe

# The generated kaitaistruct version check needed pkg_resources.parse_version,
# removed in setuptools 82. install_requires enforces kaitaistruct>=0.7 instead.


class Exif(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.endianness = self._io.read_u2le()
        _on = self.endianness
        if _on == 18761:
            self.body = ExifLe(self._io)
        elif _on == 19789:
            self.body = ExifBe(self._io)
