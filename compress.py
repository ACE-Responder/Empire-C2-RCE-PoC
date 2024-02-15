import zlib
import struct

class compress(object):
    """
    Base clase for init of the package. This will handle
    the initial object creation for conducting basic functions.
    """

    CRC_HSIZE = 4
    COMP_RATIO = 9

    def __init__(self, verbose=False):
        """
        Populates init.
        """
        pass

    def comp_data(self, data, cvalue=COMP_RATIO):
        """
        Takes in a string and computes
        the comp obj.
        data = string wanting compression
        cvalue = 0-9 comp value (default 6)
        """
        cdata = zlib.compress(data, cvalue)
        return cdata

    def crc32_data(self, data):
        """
        Takes in a string and computes crc32 value.
        data = string before compression
        returns:
        HEX bytes of data
        """
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return crc

    def build_header(self, data, crc):
        """
        Takes comp data, org crc32 value,
        and adds self header.
        data =  comp data
        crc = crc32 value
        """
        header = struct.pack("!I", crc)
        built_data = header + data
        return built_data