# -*- coding: utf-8 -*-

import olefile
import zlib
import struct
import sys
from io import BytesIO

def u32(x):
    return struct.unpack("<L", x)[0]

def u64(x):
    return struct.unpack("<Q", x)[0]

class hwp_parser():
    def __init__(self, filename):
        self.filename = filename
        self.ole = olefile.OleFileIO(filename)
        self.ole_dir = ["/".join(i) for i in self.ole.listdir()]
        # print("[*] ole dir : {}\n".format(self.ole_dir))
        ## https://github.com/mete0r/pyhwp/blob/82aa03eb3afe450eeb73714f2222765753ceaa6c/pyhwp/hwp5/msoleprops.py#L151
        self.SUMMARY_INFORMATION_PROPERTIES = [
            dict(id=0x02, name='PIDSI_TITLE', title='Title'),
            dict(id=0x03, name='PIDSI_SUBJECT', title='Subject'),
            dict(id=0x04, name='PIDSI_AUTHOR', title='Author'),
            dict(id=0x05, name='PIDSI_KEYWORDS', title='Keywords'),
            dict(id=0x06, name='PIDSI_COMMENTS', title='Comments'),
            dict(id=0x07, name='PIDSI_TEMPLATE', title='Templates'),
            dict(id=0x08, name='PIDSI_LASTAUTHOR', title='Last Saved By'),
            dict(id=0x09, name='PIDSI_REVNUMBER', title='Revision Number'),
            dict(id=0x0a, name='PIDSI_EDITTIME', title='Total Editing Time'),
            dict(id=0x0b, name='PIDSI_LASTPRINTED', title='Last Printed'),
            dict(id=0x0c, name='PIDSI_CREATE_DTM', title='Create Time/Data'),
            dict(id=0x0d, name='PIDSI_LASTSAVE_DTM', title='Last saved Time/Data'),
            dict(id=0x0e, name='PIDSI_PAGECOUNT', title='Number of Pages'),
            dict(id=0x0f, name='PIDSI_WORDCOUNT', title='Number of Words'),
            dict(id=0x10, name='PIDSI_CHARCOUNT', title='Number of Characters'),
            dict(id=0x11, name='PIDSI_THUMBNAIL', title='Thumbnail'),
            dict(id=0x12, name='PIDSI_APPNAME', title='Name of Creating Application'),
            dict(id=0x13, name='PIDSI_SECURITY', title='Security'),
        ]

    def HwpSummaryInfo_parse(self, data):
        info_data = []
        property_data = []
        return_data = []

        start_offset = 0x2c
        data_size_offset = u32(data[start_offset:start_offset+4])
        data_size = u32(data[data_size_offset:data_size_offset+4])
        property_count = u32(data[data_size_offset+4:data_size_offset+8])

        start_offset = data_size_offset + 8
        
        for i in range(property_count):
            property_ID = u32(data[start_offset:start_offset+4])
            unknown_data = u32(data[start_offset+4:start_offset+8])
            property_data.append({"property_ID":property_ID, "unknown_data":unknown_data})
            start_offset = start_offset + 8

        data = data[start_offset:]
        
        start_offset = 0x0
        for i in range(property_count):
            if data[start_offset:start_offset+4] == b"\x1f\x00\x00\x00":
                size = u32(data[start_offset+4:start_offset+8]) * 2
                result = data[start_offset+8:start_offset+8+size]
                info_data.append(result.decode("utf-16-le"))

                start_offset = start_offset + 8 + size
                if data[start_offset:start_offset+2] == b"\x00\x00":
                    start_offset += 2

            elif data[start_offset:start_offset+4] == b"\x40\x00\x00\x00":
                date = u64(data[start_offset+4:start_offset+12])
                start_offset = start_offset + 12
                info_data.append(str(date))

        for i in range(len(info_data)):
            for information in self.SUMMARY_INFORMATION_PROPERTIES:
                if information['id'] == property_data[i]['property_ID']:
                    return_data.append({"property_ID":property_data[i]['property_ID'], 
                                        "title":information['title'], 
                                        "name":information['name'], 
                                        "data":info_data[i],
                                        "unknown_data":property_data[i]['unknown_data']})
                    continue

        return return_data

    def FileHeader_parse(self, data):
        ## https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/010-hwp-parser/HWPFileHeader.bt 참고
        signature = data[:32]
        version = u32(data[32:36])
        flags = u32(data[36:40])
        return {"signature":signature, "version":version, "flags":flags}
    
    def extract_data(self, name):
        stream = self.ole.openstream(name)
        data = stream.read()
        if any(i in name for i in ("BinData", "BodyText", "Scripts", "DocInfo")):
            return zlib.decompress(data,-15)
        else:
            return data

    def extract_HwpSummaryInfo(self):
        for name in self.ole_dir:
            if "hwpsummaryinformation" in name.lower():
                data = self.extract_data(name)
                HwpSummaryInfo = self.HwpSummaryInfo_parse(data)
                return HwpSummaryInfo
        return None ## check AttributionError, TypeError

    def extract_FileHeader(self):
        for name in self.ole_dir:
            if "fileheader" in name.lower():
                data = self.extract_data(name)
                fileheader = self.FileHeader_parse(data)
                return fileheader
        return None

    def extract_eps(self):
        data = []
        for name in self.ole_dir:
            if ".ps" in name.lower() or ".eps" in name.lower():
                #print("[*] Extract eps file : {}".format(name.replace("/","_")))
                data.append([name.replace("/","_"), self.extract_data(name)])
        return data