#! /usr/bin/python3

import os as _os
import gzip as _gzip
import functools as _functools
import collections as _collections

from numbers import Number as _Number
from string import whitespace as _whitespaces
from bisect import bisect_left as _bisect_left
from itertools import chain as _itertools_chain
from binascii import unhexlify as _unhexlify


try:
    import cPickle as _pickle
except ImportError:
    import pickle as _pickle


_whitespaces = _whitespaces.encode("utf8")


SegmentTuple = _collections.namedtuple('SegmentTuple', ('name', 'perm', 'startEA', 'endEA', 'offset'))
FunctionTuple = _collections.namedtuple('FunctionTuple', ('startEA', 'endEA', 'FAKE_FIELD_chunks', 'FAKE_FIELD_blocks'))
ReferenceTuple = _collections.namedtuple('ReferenceTuple', ('to', 'frm'))  # TODO: Should i save more xref info?
BasicBlockTuple = _collections.namedtuple('BasicBlockTuple', ('startEA', 'endEA', 'FAKE_FIELD_preds', 'FAKE_FIELD_succs'))


######################################################################
######################################################################
# Code for IDA
######################################################################
######################################################################
def ida_imports(func):
    @_functools.wraps(func)
    def wrapper(*args, **kwargs):
        import idc
        import idaapi
        import idautils
        import ida_loader
        return func(*args, **kwargs)
    return wrapper

@ida_imports
def ida_iter_heads():
    addr = idc.MinEA()
    while addr != idc.BADADDR:
        yield addr
        addr = idc.NextHead(addr)

@ida_imports
def ida_iter_names():
    return idautils.Names()

@ida_imports
def ida_iter_functions():
    for addr in idautils.Functions():
        func = idaapi.get_func(addr)

        blocks = []
        for block in idaapi.FlowChart(func):
            blocks.append(BasicBlockTuple(startEA=block.startEA,
                                          endEA=block.endEA,
                                          FAKE_FIELD_preds=[b.startEA for b in block.preds()],
                                          FAKE_FIELD_succs=[b.startEA for b in block.succs()]))

        yield FunctionTuple(startEA=func.startEA,
                            endEA=func.endEA,
                            FAKE_FIELD_chunks=list(idautils.Chunks(addr)),
                            FAKE_FIELD_blocks=blocks)

@ida_imports
def ida_iter_segments():
    seg = idaapi.get_first_seg()
    while seg:

        # TODO: CRITICAL!! Figure out how to calculate segment file size
        yield SegmentTuple(name=idaapi.get_segm_name(seg),
                           perm=seg.perm,
                           startEA=seg.startEA,
                           endEA=seg.endEA,
                           offset=ida_loader.get_fileregion_offset(seg.startEA))

        seg = idaapi.get_next_seg(seg.startEA)

@ida_imports
def ida_generate_db(db_path=None):
    import time

    if db_path is None:
        db_path = idaapi.ask_file(1, "*.geckoidb", "Enter the DB's path")

    if not db_path:
        raise Exception("Invalid DB path")

    output = {
        'segments': [],
        'functions': [],

        'labels': {},

        'heads': [],
        'code_references': [],
        'data_references': [],
    }

    start_time = time.time()

    print('Exporting segments')
    output['segments'].extend(ida_iter_segments())

    print('Exporting functions')
    output['functions'].extend(ida_iter_functions())

    print('Exporting labels')
    for ea, name in ida_iter_names():
        # TODO: assert name not in output['labels']
        output['labels'][name] = ea

    print('Exporting heads + xrefs')
    for head in ida_iter_heads():
        output['heads'].append(head)

        # TODO: Should i also do XrefsFrom?
        for ref in idautils.CodeRefsFrom(head, 1):
            output['code_references'].append(ReferenceTuple(frm=head, to=ref))

        # TODO: Should i also do DataRefsFrom?
        for ref in idautils.DataRefsFrom(head):
            output['data_references'].append(ReferenceTuple(frm=head, to=ref))

    print('Finished processing in ', int(time.time() - start_time), 'seconds')

    start_time = time.time()

    print('Storing to DB')
    with _gzip.open(db_path, 'wb') as f:
        _pickle.dump(output, f, protocol=1)

    print('Finished storing DB in ', int(time.time() - start_time), 'seconds')


if __name__ == '__main__':
    try:
        import idc
        import idaapi
        import idautils
        import ida_loader
    except:
        pass
    else:
        ida_generate_db()
        raise Exception("Done")  # TODO: improve
######################################################################
######################################################################


import gecko as _gecko


######################################################################
# Classes to emulate IDA classes
######################################################################
class DefaultAliasedAddressMembers(_gecko.AliasedObject):
    __aliases__ = {
        'start_ea': 'startEA',
        'end_ea': 'endEA',
    }

    def __contains__(self, thing):
        # TODO: Type checking?
        return self.startEA <= thing < self.endEA

    def contains(self, other):
        return other in self


class Segment(DefaultAliasedAddressMembers):
    def __init__(self, name, perm, startEA, endEA, offset):
        self.name = name
        self.perm = perm
        self.startEA = startEA
        self.endEA = endEA
        self._size = self.endEA - self.startEA
        self.offset = offset

    def size(self):
        return self._size

class BasicBlock(DefaultAliasedAddressMembers):
    def __init__(self, startEA, endEA):
        self.startEA = startEA
        self.endEA = endEA
        self._preds = []
        self._succs = []

    def preds(self):
        return self._preds

    def succs(self):
        return self._succs

class Function(DefaultAliasedAddressMembers):
    def __init__(self, startEA, endEA, chunks, blocks):
        self.startEA = startEA
        self.endEA = endEA
        self._chunks = sorted(chunks, key=lambda c: c[0])
        self._blocks = []

        # In order to connect all the basic blocks i go over them all twice,
        # once to build a quick lookup, then again to connect all the nodes.
        # (This assumes each startEA is unique.)
        blocks_by_addr = {}
        for b in blocks:
            block = BasicBlock(b.startEA, b.endEA)
            blocks_by_addr[b.startEA] = (block, b.FAKE_FIELD_succs, b.FAKE_FIELD_preds)

        for (block, succs, preds) in blocks_by_addr.values():
            for s in succs:
                block._succs.append(blocks_by_addr[s])
            for p in preds:
                block._preds.append(blocks_by_addr[p])

            self._blocks.append(block)

    def __contains__(self, thing):
        # TODO: Type checking

        if self.startEA <= thing < self.endEA:
            return True

        for startEA, endEA in self._chunks:
            if startEA <= thing < endEA:
                return True


######################################################################
# General stuffs
######################################################################
class VirtuallyMappedFile(object):
    ERR_UNMAPPED_RANGE = -1
    ERR_SEGMENT_NOT_FILE_BACKED = -2

    def __init__(self, bin_path, segments):
        """
        TODO: Document

        'segments' is a list of IdaAPI.Segment(s)
        """

        # TODO: Handle segments which have a bigger size in memory then on disk? (ex. read last segment without mapping)
        self._f = open(bin_path, 'rb')
        self._segments = sorted(segments, key=lambda s: s.startEA)
        self._charmap = [chr(i) for i in range(256)]

    def __del__(self):
        self._f.close()

    def _get_next_segment(self, address):
        found = False
        for seg in self._segments:
            if address >= seg.endEA:
                found = True
                continue

            if found:
                return seg

        # If it wasn't contained in any segment, must be before all the segments (or after)
        if not found and self._segments:
            if address < self._segments[0].startEA:
                return self._segments[0]

    def _get_segment(self, address):
        for seg in self._segments:
            if address in seg:
                return seg

    def _range_to_offset_list(self, address, size, error_on_miss=True):
        offsets = []
        seg = ''
        while seg is not None and size > 0:
            seg = self._get_segment(address)

            if seg is not None:

                # Segment not backed by file (ex. BSS)
                if seg.offset == -1:
                    curr_offset = self.ERR_SEGMENT_NOT_FILE_BACKED
                else:
                    curr_offset = (address - seg.startEA) + seg.offset

                curr_size = size
                if address + curr_size >= seg.endEA:
                    curr_size = seg.endEA - address

            else:
                seg = self._get_next_segment(address)

                # No next segment, rest is null padding
                if seg is None:
                    return offsets + [(self.ERR_UNMAPPED_RANGE, size)]

                # Null pad until the next segment
                else:
                    curr_offset = self.ERR_UNMAPPED_RANGE
                    curr_size = seg.startEA - address

            if not curr_size:
                break

            offsets.append((curr_offset, curr_size))

            size -= curr_size
            address += curr_size

        return offsets

    def read(self, address, size, padd_not_file_backed_segments='\x00', raise_error=True):
        data = b''
        for curr_offset, curr_size in self._range_to_offset_list(address, size):

            # TODO: Proper error handling
            if curr_offset < 0:
                if curr_offset == self.ERR_SEGMENT_NOT_FILE_BACKED and (padd_not_file_backed_segments in self._charmap):
                    data += padd_not_file_backed_segments * curr_size
                    continue

                if raise_error:
                    raise Exception("Can't read from address")
                else:
                    return data

            else:
                self._f.seek(curr_offset)
                data += self._f.read(curr_size)

        return data


######################################################################
# Implementation of IDA's api
######################################################################
class IDAApi(_gecko.AliasedObject):
    BADADDR = -1

    SEARCH_DOWN = _gecko.bit_field(0)
    SEARCH_UP = _gecko.bit_field(1)

    __aliases__ = {
        'FindBinary': 'find_binary',
        'GetManyBytes': 'get_bytes',
    }

    def __init__(self, db_path, bin_path):
        self._load_db(db_path=db_path, bin_path=bin_path)

    def _load_db(self, db_path=None, bin_path=None):
        self._db_path = db_path or self._db_path
        self._bin_path = bin_path or self._bin_path

        assert _os.path.exists(self._db_path) and _os.path.isfile(self._db_path), 'Error with db path'

        with _gzip.open(self._db_path, 'rb') as f:
            geckoidb = _pickle.load(f)

        self._labels = geckoidb['labels']
        self._heads = sorted(geckoidb['heads'])

        # TODO: Implement refs using dict? ({addr: [ref for ref in refs if ref.frm==addr or ref.to==addr]})
        self._code_references = geckoidb['code_references']
        self._data_references = geckoidb['data_references']

        self._segments = []
        for seg in sorted(geckoidb['segments'], key=lambda s: s.startEA):
            self._segments.append(Segment(seg.name, seg.perm, seg.startEA, seg.endEA, seg.offset))

        self._functions = []
        for func in sorted(geckoidb['functions'], key=lambda f: f.startEA):
            self._functions.append(Function(func.startEA, func.endEA,
                                            func.FAKE_FIELD_chunks, func.FAKE_FIELD_blocks))

        # TODO: IMPORTANT! Figure out get_segment_file_size in IDA and then use angr's address space?
        self._address_space = VirtuallyMappedFile(self._bin_path, self._segments)

    # TODO: Implement
    def MinEA(self):
        return 0

    def MaxEA(self):
        return 0xFFFFFFFFFFFFFFFF

    def _Heads(self, start=None, end=None, reverse=False):
        if start is None:
            start = self.MinEA()
        if end is None:
            end = self.MaxEA()

        if reverse:
            inc = -1
            i = _bisect_left(self._heads, end)
        else:
            inc = 1
            i = _bisect_left(self._heads, start)

        # TODO: Make global num_heads?
        num_heads = len(self._heads)
        while (0 <= i < num_heads):
            ea = self._heads[i]

            if start <= ea <= end:
                yield ea

            i += inc

    def Heads(self, start=None, end=None):  # I don't want the optional 'reverse' arg like in _Heads
        return self._Heads(start=start, end=end)

    def NextHead(self, ea):
        # TODO: ea+1 is hacky
        for h in self._Heads(start=ea + 1):
            return h

    def PrevHead(self, ea):
        # TODO: ea+1 is hacky
        for h in self._Heads(end=ea - 1, reverse=True):
            return h

    def get_func(self, ea):
        for func in self._functions:
            if ea in func:
                return func

    def FlowChart(self, f):
        if isinstance(f, _Number):
            f = self.get_func(f)

        if not isinstance(f, Function):
            raise Exception("Bad argument FlowChart(f)")

        for block in f._blocks:
            yield block

    def LocByName(self, name):
        return self._labels.get(name)

    def _Refs(self, ref_db_name, filter_callback=lambda r: True, translation_callback=lambda r: r):
        for ref in getattr(self, ref_db_name):
            if filter_callback(ref):
                yield translation_callback(ref)

    def CodeRefsTo(self, addr, flow):
        return self._Refs('_code_references',
                          filter_callback=lambda ref: ref.to == addr,
                          translation_callback=lambda ref: ref.frm)

    def CodeRefsFrom(self, addr, flow):
        return self._Refs('_code_references',
                          filter_callback=lambda ref: ref.frm == addr,
                          translation_callback=lambda ref: ref.to)

    def DataRefsTo(self, addr):
        return self._Refs('_data_references',
                          filter_callback=lambda ref: ref.to == addr,
                          translation_callback=lambda ref: ref.frm)

    def DataRefsFrom(self, addr):
        return self._Refs('_data_references',
                          filter_callback=lambda ref: ref.frm == addr,
                          translation_callback=lambda ref: ref.to)

    def XrefsTo(self, addr):
        filter_callback = lambda ref: ref.to == addr
        return _itertools_chain(
            self._Refs('_code_references', filter_callback=filter_callback),
            self._Refs('_data_references', filter_callback=filter_callback)
        )

    def XrefsFrom(self, addr):
        filter_callback = lambda ref: ref.frm == addr
        return _itertools_chain(
            self._Refs('_code_references', filter_callback=filter_callback),
            self._Refs('_data_references', filter_callback=filter_callback)
        )

    @staticmethod
    def _search_string_to_bytes_list(searchstr, sflag=0, radix=16):
        """
        # TODO: Document

        This yields so in the future i can support wildcards
        """

        # TODO: Implement radix?

        if isinstance(searchstr, str):
            searchstr = searchstr.encode('utf8')

        searchstr = searchstr.lstrip()

        match = b''
        for c in [b'"', b"'"]:
            if searchstr.startswith(c):
                searchstr = searchstr[1:]
                match = c
                break

        # Decode a search string representing a string (ex: '"Hello\nworld!"')
        if match:
            i = searchstr.rfind(match)
            if i not in (-1, 0) and searchstr[i - 1] != '\\':
                searchstr = searchstr[:i]
            # TODO: Actual string parsing
            yield searchstr

        # Decode a search string representing hex bytes
        else:
            for b in _whitespaces:
                searchstr = searchstr.replace(b, b'')

            yield _unhexlify(searchstr)

    def _find_all_binary(self, startea, endea, ubinstr, radix, sflag):
        # TODO: IMPORTANT!! Implement SEARCH_UP
        # TODO: IMPORTANT!! Implement SEARCH_CASE

        needles = list(self._search_string_to_bytes_list(ubinstr))

        prev = b''
        chunk_size = 0x1000 * 4  # TODO: Find good size. page?
        while startea < endea:

            curr_size = endea - startea
            if curr_size > chunk_size:
                curr_size = chunk_size

            chunk = self._read_memory(startea, curr_size)
            amount_read = len(chunk)

            # Check if we need to combine the previous chunk with the current
            # TODO: Implement better/faster
            while prev:
                combined = prev + chunk
                for needle in needles:
                    if combined.startswith(needle):
                        yield startea - len(prev)
                        break

                prev = prev[1:]

            # Scan for every needle from the start and match the first one, yield it, and continue from there anew
            # TODO: Implement with re.search/findall?
            index = -1
            while 1:
                min_index = -1
                for needle in needles:
                    needle_index = chunk.find(needle, index + 1)
                    if needle_index != -1 and (min_index == -1 or needle_index < min_index):
                        min_index = needle_index

                if min_index == -1:
                    break

                yield startea + min_index
                index = min_index

            prev = ''
            if amount_read == 0:

                break_outer = False
                while 1:
                    tmp = self._address_space._get_next_segment(startea)

                    # Reached end of segments
                    if tmp is None:
                        break_outer = True
                        break

                    # Is the segment file-backed?
                    if tmp.offset >= 0:
                        startea = tmp.startEA
                        break

                    else:
                        startea = tmp.endEA

                if break_outer:
                    break

            else:

                # If we failed to read the wanted amount then the memory isn't concurrent
                if amount_read == curr_size:
                    prev = chunk[-len(needle) + 1:]

                startea += amount_read

    def find_binary(self, ea, flags, searchstr, radix=16):
        # TODO: Implement radix?
        # TODO: Implement wild cards?
        is_search_up = flags & self.SEARCH_UP

        if is_search_up:
            start = self.MinEA()
            end = ea
        else:
            start = ea
            end = self.MaxEA()

        # TODO: Improve SEARCH_UP method (find all and return last)
        # found will contain BADADDR if we don't enter the loop
        found = self.BADADDR
        for found in self._find_all_binary(start, end, searchstr, radix, flags):

            # If search_down find first occurence (otherwise we want last)
            if not is_search_up:
                return found

        # found either contains the last found address or BADADDR
        return found

    def _read_memory(self, ea, size):
        return self._address_space.read(ea, size, raise_error=False, padd_not_file_backed_segments=None)

    def get_bytes(self, ea, size):
        return self._read_memory(ea, size)
