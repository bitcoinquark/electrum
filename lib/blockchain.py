# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import gzip
import os
import threading
from io import BytesIO

from .equihash import is_gbp_valid
from . import util
from . import bitcoin
from . import constants
from .bitcoin import *

MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

USE_COMPRESSSION = False
COMPRESSION_LEVEL = 1


# Encapsulated read/write to switch between non-compressed and compressed files by only changing USE_COMPRESSION flag
def read_file(filename, callback, lock):
    if callable(callback):
        with lock:
            if USE_COMPRESSSION:
                with gzip.open(filename, 'rb') as f:
                    return callback(f)
            else:
                with open(filename, 'rb') as f:
                    return callback(f)


def write_file(filename, callback, lock, mode='rb+'):
    if callable(callback):
        with lock:
            if USE_COMPRESSSION:
                with gzip.open(filename, 'wb', COMPRESSION_LEVEL) as f:
                    callback(f)
            else:
                with open(filename, mode) as f:
                    callback(f)

def serialize_header(res, height):
    
    if is_bitcoin_quark(height):
        s = int_to_hex(res.get('version'), 4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(res.get('block_height'), 4) \
            + rev_hex(res.get('reserved')) \
            + int_to_hex(int(res.get('timestamp')), 4) \
            + int_to_hex(int(res.get('bits')), 4) \
            + rev_hex(res.get('nonce')) \
            + rev_hex(res.get('solution'))
            
        return s
    else:
        s = int_to_hex(res.get('version'), 4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp')), 4) \
            + int_to_hex(int(res.get('bits')), 4) \
            + int_to_hex(int(res.get('nonce')), 4)
        return s

def deserialize_header(s, height):
    if not s:
        raise Exception('Invalid header: {}'.format(s))
    #if len(s) != 80:
    #    raise Exception('Invalid header length: {}'.format(len(s)))
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h = {}
    if is_bitcoin_quark(height):
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['reserved']= hash_encode(s[72:100])
        h['timestamp'] = hex_to_int(s[100:104])
        h['bits'] = hex_to_int(s[104:108])
        h['nonce'] = hash_encode(s[108:140])
        h['solution'] = hash_encode(s[140:])
        h['block_height'] = height
    else:
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
        h['block_height'] = height
    return h

def hash_header(header, height):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header, height))))


blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
        h = b.read_header(b.checkpoint)
        if b.parent().can_connect(h, check_height=False):
            blockchains[b.checkpoint] = b
        else:
            util.print_error("cannot connect", filename)
    return blockchains

def check_header(header):
    if type(header) is not dict:
        return False
    for b in blockchains.values():
        if b.check_header(header):
            return b
    return False

def can_connect(header):
    for b in blockchains.values():
        if b.can_connect(header):
            return b
    return False


class Blockchain(util.PrintError):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config, checkpoint, parent_id):
        self.fork_byte_offset = constants.net.BTQ_FORK_HEIGHT * constants.net.HEADER_SIZE_LEGACY
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        self.checkpoints = constants.net.CHECKPOINTS
        self.parent_id = parent_id
        self.lock = threading.Lock()
        self._size = 0
        self.update_size()
        util.set_verbosity(True)

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.checkpoint, blockchains.values()))
        return max([x.checkpoint for x in children]) if children else None

    def get_checkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.checkpoint

    def get_branch_size(self):
        return self.height() - self.get_checkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

    def check_header(self, header):
        height = header.get('block_height')
        header_hash = hash_header(header, height)
        return header_hash == self.get_hash(height)

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.path()
        if os.path.exists(p):
            def get_offset(f):
                return f.seek(0, 2)
            
            size = read_file(p, get_offset, self.lock)
            
            if is_bitcoin_quark(self.checkpoint):
                self._size = size // constants.net.HEADER_SIZE
            else:
                checkpoint_size = self.checkpoint * constants.net.HEADER_SIZE_LEGACY
                full_size = (size + checkpoint_size)
                
                # Check fork boundary crossing
                if full_size <= self.fork_byte_offset:
                    self._size = size // constants.net.HEADER_SIZE_LEGACY
                else:
                    prb = (self.fork_byte_offset - checkpoint_size) // constants.net.HEADER_SIZE_LEGACY
                    pob = (full_size - self.fork_byte_offset) // constants.net.HEADER_SIZE
                    self._size = prb + pob
        else:
            self._size = 0

    def verify_header(self, header, prev_hash, target):
        
        block_height = header.get('block_height')
        _hash = hash_header(header, block_height)
        if prev_hash != header.get('prev_block_hash'):
            raise Exception("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net.TESTNET:
            return
        bits = self.target_to_bits(target)
        if bits != header.get('bits'):
            raise Exception("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        if int('0x' + _hash, 16) > target:
            raise Exception("insufficient proof of work: %s vs target %s" % (int('0x' + _hash, 16), target))
        if is_bitcoin_quark(block_height):
            header_bytes = bytes.fromhex(serialize_header(header, block_height))
            nonce = uint256_from_bytes(bfh(header.get('nonce'))[::-1])
            solution = bfh(header.get('solution'))[::-1]
            offset, length = var_int_read(solution, 0)
            solution = solution[offset:]
            
            if not is_gbp_valid(header_bytes, nonce, solution, constants.net.EQUIHASH_N, constants.net.EQUIHASH_K):
                raise BaseException("Invalid equihash solution")

    def verify_chunk(self, height, data):
        size = len(data)
        offset = 0
        prev_hash = self.get_hash(height-1)
        headers = {}
        target = 0
        
        while offset < size:
            header_size = get_header_size(height)
            raw_header = data[offset:(offset + header_size)]
            header = deserialize_header(raw_header, height)
            headers[height] = header
            # Check retarget
            if needs_retarget(height) or target == 0:
                target = self.get_target(height, headers)
                
            self.verify_header(header, prev_hash, target)

            #print ("after verify_header")
            prev_hash = hash_header(header, height)
            #print ("after verify_header")
            offset += header_size
            height += 1

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        if USE_COMPRESSSION:
            filename += '.gz'
        return os.path.join(d, filename)

    def save_chunk(self, height, chunk):
        delta = height - self.checkpoint
        if delta < 0:
            chunk = chunk[-delta:]
            height = self.checkpoint
            
        offset, header_size = self.get_offset(height)
        self.write(chunk, offset, height // difficulty_adjustment_interval() > len(self.checkpoints))
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        
        parent_branch_size = self.parent().height() - self.checkpoint + 1
        if parent_branch_size >= self.size():
            return
        
        self.print_error("swap", self.checkpoint, self.parent_id)
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        
        def my_data_read(f):
            return f.read()
        
        my_data = read_file(self.path(), my_data_read, self.lock)

        delta = (checkpoint - parent.checkpoint)
        offset = 0
        size = 0

        if not is_bitcoin_quark(parent.checkpoint) and is_bitcoin_quark(checkpoint):
            prb = (constants.net.BTQ_FORK_HEIGHT - parent.checkpoint)
            pob = checkpoint - constants.net.BTQ_FORK_HEIGHT
            offset = (prb * constants.net.HEADER_SIZE_LEGACY) + (pob * constants.net.HEADER_SIZE)
            size = parent_branch_size * constants.net.HEADER_SIZE
        else:
            offset = delta * get_header_size(parent.checkpoint)
            size = parent_branch_size * constants.net.HEADER_SIZE

        def parent_data_read(f):
            f.seek(offset)
            return f.read(size)

        parent_data = read_file(parent.path(), parent_data_read, parent.lock)
        
        self.write(parent_data, 0)
        parent.write(my_data, offset)
        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id
        parent.parent_id = parent_id

        self.checkpoint = parent.checkpoint
        parent.checkpoint = checkpoint

        self._size = parent._size
        parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def write(self, data, offset, truncate=True):
        filename = self.path()
        current_offset, header_size = self.get_offset(self.size())

        def write_data(f):
            if truncate and offset != current_offset:
                f.seek(offset)
                f.truncate()
            f.seek(offset)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        write_file(filename, write_data, self.lock)

        self.update_size()

    def save_header(self, header):
        height = header.get('block_height')
        delta = height - self.checkpoint
        ser_header = serialize_header(header, height)

        offset, header_size = self.get_offset(height)
        data = bfh(ser_header)
        length = len(data)

        assert delta == self.get_branch_size()
        assert length == header_size
        self.write(data, offset)
        self.swap_with_parent()

    def read_header(self, height):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height < self.checkpoint:
            return self.parent().read_header(height)
        if height > self.height():
            return
        
        offset, header_size = self.get_offset(height)

        name = self.path()

        def get_header(f):
            f.seek(offset)
            return f.read(header_size)

        h = read_file(name, get_header, self.lock)

        if len(h) != header_size or h == bytes([0])*header_size:
            return None

        return deserialize_header(h, height)

    def get_header(self, height, headers=None):
        
        if headers is None:
            headers = {}
        
        header = headers[height] if height in headers else self.read_header(height)
        
        return header

    def get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif height < len(self.checkpoints) * 2016:
            assert (height+1) % 2016 == 0, height
            index = height // 2016
            h, t = self.checkpoints[index]
            return h
        else:
            return hash_header(self.read_header(height), height)

    def get_target(self, height, headers=None):
        
        if headers is None:
            headers = {}
            
        # Check for genesis
        if height == 0:
            new_target = constants.net.POW_LIMIT_LEGACY     
            return new_target;   
        if height < constants.net.BTQ_FORK_HEIGHT:
            new_target = self.get_bitcoin_target(height, headers)
            return new_target;
        elif height < constants.net.BTQ_FORK_HEIGHT + constants.net.PREMINE_WINDOW:
            new_target = constants.net.POW_LIMIT
            return new_target;
        elif height < constants.net.BTQ_FORK_HEIGHT + constants.net.PREMINE_WINDOW + constants.net.POW_AVERAGING_WINDOW:
            new_target = constants.net.POW_LIMIT_START
            return new_target;
        
        prior = self.get_header(height - 1, headers)
        bits = prior['bits']
        
        #difficulty adjustement
        mtp_6blocks = (self.get_median_time_past(headers, height - 1)
                       - self.get_median_time_past(headers, height - 7))
        
        
        if mtp_6blocks > 12 * 3600:
            # If it took over 12hrs to produce the last 6 blocks, increase the
            # target by 25% (reducing difficulty by 20%).
            new_target = self.bits_to_target(bits)
            new_target += new_target >> 2
            new_target = min(constants.net.POW_LIMIT, new_target);
            return new_target;
        
        #simple moving average
        new_target = self.get_bitcoinquark_target(height, headers)
        
        return new_target
    
    def get_bitcoin_target(self, height, headers):
        
        if height == 0:
            new_target = constants.net.POW_LIMIT_LEGACY     
            return new_target;        
           
        index = height // 2016 - 1
        # compute target from chunk x, used in chunk x+1
        if index == -1:
            return constants.net.POW_LIMIT_LEGACY
        
        # from checkpoints
        if index < len(self.checkpoints):
            h, t = self.checkpoints[index]
            return t
        
        last_height = (height - 1)
        last = self.get_header(last_height, headers)		
		
        if height % difficulty_adjustment_interval() != 0:
            if constants.net.TESTNET:
                cur = self.get_header(height, headers)
                # Special testnet handling
                if cur.get('timestamp') > last.get('timestamp') + constants.net.POW_TARGET_SPACING * 2:
                    new_target = constants.net.POW_LIMIT_LEGACY
                else:
                    # Return the last non-special-min-difficulty-rules-block
                    prev_height = last_height - 1
                    prev = self.get_header(prev_height, headers)

                    while prev is not None and last.get('block_height') % difficulty_adjustment_interval() != 0 \
                            and last.get('bits') == constants.net.POW_LIMIT:
                        last = prev
                        prev_height -= 1
                        prev = self.get_header(prev_height, headers)

                    new_target = self.bits_to_target(last.get('bits'))
            else:
                new_target = self.bits_to_target(last.get('bits'))
        else:
            # new target
            first = self.read_header(index * 2016)
            last = self.read_header(index * 2016 + 2015)
            bits = last.get('bits')
            target = self.bits_to_target(bits)
            nActualTimespan = last.get('timestamp') - first.get('timestamp')
            nTargetTimespan = 14 * 24 * 60 * 60
            nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
            nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
            new_target = min(constants.net.POW_LIMIT_LEGACY, (target * nActualTimespan) // nTargetTimespan)
            
        return new_target
    
    def get_bitcoinquark_target(self, height, headers):
        
        pow_limit = constants.net.POW_LIMIT
        height -= 1
        last = self.get_header(height, headers)
        
        if last is None:
            new_target = pow_limit
        else:
            first = last
            total = 0
            i = 0

            while i < constants.net.POW_AVERAGING_WINDOW and first is not None:
                total += self.bits_to_target(first.get('bits'))
                prev_height = height - i - 1
                first = self.get_header(prev_height, headers)
                i += 1

            # This should never happen else we have a serious problem
            assert first is not None
            
            avg = total // constants.net.POW_AVERAGING_WINDOW
            actual_timespan = self.get_median_time_past(headers, last.get('block_height')) \
                - self.get_median_time_past(headers, first.get('block_height'))

            if actual_timespan < min_actual_timespan():
                actual_timespan = min_actual_timespan()

            if actual_timespan > max_actual_timespan():
                actual_timespan = max_actual_timespan()

            avg = avg // averaging_window_timespan()
            avg *= actual_timespan

            if avg > pow_limit:
                avg = pow_limit

            new_target = int(avg)

        return new_target      
        
    
    def get_median_time_past(self, headers, height):
        if height < 0:
            return 0
        header = self.get_header(height, headers)
        times = []
        i = 0
        
        while i < 11 and header is not None:
            times.append(header.get('timestamp'))
            prev_height = height - i - 1
            header = self.get_header(prev_height, headers)
            i += 1
            
        return sorted(times)[len(times) // 2]    

    def bits_to_target(self, bits):
        size = bits >> 24
        word = bits & 0x007fffff

        if size <= 3:
            word >>= 8 * (3 - size)
            ret = word
        else:
            ret = word
            ret <<= 8 * (size - 3)

        return ret

    def target_to_bits(self, target):
        assert target >= 0
        nsize = (target.bit_length() + 7) // 8
        if nsize <= 3:
            c = target << (8 * (3 - nsize))
        else:
            c = target >> (8 * (nsize - 3))
        if c & 0x00800000:
            c >>= 8
            nsize += 1
        assert (c & ~0x007fffff) == 0
        assert nsize < 256
        c |= nsize << 24
        return c

    def can_connect(self, header, check_height=True):
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            #self.print_error("cannot connect at height", height)
            return False
        if height == 0:
            return hash_header(header, height) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        
        target = self.get_target(height, {height: header})
        try:
            self.verify_header(header, prev_hash, target)
        except BaseException as e:
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            self.verify_chunk(idx * 2016, data)
            self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx * 2016, data)
            return True
        except BaseException as e:
            self.print_error('verify_chunk %d failed'%idx, str(e))
            return False
        
    def get_offset(self, height):
        delta = height - self.checkpoint
        header_size = get_header_size(height)

        if is_bitcoin_quark(height) and not is_bitcoin_quark(self.checkpoint):
            pr = (constants.net.BTQ_FORK_HEIGHT - self.checkpoint) * (constants.net.HEADER_SIZE_LEGACY)
            po = (height - constants.net.BTQ_FORK_HEIGHT) * (constants.net.HEADER_SIZE)
            offset = pr + po
        else:
            offset = abs(delta) * header_size

        return offset, header_size

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // 2016
        for index in range(n):
            height = (index+1) * 2016
            if is_bitcoin_quark(height):
                break          
            h = self.get_hash(height - 1)
            target = self.get_target(height)
            cp.append((h, target))
        return cp
