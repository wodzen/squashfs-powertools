import struct
import sys
import lzma, gzip, lz4.frame, lzo, zstd
import math

SQUASHFS_SUPERBLOCK_SIZE = 96
SQUASHFS_INODE_HEADER_SIZE = 16
SQUASHFS_MAGIC_LE = 0x73717368
SQUASHFS_MAGIC_BE = 0x68737173

# squashfs fields
SUPERBLOCK_KEYS = [
    'Magic Number',
    'Inode Count',
    'Modification Time',
    'Block Size',
    'Fragment Entry Count',
    'Compression Type', 
    'Block Log',
    'Flags',
    'No IDs',
    'Major Version',
    'Minor Version',
    'Root Inode',
    'Bytes Used',
    'ID Table Start',
    'Xattr ID Table Start',
    'Inode Table Start',
    'Directory Table Start',
    'Fragment Table Start',
    'Export Table Start',
]

SUPERBLOCK_FLAGS = {
    'UNCOMPRESSED_INODES': 0x0001,
    'UNCOMPRESSED_DATA': 0x0002,
    'CHECK': 0x0004,
    'UNCOMPRESSED_FRAGMENTS': 0x0008,
    'NO_FRAGMENTS': 0x0010,
    'ALWAYS_FRAGMENTS': 0x0020,
    'DUPLICATES': 0x0040,
    'EXPORTABLE': 0x0080,
    'UNCOMPRESSED_XATTRS': 0x0100,
    'NO_XATTRS': 0x0200,
    'COMPRESSOR_OPTIONS': 0x0400,
    'UNCOMPRESSED_IDS': 0x0800,
}

INODE_HEADER_KEYS = [
    'Type',
    'Permissions',
    'UID',
    'GID',
    'mtime',
    'Inode Number',
]

INODE_BASIC_DIRECTORY_KEYS = [
    'Directory Block Start',
    'Hard Link Count',
    'File Size',
    'Block Offset',
    'Parent Inode Number',
]

INODE_BASIC_FILE_KEYS = [
    'Blocks Start',
    'Frag Index',
    'Block Offset',
    'File Size',
    'Block Sizes',
]

INODE_BASIC_SYMLINK_KEYS = [
    'Hard Link Count',
    'Target Size',
    'Target Path',
]

INODE_BASIC_DEVICE_KEYS = [
    'Hard Link Count',
    'Device',
]

INODE_BASIC_IPC_KEYS = [
    'Hard Link Count',
]

# squashfs extened inode type keys
INODE_EXT_DIRECTORY_KEYS = [
    'Hard Link Count',
    'File Size',
    'Directory Block Start',
    'Parent Inode Number',
    'Index Count',
    'Block Offset',
    'Xattr Idx',
    'index',
]

DIRECTORY_INDEX_KEYS = [
    'Index',
    'Start',
    'Name Size',
    'Name',
]

INODE_EXT_FILE_KEYS = [
    'Block Start',
    'File Size',
    'Sparse',
    'Hard Link Count',
    'Frag Index',
    'Block Offset',
    'Xattr Ids',
    'Block Sizes',
]

INODE_EXT_SYMLINK_KEYS = [
    'Hard Link Count',
    'Target Size',
    'Target Path',
    'Xattr Idx',
]

INODE_EXT_DEVICE_KEYS = [
    'Hard Link Count',
    'Device',
    'Xattrs Idx',
]

INODE_EXT_IPC_KEYS = [
    'Hard Link Count',
    'Xattr Idx',
]

def parse_squashfs_superblock(file_path):

    # read the first 96 bytes for superblock
    with open(file_path, 'rb') as file:

        superblock_data = file.read(SQUASHFS_SUPERBLOCK_SIZE)

        # check the magic number to verify it's a squashfs
        magic_number = struct.unpack('<I', superblock_data[:4])[0]
        if magic_number == SQUASHFS_MAGIC_LE:
            superblock = struct.unpack('<5I6H8Q', superblock_data)
        elif magic_number == SQUASHFS_MAGIC_BE:
            superblock = struct.unpack('>5I6H8Q', superblock_data)
        else:
            print("No squashfs magic found.")
            return None

        # unpack the superblock data according to the squashfs specification
        superblock = struct.unpack('<5I6H8Q', superblock_data)

        superblock_hex = tuple(hex(value) for value in superblock)
        superblock_dict = dict(zip(SUPERBLOCK_KEYS, superblock_hex))
        
        return superblock_dict

def parse_squashfs_superblock_flags(flags):
    flags = int(flags, 16)
    flags_bool = {name: bool(flags & bitmask) for name, bitmask in SUPERBLOCK_FLAGS.items()}
    return flags_bool

def parse_squashfs_inode_table(file_path, superblock_info, superblock_flags):
    
    inode_table = {}
    start = int(superblock_info['Inode Table Start'], 16)
    end = int(superblock_info['Directory Table Start'], 16)
    block_size = int(superblock_info['Block Size'], 16)
    method = int(superblock_info['Compression Type'], 16)

    i = 0
    with open(file_path, 'rb') as file:
        
        file.seek(start)

        # TODO while parsing metadata (using metadata size difference)
        # if its contiguous maybe we just decompress and add all of the metadata blocks together

        # bitwise check if block is encryped and get size 
        metadata_mask=file.read(2)
        header = struct.unpack('<H', metadata_mask)[0]
        data_size = header & 0x7FFF  
        compressed = not (header & 0x8000)

        # read data between inode  and directory tables
        inode_data = file.read(end-(start))
        
        # attempt to decompress metadata block(s)
        if(compressed):
            inode_data = decompress_data(inode_data, method)

        if inode_data != None:

            seek_offset = 0

            # step through inode table metadata block(s)
            while((start + seek_offset) <= (start + data_size)):

                inode_data = inode_data[seek_offset:]
                
                try:
                    inode_header = struct.unpack('<4H2I', inode_data[:16])
                    
                    # dict inode header
                    inode_hex = tuple(hex(value) for value in inode_header)
                    inode_dict = dict(zip(INODE_HEADER_KEYS, inode_hex))
                    
                except:
                    print(f'Failed to parse inode header: {seek_offset}.\n\t{inode_header}')
                    break

                inode_type = int(inode_dict['Type'], 16)
                try:
                    match inode_type:
                        # BASIC DIRECTORY
                        case 1:

                            # unpack to dict
                            inode_struct = '<2I2HI'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:32])
                            inode_type_hex = tuple(hex(value) for value in inode_header)
                            inode_type_dict = dict(zip(INODE_BASIC_DIRECTORY_KEYS, inode_hex))

                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + len(inode_struct_data)

                        # BASIC FILE
                        case 2:

                            # data without dynamic block sizes
                            inode_struct = '<4I'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:32])
                            
                            # check if the file ends with a fragment
                            is_fragment_block_index = not (inode_struct_data[1] == 0xffffffff)

                            # round up to full blocks required
                            inode_basic_file_size = inode_struct_data[3]
                            block_sizes_listsize = math.ceil(inode_basic_file_size / block_size)

                            # round down to last full block
                            if is_fragment_block_index:
                                block_sizes_listsize = inode_basic_file_size //  block_size                

                            # tuple dynamic block sizes
                            inode_struct = '<%sI'%block_sizes_listsize
                            inode_list_len = (32 + (4 * block_sizes_listsize))
                            block_sizes_data = struct.unpack(inode_struct, inode_data[32:inode_list_len])
                            block_sizes_data = tuple(hex(value) for value in block_sizes_data)

                            # add dynamic block sizes
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_BASIC_FILE_KEYS, inode_type_hex))
                            block_sizes_data = {'Block Sizes':block_sizes_data}
                            inode_type_dict.update(block_sizes_data)

                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + (4 * block_sizes_listsize)
                        
                        # BASIC SYMLINK
                        case 3:

                            # get target size for symlink path read
                            inode_struct = '<2I'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:24])
                            target_size = inode_struct_data[1]
                            
                            # unpack to dict
                            inode_struct = '<2I%ss'%target_size
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:(24+target_size)])
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_BASIC_SYMLINK_KEYS, inode_type_hex))
                            
                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + len(inode_struct_data)

                        # BASIC BLOCK/CHAR DEVICE
                        case 4, 5:
                            
                            # unpack to dict
                            inode_struct = '<2I'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:24])
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_BASIC_DEVICE_KEYS, inode_type_hex))

                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + len(inode_struct_data)

                        # BASIC IPC QUEUE/SOCKET
                        case 6, 7:

                            # unpack to dict
                            inode_struct = '<I'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[SQUASHFS_INODE_HEADER_SIZE:20])
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_BASIC_IPC_KEYS, inode_type_hex))

                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + len(inode_struct_data)
                            
                        # EXTENDED DIRECTORY
                        case 8:

                            # get directory index count and unpack to dict
                            inode_struct = '<4I2HI'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[SQUASHFS_INODE_HEADER_SIZE:20])
                            index_count = inode_struct_data[4]
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_EXT_DIRECTORY_KEYS, inode_type_hex))
                            
                            # handle dynamic directory index entries with dynamic name
                            inode_struct_len = len(inode_struct_data)
                            directory_index_dict = {}
                            directory_index_size = 0
                            for index in range(0, index_count):

                                # get directory index data before dynamic name
                                directory_index_struct = '<3I'
                                directory_index_data = inode_data[SQUASHFS_INODE_HEADER_SIZE+inode_struct_len+12:]
                                directory_index_struct_data = struct.unpack(directory_index_struct, directory_index_data)
                                # TODO name size +||- 1?
                                name_size = (directory_index_struct_data[2]-1)
                                
                                # unpack directory index entry to dict
                                directory_index_struct = '<3I%ss'%name_size
                                directory_index_data = inode_data[SQUASHFS_INODE_HEADER_SIZE+inode_struct_len+12+name_size:]
                                directory_index_struct_data = struct.unpack(directory_index_struct, directory_index_data)
                                directory_index_hex = tuple(hex(value) for value in directory_index_struct_data)
                                directory_index_entry_dict = dict(zip(DIRECTORY_INDEX_KEYS, directory_index_hex))
                                
                                # add directory index entry dict to directory index dict
                                directory_index_entry_data = {f'{index}':directory_index_entry_dict}
                                directory_index_dict.update(directory_index_entry_data)

                                # for seek offset
                                directory_index_size += len(directory_index_data)
                            
                            # add directory index dict(s) to inode
                            directory_index_dict = {'Index':directory_index_dict}
                            inode_type_dict.update(directory_index_dict)

                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + inode_struct_len + directory_index_size
                        
                        # EXTENDED FILE TODO
                        case 9:

                            # data without dynamic block sizes
                            inode_struct = '<4I'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:32])
                            
                            # check if the file ends with a fragment
                            is_fragment_block_index = not (inode_struct_data[1] == 0xffffffff)

                            # round up to full blocks required
                            inode_basic_file_size = inode_struct_data[3]
                            block_sizes_listsize = math.ceil(inode_basic_file_size / block_size)

                            # round down to last full block
                            if is_fragment_block_index:
                                block_sizes_listsize = inode_basic_file_size //  block_size                

                            # tuple dynamic block sizes
                            inode_struct = '<%sI'%block_sizes_listsize
                            inode_list_len = (32 + (4 * block_sizes_listsize))
                            block_sizes_data = struct.unpack(inode_struct, inode_data[32:inode_list_len])
                            block_sizes_data = tuple(hex(value) for value in block_sizes_data)

                            # add dynamic block sizes
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_BASIC_FILE_KEYS, inode_type_hex))
                            block_sizes_data = {'Block Sizes':block_sizes_data}
                            inode_type_dict.update(block_sizes_data)

                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + (4 * block_sizes_listsize)

                        # EXTENDED SYMLINK  
                        case 10:

                            # get target size for symlink path read
                            inode_struct = '<2I'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:24])
                            target_size = inode_struct_data[1]
                            
                            # unpack to dict
                            inode_struct = '<2I%ssI'%target_size
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:(24+target_size)])
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_EXT_SYMLINK_KEYS, inode_type_hex))
                            
                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + len(inode_struct_data)

                        # EXTENDED DEVICE
                        case 11, 12:

                            # unpack to dict
                            inode_struct = '<3I'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:28])
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_EXT_DEVICE_KEYS, inode_type_hex))

                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + len(inode_struct_data)
                        
                        # EXTENDED IPC
                        case 13, 14:

                            # unpack to dict
                            inode_struct = '<2I'
                            inode_struct_data = struct.unpack(inode_struct, inode_data[16:24])
                            inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                            inode_type_dict = dict(zip(INODE_EXT_IPC_KEYS, inode_type_hex))

                            # seek offset
                            inode_type_size = SQUASHFS_INODE_HEADER_SIZE + len(inode_struct_data)

                        case _:
                            break

                                
                    # merge inode type struct with standard header and add to inode table
                    inode_table[f'{i}'] = (inode_dict | inode_type_dict)
                    i+=1
                    seek_offset += (16 + inode_type_size)

                except:
                    print(f'Failed to parse inode data {inode_type}')
                    break

        return inode_table

# TODO
def decompress_data(data, method):

    try:
        match method:
            case 1:
                data = gzip.decompress(data)
            case 2:
                data = lzma.decompress(data)
            case 3:
                data = lzo.decompress(data)
            case 4:
                data = lzma.decompress(data)
            case 5:
                lz4.frame.decompress(data)
            case 6: 
                zstd.decompress(data)

        return data
            
    except Exception as e:
        print(f'Failed to decompress inode table metadata blocks ({method}): {e}')
        return None

def main():

    if len(sys.argv) != 2:
        print("Usage: python3 squashfs_parser.py <file.squashfs>")
        sys.exit(1)

    squashfs_file = sys.argv[1]

    # print squashfs superblock values
    print('_'*36)
    print('\nSUPERBLOCK FIELDS\n')
    superblock_info = parse_squashfs_superblock(squashfs_file)
    for key, value in superblock_info.items():
        print(f'{key}: {value}')

    # print squashfs superblock flags
    print('_'*36)
    print('\nSUPERBLOCK FLAGS\n')
    superblock_flags = parse_squashfs_superblock_flags(superblock_info['Flags'])
    for key, value in superblock_flags.items():
        print(f'{key}: {value}')

    # print inode table
    print('_'*36)
    print('\nINODE TABLE\n')
    squashsfs_inode_table = parse_squashfs_inode_table(squashfs_file, superblock_info, superblock_flags)
    for key, value in squashsfs_inode_table.items():
        print(f'{key}: {value}')

if __name__ == "__main__":
    main()