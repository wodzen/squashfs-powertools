import struct
import sys
import lzma
import math

SQUASHFS_SUPERBLOCK_SIZE = 96
SQUASHFS_MAGIC_LE = 0x73717368
SQUASHFS_MAGIC_BE = 0x68737173


# TODO
COMP = {
    1: 'gzip',
    2: 'LZMA',
    3: 'LZO',
    4: 'XZ',
    5: 'LZ4',
    6: 'ZSTD'
}

def parse_squashfs_superblock(file_path):

    # Read the first 96 bytes for superblock
    with open(file_path, 'rb') as file:

        superblock_data = file.read(SQUASHFS_SUPERBLOCK_SIZE)

        # Check the magic number to verify it's a SquashFS filesystem
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

        # create a dictionary with the parsed data
        keys = ['Magic Number', 'Inode Count', 'Modification Time', 'Block Size',
                'Fragment Entry Count', 'Compression Type', 'Block Log', 'Flags', 'No IDs',
                'Major Version', 'Minor Version', 'Root Inode', 'Bytes Used',
                'ID Table Start', 'Xattr ID Table Start', 'Inode Table Start',
                'Directory Table Start', 'Fragment Table Start', 'Export Table Start']
        
        return dict(zip(keys, superblock_hex))


FLAGS = {
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
    'UNCOMPRESSED_IDS': 0x0800
}
def parse_squashfs_superblock_flags(flags):
    flags = int(flags, 16)
    flags_bool = {name: bool(flags & bitmask) for name, bitmask in FLAGS.items()}
    return flags_bool

INODE_HEADER_KEYS = ['Type', 'Permissions', 'UID', 'GID', 'mtime', 'Inode Number']
INODE_BASIC_DIRECTORY_KEYS = ['Directory Block Start', 'Hard Link Count', ' File Size', ' Block Offset', 'Parent Inode Number']
INODE_BASIC_FILE_KEYS = ['Blocks Start', 'Frag Index', 'Block Offset', 'File Size', 'Block Sizes']
def parse_squashfs_inode_table(file_path, superblock_info, superblock_flags):
    
    inode_table = {}
    start = int(superblock_info['Inode Table Start'], 16)
    end = int(superblock_info['Directory Table Start'], 16)
    block_size = int(superblock_info['Block Size'], 16)

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
        
        if(compressed):
            #data = decompress_data(inode_data, type)
            #print(data)
            print('compressed')
        else:
            inode_data = file.read(end-start)

        seek_offset = 0

        while((start + seek_offset) <= (start + data_size)):

            inode_data = inode_data[seek_offset:]
            print(seek_offset)
            try:
                inode_header = struct.unpack('<4H2I', inode_data[:16])
                
                # zip inode header
                inode_hex = tuple(hex(value) for value in inode_header)
                inode_dict = dict(zip(INODE_HEADER_KEYS, inode_hex))
                
                
            except:
                #continue
                print(f'Failed to parse inode header')

            try:
                inode_type = int(inode_dict['Type'], 16)
                match inode_type:

                    # BASIC DIRECTORY
                    case 1:
                        inode_struct = '<2I2HI'

                        inode_struct_data = struct.unpack(inode_struct, inode_data[16:32])
                        inode_type_hex = tuple(hex(value) for value in inode_header)
                        inode_type_dict = dict(zip(INODE_BASIC_DIRECTORY_KEYS, inode_hex))

                        inode_type_size = 16 + 16

                    # BASIC FILE
                    case 2:

                        # data without dynamic block sizes
                        inode_struct = '<4I'
                        inode_struct_data = struct.unpack(inode_struct, inode_data[16:32])
                        
                        # check if the file ends with a fragment
                        is_fragment_block_index = not (inode_struct_data[1] == 0xFFFFFFFF)

                        # round up to blocks needed to store
                        inode_basic_file_size = inode_struct_data[3]
                        block_sizes_listsize = math.ceil(inode_basic_file_size / block_size)

                    
                        if is_fragment_block_index:
                            block_sizes_listsize = inode_basic_file_size //  block_size                

                        # tuple dynamic block sizes
                        inode_struct = '<%sI'%block_sizes_listsize
                        inode_list_len = (32 + (4 * block_sizes_listsize))
                        block_sizes_data = struct.unpack(inode_struct, inode_data[32:inode_list_len])
                        block_sizes_data = tuple(hex(value) for value in block_sizes_data)

                        # add dynamic block sizes to dict - TODO
                        inode_type_hex = tuple(hex(value) for value in inode_struct_data)
                        inode_type_dict = dict(zip(INODE_BASIC_FILE_KEYS, inode_type_hex))
                        block_sizes_data = {'Block Sizes':block_sizes_data}
                        inode_type_dict.update(block_sizes_data)

                        inode_type_size = 16 + (4 * block_sizes_listsize)

            except:
                print(f'Failed to parse inode data')
                continue

            # append type header to standard header
            inode_table[f'{i}'] = (inode_dict | inode_type_dict)
            i+=1
            seek_offset += (16 + inode_type_size)
        return inode_table

# TODO
def decompress_data(data, type):
    try:
        data = lzma.decompress(data)
        return data
    except Exception as e:
        print(e)
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 superblock.py <.squashfs_file>")
        sys.exit(1)

    squashfs_file = sys.argv[1]
    superblock_info = parse_squashfs_superblock(squashfs_file)
    superblock_flags = parse_squashfs_superblock_flags(superblock_info['Flags'])

    # print squashfs superblock values
    print('SUPERBLOCK')
    for key, value in superblock_info.items():
        print(f'{key}: {value}')

    print('\nFLAGS')
    # print squashfs superblock flags
    for key, value in superblock_flags.items():
        print(f'{key}: {value}')

    print('\nINODES')
    squashsfs_inode_table = parse_squashfs_inode_table(squashfs_file, superblock_info, superblock_flags)
    for key, value in squashsfs_inode_table.items():
        print(f'{key}: {value}')

if __name__ == "__main__":
    main()