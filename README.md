# squashfs-powertools



### SquashFS Filesystem Design
```
 _______________
|               |  Important information about the archive, including
|  Superblock   |  locations of other sections.
|_______________|
|               |  If non-default compression options have been used,
|  Compression  |  they can optionally be stored here, to facilitate
|    options    |  later, offline editing of the archive.
|_______________|
|               |
|  Data blocks  |  The contents of the files in the archive,
|  & fragments  |  split into separately compressed blocks.
|_______________|
|               |  Metadata (ownership, permissions, etc) for
|  Inode table  |  items in the archive.
|_______________|
|               |
|   Directory   |  Directory listings, including file names, and
|     table     |  references to inodes.
|_______________|
|               |
|   Fragment    |  Description of fragment locations within the
|    table      |  Datablocks & Fragments section.
|_______________|
|               |  A mapping from inode numbers to disk locations,
| Export table  |  required for NFS export.
|_______________|
|               |
|    UID/GID    |  A list of unique UID/GIDs. Inodes use an index into
|  lookup table |  this table to save memory.
|_______________|
|               |
|     Xattr     |  Extended attributes for items in the archive.
|     table     |
|_______________|
```

### SquashFS Superblock Format
```
Offset   Type       Description
0        uint32     Magic number (0x73717368)
4        uint32     Inode count
8        uint32     Modification time
12       uint32     Block size
16       uint32     Fragment entry count
20       uint16     Compression type
22       uint16     Block log
24       uint16     Flags
26       uint16     No ids
28       uint16     Major version
30       uint16     Minor version
32       uint64     Root inode
40       uint64     Bytes used
48       uint64     Id table start
56       uint64     Xattr id table start
64       uint64     Inode table start
72       uint64     Directory table start
80       uint64     Fragment table start
88       uint64     Export table start
```

### Resources

https://dr-emann.github.io/squashfs/#inode-directory-basic

https://dr-emann.github.io/squashfs/squashfs.html