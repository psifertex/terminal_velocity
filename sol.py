import re

from pwn import *

r = remote("localhost", 3535)

# Level 0
r.sendlineafter("Enter the password:", "Level 0 Is Really Easy")

# Level 1
r.sendafter("18t", ".[8;24;80t")
r.sendlineafter('Press enter to continue', '')

# Level 2
r.readuntil("The password is: ")
l2pw = r.read(18)
r.sendlineafter('Enter the password: ', l2pw)
r.sendlineafter('Press enter to continue', '')

# Level 3
r.sendlineafter('[11t', '\033[2t')
r.sendlineafter('Press enter to continue', '')

# Level 4
r.readline()
l4pw = ''.join([chr(r.read(9)[0]) for i in range(11)])
r.sendlineafter('Enter the password:', l4pw)
r.sendlineafter('Press enter to continue', '')


# Level 5

annoying_blob = r.readuntil('Enter the password:')
terminal_window = [[' ' for i in range(80)] for j in range(24)]

MOVE_BOTH = r'\[(\d+);(\d+)[fH](.)?'
MOVE_COL = r'\[(\d+)G(.)?'
MOVE_ROW = r'\[(\d+)d(.)?'

row = 0
col = 0
for escape in annoying_blob.split(b'\x1b'):
    escape = escape.decode()
    move_col = re.match(MOVE_COL, escape)
    if move_col is not None:
        col = int(move_col[1])
        char = move_col[2]
        if char is not None:
            terminal_window[row][col] = char
    move_row = re.match(MOVE_ROW, escape)
    if move_row is not None:
        row = int(move_row[1])
        char = move_row[2]
        if char is not None:
            terminal_window[row][col] = char
    move_both = re.match(MOVE_BOTH, escape)
    if move_both is not None:
        row = int(move_both[1])
        col = int(move_both[2])
        char = move_both[3]
        if char is not None:
            terminal_window[row][col] = char

for row in terminal_window:
    print(''.join(row))
pw = 'BobTheBuilder'
r.sendline(pw)
r.sendlineafter('Press enter to continue', '')


# Level 6
r.sendlineafter('Press enter to continue', '')

r.readuntil('FILE1')

import base64
file1 = r.readuntil('FILE2:\n', drop=True).split(b'File=inline=1;size=24998:')[1].split(b'\x07')[0]
file1_decoded = base64.b64decode(file1)
with open('file1_dec.png', 'wb') as f:
    f.write(file1_decoded)

file2 = r.readuntil('FILE3', drop=True)
file3 = r.readuntil('Enter the password:', drop=True)

pw = 'PINEY_'

r.interactive()
