from pprint import pprint
from pwn import *
import sys


def extract_esc(cmd):
	i = 0
	bits = []
	last_esc = True
	while i < len(cmd):
		if cmd[i:i+1] == b'\x08':
			bits.append(cmd[i:i+1])
			i += 1
			last_esc = True
		elif i + 2 < len(cmd) and cmd[i:i+2] == b'\x1b[':  # CSI
			end = i
			while cmd[end] not in b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~`@{}':
				end += 1
			bits.append(cmd[i:end+1])
			i = end + 1
			last_esc = True
		elif i + 2 < len(cmd) and cmd[i:i + 2] == b'\x1bP':  # DCS
			end = i
			while cmd[end:end+2] != b'\x1b\\':
				end += 1
			bits.append(cmd[i:end + 1])
			i = end + 1
			last_esc = True
		elif i + 2 < len(cmd) and cmd[i:i + 2] == b'\x1bO':  # SS3
			bits.append(cmd[i:i + 2])
			i += 2
			last_esc = True
		elif i + 2 < len(cmd) and cmd[i:i + 2] == b'\x1bD':  # IND
			bits.append(cmd[i:i + 2])
			i += 2
			last_esc = True
		elif i + 2 < len(cmd) and cmd[i:i + 1] == b'\x1b':
			bits.append(cmd[i:i + 2])
			i += 2
			last_esc = True
		else:
			if last_esc:
				bits.append(cmd[i:i+1])
			else:
				bits[-1] += cmd[i:i+1]
			i += 1
			last_esc = False
	return bits

def sendline(r, text):
	print(b"<<< " + text)
	r.sendline(text)


def main():
	if len(sys.argv) > 1:
		host = sys.argv[1]
	else:
		host = "localhost"
	r = remote(host, 3535)

	pprint(extract_esc(r.recvuntil(b"Enter the password: ")))

	PASS_PT_0 = b"Level 0 Is Really Easy"
	PASS_PT_1 = b"G1V3M3TH3N3XTL3V3L"
	PASS_PT_2 = b"HalfwayDone"
	PASS_PT_3 = b"BobTheBuilder"
	PASS_PT_4 = b"PINEY_FLATS_TN_USA"

	sendline(r, PASS_PT_0)
	sendline(r, b"\x1b[8;24;80t")

	pprint(extract_esc(r.recvuntil(b"Press enter to continue.")))
	sendline(r, b'')
	pprint(extract_esc(r.recvuntil(b"The password is: ")))
	password = r.recvuntil(b"\n").strip()

	assert password == PASS_PT_1

	pprint(extract_esc(r.recvuntil(b"Enter the password: ")))
	sendline(r, password)
	pprint(extract_esc(r.recvuntil(b"Press enter to continue.")))
	sendline(r, b'')
	pprint(extract_esc(r.recvuntil(b"\x1b[1t")))
	sendline(r, b"\x1b[2t")
	pprint(extract_esc(r.recvuntil(b"Press enter to continue.")))
	sendline(r, b'')

	pprint(extract_esc(r.recvuntil(b"Enter the password: ")))

	sendline(r, PASS_PT_2)
	pprint(extract_esc(r.recvuntil(b"Press enter to continue.")))
	sendline(r, b'')
	pprint(extract_esc(r.recvuntil(b"Enter the password: ")))
	sendline(r, PASS_PT_3)
	pprint(extract_esc(r.recvuntil(b"Press enter to continue.")))
	sendline(r, b'')
	pprint(extract_esc(r.recvuntil(b"Press enter to continue.")))
	sendline(r, b'')
	pprint(extract_esc(r.recvuntil(b"Enter the password: ")))
	sendline(r, PASS_PT_4)
	pprint(extract_esc(r.recvuntil(b"Press enter to continue.")))
	sendline(r, b'')
	pprint(extract_esc(r.recvuntil(b"Your flag is: ")))

	flag = r.recv()

	print(flag.decode())


if __name__ == '__main__':
	main()
