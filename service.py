import socket
import socketserver
import threading
import time
import random
import errno
import sys

random.seed(time.time())

DEBUG = True
HARDER = True

ESC='\033'
CSI = ESC + '['
DCS = ESC + "P" #Terminated by ST
ST = ESC + "\\"
OSC = ESC + ']'
SOS = ESC + 'X'
BEL = '\007'
FINGERPRINT=ESC+'>0c'

CHARATTRIB = {'normal':    '0',
              'bold':      '1',
              'faint':     '2',
              'italic':    '3',
              'underline': '4',
              'blink':     '5',
              'inverse':   '7',
              'hidden':    '8',
              'crossed':   '8',
              'normal48':  '48',
}


BGCOLORS = {'black':   '40',
            'red':     '41',
            'green':   '42',
            'yellow':  '43',
            'blue':    '44',
            'magenta': '45',
            'cyan':    '46',
            'white':   '47',
            'default': '49',
}

FGCOLORS = {'black':   '30',
            'red':     '31',
            'green':   '32',
            'brightgreen':   '92',
            'yellow':  '33',
            'blue':    '34',
            'magenta': '35',
            'cyan':    '36',
            'white':   '37',
            'default': '39',
}

CURSORSTYLE = {'blinkingblock':     '0',
               'steadyblock':       '2',
               'blinkingunderline': '3',
               'steadyunderline':   '4',
               'blinkingbar':       '5',
               'steadybar':         '6',
}                         

def BG(color):
    colors = {**BGCOLORS, **CHARATTRIB}
    return CSI + colors[color] + 'm'


def FG(color):
    colors = {**FGCOLORS, **CHARATTRIB}
    return CSI + colors[color] + 'm'

def CURSOR(style):
    return CSI + CURSORSTYLE[style] + ' q'

def INVISIBLE():
    return CSI + '?25l'

def VISIBLE():
    return CSI + '?25h'

def UP(count):
    if count == 0:
        return ''
    return random.choice([
        CSI + str(count) + 'A',
        (CSI + '1A') * count,
])

def DOWN(count):
    if count == 0:
        return ''
    return random.choice([
        CSI + str(count) + 'B',
        (CSI + '1B') * count,
])

def LEFT(count):
    if count == 0:
        return ''
    if random.randint(1,4) == 1:
        return CSI + str(count) + 'D'
    else:
        out = ''
        while (count >= 1):
            out += random.choice([
        '\010',
        (CSI + '1D'),
])
            count -= 1
        return out

def RIGHT(count):
    if count == 0:
        return ''
    return random.choice([
        CSI + str(count) + 'C',
        (CSI + '1C') * count,
])

def DEL(count):
    if count == 0:
        return ''
    return random.choice([
        (CSI + '3~') * count
])

def BACKSPACE(count):
    if count == 0:
        return ''
    return random.choice([
        LEFT(count) + DEL(count),
        '\010' * count,
])

def GOTO(x,y):
    return random.choice([
        CSI + str(y) + ";" + str(x) + "H",
        CSI + str(y) + ";" + str(x) + "f",
        CSI + str(y) + 'd' + CSI + str(x) + "G",
    ])

def ERASECHAR():
    return random.choice([ '\010',
        CSI+'1D'+CSI+'3~',
        CSI+'D' + CSI+'3~',
    ])

def ERASELINE():
    # This only works on iTerm2!
    #    '\010' * 80 + '\177' * 80,
    return random.choice([
        '\015' + CSI + '2K', # Move left, kill whole line
        CSI + '1K' + CSI + '0K' + '\015', # kill left right then move left
        #'\033J' + '\033K' + '\015',
        '\015' + CSI + 'K',
    ])

def ERASESCREEN():
    return INIT() + random.choice([  
        # Clear screen
        CSI + '2J',
        CSI + '80T',
        " " + CSI +'1920b',
    ]) + random.choice([
        # Move to home position
        GOTO(1,1),
    ])


def STAT(s, x, y): #string at coords
    return random.choice([
        GOTO(x,y) + s,
        ])

def SAVECURSOR():
    return ESC + '7'

def RESTORECURSOR():
    return ESC + '8'

def ICONIFY():
    return CSI + '2t'

def DEICONIFY():
    return CSI + '1t'

def ALTSCREEN():
    return CSI + '?47h'

def EXITALT():
    return CSI + '?47l'

def FOCUSALERT():
    return CSI + '?1004h'

def NOFOCUSALERT():
    return CSI + '?1004l'

def NOSCROLL(): #Disable scrolling
    pass


def INIT():
    return FG("normal") + FG("green") + FG("brightgreen") + BG("black") + CURSOR("blinkingbar") + VISIBLE()

TERMS = [
    [['FP Matches'], 'Name', 'Kill Command'],
    [['1;3201;0c'], 'Gnome-Terminal', ''],
    [['1;2c'], 'Terminal.App', ''],
    [['0;95;c'], 'iTerm', ''],
    [['0;271;0c'], 'xTerm', '']
]

def CHAFF(input):
    if HARDER == False:
        return input
    output = ''
    for char in input:
        output += char
        output += random.choice([
            #need more chaff, should be lots of good options here!
            CSI + '?' + str(random.randint(2222,9999)) + 'h',
            CSI + '?' + str(random.randint(2222,9999)) + 'l',
                ])
    return output

level0password = 'L0IsReallyEasyRight?'
level1password = 'G1VEMETHENEXTLEVEL'
level2password = 'NOTHESEARENOTFLAGS'

def genl0pw(pw):
    y = 8
    x = 19
    amap = []
    for i in range(len(pw)):
        amap.append([i, pw[i]])
    random.shuffle(amap)
    output = ''
    for e in amap:
        output += STAT(CHAFF(e[1]), x + e[0], y)
    return output


def level0():
    return f'''Welcome to the Terminal Velocity Server

Emoji? Back in my day we made do with only 7-bits for text and that was plenty.
None of these smiling poop faces. But wait, I hear you say -- there's all sorts
of new fancy attacks like text direction and homograph attacks so surely UTF is
more fun? Maybe, but do you really know what the simple terminal is capable of?

LEVEL 0 PASSWORD: Not the password.

Hopefully you have the right tool and this is trivial.''' + \
genl0pw(level0password + "                 ") + \
STAT("Enter the password: ",0, 12)

def level1():
    return f'''{FG("black") + FG("hidden")}The password is: {level1password}
{FG("normal") + FG("green") + FG("brightgreen")}LEVEL 1

Ok, now we're going to spice things up a tiny bit. How about this?

Enter the password: '''


def level2():
    return f'''
{CHAFF(level2password)}{ERASELINE()}
Ok, ok, you solved that one. It wasn't that hard though. Just copying and pasting can do it, right?
Fine. This is at least bit harder.

Enter the password: '''

spinner='\\|/-'

names=[]
with open("names.txt","r") as f:
    names = f.readlines()

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def CHECKICON(self):
        self.send("Feature check! There's a lot of cut-rate terminal emulators out there.\n")
        self.send("Let's see yours handles this particular feature.")
        self.send(ICONIFY())
        self.send("Press enter to continue.")
        #hide text:
        self.send(FG('hidden'))
        self.send(FG('black'))
        self.send(CSI + "11t")
        self.send(DEICONIFY())
        check = self.get()
        self.send(FG('normal'))
        self.send(FG('normal48'))
        self.send(ERASESCREEN())
        return check[0:4] == "\033[2t"

    def wait(self, count=30, delay=0.2):
        for x in range(count):
            self.send(spinner[x % len(spinner)])
            time.sleep(delay)
            self.send(BACKSPACE(1))


    def CHECKWINDOW(self):
        self.send(ERASESCREEN())
        self.draw(
'''
m     m #               m             "                    m    #
#  #  # # mm    mmm   mm#mm         mmm     mmm          mm#mm  # mm    mmm
" #"# # #"  #  "   #    #             #    #   "           #    #"  #  #"  #
 ## ##" #   #  m"""#    #             #     """m           #    #   #  #""""
 #   #  #   #  "mm"#    "mm         mm#mm  "mmm"           "mm  #   #  "#mm"




        mmmm    m mm   mmm   mmmm    mmm    m mm          mmm    mmm    m mm
        #" "#   #"  " #" "#  #" "#  #"  #   #"  "        #   "  #"  "   #"  "
        #   #   #     #   #  #   #  #""""   #             """m  #       #
        ##m#"   #     "#m#"  ##m#"  "#mm"   #            "mmm"  "#mm"   #
        #                    #
        "                    "

                                      "                    mmm
  mmm    mmm   m mm           mmm   mmm    mmmmm   mmm    "   #
 #"  #  #"  #  #"  #         #   "    #       m"  #"  #    m#"
 #""""  #""""  #   #          """m    #     m"    #""""    "
 "#mm"  "#mm"  #   #         "mmm"  mm#mm  #mmmm  "#mm"    #

Press enter to continue. 
''')
        self.send(GOTO(24,30))
        self.send(FG('normal'))
        self.send(FG('black'))
        self.send(BG('black'))
        self.send(FG('hidden'))
        self.send(CSI + '18t')
        self.send(INVISIBLE())
        check = self.get()
        width=check.strip()[:-1].split(";")[-1]
        height=check.split(";")[1]
        self.send(FG('normal'))
        self.send("Querying ")
        self.wait()
        self.send(ERASESCREEN())
        if DEBUG:
            print(f"\tWidth: {width}, height: {height}")
        return (width, height)

    def draw(self, screen):
        out = ''
        amap = []
        screen = screen.split('\n')
        max = 0
        for row in range(len(screen)):
            for col in range(len(screen[row])):
                amap.append([row + 1, col + 1, screen[row][col]])
        random.shuffle(amap)
        for coord in amap:
            out += STAT(CHAFF(coord[2]), coord[1], coord[0])
        self.send(out)

    def sendandwait(self, msg):
        if isinstance(msg, str):
            msg = bytes(msg, 'utf8')
        self.request.sendall(msg)
        self.send("\n\nPress enter to continue.")
        check = self.get()

    def send(self, msg):
        if isinstance(msg, str):
            msg = bytes(msg, 'utf8')
        self.request.sendall(msg)

    def get(self):
        return str(self.request.recv(256), 'utf8')

    def wrong(self, msg = "I'm sorry, you are apparently not ready for this challenge."):
        self.send(ERASESCREEN())
        self.send(EXITALT())
        self.send(ERASESCREEN())
        self.send(msg)

    def handle(self):
        try:
            self.peer = self.request.getpeername()[0]
            self.request.settimeout(30)
            if DEBUG:
                print(f'Connection from {self.peer}')
            random.seed(time.time() + random.randint(0, 2**32)) #bad random, but don't really care, it's good enough, just want it different per thread
            self.send(EXITALT())
            self.send(ALTSCREEN())
            self.send(INIT())

            self.send(ERASESCREEN())
            self.send(level0())
            level0answer = self.get().strip()
            if level0answer != level0password:
                self.wrong()
                return
            print(f'\t{self.peer} solved level 0.')

            (width, height) = self.CHECKWINDOW();
            self.send(ERASESCREEN())
            if int(width) > 0 and int(height) > 0:
                if (width, height) == ("80", "24"):
                    self.sendandwait("Correct! The original size for a terminal, it's just right.")
                else:
                    if (int(width) * int(height)) > 80*40:
                        self.wrong("Sorry, no, that's are too big. ಠ_ಠ")
                        return
                    else:
                        self.wrong("No, that's too small. Who even uses a terminal that little?")
                        return
            else:
                self.wrong(f'''What kind of cheap terminal are you even 
                running over there? Can't even report size...''')
                return


            self.send(level1())
            level1answer = self.get().strip()
            if level1answer != level1password:
                self.wrong()
                return
            print(f'\t{self.peer} solved level 1.')

            if not self.CHECKICON():
                self.wrong()
                return
            self.sendandwait("Congratulations! You've got a pretty fancy terminal there!")

            self.send(ERASESCREEN())

            self.send(level2())
            level2answer = self.get().strip()
            if level2answer != level2password:
                self.wrong()
                return



            self.send(EXITALT())
        except socket.timeout:
            self.send(ERASESCREEN())
            self.send(EXITALT())
            self.send(ERASESCREEN())
            self.send('\n\nTimeout, closing connection.\n')
            pass
        except IOError as e:
            if e.errno == errno.EPIPE:
                pass
            else:
                raise


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def interact():
    try:
        #Better testing if available
        from IPython import embed
        embed(colors='neutral')
    except:
        import code
        code.InteractiveConsole(locals=globals()).interact()

def client(ip, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.sendall(bytes(message, 'ascii'))
        response = str(sock.recv(1024), 'ascii')
        print('Received: {}'.format(response))

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        interact()
        sys.exit(0)
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = '0.0.0.0', 3535
    ThreadedTCPServer.allow_reuse_address = True
    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    server.serve_forever()
