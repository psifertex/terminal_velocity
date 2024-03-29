# Terminal Velocity

Misc CTF Challenge for CSAW Finals 2021

This is a challenge I've had in mind for almost 15 years and never got around to building until now. It (ab)uses a number of terminal escape codes to trigger both legitimate and scary and potentially dangerous terminal features, many of which are enabled by default in modern terminals! While a number of more serious exploits were patched in terminals since this original idea (it used to be trivial to kill many terminals with such escapes as "move cursor left 2^32 times or other similar ridiculous instructions), but most of the remaining shenanigans are merely abusing "legitimate" features that maybe are undesirable when simply viewing a text file or connecting to a network socket.

It's worth noting that because this service uses the usual netcat connection from clients, it will be line-buffered. This prevents some more egregious abuse of terminal escapes and requires some slight trickery to receive the return escape codes as hidden parts of existing responses during the various "press enter to continue" or similar prompts. Using something like telnet or ssh would fix this and allow for even more dangerous terminal manipulations.

Part of the goal of this challenge is to encourage people to be a bit more careful even when taking actions they might otherwise consider benign. Text should be considered harmful. 

# Deploying / Running

```
$ docker build -t terminal .
$ docker run -it -p 3535:3535 terminal
```

Or just run `python3 service.py` and connect to your local machine on port 3535.

## Solutions

Two play-testers provided (partial) solutions which needs some tweaks for the final updates. This writeup covers the main tasks:

### Level 0

When you first connect to the server you simply see a password (`Level 0 Is Really Easy`) which when pasted is indeed, correct.

The only tricky thing is if you try to sniff the connection or use a non-terminal to access it, you'll see that the password is originally something else that is overwritten.

### Screen Check

After solving level 0, you will be asked "What is the proper screen size"? Some people may simply know the default terminal size is 80x24 and adjust accordingly, but if not, the server helpfully tells you whether your terminal was too big or too small after verifying that it can read your screen dimensions. If you're not running a real terminal, you'll need to learn to fake the correct response.

### Level 1

Level one simply prints the password out in a black text on a black background. You can simply copy/paste it from the terminal _but_ if you try to view it from the raw network traffic you will see that it is interspersed with unrelated escape codes that you have to filter out. 

Correct pass: `G1V3M3TH3N3XTL3V3L`

### Feature Check: Iconify

The next check will attempt to icnoify your terminal and query the status of the terminal (it also has the side effect of querying a user's iTerm current profile name). Correct approaches to solving this usually involve analyzing the query string that is sent and finding what is being looked up. Note that some VT100 references will give misleading answers and the [oracle](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html) should always be consulted (if people get stuck I'd give this as a hint out since it's a better reference. All references are painfully hard to search though which is hilarious.)

Note: if you don't have a terminal capable of following this live (Terminal.app is the only one I know that does it all correctly) and you don't want to write a terminal emulator/manual interaction script (definitely the right approach for what's coming next), then you can work around it by just pressing backspace twice and entering `2t` before pressing enter.


### Level 2

Level two is similar except the line of correct text is erased after rendered. An emulator that simulates specific character drawing will be able to recover the text, or a filter that blocks the "erase" escape codes (though there are several used) can work here.

Correct password: `HalfwayDone`


## Level 3

Level three is pretty nasty (the user is warned though!)

It will attempt to do all sorts of nasty things to their terminal including printing locking the prompt, crashing it with bogus operations. One printer accidentally spewed out paper and one Windows machine blue screened during the testing of these features, so this can be tough! (The printer bug was fixed with all the aforementioned iTerm detection above ). By this point users should be _strongly_ considering not directly interacting with the port but using pwntools with heavy filtering or some other method. (Fun fact, Windows terminal actually looks _super_ robust against these sorts of shenanigans and the developers even built an entire fuzzing harness that really needs to be run against all other major browsers which still have many bugs).

Anyway, for players who have been building a very simply terminal emulator to this point, just having the ability to emulate three different cases of move and draw commands will let them re-create the correct text for this level.

Correct password: `BobTheBuilder`

### Level 4

The final level brings image formats! Yup, there are actually many different valid forms of images that can be displayed in terminals. Though, if I've done my job correctly, the previous level will have broken or rendered useless most of the terminals that otherwise could just show the images directly.

The three images that are displayed are:
1) Simple base64 encoded file in iTerm image format
2) A [sixel](https://en.wikipedia.org/wiki/Sixel)
and
3) A Tektronix image

There are several different approaches/tools to solving the last two images. Just using a compatible terminal and separately cat'ing the file after extracting them from the session is sufficient. 

xTerm has the only support for the final Tektronix image format I have found. When assembled, the images reveal the final passcode: `PINEY_FLATS_TN_USA` a random city with no meaning at all behind it.


Entering the final password reveals the flag for the challenge!

Hopefully people have a lot more respect about what their terminals are capable of after working on this challenge and maybe even take more care when randomly connecting to servers on the internet. 

