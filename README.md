# Keepass4Me
***

## Description
Keepass .kdbx master password cracker (ver. 4 .kdbx files included).

## Installation
    $ git clone https://gitlab.sensepost.com/teddy.thobane/keepass4me.git
    $ cd Keepass4Me
    $ pip -r requirements

## Usage
    usage: k4me.py [-h] file wordlist threads

    Keepass (.kdbx) database password cracker

    positional arguments:
    file        The .kdbx file to crack.
    wordlist    The wordlist to use in the attack.
    threads     The number of concurrent threads with which to run the attack.

    optional arguments:
    -h, --help  show this help message and exit
