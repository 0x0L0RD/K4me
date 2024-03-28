# Keepass4Me
***

## Description
Keepass .kdbx master password cracker (ver. 4 .kdbx files included).

## Installation
    $ git clone https://gitlab.sensepost.com/teddy.thobane/keepass4me.git
    $ cd Keepass4Me
    $ pip -r requirements

## Usage
    k4me.py [-h] file wordlist threads synchronism

    Keepass (.kdbx) database password cracker

    positional arguments:
    file         The .kdbx file to crack.
    wordlist     The wordlist to use in the attack.
    threads      The number of concurrent threads with which to run the attack.
    synchronism  Indicates whether the threads start 'synchronously' or 'asynchronously' ('s' or 'a').

    options:
    -h, --help   show this help message and exit
