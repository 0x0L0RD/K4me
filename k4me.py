#!/usr/bin/python3

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from pykeepass import PyKeePass
from sys import argv
from os import path, remove
from joblib import Parallel, delayed
from threading import Thread
from tqdm import tqdm
from datetime import datetime
from time import time

PROG_NAME = "k4me.py"
DESC = "Keepass (.kdbx) database password cracker"
SUCCESS_FILE = "./kdbxPassword.txt"
STATUS_SUCCESS = 0
STATUS_BAD_PARAMS = 1
STATUS_FAILURE = -1
STATUS_INTERRUPT = 2

def attack_thread(dictionary: list, dbFile:str, thread_number:int):
    start_time = datetime.fromtimestamp(time())
    print(f"Thread {thread_number} started.")

    for word in dictionary:
        if path.exists(SUCCESS_FILE):
            exit(STATUS_SUCCESS)

        bullet = word.strip()

        try:
            _ = PyKeePass(dbFile, bullet)
            total_time = datetime.fromtimestamp(time()) - start_time
            print(f"\n\033[1m[*] Passphrase found!!\033[0m\n\tPASSPHRASE: \033[32;1;4m{bullet}\033[0m\n\tTime taken: {total_time.total_seconds()} seconds.")
            
            with open(SUCCESS_FILE, "w+") as f:
                f.write(f"{bullet}\n")
            
            exit(STATUS_SUCCESS)

        except:
            continue
    
    if not path.exists(SUCCESS_FILE):
        total_time = datetime.fromtimestamp(time()) - start_time
        print(f"[i] Thread {thread_number}:{(' '*(5 - len(str(thread_number))))} \033[1mEXHAUSTED\033[0m\n\tTime taken: {total_time.total_seconds()} seconds.")

    return STATUS_FAILURE

def initiate_attack_asynchronous(kdbFileName:str, wordlistFile:str, thread_count:int):
    num_lines = 0
    thread_number = 1
    fileStream = open(wordlistFile,'r', encoding="latin-1")

    for _ in fileStream:
        num_lines += 1 

    max_size = int(num_lines / thread_count)
    
    print("[i] Processing wordlist...")

    fileStream.seek(0,0)
    sub_list = []
    
    for _ in tqdm(range(0, num_lines)):
        word = fileStream.readline().strip()
        if len(sub_list) == max_size:
            next_thread = Thread(target=attack_thread, args=(sub_list, kdbFileName, thread_number))
            thread_number += 1
            sub_list = []
            next_thread.start()
        
        sub_list.append(word)

    fileStream.close()
    print("All threads have been initialized. Now we wait.")

def initiate_attack_synchronous(kdbFileName:str, wordlistFile:str, thread_count:int):
    sub_wordlists = []

    num_lines = 0

    fileStream = open(wordlistFile,'r', encoding="latin-1")

    for _ in fileStream:
        num_lines += 1 

    max_size = int(num_lines / thread_count)

    print("[i] Processing wordlist...")

    fileStream.seek(0,0)
    sub_list = []
     
    for _ in tqdm(range(0, num_lines)):
        word = fileStream.readline().strip()
        if len(sub_list) == max_size:
            sub_wordlists.append(sub_list)
            sub_list = []
        
        sub_list.append(word)
    
    if len(sub_list) > 0:
        sub_wordlists.append(sub_list)
        sub_list = []

    
    print(f"[+] Wordlist processed successfully!\n[i] Preparing threads, initializing brute-force attack...")

    Parallel(n_jobs=thread_count)(delayed(attack_thread)(w, kdbFileName, sub_wordlists.index(w)+1) for w in tqdm(sub_wordlists))
    
def main():
    try:
        sync = True
        argParser = ArgumentParser(prog=PROG_NAME, description=DESC, formatter_class=ArgumentDefaultsHelpFormatter,)
        argParser.add_argument("file", type=str, help="The .kdbx file to crack.")
        argParser.add_argument("wordlist", type=str, help="The wordlist to use in the attack.")
        argParser.add_argument("threads", type=int, help="The number of concurrent threads with which to run the attack.", default=2)
        argParser.add_argument("synchronism", type=str, help="Indicates whether the threads start 'synchronously' or 'asynchronously' ('s' or 'a').", default="s")

        if len(argv) < 4:
            argParser.print_help()
            exit(STATUS_BAD_PARAMS)

        args = argParser.parse_args()

        if not path.exists(args.file):
            print(f"[-] Error: Keepass Database file '{args.file}' does not exist.")
            exit(STATUS_FAILURE)

        elif not path.exists(args.wordlist):
            print(f"[-] Error: Wordlist file '{args.wordlist}' does not exist.")
            exit(STATUS_FAILURE)

        elif not args.synchronism in ["s", "a"]:
            print(f"[-] Invalid synchronism argument.")
            exit(STATUS_BAD_PARAMS)
        
        if not args.synchronism == "s":
            sync = False

        if path.exists(SUCCESS_FILE):
            remove(SUCCESS_FILE)

        print(f"[i] Initializing...")

        if sync:
            initiate_attack_synchronous(args.file, args.wordlist, args.threads)
        else:
            initiate_attack_asynchronous(args.file, args.wordlist, args.threads)
    except KeyboardInterrupt:
        print("[*] Keyboard Interrupt detected. Quitting...")
        exit(STATUS_INTERRUPT)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
