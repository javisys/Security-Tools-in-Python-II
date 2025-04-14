# Javier Ferrándiz Fernández | https://github.com/javisys
import hashlib
import argparse
import time
from tqdm import tqdm
import os
import sys

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception as e:
        print(f"An error occurred while checking for administrative privileges: {e}")
        return False

def crack_hash(hash_to_crack, dictionary_file, hash_algorithm="sha256"):
    try:
        with open(dictionary_file, "r") as words:
            for word in tqdm(words, desc="Cracking hash"):
                word = word.strip()
                hash_object = hashlib.new(hash_algorithm)
                hash_object.update(word.encode())
                if hash_object.hexdigest().lower() == hash_to_crack.lower():
                    print(f"\nHash found! The word is: {word}")
                    return
        print("\nHash not found in dictionary")
    except FileNotFoundError:
        print(f"The file {dictionary_file} not found")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    if not is_admin():
        print("This script must be run as an administrator.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Crack hashes using a dictionary file.")
    parser.add_argument("hash", help="The hash to crack.")
    parser.add_argument("dictionary", help="The dictionary file to use.")
    parser.add_argument("-a", "--algorithm", default="sha256", help="The hash algorithm to use (default: sha256).")
    
    args = parser.parse_args()
    
    start_time = time.time()
    crack_hash(args.hash, args.dictionary, args.algorithm)
    end_time = time.time()
    
    print(f"Execution time: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
