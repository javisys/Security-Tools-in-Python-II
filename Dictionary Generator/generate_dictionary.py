# Javier Ferrándiz Fernández | https://github.com/javisys
import argparse
import time
from itertools import product
from tqdm import tqdm

def generate_dictionary(words, max_length, output_file, include_specials=False, include_numbers=False, prefix="", suffix="", case_sensitive=False):
    characters = words
    if include_specials:
        characters += "!@#$%^&*()-_=+[]{}|;:'\",.<>?/\\`~"
    if include_numbers:
        characters += "0123456789"
    if not case_sensitive:
        characters = ''.join(set(characters.lower() + characters.upper()))

    with open(output_file, "w") as f:
        for length in range(1, max_length + 1):
            for combo in tqdm(product(characters, repeat=length), desc=f"Generating length {length}"):
                f.write(prefix + "".join(combo) + suffix + "\n")

def main():
    parser = argparse.ArgumentParser(description="Generate a dictionary file with specified parameters.")
    parser.add_argument("words", help="The base words or characters to use for generating the dictionary.")
    parser.add_argument("max_length", type=int, help="The maximum length of the generated words.")
    parser.add_argument("output_file", help="The output file to save the generated dictionary.")
    parser.add_argument("-s", "--specials", action="store_true", help="Include special characters in the dictionary.")
    parser.add_argument("-n", "--numbers", action="store_true", help="Include numbers in the dictionary.")
    parser.add_argument("-p", "--prefix", default="", help="Prefix to add to each generated word.")
    parser.add_argument("-x", "--suffix", default="", help="Suffix to add to each generated word.")
    parser.add_argument("-c", "--case_sensitive", action="store_true", help="Make the dictionary case sensitive.")
    
    args = parser.parse_args()
    
    start_time = time.time()
    generate_dictionary(args.words, args.max_length, args.output_file, args.specials, args.numbers, args.prefix, args.suffix, args.case_sensitive)
    end_time = time.time()
    
    print(f"Dictionary generation completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
