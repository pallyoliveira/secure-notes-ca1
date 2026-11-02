"""
BLOCK: Application — command-line menu
SLOT:  app            (every app needs exactly one app block)

The part the user actually sees. Run it with:   python app.py

It deliberately contains no security logic of its own. It asks the auth block
whether a login succeeded and the storage block for the data. Keeping the
interface separate from the rules is good design and makes both easier to
reason about — which is itself worth a paragraph in your report.
"""

import getpass
import os
import sys

# This block needs nothing beyond Python itself, so the list is empty. The
# call is here anyway so that every app block starts the same way — if you
# write your own block that needs a package, add it to the list and the
# behaviour is already built.
import _preflight

if not _preflight.ensure([]):
    sys.exit(1)

import storage
import auth
import validate
import audit
import logging

logging.basicConfig(
    filename="error.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

BLOCK_NAME = "App: command-line menu"

# Which user is signed in right now. None means nobody.
# This lives in memory only, so closing the program signs you out.
current_user = None


# ---------------------------------------------------------------- appearance
# Terminals colour text using "ANSI escape codes" — short sequences starting
# with \033[ that the terminal reads as instructions rather than printing.
#
# Not every terminal understands them, and when output is piped to a file
# they turn into visible rubbish. So we check first and fall back to plain
# text. Writing output that adapts to where it is going is a small habit with
# a big payoff.
def _colour_supported():
    if os.environ.get("NO_COLOR"):          # a convention many tools respect
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    # isatty() is False when output is redirected to a file or another program.
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


COLOUR = _colour_supported()


def c(text, code):
    """Wrap text in a colour, or return it unchanged if colour is unavailable."""
    return f"\033[{code}m{text}\033[0m" if COLOUR else text


def bold(t):   return c(t, "1")
def dim(t):    return c(t, "2")
def green(t):  return c(t, "32")
def red(t):    return c(t, "31")
def amber(t):  return c(t, "33")
def blue(t):   return c(t, "36")


def rule(width=56):
    print(dim("  " + "─" * width))


def banner():
    """The title block shown once at startup."""
    print()
    print("  " + c("╭" + "─" * 54 + "╮", "36"))
    print("  " + c("│", "36") + bold("  SECURE NOTES".ljust(54)) + c("│", "36"))
    print("  " + c("│", "36") + dim("  a small application with authentication".ljust(54)) + c("│", "36"))
    print("  " + c("╰" + "─" * 54 + "╯", "36"))


def ok(msg):
    print("  " + green("✓ ") + msg)


def fail(msg):
    print("  " + red("✗ ") + msg)


def info(msg):
    print("  " + blue("· ") + msg)


def menu(title, options):
    """Draw a boxed menu and return the key the user typed.

    options is a list of (key, label) pairs. Keeping the drawing in one place
    means every menu looks the same without repeating the code.
    """
    print()
    rule()
    print("  " + bold(title))
    rule()
    for key, label in options:
        print(f"   {c(key, '36;1')}  {label}")
    rule()
    return input("  " + bold("> ")).strip().lower()


# Blocks whose names contain any of these are the deliberately weak ones.
# The app flags them so a screenshot of your running program shows plainly
# which version you built. That is useful evidence for your report.
WEAK_MARKERS = ("PLAIN TEXT", "without salt", "none", "no rate limiting")


def show_blocks():
    """Print which blocks were assembled, flagging the weak choices."""
    import passwords
    print()
    print("  " + bold("Assembled from"))
    rule()
    weak_count = 0
    for slot, module in (("storage", storage), ("passwords", passwords),
                         ("validate", validate), ("auth", auth), ("audit", audit)):
        name = getattr(module, "BLOCK_NAME", module.__name__)
        is_weak = any(m.lower() in name.lower() for m in WEAK_MARKERS)
        if is_weak:
            weak_count += 1
            mark, shown = red("!"), amber(name)
        else:
            mark, shown = green("•"), name
        print(f"   {mark} {dim(slot.ljust(10))} {shown}")
    rule()
    if weak_count:
        print("  " + red(f"! {weak_count} deliberately weak block(s) in this build."))
        print("  " + dim("  Good for seeing the problem. Not what you submit."))
        print("  " + dim("  Rebuild with:  python build.py --preset safe"))
    else:
        print("  " + green("✓ No deliberately weak blocks in this build."))


def do_register():
    print()
    print("  " + bold("Create an account"))
    rule()
    username = input("  Username: ").strip()
    # getpass hides typing, so the password does not sit on screen or in your
    # terminal's scrollback. input() would show it.
    password = getpass.getpass("  Password: ")
    good, message = auth.register(username, password)
    (ok if good else fail)(message)


def do_login():
    global current_user          # we are changing the variable defined above
    print()
    print("  " + bold("Sign in"))
    rule()
    username = input("  Username: ").strip()
    password = getpass.getpass("  Password: ")
    good, message = auth.login(username, password)
    (ok if good else fail)(message)
    if good:
        current_user = username


def do_logout():
    global current_user
    if current_user:
        audit.record("logout", current_user)
    current_user = None
    ok("Signed out.")


def safe_terminal_text(text):
    """Remove control characters before displaying text in the terminal."""
    return "".join(char for char in str(text) if char.isprintable())


def do_list():    
    items = storage.list_items(current_user)
    print()    
    if not items: 
        print(" " + dim("You have no notes yet. Choose 2 to add one.")) 
        return 
    print(" " + bold(f"Your notes") + dim(f" ({len(items)})")) 
    rule() 
    # Display notes using sequential positions instead of database IDs. 
    for position, item in enumerate(items): 
        number = c(str(position + 1).rjust(3), "36;1") 
        print(f" {number} {safe_terminal_text(item['text'])}") 
    rule() 

def save_note(user, original_text, text):
    try:
        if original_text != text:
            raise ValueError("Invalid characters")

        good, message = validate.item_text(text)
        if not good:
            raise ValueError(message)
        return storage.add_item(user, text)

    except ValueError as error:
        fail(str(error))
        return None

    except Exception:
     logging.exception("Failed to save note")
     fail("Could  not save the note. Please try again.")
    return None

def do_add():
    print()
    original_text = input("  " + bold("New note: ")).strip()
    text = safe_terminal_text(original_text)
    item_id = save_note(current_user, original_text, text)
    if item_id is None:
        return
    audit.record("item_added", current_user, f"id={item_id}")
    ok(f"Saved as note.")

def do_delete():
    print()

    items = storage.list_items(current_user)

    if not items:
        fail("You have no notes to delete.")
        return

    do_list()

    raw = input("  " + bold("Delete which note number? ")).strip()

    if not raw.isdigit():
        fail("Please enter a number.")
        return

    position = int(raw)

    # Find the correct note using the user's position
    selected_item = next(
        (item for item in items if item["position"] == position),
        None
    )
  

    if selected_item is None:
        fail("No note with that number.")
        print(f"Selected item: {selected_item}")  # Debugging line
        return

    # Get the real database ID of that note
    item_id = selected_item["id"]

    if storage.delete_item(current_user, item_id):
        audit.record(
            "item_deleted",
            current_user,
            f"id={item_id}, position={position}"
        )
        ok("Deleted.")
    else:
        fail("Could not delete the note.")
        

def main():
    # PRINCIPLE: Economy of mechanism — this file draws menus and reads input.
    # It contains no security decisions at all; it asks auth and storage, and
    # believes their answers. Small pieces with one job each are easier to
    # reason about, and a security review can skip this file almost entirely.
    storage.init()
    banner()
    show_blocks()

    while True:
        if current_user is None:
            choice = menu("Not signed in", [
                ("1", "Register a new account"),
                ("2", "Sign in"),
                ("q", "Quit"),
            ])
            if choice == "1":
                do_register()
            elif choice == "2":
                do_login()
            elif choice == "q":
                print("\n  " + dim("Bye.\n"))
                return
            else:
                fail("Unknown option.")
        else:
            count = len(storage.list_items(current_user))
            choice = menu(f"Signed in as {green(current_user)}" + dim(f"   {count} note(s)"), [
                ("1", "List notes"),
                ("2", "Add a note"),
                ("3", "Delete a note"),
                ("4", "Sign out"),
                ("q", "Quit"),
            ])
            if choice == "1":
                do_list()
            elif choice == "2":
                do_add()
            elif choice == "3":
                do_delete()
            elif choice == "4":
                do_logout()
            elif choice == "q":
                do_logout()
                print("\n  " + dim("Bye.\n"))
                return
            else:
                fail("Unknown option.")


# This line means "only run main() if this file was started directly".
# If something imports it instead, nothing happens. It is standard Python.
if __name__ == "__main__":
    main()
