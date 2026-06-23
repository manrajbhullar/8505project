import subprocess
import pexpect
import sys

username = "bcit"
password = "manraj"

# Create the user
try:
    subprocess.run(
        ["useradd", "-m", username],
        check=True
    )
    print(f"User '{username}' created.")
except subprocess.CalledProcessError as e:
    print(f"useradd failed: {e}")
    sys.exit(1)

# Set the password using passwd and pexpect
try:
    child = pexpect.spawn(f"passwd {username}")

    child.expect("New password:")
    child.sendline(password)

    child.expect("Retype new password:")
    child.sendline(password)

    child.expect(pexpect.EOF)

    print("Password set successfully.")

except pexpect.exceptions.ExceptionPexpect as e:
    print(f"passwd failed: {e}")