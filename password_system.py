"""Interactive CLI for the password protection system.

Run with:
    python password_system.py

All I/O lives here; the actual account logic (hashing, lockout, persistence)
is in account_system.py and is unit tested separately.
"""

from getpass import getpass

from account_system import AccountSystem, AccountError, MIN_PASSWORD_LENGTH


def create_account_flow(system):
    username = input("Enter a username: ")
    password = getpass(f"Create a password (min {MIN_PASSWORD_LENGTH} characters): ")
    question = input("Set a security question (used for password recovery): ")
    answer = getpass("Answer to your security question: ")
    try:
        system.create_account(username, password, question, answer)
        print("Account created successfully!")
    except AccountError as e:
        print(f"Error: {e}")


def login_flow(system):
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")
    try:
        if system.login(username, password):
            print(f"Welcome, {username}! Login successful.")
        else:
            print(f"Incorrect password. Attempts left: {system.remaining_attempts(username)}")
    except AccountError as e:
        print(f"Error: {e}")


def reset_password_flow(system):
    username = input("Enter your username to reset password: ")
    try:
        question = system.get_security_question(username)
    except AccountError as e:
        print(f"Error: {e}")
        return
    print(f"Security question: {question}")
    answer = getpass("Your answer: ")
    new_password = getpass(f"Enter a new password (min {MIN_PASSWORD_LENGTH} characters): ")
    try:
        system.reset_password(username, answer, new_password)
        print("Password reset successfully. You can now log in.")
    except AccountError as e:
        print(f"Error: {e}")


def main():
    system = AccountSystem()
    while True:
        print("\n<<< ACCOUNT SYSTEM >>>")
        print("1. Create Account")
        print("2. Login")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            create_account_flow(system)
        elif choice == "2":
            login_flow(system)
        elif choice == "3":
            reset_password_flow(system)
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()
