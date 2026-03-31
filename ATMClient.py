"""CLI wrapper around the reusable ATM protocol client."""

import sys

from secure_banking.protocol import ATMProtocolClient


def get_valid_amount(prompt: str) -> float:
    while True:
        value = input(prompt).strip()
        try:
            amount = float(value)
        except ValueError:
            print("Invalid input. Please enter a valid number (e.g., 100.50).")
            continue

        if amount <= 0:
            print("Amount must be greater than 0. Try again.")
            continue

        return amount


def phase3_menu(client: ATMProtocolClient, my_id: str) -> None:
    while True:
        if not client.authenticated:
            print("\n1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose an option: ").strip()

            if choice == "1":
                username = input("Enter username: ").strip()
                email = input("Enter email: ").strip()
                password = input("Enter password: ").strip()
                print(f"[{my_id}] Server response: {client.register(username, email, password)}")
            elif choice == "2":
                email = input("Enter email: ").strip()
                password = input("Enter password: ").strip()
                print(f"[{my_id}] Server response: {client.login(email, password)}")
            elif choice == "3":
                client.close(send_exit=True)
                break
            else:
                print("Invalid option.")
        else:
            print("\n1. Balance")
            print("2. Deposit")
            print("3. Withdraw")
            print("4. Logout")
            choice = input("Choose an option: ").strip()

            if choice == "1":
                print(f"[{my_id}] Server response: {client.balance()}")
            elif choice == "2":
                amount = get_valid_amount("Enter deposit amount: ")
                print(f"[{my_id}] Server response: {client.deposit(amount)}")
            elif choice == "3":
                amount = get_valid_amount("Enter withdrawal amount: ")
                print(f"[{my_id}] Server response: {client.withdraw(amount)}")
            elif choice == "4":
                print(f"[{my_id}] Server response: {client.logout()}")
            else:
                print("Invalid option.")


def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: python ATMClient.py "Client A"')
        sys.exit(1)

    my_id = sys.argv[1]
    client = ATMProtocolClient()
    print(f"---- ATM Client [{my_id}] ----\n")
    try:
        status = client.connect(my_id)
        print(f"[{my_id}] Secure session established: {status['protocolSummary']}")
        phase3_menu(client, my_id)
    finally:
        if client.sock is not None:
            client.close(send_exit=False)


if __name__ == "__main__":
    main()
