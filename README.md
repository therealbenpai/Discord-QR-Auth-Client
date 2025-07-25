# Discord QR Auth Client

A simple client for Discord QR authentication. This client allows you to authenticate with Discord using a QR code, making the process quick and easy.

## Features

- Scan QR codes to log in to Discord
- Lightweight and easy to use
- Built with Python
- Get a user token for the authenticated user for usage in other applications
- Supports multiple platforms

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/therealbenpai/Discord-QR-Auth-Client.git
    cd Discord-QR-Auth-Client
    ```

2. Create a virtual environment:

    ```bash
    python -m venv .venv
    ```

3. Activate the virtual environment:

    - On Windows:

        ```bash
        .venv\Scripts\activate
        ```

    - On macOS/Linux:

        ```bash
        source .venv/bin/activate
        ```

4. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

5. Run the client:

    ```bash
    python main.py
    ```

## Usage

1. Start the client by running `python main.py`.
2. A QR code will be displayed on the screen.
3. Open the Discord app on your mobile device and navigate to the login screen.
4. Select "Scan QR Code" and point your device's camera at the QR code displayed
    on your computer.
5. Once scanned, the client will authenticate and retrieve your user token.
6. The user token will be printed to the console for use in other applications.

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, feel free to open
    an issue or submit a pull request.
