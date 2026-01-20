# LoginRegisterAuth

A Framework for Blockchain-Based Anonymous and Revocable User Authentication Scheme.

## Github Repository

[https://github.com/Ahmad1234567/BAAR-A-FRAMEWORK-FOR-BLOCKCHAIN-BASED-ANONYMOUS-AND-REVOCABLE-USER-AUTHENTICATION-SCHEME.git](https://github.com/Ahmad1234567/BAAR-A-FRAMEWORK-FOR-BLOCKCHAIN-BASED-ANONYMOUS-AND-REVOCABLE-USER-AUTHENTICATION-SCHEME.git)

## Prerequisites

*   **Python 3.9.13**: It is required to install Python version 3.9.13 for this project to run properly.
*   **Ganache**: A local blockchain for Ethereum development. Ensure it is running on `http://127.0.0.1:7545`.

## Installation

1.  Navigate to the project directory:
    ```bash
    cd "D:\1 - PHD\LoginRegisterAuth"
    ```

2.  (Optional) Create and activate a virtual environment:
    ```bash
    python -m venv venv
    # Windows
    .\venv\Scripts\activate
    ```

3.  Install the required dependencies:
    ```bash
    pip install -r requirements.lock.txt
    ```

## Running the Application

1.  Start your Ganache workspace. Ensure it is listening on port `7545`.

2.  Run the main application script:
    ```bash
    python main3.py
    ```

3.  The application will start on port `5001`.
    *   Server URL: `http://127.0.0.1:5001`

## Usage

The application provides a Flask API for user authentication using Ethereum smart contracts.

### Main Endpoints

*   **POST** `/register`: Register a new user.
*   **POST** `/login`: Login a user.
*   **POST** `/anonymous_login`: Login anonymously.
*   **POST** `/add_admin`: Add a new admin (Admin only).
*   **POST** `/revoke_access`: Revoke a user's access (Admin only).
*   **GET** `/get_all_users`: List all registered users (Admin only).

Refer to the source code in `main3.py` for more details on the available endpoints and their parameters.
