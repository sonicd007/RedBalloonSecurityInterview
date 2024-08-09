# Solution Package

## Setup Instructions

To set up the virtual environment, source it, install the requirements, and run the application, follow these steps:

### Step 1: Set up the Virtual Environment

1. Navigate to the project directory:
    ```bash
    cd ./src
    ```

2. Create a virtual environment:
    ```bash
    python3 -m venv venv
    ```

3. Activate the virtual environment:
    - On Linux/macOS:
        ```bash
        source venv/bin/activate
        ```
    - On Windows:
        ```bash
        .\venv\Scripts\activate
        ```

### Step 2: Install the Requirements

1. Navigate to the `src` directory:
    ```bash
    cd src
    ```

2. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

### Step 3: Run the Application

1. Run the application:
    ```bash
    python verify.py
    ```

## Project Structure

- **docs**: Contains writeup information.
  - `design_choice.html`: Document detailing design choices.
  - `ServerArchitecture.png`: Image depicting server architecture.
  - `verify_checksums.html`: Document explaining checksum verification.
  - `verify_digital_signature.html`: Document explaining digital signature verification.
  - `writeup.html`: General writeup.
  
- **src**: Contains the solution files.
  - `asn1_class_models/`: Directory containing ASN.1 class models.
  - `challenge_packet.py`: Script for handling challenge packets.
  - `checksum_handler.py`: Script for checksum handling.
  - `checksum_tracker.py`: Script for tracking checksums.
  - `clear_data_files.sh`: Script for clearing data files.
  - `crypto_operations.py`: Script for cryptographic operations.
  - `file_data_checksums.py`: Script for file data checksums.
  - `generic_error.py`: Script for handling generic errors.
  - `packet_error.py`: Script for handling packet errors.
  - `packet_parser.py`: Script for parsing packets.
  - `requirements.txt`: List of required Python packages.
  - `server.py`: Script for server operations.
  - `verify.py`: Main script for verification.
  - `cat.jpg`, `key.bin`, `payload_dump.bin`: Supporting files for the solution.

- **Writeup.html**: The table of contents for the `docs` directory.

## Additional Information

- Ensure the virtual environment is activated whenever running scripts or installing packages.
- Refer to the `Table_of_contents.html` file in the root directory for a comprehensive overview of the documentation.

## Known Issues
line 379 in server.py is supposed to enable the multi processing to satisfy the asynchronous needs of client connection. Unfortunately I have an issue where the logs aren't being logged. Ideally if this bug was worked out then all aspects of the design should've been met

line 382 is what I used for local development to make it easier to debug and test. This works and gives the expected results. Unfortunately this is also synchronous and not multi process.

