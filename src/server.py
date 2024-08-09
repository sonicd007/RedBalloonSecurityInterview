import ast
import logging
import multiprocessing
import os
import pickle
import signal
import socket
import sys
import threading
import time
from logging.handlers import QueueHandler
import argparse
import zlib

from challenge_packet import ChallengePacket
from generic_error import GenericError
from packet_error import PacketError

CHECKSUM_FILE_PATH = "checksum_data.pkl"
UNSOLVED_CHECKSUMS_FILE_PATH = "unsolved_checksums.pkl"

def logger_process(queue, artificial_delay):
    """Function that logs messages from the queue."""
    checksum_logger = logging.getLogger("checksum")
    checksum_logger.setLevel(logging.INFO)
    checksum_handler = logging.FileHandler('checksum_failures.log')
    checksum_handler.setFormatter(logging.Formatter('%(message)s'))
    checksum_logger.addHandler(checksum_handler)

    generic_logger = logging.getLogger("server")
    generic_logger.setLevel(logging.DEBUG)
    generic_handler = logging.FileHandler('server_clients.log')
    generic_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    generic_logger.addHandler(generic_handler)
    
    signature_logger = logging.getLogger("signature")
    signature_logger.setLevel(logging.DEBUG)
    signature_handler = logging.FileHandler('verification_failures.log')
    signature_handler.setFormatter(logging.Formatter('%(message)s'))
    signature_logger.addHandler(signature_handler)
    
    generic_logger.debug("Logger Process is starting up.")
    
    while True:
        try:
            if queue.empty():
                time.sleep(0.01)
                continue
            
            record = queue.get(timeout=1)
            if record == "STOP":
                break
            if isinstance(record, PacketError):
                if hasattr(record, 'error_type'):
                    if artificial_delay:
                        time.sleep(artificial_delay)
                    if record.error_type == 'checksum':
                        if hasattr(record, 'error_message'):
                            checksum_logger.info(record.error_message)
                    elif record.error_type == 'signature':
                        if hasattr(record, 'error_message'):
                            signature_logger.info(record.error_message)
            elif isinstance(record, GenericError):
                if hasattr(record, 'error_type'):
                    if record.error_type == 'generic':
                        if hasattr(record, 'error_message'):
                            generic_logger.error(record.error_message)
            else:
                generic_logger.error("Unknown error type: %s" % str(record))
        except TimeoutError:
            time.sleep(0.01)
            pass
        except Exception as e:
            generic_logger.error("Logging process encountered an error: %s" % str(e))
    
    generic_logger.debug("Logger Process is shutting down.")
    # Ensure handlers are flushed and closed
    checksum_logger.removeHandler(checksum_handler)
    checksum_handler.close()
    signature_logger.removeHandler(signature_handler)
    signature_handler.close()
    generic_logger.removeHandler(generic_handler)
    generic_handler.close()

def handle_client(log_queue, checksum_queue, data, packet_key_mappings, packet_binary_mappings):
    """Handle incoming client packets."""
    try:
        packet = ChallengePacket(data)
    except ValueError as e:
        error_log_message = f"Packet parsing error: {e}"
        log_queue.put(GenericError(error_message=error_log_message))
        return

    id = packet.packet_parser.get_packet_id()
    public_key_file_name = packet_key_mappings.get(id)
    binary_file_name = packet_binary_mappings.get(id)

    if not public_key_file_name:
        error_log_message = f"No public key found for packet ID {id}. Skipping..."
        log_queue.put(GenericError(error_message=error_log_message))
        return

    if not binary_file_name:
        error_log_message = f"No binary file found for packet ID {id}. Skipping..."
        log_queue.put(GenericError(error_message=error_log_message))
        return

    try:
        with open(public_key_file_name, "rb") as public_key_file:
            public_key_binary_data = public_key_file.read()

            modulus_length = 64  # 512 bits / 8 bits per byte
            exponent_length = len(public_key_binary_data) - modulus_length

            modulus = int.from_bytes(public_key_binary_data[exponent_length:], byteorder='big')
            exponent = int.from_bytes(public_key_binary_data[:exponent_length], byteorder='big')

            error_log_message = f"No binary file found for packet ID {id}. Skipping..."
            print(f"Modulus is: {modulus}")
            print(f"Exponent is: {exponent}")
            packet.dump_packet_info()
            signed_hash = packet.get_signed_payload_hash(modulus, exponent)

            # Verify Authenticity
            if signed_hash == packet.expected_payload_hash:
                print("Signature is valid")
            else:
                print("Invalid signature. Logging...")
                error_log_message = f'{id}\n{packet.packet_parser.get_packet_sequence_number()}\n{signed_hash}\n{packet.expected_payload_hash}\n'
                log_queue.put(PacketError('signature', error_log_message))
                raise ValueError("Signed Hash does not match received payload")

            # Send checksum data off to processing queue
            checksum_processing_data = {
                "id": packet.packet_parser.get_packet_id(),
                "packet_sequence_number": packet.packet_parser.get_packet_sequence_number(),
                "XOR_key": packet.packet_parser.get_multibyte_repeating_xor_key(),
                "number_of_checksums": packet.packet_parser.get_number_checksums(),
                "checksum_blocks": packet.packet_parser.get_unencoded_checksum_blocks(),
                "binary_file_name": binary_file_name
            }
            
            # Add the checksums to our processing queue
            checksum_queue.put(checksum_processing_data)
            
    except Exception as ex:
        error_log_message = f"Error processing packet: {ex}"
        log_queue.put(GenericError(error_message=error_log_message))

    print(f"Processing data completed by process ID: {os.getpid()}")   

def load_data(file_path):
    """Loads data from a file if it exists."""
    if os.path.exists(file_path):
        with open(file_path, "rb") as file:
            return pickle.load(file)
    else:
        return {}

def update_data(file_path, data):
    """Updates a file with the provided data."""
    with open(file_path, "wb") as file:
        pickle.dump(data, file)

def load_checksum_file():
    """Loads the checksum processing data from the checksum file."""
    return load_data(CHECKSUM_FILE_PATH)

def load_unsolved_checksums_file():
    """Loads the unsolved checksum data from the unsolved checksums file."""
    return load_data(UNSOLVED_CHECKSUMS_FILE_PATH)

def update_checksum_file(data):
    """Updates the checksum processing data."""
    update_data(CHECKSUM_FILE_PATH, data)

def update_unsolved_checksums_file(data):
    """Updates the unsolved checksum data."""
    update_data(UNSOLVED_CHECKSUMS_FILE_PATH, data)

# TODO: Refactor this function and process_checksum_data since they're very similar. Enforce DRY
def attempt_solve_unsolved_checksums(checksum_processing, unsolved_packet_checksums, log_queue)->bool:
    """Attempts to solve unsolved checksums using available data."""
    packets_to_remove = []

    for packet_id, checksum_data_record in unsolved_packet_checksums.items():
        try:
            num_checksums = checksum_data_record["number_of_checksums"]
            currently_solving_sequence = checksum_data_record["packet_sequence_number"]
            solved = False
            # TODO: This is a quick fix because I'm running out of time on this assignment and just want to get it working
            if checksum_data_record["packet_id"] in checksum_processing:
                checksum_data_record["historical_checksums"] = checksum_processing[checksum_data_record["packet_id"]]["historical_checksums"]

            with open(checksum_data_record["binary_file_name"], "rb") as binary_file:
                binary_data = binary_file.read()
                for i in range(checksum_data_record["packet_sequence_number"], checksum_data_record["packet_sequence_number"] + num_checksums):
                    if i == 0:
                            crc32_checksum = zlib.crc32(binary_data)
                    else:
                        if currently_solving_sequence - 1 in checksum_data_record["historical_checksums"]:
                            crc32_checksum = zlib.crc32(binary_data, checksum_data_record["historical_checksums"][currently_solving_sequence - 1])
                        else:
                            break  # Cannot solve this checksum yet

                    hex_checksum = crc32_checksum.to_bytes(4, byteorder='big')
                    packet_checksum_value = checksum_data_record["checksum_blocks"][i]

                    if hex_checksum.hex() != packet_checksum_value.hex():
                        error_log_message = f'{checksum_data_record["packet_id"]}\n{checksum_data_record["packet_sequence_number"]}\n{currently_solving_sequence}\n{packet_checksum_value.hex()}\n{hex_checksum.hex()}\n'
                        log_queue.put(PacketError('checksum', error_log_message))
                    else:
                        checksum_data_record["last_confirmed_crc_sequence_number"] = currently_solving_sequence + i
                        checksum_data_record["historical_checksums"][currently_solving_sequence] = crc32_checksum
                        checksum_processing[packet_id] = checksum_data_record
                        currently_solving_sequence += 1
                        update_checksum_file(checksum_processing)

                        solved = True
                        break

            if solved:
                packets_to_remove.append(packet_id)

        except Exception as ex:
            print(f"Error solving checksum for packet_id {packet_id}: {ex}")

    # Remove solved packets from unsolved_packet_checksums
    for packet_id in packets_to_remove:
        del unsolved_packet_checksums[packet_id]
        update_unsolved_checksums_file(unsolved_packet_checksums)
        
def process_checksum_data(checksum_meta_data, log_queue, checksum_processing, unsolved_packet_checksums):
    """Processes checksum data and handles checksum validation."""
    checksum_data_record = {
        "packet_id": checksum_meta_data["id"],
        "packet_sequence_number": checksum_meta_data["packet_sequence_number"],
        "XOR_key": checksum_meta_data["XOR_key"],
        "number_of_checksums": checksum_meta_data["number_of_checksums"],
        "checksum_blocks": checksum_meta_data["checksum_blocks"],
        "binary_file_name": checksum_meta_data["binary_file_name"],
        "last_confirmed_crc_sequence_number": "",
        "checksum_string_before_xor_encoding": "",
        "sequence_0_crc32": "",
        "historical_checksums": {}
    }

    chunk_size = 4  # 4 bytes
    num_checksums = checksum_data_record["number_of_checksums"]
    file_path = checksum_data_record["binary_file_name"]
    currently_solving_sequence = checksum_data_record["packet_sequence_number"]
    # TODO: This is a quick fix because I'm running out of time on this assignment and just want to get it working. 
    if checksum_data_record["packet_id"] in checksum_processing:
        checksum_data_record["historical_checksums"] = checksum_processing[checksum_data_record["packet_id"]]["historical_checksums"]
    
    try:
        with open(file_path, "rb") as binary_file:
            binary_data = binary_file.read()  # TODO: Stream the file instead of loading it entirely, also this is a lot of disk IO, ideally this would be cached somewhere to limit disk IO
            for i in range(checksum_data_record["packet_sequence_number"], checksum_data_record["packet_sequence_number"]+num_checksums):
                if i == 0:
                    crc32_checksum = zlib.crc32(binary_data)
                else:
                    if currently_solving_sequence - 1 in checksum_data_record["historical_checksums"]:
                        crc32_checksum = zlib.crc32(binary_data, checksum_data_record["historical_checksums"][currently_solving_sequence - 1])
                    else:
                        unsolved_packet_checksums[checksum_data_record["packet_id"]] = checksum_data_record
                        update_unsolved_checksums_file(unsolved_packet_checksums)
                        continue

                hex_checksum = crc32_checksum.to_bytes(chunk_size, byteorder='big')
                packet_checksum_value = checksum_data_record["checksum_blocks"][i]

                if hex_checksum.hex() != packet_checksum_value.hex():
                    error_log_message = f'{checksum_data_record["packet_id"]}\n{checksum_data_record["packet_sequence_number"]}\n{currently_solving_sequence}\n{packet_checksum_value.hex()}\n{hex_checksum.hex()}\n'
                    log_queue.put(PacketError('checksum', error_log_message))
                else:
                    # Update our book keeping
                    checksum_data_record["last_confirmed_crc_sequence_number"] = currently_solving_sequence
                    checksum_data_record["historical_checksums"][currently_solving_sequence] = crc32_checksum
                    checksum_processing[checksum_data_record["packet_id"]] = checksum_data_record
                    currently_solving_sequence += 1
                    update_checksum_file(checksum_processing)

    except Exception as ex:
        log_queue.put(GenericError(ex))

def checksum_process(log_queue: multiprocessing.Queue, checksum_queue: multiprocessing.Queue):
    """Processes checksum data indefinitely."""
    checksum_processing = load_checksum_file()
    unsolved_packet_checksums = load_unsolved_checksums_file()

    while True:
        try:
            if checksum_queue.empty():
                time.sleep(0.01)
                continue
            checksum_meta_data = checksum_queue.get(timeout=1)
            process_checksum_data(checksum_meta_data, log_queue, checksum_processing, unsolved_packet_checksums)
        except TimeoutError:
            time.sleep(0.01)
            pass
        except Exception as e:
            log_queue.put(GenericError(e))
        attempt_solve_unsolved_checksums(checksum_processing, unsolved_packet_checksums, log_queue)    
        
def cleanup(pool, logger_proc, log_queue, sock):
    """Clean up resources."""
    print("Cleaning up resources...")
    if pool:
        pool.terminate()
        pool.join()
    if logger_proc and logger_proc.is_alive():
        log_queue.put("STOP")
        logger_proc.join(timeout=2)
        if logger_proc.is_alive():
            logger_proc.terminate()
            logger_proc.join()
    if sock:
        sock.close()
    print("Goodbye!")

def sigterm_handler(sig, frame, sock, pool, logger_proc, log_queue):
    """Signal handler for SIGINT."""
    print("\nInterrupt received, shutting down...")
    cleanup(pool, logger_proc, log_queue, sock)
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--keys", help='Dictionary of {packet_id: key_file_path} mappings')
    parser.add_argument("-b", "--binaries", help='Dictionary of {packet_id: binary_path} mappings')
    parser.add_argument("-d", "--delay", help='Delay in seconds for writing to log files', type=int)
    parser.add_argument("-p", "--port", help='Port to receive packets on', type=int)
    args = parser.parse_args()

    delay_in_seconds = args.delay or 0
    server_listen_port = args.port or 1337
    packet_key_mappings = ast.literal_eval(args.keys) if args.keys else {}
    packet_binary_mappings = ast.literal_eval(args.binaries) if args.binaries else {}

    if delay_in_seconds > 0:
        print(f"Log writing will be artificially delayed by {delay_in_seconds} seconds")

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    try:
        sock.bind(('', server_listen_port))
    except Exception as e:
        print(f'Failed to bind to port {server_listen_port}. Is there another program using that port?')
        sys.exit(1)

    print(f"Server is now listening on port {server_listen_port}")

    log_queue = multiprocessing.Queue()
    logger_proc = multiprocessing.Process(target=logger_process, args=(log_queue, delay_in_seconds))
    #logger_proc.daemon = True
    logger_proc.start()

    checksum_queue = multiprocessing.Queue()
    checksum_proc = multiprocessing.Process(target=checksum_process, args=(log_queue, checksum_queue))
    #checksum_proc.daemon = True
    checksum_proc.start()
    
    try:
        max_num_processes = max(len(os.sched_getaffinity(0)) - 2, 1) # we have the logger process and checksum process hence the minus 2
    except NotImplementedError:
        max_num_processes = 1

    pool = multiprocessing.Pool(processes=max_num_processes)
    
    signal.signal(signal.SIGINT, lambda sig, frame: sigterm_handler(sig, frame, sock, pool, logger_proc, log_queue))

    try:
        while True:
            data = sock.recv(4096)
            # TODO: Use envars to control this if it's a debug build vs prod build
            
            # Uncomment pool for multiprocessing (harder to debug) KNOWN ISSUE: logs aren't logging and this isn't working for me currently. Unfortunately I've run out of time to fix this.
            #pool.apply_async(handle_client, args=(log_queue, checksum_queue, data, packet_key_mappings, packet_binary_mappings))
            
            # Uncomment below for synchronous processing (easier to debug) KNOWN ISSUE: This is working synchronously which doesn't meet the design requirements. It does however show that the code works.
            handle_client(log_queue=log_queue, checksum_queue=checksum_queue, data=data, packet_key_mappings=packet_key_mappings, packet_binary_mappings=packet_binary_mappings)
            
    except KeyboardInterrupt:
        print("\nInterrupt received, shutting down...")
    except Exception as e:
        print(f"A critical error occurred: {e}")
    finally:
        cleanup(pool, logger_proc, log_queue, sock)

if __name__ == "__main__":
    main()
