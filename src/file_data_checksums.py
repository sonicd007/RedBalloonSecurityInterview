from dataclasses import dataclass

@dataclass
class FileDataChecksums:
    block_number:int
    received_checksum:str
    expected_checksum:str
    checksum_processed:bool
    