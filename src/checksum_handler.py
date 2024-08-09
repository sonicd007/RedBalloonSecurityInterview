
from crypto_operations import CryptoOperations
from packet_parser import PacketParser


class ChecksumHandler:
    def __init__(self, packet_parser: PacketParser, crypto_operations: CryptoOperations):
        self.packet_parser = packet_parser
        self.crypto_operations = crypto_operations

    def extract_original_checksums(self, checksum_length_in_bytes=4):
        num_checksums = self.packet_parser.get_number_checksums()
        sequence_number = self.packet_parser.get_packet_sequence_number()
        checksums = self.packet_parser.repeating_xord_cyclic_checksum_crc32_dwords_raw
        xor_key = self.packet_parser.multibyte_repeating_xor_key_raw
        sender_block_checksums = {} # {key: packet id, value: { key: sequence #, checksum}}
        for i in range(num_checksums):
            start = i * checksum_length_in_bytes
            end = start + checksum_length_in_bytes
            sender_block_checksum = checksums[start:end]
            # sender_block_checksums.sequence_number.append(sender_block_checksum)
        return sender_block_checksums

    def verify_checksums(self):
        original_checksums = self.extract_original_checksums()
        # for i, original_checksum in enumerate(original_checksums):
        #     data_block = self.get_data_for_checksum(i)
        #     computed_crc32 = self.crypto_operations.compute_crc32(data_block)
        #     if computed_crc32.to_bytes(4, byteorder='big') != original_checksum:
        #         return False
        return True
