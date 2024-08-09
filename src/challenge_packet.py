from checksum_handler import ChecksumHandler
from crypto_operations import CryptoOperations
from packet_parser import PacketParser


class ChallengePacket:
    MINIMUM_KNOWN_PACKET_SIZE = 4 + 4 + 2 + 2 + 64 # Ignoring the repeating xor'd cyclic checksum CRC32 DWORD size since it's variable

    @staticmethod
    def verify_packet_structure(raw_data: bytes) -> bool:
        # Ensure the raw_data length is at least the required minimum size
        if len(raw_data) < ChallengePacket.MINIMUM_KNOWN_PACKET_SIZE:
            return False

        # Ensure we can safely index the array at the specified slicing points
        try:
            # Check individual bounds
            if len(raw_data[:4]) != 4:  # Packet ID
                return False
            if len(raw_data[4:8]) != 4:  # Packet Sequence Number
                return False
            if len(raw_data[8:10]) != 2:  # Multibyte Repeating XOR Key
                return False
            if len(raw_data[10:12]) != 2:  # Number of Checksums
                return False
            if len(raw_data[-64:]) != 64:  # RSA Signature
                return False
        except IndexError:
            return False

        return True
    
    def __init__(self, raw_data: bytes):
        if not self.verify_packet_structure(raw_data):
            raise ValueError("Invalid packet structure")
        
        self.packet_parser = PacketParser(raw_data)
        self.crypto_operations = CryptoOperations()
        self.checksum_handler = ChecksumHandler(self.packet_parser, self.crypto_operations)
        self.expected_payload_hash = self.crypto_operations.calculate_sha256_hash(self.packet_parser.message_payload_raw)

    def dump_packet_info(self):
        print("Packet ID: ", self.packet_parser.get_packet_id())
        print("Packet Sequence Number: ", self.packet_parser.get_packet_sequence_number())
        print("Multibyte Repeating XOR Key: ", self.packet_parser.get_multibyte_repeating_xor_key())
        print("Number of Checksums: ", self.packet_parser.get_number_checksums())
        print("Cyclic DWords Checksum data: ", self.packet_parser.get_repeating_xord_cyclic_checksum_crc32_dwords())
        print("RSA Signature: ", self.packet_parser.get_digital_signature())
        print(f"Expected sha256 of data is: {self.expected_payload_hash}")
        print()

    def decrypt_digital_signature(self, modulus, exponent):
        return self.crypto_operations.decrypt_digital_signature(self.packet_parser.rsa_sig_raw, modulus, exponent)

    def get_signed_payload_hash(self, modulus, exponent):
        return self.crypto_operations.get_signed_payload_hash(self.packet_parser.rsa_sig_raw, modulus, exponent)