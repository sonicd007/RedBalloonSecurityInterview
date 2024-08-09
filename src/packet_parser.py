class PacketParser:
    def __init__(self, raw_data: bytes):
        self.packet_id_raw = raw_data[:4]
        self.packet_seq_num_raw = raw_data[4:8].hex().lstrip('0')
        self.multibyte_repeating_xor_key_raw = raw_data[8:10]
        self.num_checksums_raw = raw_data[10:12]
        self.repeating_xord_cyclic_checksum_crc32_dwords_raw = raw_data[12:len(raw_data)-64]
        self.rsa_sig_raw = raw_data[-64:]
        self.message_payload_raw = raw_data[:-64]
        self.checksum_block_size=4 # 4 bytes (DWORD checksums)

    def get_packet_id(self) -> str:
        return f'0x{self.packet_id_raw.hex().lstrip("0")}'

    def get_packet_sequence_number(self) -> int:
        return int(self.packet_seq_num_raw, 16) if self.packet_seq_num_raw else 0

    def get_multibyte_repeating_xor_key(self) -> str:
        return self.multibyte_repeating_xor_key_raw.hex()

    def get_number_checksums(self) -> int:
        return int(self.num_checksums_raw.hex(), 16) if self.num_checksums_raw else 0

    def get_digital_signature(self) -> str:
        return self.rsa_sig_raw.hex()

    def get_repeating_xord_cyclic_checksum_crc32_dwords(self) -> str:
        return self.repeating_xord_cyclic_checksum_crc32_dwords_raw.hex()

    # Contains the xored checksum NOT USED
    def get_checksum_blocks(self) -> dict:
        num_checksums = self.get_number_checksums()
        packet_sequence_number = self.get_packet_sequence_number()
        checksum_length = self.checksum_block_size
        checksum_dictionary = {}
        
        for i in range(num_checksums):
            cur_seq_num = packet_sequence_number + i
            block_start_index = (packet_sequence_number * checksum_length) + (i * checksum_length)
            block_end_index = (packet_sequence_number * checksum_length) + ((i + 1) * checksum_length)
            block_checksum = self.repeating_xord_cyclic_checksum_crc32_dwords_raw[block_start_index:block_end_index]
            checksum_dictionary[cur_seq_num] = block_checksum
            
        return checksum_dictionary
    
    def get_unencoded_checksum_blocks(self) -> dict:
        num_checksums = self.get_number_checksums()
        packet_sequence_number = self.get_packet_sequence_number()
        xor_key = self.multibyte_repeating_xor_key_raw
        checksum_length = self.checksum_block_size
        checksum_payload = bytearray(self.repeating_xord_cyclic_checksum_crc32_dwords_raw)
        checksum_dictionary = {}
        
        try:
            # XOR decode the checksum payload
            for x in range(len(self.repeating_xord_cyclic_checksum_crc32_dwords_raw)):
                checksum_payload[x] ^= xor_key[x % 2]
        except Exception as ex:
            print(ex)    
        for i in range(num_checksums):
            cur_seq_num = packet_sequence_number + i
            #block_start_index = (packet_sequence_number * checksum_length) + (i * checksum_length)
            #block_end_index = (packet_sequence_number * checksum_length) + ((i + 1) * checksum_length)
            block_start_index = (i * checksum_length)
            block_end_index = (i * checksum_length) + checksum_length
            block_checksum = checksum_payload[block_start_index:block_end_index]
            checksum_dictionary[cur_seq_num] = block_checksum
            
        return checksum_dictionary