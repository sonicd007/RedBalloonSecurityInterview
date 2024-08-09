import binascii
import hashlib

from pyasn1.codec.der import decoder
from asn1_class_models.digest_info import DigestInfo

class CryptoOperations:
    @staticmethod
    def xor_data(data, key):
        key_length = len(key)
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % key_length]
        return result

    @staticmethod
    def compute_crc32(data):
        return binascii.crc32(data)

    @staticmethod
    def calculate_sha256_hash(data: bytes):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data)
        return sha256_hash.hexdigest()

    @staticmethod
    def remove_padding(byte_array):
        if byte_array[0] != 0x01:
            raise ValueError("Invalid padding start byte")
        padding_end_index = 1
        while padding_end_index < len(byte_array) and byte_array[padding_end_index] == 0xFF:
            padding_end_index += 1
        if padding_end_index >= len(byte_array) or byte_array[padding_end_index] != 0x00:
            raise ValueError("Invalid padding termination")
        return byte_array[padding_end_index + 1:]

    def decrypt_digital_signature(self, rsa_sig_raw, modulus, exponent):
        decrypted_signature_int = pow(int.from_bytes(rsa_sig_raw, 'big'), exponent, modulus) #TODO: Review if this is signed or unsigned int
        num_bytes = (decrypted_signature_int.bit_length() + 7) // 8
        decrypted_signature_bytes = decrypted_signature_int.to_bytes(num_bytes, byteorder='big')
        return decrypted_signature_bytes

    def get_signed_payload_hash(self, rsa_sig_raw, modulus, exponent):
        decrypted_signature = self.decrypt_digital_signature(rsa_sig_raw, modulus, exponent)
        decrypted_signature = self.remove_padding(decrypted_signature)
        decoded_data, rest = decoder.decode(decrypted_signature, asn1Spec=DigestInfo())
        digest_value = decoded_data['digest']
        return digest_value.asOctets().hex()
