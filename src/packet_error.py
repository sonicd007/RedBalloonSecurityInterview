
from dataclasses import dataclass

@dataclass
class PacketError:
    error_type: str
    error_message: str
    levelno: int = 20 # INFO
    log_delay: int = 0 # Artifical log delay