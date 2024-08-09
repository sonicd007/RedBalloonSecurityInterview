
from dataclasses import dataclass

@dataclass
class GenericError:
    error_message: str
    error_type: str = "generic"
    levelno: int = 10 # DEBUG