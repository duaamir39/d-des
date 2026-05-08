import json
import os
import datetime

def permute(block: int, table: list[int], input_size: int, output_size: int) -> int:
    """Permute an integer block using the given table."""
    output = 0
    for i, bit_pos in enumerate(table):
        # DES tables are 1-indexed, so we subtract 1.
        # The bit position from the left in a block of size input_size
        shift = input_size - bit_pos
        bit = (block >> shift) & 1
        output |= (bit << (output_size - 1 - i))
    return output

def split_half(block: int, size: int) -> tuple[int, int]:
    """Split an integer block into two halves."""
    half_size = size // 2
    mask = (1 << half_size) - 1
    left = block >> half_size
    right = block & mask
    return left, right

def merge_half(left: int, right: int, half_size: int) -> int:
    """Merge two integer halves into a single block."""
    return (left << half_size) | right

def left_shift(block: int, shift: int, size: int) -> int:
    """Circular left shift an integer block by the given shift amount."""
    mask = (1 << size) - 1
    return ((block << shift) | (block >> (size - shift))) & mask

class Logger:
    def __init__(self, log_file="logs.json"):
        self.log_file = log_file

    def log(self, operation: str, mode: str, status: str):
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "operation": operation,
            "mode": mode,
            "status": status
        }
        
        logs = []
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        logs = json.loads(content)
            except json.JSONDecodeError:
                pass

        logs.append(log_entry)
        
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)
