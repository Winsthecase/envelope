from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Tuple
from heapq import heapify, heappop


FILE_CHUNK_LENGTH = 16384 #The number of characters the read from the input file each iteration


@dataclass(order = True, slots = True)
class Node:
    """Defines a node in a huffman tree"""
    
    symbol: bytes = field(compare = False)
    count: int = field(compare = True)
    left: Node = field(default = None, compare = False)
    right: Node = field(default = None, compare = False)

    def is_leaf(self) -> bool:
        """Returns True if node is a leaf node"""
        
        return self.left == None

    def extract_codes(self, codes: Dict[str, str], _code: str = "") -> None:
        """Returns binary codes from the huffman tree"""
        
        if self.is_leaf():
            codes[self.symbol] = _code
        else:
            self.left.extract_codes(codes, _code + '0')
            self.right.extract_codes(codes, _code + '1')

    def encode_tree(self, _binary: str = "") -> str:
        """Encodes huffman tree into a binary string"""
        
        if self.is_leaf():
            _binary += '1'
            _binary += f"{self.symbol:08b}"
       
            return _binary
        else:
            _binary += '0'
            _binary = self.left.encode_tree(_binary)
            _binary = self.right.encode_tree(_binary)

            return _binary

    @staticmethod
    def decode_tree(binary_iterator: iter) -> Node:
        """Builds huffman tree from a binary string iterator"""
        
        bit = next(binary_iterator)
        if bit == '1':
            byte = "".join(next(binary_iterator) for _ in range(8))
            char = int(byte, 2).to_bytes(1, "big")

            return Node(char, 0)

        else:
            left = Node.decode_tree(binary_iterator)
            right = Node.decode_tree(binary_iterator)

            return Node(left.symbol + right.symbol, 0, left, right)
            
    @staticmethod
    def create_tree(count: Dict[str, int]) -> Node:
        """Builds huffman tree from a byte count dictionary"""
        
        nodes = [Node(symbol, value) for symbol, value in count.items()]
        heapify(nodes)

        while len(nodes) != 1:
            left = heappop(nodes)

            right = heappop(nodes)

            nodes.append(
                Node(
                    left.symbol + right.symbol,
                    left.count + right.count,
                    left,
                    right
                    )
                )

        root, = nodes

        return root


def count(data: bytes) -> Dict[str, int]:
    """Returns a byte count dictionary from data"""
    
    byte_count = {}

    for byte in data:
        if byte_count.get(byte):
            byte_count[byte] += 1
        else:
            byte_count[byte] = 1

    return byte_count


def padded(binary: str) -> Tuple[str, str]:
    """Returns a \'0\' padded binary string"""
    
    length = len(binary)
    remainder = length % 8
    padding_length = 8 - remainder if remainder != 0 else 0

    binary = binary.ljust(length + padding_length, '0')

    return binary


def encode_bytes(data: str, codes: Dict[str, str]) -> str:
    """Encodes text as a binary string"""
    
    binary = ""
    for byte in data:
        binary += codes[byte]

    return binary


def to_bytes(binary: str) -> bytes:
    """Converts a binary string to a bytes object"""
    
    array = bytearray()
    for i in range(0, len(binary), 8):
        byte = int(binary[i: i + 8], 2)
        array.append(byte)

    encoded_bytes = bytes(array)

    return encoded_bytes


def to_bits(binary: bytes) -> str:
    """Converts a bytes object to \'0\' padded binary string of length 8"""
    
    bits = ""
    for byte in binary:
        bits += f"{byte:08b}"

    return bits


def decode_bytes(binary_iterator: iter, codes: Dict[str, bytes], num_bytes: int) -> bytes:
    """Decodes binary string"""
    
    num_decoded = 0
    bits = ""
    data = b""

    while num_decoded != num_bytes:
        bits += next(binary_iterator)

        byte = codes.get(bits)
        if byte:
            data += byte
            num_decoded += 1
            bits = ""

    return data

def compress(data: bytes):
    "Compresses an array of bytes"
    
    codes = {}
    byte_count = count(data)
    tree = Node.create_tree(byte_count)
    tree.extract_codes(codes)

    encoded_data = padded(encode_bytes(data, codes))
    encoded_tree = padded(tree.encode_tree())

    tree_bit_size = 10 * len(byte_count) - 1
    padding_size = 8 - tree_bit_size % 8
    tree_byte_size = (tree_bit_size + padding_size) // 8 

    tree_size = f"{tree_byte_size:016b}"
    data_size = f"{len(data):016b}"
    encoded_data_size = f"{len(encoded_data) // 8:016b}"
    header = tree_size + data_size + encoded_data_size

    compressed_bytes = to_bytes(header + encoded_tree + encoded_data)

    return compressed_bytes


def compress_file(filepath: str) -> None:
    """Compresses file, producing a compressed .letter file"""
    
    name, extension = filepath.split('.')
    output_filepath = name + '_' + extension + ".letter"

    with open(filepath, "rb") as input_file, open(output_filepath, "wb") as output_file:
        while (data := input_file.read(FILE_CHUNK_LENGTH)) != b'':
            compressed_bytes = compress(data)
            output_file.write(compressed_bytes)


def decompress(data: bytes, tree_data: bytes):
    """Decompresses an array of bytes"""
    
    encoded_data = to_bits(data)
    encoded_tree = to_bits(tree_data)

    codes = {}
    tree = Node.decode_tree(iter(encoded_tree))
    tree.extract_codes(codes)
    inverted_codes = {value: key for key, value in codes.items()}

    decompressed_bytes = decode_bytes(iter(encoded_data), inverted_codes, len(data))

    return decompressed_bytes


def decompress_file(filepath: str) -> None:
    """Decompresses a .letter file, producing the original file"""
    
    name, extension = filepath.split('.')
    original_name, original_extension = name.rsplit('_', 1)
    output_filepath = original_name + '.' + original_extension

    with open(filepath, "rb") as input_file, open(output_filepath, 'wb') as output_file:
        while (header := input_file.read(6)) != b'':
            tree_byte_size = int.from_bytes(header[:2], "big")
            data_size = int.from_bytes(header[2:4], "big")
            data_byte_size = int.from_bytes(header[4:], "big")

            tree_data = input_file.read(tree_byte_size)
            data = input_file.read(data_byte_size)

            decompressed_bytes = decompress(data, tree_data)

            output_file.write(decompressed_bytes)
    

if __name__ == "__main__":
    decompress_file("python_jpg.letter")
