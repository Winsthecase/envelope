from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Tuple
from heapq import heapify, heappop


FILE_CHUNK_LENGTH = 16384 #The number of characters the read from the input file each iteration


@dataclass(order = True, slots = True)
class Node:
    """Defines a node in a huffman tree"""
    
    symbol: str = field(compare = False)
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
            _binary += f"{ord(self.symbol):08b}"
       
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
            char = chr(int(byte, 2))

            return Node(char, 0)

        else:
            left = Node.decode_tree(binary_iterator)
            right = Node.decode_tree(binary_iterator)

            return Node(left.symbol + right.symbol, 0, left, right)
            
    @staticmethod
    def create_tree(count: Dict[str, int]) -> Node:
        """Builds huffman tree from a character count dictionary"""
        
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


def count(text: str) -> Dict[str, int]:
    """Returns a character count dictionary from text"""
    
    char_count = {}

    for char in text:
        if char_count.get(char):
            char_count[char] += 1
        else:
            char_count[char] = 1

    return char_count


def padded(binary: str) -> Tuple[str, str]:
    """Returns a \'0\' padded binary string"""
    
    length = len(binary)
    remainder = length % 8
    padding_length = 8 - remainder if remainder != 0 else 0

    binary = binary.ljust(length + padding_length, '0')

    return binary


def encode_text(text: str, codes: Dict[str, str]) -> str:
    """Encodes text as a binary string"""
    
    binary = ""
    for char in text:
        binary += codes[char]

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


def decode_text(binary_iterator: iter, codes: Dict[str, str], num_chars: int) -> str:
    """Decodes binary string"""
    
    num_decoded = 0
    char_bits = ""
    text = ""

    while num_decoded != num_chars:
        char_bits += next(binary_iterator)

        char = codes.get(char_bits)
        if char:
            text += char
            num_decoded += 1
            char_bits = ""

    return text


def compress(filepath: str) -> None:
    """Takes a filepath as input and compresses the corresponding .txt file, producing a compressed .letter file"""
    
    name, extension = filepath.split('.')
    output_filepath = name + ".letter"

    with open(filepath, 'r') as input_file, open(output_filepath, "wb") as output_file:
        while (text := input_file.read(FILE_CHUNK_LENGTH)) != '':
            #Encodes data
            codes = {}
            letter_count = count(text)
            tree = Node.create_tree(letter_count)
            tree.extract_codes(codes)

            encoded_text = padded(encode_text(text, codes))
            encoded_tree = padded(tree.encode_tree())

            #Creates header information
            tree_bit_size = 10 * len(letter_count) - 1
            padding_size = 8 - tree_bit_size % 8
            tree_byte_size = (tree_bit_size + padding_size) // 8 

            tree_size = f"{tree_byte_size:016b}"
            text_size = f"{len(text):016b}"
            encoded_text_size = f"{len(encoded_text) // 8:016b}"
            header = tree_size + text_size + encoded_text_size

            #Writes encoded data
            compressed_bytes = to_bytes(header + encoded_tree + encoded_text)

            output_file.write(compressed_bytes)


def decompress(filepath: str) -> None:
    """Takes a filepath as input and decompresses the corresponding .letter file, producing an uncompressed .txt file"""
    
    name, extension = filepath.split('.')
    output_filepath = name + "_decompressed.txt"

    with open(filepath, "rb") as input_file, open(output_filepath, 'w') as output_file:
        while (header := input_file.read(6)) != b'':
            #Reads header information
            tree_byte_size = int.from_bytes(header[:2], "big")
            text_size = int.from_bytes(header[2:4], "big")
            text_byte_size = int.from_bytes(header[4:], "big")

            #Reads encoded data
            encoded_tree = to_bits(input_file.read(tree_byte_size))
            encoded_text = to_bits(input_file.read(text_byte_size))

            #Decodes encoded data
            codes = {}
            tree = Node.decode_tree(iter(encoded_tree))
            tree.extract_codes(codes)
            inverted_codes = {value: key for key, value in codes.items()}

            decoded_text = decode_text(iter(encoded_text), inverted_codes, text_size)

            #writes decoded data
            output_file.write(decoded_text)
           

if __name__ == "__main__":
    pass
