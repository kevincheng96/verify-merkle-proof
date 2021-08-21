import json
import rlp
from web3 import Web3
from web3.auto.infura import w3
from eth_utils import remove_0x_prefix, to_int, to_checksum_address, to_hex, encode_hex, decode_hex, keccak

# COMP token address
CONTRACT_ADDRESS = Web3.toChecksumAddress('0xc00e94cb662c3520282e6f5717214004a7f26888')
# Address with non-zero token balance
HOLDER_ADDRESS = Web3.toChecksumAddress('0x2775b1c75658Be0F640272CCb8c72ac986009e38') 


def getStorageAtIndex(i):
    pos = str(i).rjust(64, '0')
    key = remove_0x_prefix(HOLDER_ADDRESS).rjust(64, '0').lower()
    storage_key = to_hex(w3.sha3(hexstr=key + pos))
    x = w3.eth.getStorageAt(CONTRACT_ADDRESS, storage_key)
    return to_int(x)

def getProof(i):
    pos = str(i).rjust(64, '0')
    key = remove_0x_prefix(HOLDER_ADDRESS).rjust(64, '0').lower()
    storage_key = to_hex(w3.sha3(hexstr=key + pos))
    return w3.eth.getProof(CONTRACT_ADDRESS, [storage_key], 'latest')

# Working with bytes, not hex strings. Only the key is a hex string, mainly for iterating through nibbles.
def _verify(expected_root, key, proof, key_index, proof_index, expected_value):
    ''' Iterate the proof following the key.
        Return True if the value at the leaf is equal to the expected value.
        @param expected_root is the expected root of the current proof node.
        @param key is the key for which we are proving the value.
        @param proof is the proof the key nibbles as path.
        @param key_index keeps track of the index while stepping through
            the key nibbles.
        @param proof_index keeps track of the index while stepping through
            the proof nodes.
        @param expected_value is the key's value expected to be stored in
            the last node (leaf node) of the proof.
    '''
    node = proof[proof_index] # RLP encoded node
    dec = rlp.decode(node)

    if key_index == 0:
        # Trie root is always a hash
        assert keccak(node) == expected_root
    elif len(node) < 32:
        # If rlp < 32 bytes, then it is not hashed
        assert dec == expected_root
    else:
        assert keccak(node) == expected_root
    
    if len(dec) == 17:
        # branch node
        if key_index >= len(key):
            # We have finished traversing through the nibbles in the key. This should be the end of the proof.
            if dec[-1] == expected_value:
                # Value stored in the branch
                return True
        else:
            # Need to find the nibble value (0-15) at key_index of the key. 
            # Then read the value stored at the digit index of the decoded node. This value is the hash of the child node.
            nibble_index_of_next_key = int(key[key_index], 16)
            new_expected_root = dec[nibble_index_of_next_key]
            if new_expected_root != b'':
                return _verify(new_expected_root, key, proof, key_index + 1, proof_index + 1,
                               expected_value)
    elif len(dec) == 2:
        # Leaf or extension node
        # Get prefix and optional nibble from the first byte
        (prefix, nibble) = dec[0][:1].hex()
        if prefix == '2':
            # Even leaf node
            key_end = dec[0][1:].hex()
            # Decode the RLP-encoded value
            value = rlp.decode(dec[1])        
            if key_end == key[key_index:] and expected_value == value:
                return True
        elif prefix == '3':
            # Odd leaf node
            key_end = nibble + dec[0][1:].hex()
            # Decode the RLP-encoded value
            value = rlp.decode(dec[1])
            if key_end == key[key_index:] and expected_value == value:
                return True
        # UNTESTED PATH
        elif prefix == '0':
            # Even extension node
            shared_nibbles = dec[0][1:].hex()
            extension_length = len(shared_nibbles)
            if shared_nibbles == key[key_index:key_index + extension_length]:
                new_expected_root = dec[1]
                return _verify(new_expected_root, key, proof,
                               key_index + extension_length, proof_index + 1,
                               expected_value)
        # UNTESTED PATH
        elif prefix == '1':
            # Odd extension node
            shared_nibbles = nibble + dec[0][1:].hex()
            extension_length = len(shared_nibbles)
            if shared_nibbles == key[key_index:key_index + extension_length]:
                new_expected_root = dec[1]
                return _verify(new_expected_root, key, proof,
                               key_index + extension_length, proof_index + 1,
                               expected_value)
        else:
            # This should not be reached if the proof has the correct format
            assert False
    return True if expected_value == b'' else False

# First find the slot position `p` of mapping.
# (For the COMP token, `balances` mapping is at slot 1, after the `allowances` mapping.)
# Then, use the slot position and holder address to generate a storage key to ask the proof for .
# COMP token contract code: https://etherscan.io/address/0xc00e94cb662c3520282e6f5717214004a7f26888#code
for i in range(0, 3):
    val = getStorageAtIndex(i)
    if val != 0:
        print('position is {}'.format(i))
        print('int value at storage position is: ' + str(val)) # This is the COMP balance of the address
        print('proof is: ')
        entire_proof = json.loads(Web3.toJSON(getProof(i)))
        print(entire_proof)
        storage_proof = entire_proof['storageProof'][0]
        decoded_root = decode_hex(entire_proof['storageHash']) # bytes
        hashed_key = remove_0x_prefix(to_hex(keccak(hexstr=storage_proof['key']))) # string
        decoded_proofs = list(map(lambda x: decode_hex(x), storage_proof['proof'])) # bytes
        decoded_value = decode_hex(storage_proof['value'])
        print(_verify(decoded_root, hashed_key, decoded_proofs, 0, 0, decoded_value))
