import json
import rlp
import csv
from web3 import Web3
from web3.auto.infura import w3
from eth_utils import remove_0x_prefix, to_int, to_checksum_address, to_hex, encode_hex, decode_hex, keccak

# COMP token address
CONTRACT_ADDRESS = Web3.toChecksumAddress('0xc00e94cb662c3520282e6f5717214004a7f26888')
# CONTRACT_ADDRESS = Web3.toChecksumAddress('0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d')
# Address with non-zero token balance
# HOLDER_ADDRESS = Web3.toChecksumAddress('0x2775b1c75658Be0F640272CCb8c72ac986009e38') 
# a16z
# HOLDER_ADDRESS = Web3.toChecksumAddress('0x9aa835bc7b8ce13b9b0c9764a52fbf71ac62ccf1') 

HOLDER_ADDRESS = Web3.toChecksumAddress('0x1b523dc90a79cf5ee5d095825e586e33780f7188') 

def get_storage_key(key, slot_index):
    key = to_hex(key) if type(key) is int else key
    slot_index = to_hex(slot_index) if type(slot_index) is int else slot_index
    key = key.replace('0x', '')
    slot_index = slot_index.replace('0x', '')
    key = key.rjust(64, '0').lower()
    pos = slot_index.rjust(64, '0')
    return to_hex(w3.sha3(hexstr=key + pos))

def get_storage_at_index(contract_address, holder_address, slot_index):
    pos = str(i).rjust(64, '0')
    key = remove_0x_prefix(holder_address).rjust(64, '0').lower()
    storage_key = get_storage_key(holder_address, slot_index)
    x = w3.eth.getStorageAt(contract_address, storage_key)
    return to_int(x)

def get_proof(contract_address, holder_address, i):
    pos = str(i).rjust(64, '0')
    key = remove_0x_prefix(holder_address).rjust(64, '0').lower()
    storage_key = to_hex(w3.sha3(hexstr=key + pos))
    return w3.eth.getProof(contract_address, [storage_key], 'latest')

def get_storage_at_checkpoint(contract_address, holder_address, slot_index, checkpoint_index):
    storage_key = get_storage_key(holder_address, slot_index)
    nested_storage_key = get_storage_key(checkpoint_index, storage_key)
    x = w3.eth.getStorageAt(contract_address, nested_storage_key)
    # fromBlock = u32, votes = u96. These two are stored in the same 32 byte block, with earlier
    # variables being stored lower-order aligned (aligned to right).
    block_num = x[28:32]
    votes = x[16:28]
    return to_int(x)

# Get proof for COMP checkpoint
# Need to know which checkpoint index to grab proof for
def get_proof_for_checkpoint(contract_address, holder_address, slot_index, checkpoint_index):
    storage_key = get_storage_key(holder_address, slot_index)
    nested_storage_key = get_storage_key(checkpoint_index, storage_key)
    # add one because "votes" is second variable in struct
    # nested_storage_key = to_hex(to_int(hexstr=nested_storage_key) + 1)
    return w3.eth.getProof(contract_address, [nested_storage_key], 'latest')

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
        elif prefix == '0':
            # Even extension node
            shared_nibbles = dec[0][1:].hex()
            extension_length = len(shared_nibbles)
            if shared_nibbles == key[key_index:key_index + extension_length]:
                new_expected_root = dec[1]
                return _verify(new_expected_root, key, proof,
                               key_index + extension_length, proof_index + 1,
                               expected_value)
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

# First find the slot position `p` of the mapping in the solidity contract.
# (For the COMP token, `balances` mapping is at slot 1, after the `allowances` mapping.)
# Then, use the slot position and holder address to generate a storage key to ask the proof for .
# COMP token contract code: https://etherscan.io/address/0xc00e94cb662c3520282e6f5717214004a7f26888#code
def run(holder_address):
    for i in range(0, 7):
        val = get_storage_at_index(CONTRACT_ADDRESS, holder_address, i)
        if val != 0:
            # print('position is {}'.format(i))
            # print('int value at storage position is: ' + str(val)) # This is the COMP balance of the address
            # print('proof is: ')
            entire_proof = json.loads(Web3.toJSON(get_proof(CONTRACT_ADDRESS, holder_address,i)))
            # print(entire_proof)
            storage_proof = entire_proof['storageProof'][0]
            decoded_root = decode_hex(entire_proof['storageHash']) # bytes
            hashed_key = remove_0x_prefix(to_hex(keccak(hexstr=storage_proof['key']))) # string
            decoded_proofs = list(map(lambda x: decode_hex(x), storage_proof['proof'])) # bytes
            # print(decoded_proofs[0])
            decoded_value = decode_hex(storage_proof['value'])
            _verify(decoded_root, hashed_key, decoded_proofs, 0, 0, decoded_value)

def run_checkpoint(holder_address, checkpoint_index):
    # Checkpoint is stored at slot 3.
    entire_proof = json.loads(Web3.toJSON(get_proof_for_checkpoint(CONTRACT_ADDRESS, holder_address, 3, checkpoint_index)))
    print(entire_proof)
    storage_proof = entire_proof['storageProof'][0]
    decoded_root = decode_hex(entire_proof['storageHash']) # bytes
    hashed_key = remove_0x_prefix(to_hex(keccak(hexstr=storage_proof['key']))) # string
    decoded_proofs = list(map(lambda x: decode_hex(x), storage_proof['proof'])) # bytes
    # print(decoded_proofs[0])
    decoded_value = decode_hex(storage_proof['value'])
    print(_verify(decoded_root, hashed_key, decoded_proofs, 0, 0, decoded_value))

run_checkpoint(Web3.toChecksumAddress("0x9aa835bc7b8ce13b9b0c9764a52fbf71ac62ccf1"), 690)

# total = 0
# with open('addresses.csv', newline='') as f:
#     reader = csv.reader(f)
#     data = list(reader)
#     print(len(data))
#     for row in data[10600:]:
#         if total % 100 == 0:
#             print(total)
#         total += 1
#         try:
#             address = Web3.toChecksumAddress(row[0])
#         except:
#             continue
#         run(address)

# TEST
# proof_node = "0xf90211a0a5177e86acbc4cf377a71bb1eefc5a6fbc291bdaa24a1329fc0a7d8b1d1c1b6ea04617a3e6d77a766bf9765ea99f6551a608da5a3a92b6d3d4d77cd72c2956a691a089378dc01a14c46f4bc70b18f4f89ed999f662b10321be19f17f8a28f3ed628aa032b7aa9f61401e9dfa443173d009991ef1b11695b833b791ba955e2d201582a2a078a52bd9e3780cefaa22782c1d848d58f0c44e840be1aced5b27274e04532d44a07cc1d0bd92bf8787c419ee93c46b3081e9c327e67ca40efa12fc3340b6a57af3a0d0ed8ccb13e91933017f33bc981aa39203fdd13691c8c10ea4e1c7235b9828caa0c9aff81ec497dce19b1e11a4558b8029377bbc132ecfa78bc9f031d3b95d59c5a060258dfe689213ea4448a9a499fbad3000f28f9521a939bc1fb385b0eae28eaaa039fe2ef2f84b3e2b7c084352f2e525710232f715cdbf7a71ee17daa888e69770a0c6816a145bdb69b9e437cef45a5b8f9035b8dc53c8d9e477bd498c8f0efd21eca0c97e9000139384fde0b8c590c46e0525b73e9521dc4427fd2b47750a61dded9aa0d37b0cfb7bc7b900a79dee2d5f01e3c3fd2d788446bdccc44d44d76008c6f201a00423f3cfca18f91a52c67c6c69046fd74dadb9cf7715bfeb03ce4184d714b302a0dfa0947ef843dacb9518cbffd5d53271a3213043d88013e52620caea84123ddba054f8d0d47af761aefdce4ac8da11325d2d41fb068dc791e355933a3cac60212f80"
# print(len(rlp.decode(decode_hex(proof_node))))
# print(len(decode_hex(proof_node)))
# key = "0xea0d43baabaa35779c32a65010508497328024f66e5d6d3246da6d5f1196e017"
# print(remove_0x_prefix(to_hex(keccak(hexstr=key))))

