import json
from web3 import Web3
from web3.auto.infura import w3
from eth_utils import remove_0x_prefix, to_int, to_checksum_address, to_hex, encode_hex

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
    print(storage_key)
    print(type(storage_key))
    return w3.eth.getProof(CONTRACT_ADDRESS, [storage_key], 'latest')

# First find the slot position `p` of mapping.
# (For the COMP token, `balances` mapping is at slot 1, after the `allowances` mapping.)
# Then, use the slot position and holder address to generate a storage key to ask the proof for.
# COMP token contract code: https://etherscan.io/address/0xc00e94cb662c3520282e6f5717214004a7f26888#code
for i in range(0, 5):
    val = getStorageAtIndex(i)
    if val != 0:
        print('position is {}'.format(i))
        print('int value is: ' + str(val))
        print('proof is: ')
        print(Web3.toJSON(getProof(i)))
