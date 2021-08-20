import json
from web3 import Web3
from web3.auto.infura import w3
from eth_utils import remove_0x_prefix, to_int, to_checksum_address, to_hex

# COMP token address
CONTRACT_ADDRESS = Web3.toChecksumAddress('0xc00e94cb662c3520282e6f5717214004a7f26888')
# Address with non zero token balance
HOLDER_ADDRESS = Web3.toChecksumAddress('0x2775b1c75658Be0F640272CCb8c72ac986009e38') 

def getStorageAtIndex(i):
    pos = str(i).rjust(64, '0')
    key = remove_0x_prefix(HOLDER_ADDRESS).rjust(64, '0').lower()
    storage_key = to_hex(w3.sha3(hexstr=key + pos))
    return to_int(w3.eth.getStorageAt(CONTRACT_ADDRESS, storage_key))

for i in range(0, 20):
    if getStorageAtIndex(i) != 0:
        print("position is {}".format(i))