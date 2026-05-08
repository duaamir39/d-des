import argparse
import sys
from .cipher import DDESCipher
from .utils import Logger

def main():
    parser = argparse.ArgumentParser(description="D-DES (Dynamic Data Encryption Standard) CLI")
    
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('-k', '--key', required=True, help="8-byte encryption key")
    parser.add_argument('-i', '--input', required=True, help="Input file path")
    parser.add_argument('-o', '--output', required=True, help="Output file path")
    parser.add_argument('-m', '--mode', choices=['ECB', 'CBC'], default='CBC', help="Block cipher mode (default: CBC)")
    parser.add_argument('--iv', help="8-byte initialization vector (required for CBC mode)")
    
    args = parser.parse_args()
    
    key_bytes = args.key.encode('utf-8')
    if len(key_bytes) != 8:
        print("Error: Key must be exactly 8 characters long.")
        sys.exit(1)
        
    iv_bytes = None
    if args.mode == 'CBC':
        if not args.iv:
            print("Error: CBC mode requires an IV (--iv).")
            sys.exit(1)
        iv_bytes = args.iv.encode('utf-8')
        if len(iv_bytes) != 8:
            print("Error: IV must be exactly 8 characters long.")
            sys.exit(1)
            
    logger = Logger("logs.json")
    
    try:
        cipher = DDESCipher(key=key_bytes, mode=args.mode, iv=iv_bytes)
        
        with open(args.input, 'rb') as f:
            data = f.read()
            
        if args.action == 'encrypt':
            result = cipher.encrypt(data)
            print(f"Successfully encrypted {len(data)} bytes to {len(result)} bytes.")
            print(f"\nCiphertext (Hex): {result.hex()}\n")
            logger.log("Encrypt", args.mode, "Success")
        else:
            result = cipher.decrypt(data)
            print(f"Successfully decrypted {len(data)} bytes to {len(result)} bytes.")
            print(f"\nDecrypted Data (Hex): {result.hex()}\n")
            logger.log("Decrypt", args.mode, "Success")
            
        with open(args.output, 'wb') as f:
            f.write(result)
            
    except Exception as e:
        print(f"Error: {e}")
        logger.log(args.action.capitalize(), args.mode, f"Failure - {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
