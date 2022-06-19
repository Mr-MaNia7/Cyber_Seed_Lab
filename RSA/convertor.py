def ascii2hex():
    plaintxt = input("Enter your plain text: ").encode('utf-8')
    return plaintxt.hex()
def hex2ascii():
    hextxt = input("Enter a hexadecimal text: ")
    byte_array = bytearray.fromhex(hextxt)
    return byte_array.decode()

def main():
    print(ascii2hex())
    # print(hex2ascii())

if __name__ == "__main__":
    main()
