import sys

LONG_LLAVE = 26

def cifrar_cesar(mensaje, llave):
    traducir = ''
    for simbolo in mensaje:
        if simbolo.isalpha():
            num = ord(simbolo)
            num += llave
            
            if simbolo.isupper():
                if num > ord('Z'):
                    num -= 26
                elif num < ord('A'):
                    num += 26
            elif simbolo.islower():
                if num > ord('z'):
                    num -= 26
                elif num < ord('a'):
                    num += 26
            
            traducir += chr(num)
        else:
            traducir += simbolo
    return traducir

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py <mensaje> <llave>")
        sys.exit(1)

    mensaje = sys.argv[1]
    llave = int(sys.argv[2])

    if llave < 1 or llave > LONG_LLAVE:
        print("La llave ingresada no es válida.")
        sys.exit(1)

    resultado = cifrar_cesar(mensaje, llave)
    print(resultado)

