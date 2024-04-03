from scapy.all import *
import time
import struct
import sys

timestamp = int(time.time())

def generar_paquete_icmp(timestamp, payload, ttl=64, identificador_be=0, identificador_le=0):
    # Crear el paquete ICMP con los campos especificados
    packet = IP(dst="127.0.0.1", ttl=ttl)/ICMP(id=identificador_be, seq=identificador_le)/payload
    packet.time = timestamp
    return packet

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 pingv4.py <mensaje_cifrado>")
        sys.exit(1)

    mensaje_cifrado = sys.argv[1].replace(" ", "")  # Eliminar espacios del mensaje cifrado

    # Verificar si el mensaje cifrado es válido (solo letras minúsculas del alfabeto inglés)
    if not mensaje_cifrado.islower() or not mensaje_cifrado.isalpha():
        print("Error: Solo se permiten letras minúsculas del alfabeto inglés.")
        sys.exit(1)

    ttl = 64  # TTL generado
    
    # Payload común para todos los paquetes
    payload_comun = b'\x8c\xd2\x09\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33'

    # Crear un paquete ICMP para cada caracter del mensaje cifrado
    for indice, caracter in enumerate(mensaje_cifrado):
        # Ignorar los espacios
        if caracter == " ":
            continue

        # Convertir el caracter cifrado a su valor hexadecimal
        valor_hexadecimal = hex(ord(caracter))[2:]  # Obtener el valor hexadecimal y eliminar el prefijo '0x'

        # Modificar el payload para cambiar el bit menos significativo
        payload = bytearray(payload_comun)
        payload[0] = int(valor_hexadecimal, 16)
        payload[43:] = b'\x00' * (48 - 43)  
        
        # Crear el paquete ICMP y enviarlo
        identificador_be = indice + 1  # Identificador BE: 1, 2, 3, ...
        identificador_le = struct.unpack("<H", struct.pack(">H", identificador_be))[0]  # Identificador LE: convertir a formato little-endian
        paquete = generar_paquete_icmp(timestamp, bytes(payload), ttl, identificador_be, identificador_le)
        send(paquete, verbose=False)
        
        # Mostrar mensaje de envío
        print("Sent 1 packet.")

if __name__ == "__main__":
    main()

