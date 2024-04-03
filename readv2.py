import sys
from scapy.all import *

def extract_chars_from_pcap(pcap_file):
    extracted_chars = ""
    icmp_requests = []

    # Leer el archivo pcapng y filtrar los paquetes ICMP request
    pkts = rdpcap(pcap_file)
    for pkt in pkts:
        if ICMP in pkt and pkt[ICMP].type == 8:  # Verificar si es un paquete ICMP request
            icmp_requests.append(pkt)

    # Extraer el primer caracter del payload de cada paquete ICMP request
    for pkt in icmp_requests:
        if Raw in pkt:
            # Obtener el payload del paquete
            payload = pkt[Raw].load
            # Extraer el primer byte y convertirlo a ASCII
            if payload:
                first_byte = payload[0]
                try:
                    first_char = chr(first_byte)  # Convertir el byte a ASCII
                    extracted_chars += first_char
                except ValueError:
                    print("Error converting byte to ASCII:", sys.exc_info()[0])  # Imprimir el error
                    continue  # Pasar al siguiente byte

    return extracted_chars

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            result += char
    return result

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 readv2.py <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    extracted_string = extract_chars_from_pcap(pcap_file)

    original_message = None

    # Aplicar corrimientos César en orden decreciente y mostrar los resultados
    for shift in range(26, 0, -1):
        shifted_string = caesar_cipher(extracted_string, shift)
        adjusted_shift = abs(shift - 26)  # Ajustar el número de corrimiento
        print(f"{adjusted_shift}: {shifted_string}")
        if original_message is None and shifted_string == extracted_string:
            original_message = shifted_string
            original_shift = adjusted_shift

if __name__ == "__main__":
    main()

