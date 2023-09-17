substitution_box = {
    '0000': '1010', '0001': '0000', '0010': '1001', '0011': '1110',
    '0100': '0110', '0101': '0011', '0110': '1111', '0111': '0101',
    '1000': '0001', '1001': '1101', '1010': '1100', '1011': '0111',
    '1100': '1011', '1101': '0100', '1110': '0010', '1111': '1000'
}

inverse_substitution_box = {
    '1010': '0000', '0000': '0001', '1001': '0010', '1110': '0011',
    '0110': '0100', '0011': '0101', '1111': '0110', '0101': '0111',
    '0001': '1000', '1101': '1001', '1100': '1010', '0111': '1011',
    '1011': '1100', '0100': '1101', '0010': '1110', '1000': '1111'
}


def nibble_substitution(hex_input, is_inverse=False):
    s_box = inverse_substitution_box if is_inverse else substitution_box

    padded_bin = bin(int(hex_input, 16))[2:]
    while len(padded_bin) < 16:
        padded_bin = '0' + padded_bin

    substituted = ''

    for i in range(0, 16, 4):
        nibble = padded_bin[i:i + 4]
        substituted += s_box[nibble]

    result = hex(int(substituted, 2))[2:]
    while len(result) < 4:
        result = '0' + result

    return result


def shift_row(hex_input):
    bin_input = bin(int(hex_input, 16))[2:]

    while len(bin_input) < 16:
        bin_input = '0' + bin_input

    shifted = bin_input[8:12] + bin_input[4:8] + bin_input[:4] + bin_input[12:]

    shifted_hex = hex(int(shifted, 2))[2:]

    while len(shifted_hex) < 4:
        shifted_hex = '0' + shifted_hex

    return shifted_hex


def mix_columns(hex_input, is_inverse=False):
    def finite_field_multiply(a, b):
        result = 0
        for _ in range(4):
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0b10000:
                a ^= 0b10011
            b >>= 1
        return result

    def int_to_hex(value):
        return '{:04x}'.format(value)

    bin_input = format(int(hex_input, 16), '016b')
    c = [int(bin_input[i:i + 4], 2) for i in range(0, 16, 4)]

    if is_inverse:
        d = [
            finite_field_multiply(0x09, c[0]) ^ finite_field_multiply(0x02, c[1]),
            finite_field_multiply(0x02, c[0]) ^ finite_field_multiply(0x09, c[1]),
            finite_field_multiply(0x09, c[2]) ^ finite_field_multiply(0x02, c[3]),
            finite_field_multiply(0x02, c[2]) ^ finite_field_multiply(0x09, c[3])
        ]
    else:
        d = [
            finite_field_multiply(0x01, c[0]) ^ finite_field_multiply(0x04, c[1]),
            finite_field_multiply(0x04, c[0]) ^ finite_field_multiply(0x01, c[1]),
            finite_field_multiply(0x01, c[2]) ^ finite_field_multiply(0x04, c[3]),
            finite_field_multiply(0x04, c[2]) ^ finite_field_multiply(0x01, c[3])
        ]

    result = (d[0] << 12) | (d[1] << 8) | (d[2] << 4) | d[3]
    return int_to_hex(result)


def generate_round_keys(master_key):
    while len(master_key) < 4:
        master_key = '0' + master_key

    w = [int(master_key[i], 16) for i in range(4)]

    rcon = [0b1110, 0b1010]

    for round_num in range(2):
        w.append(w[round_num * 4] ^ (int(substitution_box[format(w[round_num * 4 + 3], '04b')], 2) ^ rcon[round_num]))
        w.append(w[round_num * 4 + 1] ^ w[-1])
        w.append(w[round_num * 4 + 2] ^ w[-1])
        w.append(w[round_num * 4 + 3] ^ w[-1])

    keys = [format((w[i] << 12) | (w[i + 1] << 8) | (w[i + 2] << 4) | w[i + 3], '04x') for i in range(0, len(w), 4)]

    return keys[1], keys[2]


def add_round_key(hex_input, round_key):
    result = hex(int(hex_input, 16) ^ int(round_key, 16))[2:]

    while len(result) < 4:
        result = '0' + result

    return result


def decrypt(ciphertext, key):
    k1, k2 = generate_round_keys(key)

    ciphertext = shift_row(ciphertext)
    ciphertext = add_round_key(ciphertext, k2)
    ciphertext = nibble_substitution(ciphertext, True)
    ciphertext = shift_row(ciphertext)
    ciphertext = mix_columns(ciphertext, True)
    ciphertext = add_round_key(ciphertext, k1)
    ciphertext = nibble_substitution(ciphertext, True)

    return ciphertext


def decrypt_and_save(key2):
    with open('secrets.txt', 'r') as file2:
        hex_numbers = file2.readline().split()

        decrypted = ''
        for hex_num in hex_numbers:
            first_half = bytes.fromhex(decrypt(hex_num, key2)[:2])
            second_half = bytes.fromhex(decrypt(hex_num, key2)[2:])
            decrypted += first_half.decode("utf-8")
            decrypted += second_half.decode("utf-8")

        with open("plain.txt", "w") as file1:
            file1.write(decrypted)


def main():
    text_block = input("Enter a text block: ")

    print(f"SubNibbles({text_block}) = {nibble_substitution(text_block)}")
    print(f"ShiftRow({text_block}) = {shift_row(text_block)}")
    print(f"MixColumns({text_block}) = {mix_columns(text_block)}")

    key = input("\nEnter a key: ")
    print(f"GenerateRoundKeys({key}) = {generate_round_keys(key)}")

    ciphertext = input("\n\nEnter the ciphertext block: ")
    key = input("Enter the key: ")

    decrypted_block = decrypt(ciphertext, key)
    print(f"Decrypted block: {decrypted_block}")

    key2 = input("\n\nEnter the decryption key: ")

    decrypt_and_save(key2)


if __name__ == "__main__":
    main()
