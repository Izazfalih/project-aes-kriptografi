"""
Proyek Kriptografi: Implementasi Mandiri Algoritma AES-128 (Advanced Encryption Standard)
Mata Kuliah: Kriptografi (Semester 5)
Implementasi murni menggunakan Python Standard Library (tanpa library kriptografi eksternal).

Mencakup:
1. Aritmatika Medan Galois GF(2^8) & Pembangkitan S-Box / Inverse S-Box
2. 4 Transformasi Utama Ronde AES: SubBytes, ShiftRows, MixColumns, AddRoundKey
3. Key Schedule / Key Expansion untuk kunci 128-bit (10 ronde)
4. Mode Operasi: ECB, CBC (dengan PKCS#7 Padding), dan CTR
5. Mode Edukasi: Inspeksi state matrix (4x4) per ronde step-by-step
6. Pengujian mandiri terhadap vektor uji standar NIST FIPS-197
"""

import os
import sys
import time
from typing import List, Tuple

# Polinomial ireduktibel standar Rijndael / AES: P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
IRREDUCIBLE_POLY = 0x11B

# Konstanta Ronde (Round Constants - Rcon) untuk AES-128
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]


def gf_mult(a: int, b: int) -> int:
    """Perkalian dua elemen dalam Medan Galois GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B  # x^4 + x^3 + x + 1
        b >>= 1
    return p


def gf_inverse(byte_val: int) -> int:
    """Menghitung invers perkalian dalam GF(2^8). Invers dari 0 didefinisikan 0."""
    if byte_val == 0:
        return 0
    # Berdasarkan Teorema Kecil Fermat: a^(254) = a^(-1) dalam GF(2^8)
    res = 1
    base = byte_val
    exp = 254
    while exp > 0:
        if exp & 1:
            res = gf_mult(res, base)
        base = gf_mult(base, base)
        exp >>= 1
    return res


def build_sbox() -> Tuple[List[int], List[int]]:
    """Membangun tabel S-Box dan Inverse S-Box melalui transformasi afin."""
    sbox = [0] * 256
    inv_sbox = [0] * 256

    for b in range(256):
        inv = gf_inverse(b)
        # Transformasi afin: s = inv ^ (inv <<< 1) ^ (inv <<< 2) ^ (inv <<< 3) ^ (inv <<< 4) ^ 0x63
        s = inv
        s ^= ((inv << 1) | (inv >> 7)) & 0xFF
        s ^= ((inv << 2) | (inv >> 6)) & 0xFF
        s ^= ((inv << 3) | (inv >> 5)) & 0xFF
        s ^= ((inv << 4) | (inv >> 4)) & 0xFF
        s ^= 0x63
        sbox[b] = s
        inv_sbox[s] = b

    return sbox, inv_sbox


S_BOX, INV_S_BOX = build_sbox()


# ==========================================================
# 1. Transformasi Matriks State & Operasi Ronde
# ==========================================================

def bytes_to_state(block: bytes) -> List[List[int]]:
    """Mengubah 16 byte menjadi matriks state 4x4 (kolom demi kolom)."""
    state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[col * 4 + row]
    return state


def state_to_bytes(state: List[List[int]]) -> bytes:
    """Mengubah matriks state 4x4 kembali menjadi 16 byte (kolom demi kolom)."""
    out = bytearray(16)
    for col in range(4):
        for row in range(4):
            out[col * 4 + row] = state[row][col]
    return bytes(out)


def sub_bytes(state: List[List[int]]) -> None:
    """Substitusi non-linear tiap byte menggunakan S-Box."""
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]


def inv_sub_bytes(state: List[List[int]]) -> None:
    """Invers substitusi byte menggunakan Inverse S-Box."""
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]


def shift_rows(state: List[List[int]]) -> None:
    """Pergeseran siklis ke kiri pada setiap baris matriks state."""
    state[1] = state[1][1:] + state[1][:1]  # Geser 1
    state[2] = state[2][2:] + state[2][:2]  # Geser 2
    state[3] = state[3][3:] + state[3][:3]  # Geser 3


def inv_shift_rows(state: List[List[int]]) -> None:
    """Pergeseran siklis ke kanan pada setiap baris matriks state."""
    state[1] = state[1][3:] + state[1][:3]  # Geser kanan 1
    state[2] = state[2][2:] + state[2][:2]  # Geser kanan 2
    state[3] = state[3][1:] + state[3][:1]  # Geser kanan 3


def mix_columns(state: List[List[int]]) -> None:
    """Difusi linear kolom dalam GF(2^8)."""
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gf_mult(0x02, s0) ^ gf_mult(0x03, s1) ^ s2 ^ s3
        state[1][c] = s0 ^ gf_mult(0x02, s1) ^ gf_mult(0x03, s2) ^ s3
        state[2][c] = s0 ^ s1 ^ gf_mult(0x02, s2) ^ gf_mult(0x03, s3)
        state[3][c] = gf_mult(0x03, s0) ^ s1 ^ s2 ^ gf_mult(0x02, s3)


def inv_mix_columns(state: List[List[int]]) -> None:
    """Invers difusi linear kolom menggunakan invers matriks koefisien."""
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gf_mult(0x0E, s0) ^ gf_mult(0x0B, s1) ^ gf_mult(0x0D, s2) ^ gf_mult(0x09, s3)
        state[1][c] = gf_mult(0x09, s0) ^ gf_mult(0x0E, s1) ^ gf_mult(0x0B, s2) ^ gf_mult(0x0D, s3)
        state[2][c] = gf_mult(0x0D, s0) ^ gf_mult(0x09, s1) ^ gf_mult(0x0E, s2) ^ gf_mult(0x0B, s3)
        state[3][c] = gf_mult(0x0B, s0) ^ gf_mult(0x0D, s1) ^ gf_mult(0x09, s2) ^ gf_mult(0x0E, s3)


def add_round_key(state: List[List[int]], round_key: List[List[int]]) -> None:
    """Operasi XOR antara matriks state dan kunci ronde."""
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]


# ==========================================================
# 2. Key Expansion (Penjadwalan Kunci AES-128)
# ==========================================================

def rot_word(word: List[int]) -> List[int]:
    """Rotasi siklis 1 byte ke kiri pada sebuah word (4 byte)."""
    return word[1:] + word[:1]


def sub_word(word: List[int]) -> List[int]:
    """Substitusi setiap byte dalam word menggunakan S-Box."""
    return [S_BOX[b] for b in word]


def key_expansion(key_bytes: bytes) -> List[List[List[int]]]:
    """Membangkitkan 11 round keys (44 words = 176 byte) untuk AES-128."""
    if len(key_bytes) != 16:
        raise ValueError("Panjang kunci harus tepat 16 byte (128 bit)!")

    words: List[List[int]] = []
    # 4 word pertama diambil langsung dari kunci awal
    for i in range(4):
        words.append([key_bytes[4 * i + j] for j in range(4)])

    # 40 word berikutnya dibangkitkan berulang
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]
        
        new_word = [words[i - 4][j] ^ temp[j] for j in range(4)]
        words.append(new_word)

    # Susun ke dalam 11 subkunci berukuran 4x4
    round_keys: List[List[List[int]]] = []
    for r in range(11):
        key_matrix = [[0] * 4 for _ in range(4)]
        for col in range(4):
            w = words[r * 4 + col]
            for row in range(4):
                key_matrix[row][col] = w[row]
        round_keys.append(key_matrix)

    return round_keys


# ==========================================================
# 3. Enkripsi dan Dekripsi Blok Tunggal (16 Byte)
# ==========================================================

def format_state(state: List[List[int]]) -> str:
    """Format matriks state heksadesimal 4x4 untuk tampilan terminal."""
    lines = []
    for row in state:
        lines.append("  " + " ".join(f"{b:02X}" for b in row))
    return "\n".join(lines)


def encrypt_block(block: bytes, round_keys: List[List[List[int]]], verbose: bool = False) -> bytes:
    """Enkripsi blok 16-byte menggunakan AES-128."""
    if len(block) != 16:
        raise ValueError("Blok input harus tepat 16 byte.")

    state = bytes_to_state(block)
    if verbose:
        print("\n=== DETAIL ENKRIPSI AES-128 STEP-BY-STEP ===")
        print(f"State Awal (Input):\n{format_state(state)}")

    # Ronde Awal (Ronde 0): AddRoundKey
    add_round_key(state, round_keys[0])
    if verbose:
        print(f"\nSetelah Ronde 0 (AddRoundKey):\n{format_state(state)}")

    # Ronde 1 sampai 9
    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])
        if verbose:
            print(f"\nAkhir Ronde {r}:\n{format_state(state)}")

    # Ronde 10 (Ronde Akhir - tanpa MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    if verbose:
        print(f"\nAkhir Ronde 10 (Output Ciphertext):\n{format_state(state)}")

    return state_to_bytes(state)


def decrypt_block(block: bytes, round_keys: List[List[List[int]]], verbose: bool = False) -> bytes:
    """Dekripsi blok 16-byte ciphertext menggunakan AES-128."""
    if len(block) != 16:
        raise ValueError("Blok input harus tepat 16 byte.")

    state = bytes_to_state(block)
    if verbose:
        print("\n=== DETAIL DEKRIPSI AES-128 STEP-BY-STEP ===")
        print(f"State Ciphertext:\n{format_state(state)}")

    # Ronde Awal Dekripsi: AddRoundKey dengan subkunci ronde 10
    add_round_key(state, round_keys[10])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    # Ronde 9 turun sampai 1
    for r in range(9, 0, -1):
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    # Ronde 0
    add_round_key(state, round_keys[0])

    if verbose:
        print(f"Hasil Dekripsi Plaintext:\n{format_state(state)}")

    return state_to_bytes(state)


# ==========================================================
# 4. Padding PKCS#7 & Mode Operasi (ECB, CBC, CTR)
# ==========================================================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Menambahkan padding PKCS#7 agar panjang data kelipatan 16 byte."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Memvalidasi dan menghapus padding PKCS#7."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Data memiliki panjang tidak valid untuk unpadding PKCS#7.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Format padding tidak valid.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Integritas padding rusak.")
    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR antara dua byte array dengan panjang yang sama."""
    return bytes(x ^ y for x, y in zip(a, b))


def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """Enkripsi menggunakan mode Electronic Codebook (ECB)."""
    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        ciphertext.extend(encrypt_block(block, round_keys))
    return bytes(ciphertext)


def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Dekripsi menggunakan mode Electronic Codebook (ECB)."""
    round_keys = key_expansion(key)
    decrypted = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted.extend(decrypt_block(block, round_keys))
    return pkcs7_unpad(bytes(decrypted))


def aes_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
    """Enkripsi mode CBC. Mengembalikan (ciphertext, iv)."""
    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise ValueError("IV harus tepat 16 byte.")

    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    prev = iv

    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        xored = xor_bytes(block, prev)
        enc = encrypt_block(xored, round_keys)
        ciphertext.extend(enc)
        prev = enc

    return bytes(ciphertext), iv


def aes_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Dekripsi mode CBC."""
    if len(iv) != 16:
        raise ValueError("IV harus tepat 16 byte.")

    round_keys = key_expansion(key)
    decrypted = bytearray()
    prev = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = decrypt_block(block, round_keys)
        decrypted.extend(xor_bytes(dec, prev))
        prev = block

    return pkcs7_unpad(bytes(decrypted))


def aes_ctr_process(data: bytes, key: bytes, nonce: bytes = None) -> Tuple[bytes, bytes]:
    """Mode CTR (Counter Mode). Fungsi enkripsi dan dekripsi adalah simetris."""
    if nonce is None:
        nonce = os.urandom(8)  # 8 byte nonce acak
    elif len(nonce) != 8:
        raise ValueError("Nonce CTR harus 8 byte.")

    round_keys = key_expansion(key)
    result = bytearray()
    num_blocks = (len(data) + 15) // 16

    for counter in range(num_blocks):
        counter_bytes = counter.to_bytes(8, byteorder='big')
        counter_block = nonce + counter_bytes
        keystream_block = encrypt_block(counter_block, round_keys)

        start = counter * 16
        end = min(start + 16, len(data))
        chunk = data[start:end]
        result.extend(xor_bytes(chunk, keystream_block[:len(chunk)]))

    return bytes(result), nonce


# ==========================================================
# 5. Uji Validasi Standar NIST FIPS-197
# ==========================================================

def run_fips197_test():
    """Uji verifikasi resmi sesuai NIST Special Publication FIPS-197 Appendix B."""
    print("\n" + "=" * 65)
    print(" VERIFIKASI RESMI VEKTOR UJI STANDAR NIST FIPS-197")
    print("=" * 65)

    test_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    test_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    print(f"Kunci Uji    (Hex) : {test_key.hex()}")
    print(f"Plaintext    (Hex) : {test_pt.hex()}")
    print(f"Target NIST  (Hex) : {expected_ct.hex()}")

    round_keys = key_expansion(test_key)
    calc_ct = encrypt_block(test_pt, round_keys)
    print(f"Hasil Enkripsi     : {calc_ct.hex()}")

    if calc_ct == expected_ct:
        print("[STATUS]: SUKSES LULUS! Hasil enkripsi presisi 100% dengan standar NIST.")
    else:
        print("[STATUS]: GAGAL! Output tidak sesuai.")
        return

    dec_pt = decrypt_block(calc_ct, round_keys)
    print(f"Hasil Dekripsi     : {dec_pt.hex()}")
    if dec_pt == test_pt:
        print("[STATUS]: SUKSES LULUS! Hasil dekripsi kembali utuh ke plaintext awal.")
    else:
        print("[STATUS]: GAGAL! Dekripsi menghasilkan nilai berbeda.")


def demo_avalanche_effect():
    """Demonstrasi Avalanche Effect: perubahan 1 bit memicu perubahan >50% bit ciphertext."""
    print("\n" + "=" * 65)
    print(" DEMO ANALISIS KEAMANAN: AVALANCHE EFFECT (EFEK SALJU LONGSOR)")
    print("=" * 65)

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt1 = bytes.fromhex("00000000000000000000000000000000")
    pt2 = bytes.fromhex("00000000000000000000000000000001")  # Beda tepat 1 bit terakhir

    rk = key_expansion(key)
    c1 = encrypt_block(pt1, rk)
    c2 = encrypt_block(pt2, rk)

    diff_bits = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(c1, c2))
    percent = (diff_bits / 128) * 100

    print(f"Plaintext 1 (Hex) : {pt1.hex()}")
    print(f"Plaintext 2 (Hex) : {pt2.hex()} (Beda 1 bit)")
    print(f"Ciphertext 1      : {c1.hex()}")
    print(f"Ciphertext 2      : {c2.hex()}")
    print(f"Jumlah Bit Berubah: {diff_bits} dari 128 bit ({percent:.2f}%)")
    print("Kriteria Kriptografis: Efek Avalanche ideal mendekati ~50% pergeseran bit.")


# ==========================================================
# 6. Antarmuka Menu Utama (CLI Interaktif)
# ==========================================================

def interactive_cli():
    """Menu interaktif utama untuk pengujian dan demonstrasi dosen."""
    while True:
        print("\n" + "=" * 60)
        print(" SISTEM PENGAMANAN DATA AES-128 (FROM SCRATCH)")
        print(" Mata Kuliah Kriptografi - Semester 5")
        print("=" * 60)
        print("1. Enkripsi Teks (Pilihan Mode: ECB / CBC / CTR)")
        print("2. Dekripsi Teks (Pilihan Mode: ECB / CBC / CTR)")
        print("3. Inspeksi Edukatif: Step-by-Step Ronde AES (State 4x4)")
        print("4. Enkripsi & Dekripsi File Dokumen/Gambar")
        print("5. Jalankan Vektor Uji Resmi NIST FIPS-197")
        print("6. Demonstrasi Pengujian Avalanche Effect")
        print("0. Keluar")
        print("=" * 60)

        pilihan = input("Pilih menu (0-6): ").strip()

        if pilihan == "0":
            print("Program selesai. Terima kasih.")
            break

        elif pilihan == "1":
            pesan = input("\nMasukkan teks pesan: ").encode('utf-8')
            kunci_str = input("Masukkan kunci (tepat 16 karakter atau hex 32 char, tekan Enter untuk default): ").strip()
            if not kunci_str:
                kunci = b"KunciRahasia1234"
            elif len(kunci_str) == 32 and all(c in "0123456789abcdefABCDEF" for c in kunci_str):
                kunci = bytes.fromhex(kunci_str)
            else:
                kunci = kunci_str.encode('utf-8')[:16].ljust(16, b'#')

            print("\nPilih Mode Operasi:")
            print("1. CBC (Cipher Block Chaining - Standar Sangat Aman)")
            print("2. ECB (Electronic Codebook)")
            print("3. CTR (Counter Mode)")
            mode = input("Pilihan mode (1-3): ").strip()

            if mode == "2":
                ct = aes_encrypt_ecb(pesan, kunci)
                print(f"\n[HASIL ENKRIPSI ECB]")
                print(f"Kunci Digunakan (Hex) : {kunci.hex()}")
                print(f"Ciphertext (Hex)      : {ct.hex()}")
            elif mode == "3":
                ct, nonce = aes_ctr_process(pesan, kunci)
                print(f"\n[HASIL ENKRIPSI CTR]")
                print(f"Kunci (Hex)           : {kunci.hex()}")
                print(f"Nonce (Hex)           : {nonce.hex()}")
                print(f"Ciphertext (Hex)      : {ct.hex()}")
            else:
                ct, iv = aes_encrypt_cbc(pesan, kunci)
                print(f"\n[HASIL ENKRIPSI CBC]")
                print(f"Kunci (Hex)           : {kunci.hex()}")
                print(f"IV Acak (Hex)         : {iv.hex()}")
                print(f"Ciphertext (Hex)      : {ct.hex()}")

        elif pilihan == "2":
            ct_hex = input("\nMasukkan Ciphertext (Hex): ").strip()
            kunci_str = input("Masukkan kunci (16 karakter / 32 hex char): ").strip()
            if len(kunci_str) == 32 and all(c in "0123456789abcdefABCDEF" for c in kunci_str):
                kunci = bytes.fromhex(kunci_str)
            else:
                kunci = kunci_str.encode('utf-8')[:16].ljust(16, b'#')

            try:
                ct = bytes.fromhex(ct_hex)
                print("\nPilih Mode Operasi Dekripsi:")
                print("1. CBC")
                print("2. ECB")
                print("3. CTR")
                mode = input("Pilihan (1-3): ").strip()

                if mode == "2":
                    pt = aes_decrypt_ecb(ct, kunci)
                    print(f"\n[HASIL DEKRIPSI]: {pt.decode('utf-8', errors='replace')}")
                elif mode == "3":
                    nonce_hex = input("Masukkan Nonce (16 karakter Hex): ").strip()
                    nonce = bytes.fromhex(nonce_hex)
                    pt, _ = aes_ctr_process(ct, kunci, nonce)
                    print(f"\n[HASIL DEKRIPSI]: {pt.decode('utf-8', errors='replace')}")
                else:
                    iv_hex = input("Masukkan IV (32 karakter Hex): ").strip()
                    iv = bytes.fromhex(iv_hex)
                    pt = aes_decrypt_cbc(ct, kunci, iv)
                    print(f"\n[HASIL DEKRIPSI]: {pt.decode('utf-8', errors='replace')}")
            except Exception as e:
                print(f"\n[ERROR DEKRIPSI]: Terjadi kesalahan dekripsi ({e}). Kunci/IV tidak cocok atau data korup.")

        elif pilihan == "3":
            print("\n--- MODE INSPEKSI STATE MATRIX EDUKATIF (NIST VECTOR) ---")
            test_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
            test_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
            rk = key_expansion(test_key)
            encrypt_block(test_pt, rk, verbose=True)

        elif pilihan == "4":
            path_file = input("\nMasukkan path file yang akan dienkripsi: ").strip()
            if not os.path.isfile(path_file):
                print(f"File tidak ditemukan: {path_file}")
                continue

            kunci = os.urandom(16)
            with open(path_file, 'rb') as f:
                konten = f.read()

            start_t = time.time()
            ct, iv = aes_encrypt_cbc(konten, kunci)
            durasi = time.time() - start_t

            out_enc = path_file + ".aes"
            with open(out_enc, 'wb') as f:
                f.write(iv + ct)  # Simpan IV di 16 byte pertama

            print(f"\n[SUKSES] File terenkripsi disimpan di: {out_enc}")
            print(f"Ukuran File    : {len(konten)} byte -> {len(ct)} byte terenkripsi")
            print(f"Waktu Eksekusi : {durasi*1000:.2f} ms")
            print(f"Kunci Rahasia  : {kunci.hex()}")

            # Uji verifikasi langsung dekripsi
            with open(out_enc, 'rb') as f:
                saved = f.read()
            read_iv = saved[:16]
            read_ct = saved[16:]
            dec = aes_decrypt_cbc(read_ct, kunci, read_iv)
            out_dec = path_file + ".decrypted"
            with open(out_dec, 'wb') as f:
                f.write(dec)
            print(f"[VERIFIKASI] File berhasil didekripsi ulang ke: {out_dec}")

        elif pilihan == "5":
            run_fips197_test()

        elif pilihan == "6":
            demo_avalanche_effect()

        else:
            print("Pilihan tidak valid.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_fips197_test()
    else:
        interactive_cli()
