# PROPOSAL & KONSEP PROYEK KRIPTOGRAFI
## Implementasi Mandiri Algoritma AES-128 (*Advanced Encryption Standard*) dari Dasar (*From Scratch*) dengan Analisis Mode Operasi dan Visualisasi Edukatif Matriks State

* **Mata Kuliah**: Kriptografi (IF21A05)
* **Semester / Jenjang**: 5 (Lima) / S-1 Teknik Informatika
* **Penyusun**: Izaz Falih (NIM: H1D024034)

---

### 1. Latar Belakang
Kriptografi simetris modern merupakan pilar utama dalam keamanan data digital, pertukaran informasi di jaringan internet, serta proteksi basis data. Setelah standar DES (*Data Encryption Standard*) dinyatakan rentan terhadap serangan *brute-force* karena ukuran kuncinya yang terbatas (56 bit), NIST (*National Institute of Standards and Technology*) meresmikan algoritma Rijndael sebagai AES (*Advanced Encryption Standard*) melalui publikasi FIPS-197.

AES merupakan *iterative block cipher* berbasis jaringan substitusi-permutasi (*Substitution-Permutation Network* / SPN). Berbeda dari cipher klasik yang beroperasi pada karakter alfabet atau representasi biner sederhana, AES berakar kuat pada matematika Aljabar Abstrak, khususnya aritmatika medan berhingga Galois Field $GF(2^8)$. 

Sering kali mahasiswa dan pengembang hanya memanfaatkan *library* instan tanpa memahami mekanisme transformasi byte dan difusi di dalamnya. Proyek ini dibangun untuk mengimplementasikan algoritma AES-128 secara murni (*from scratch*) tanpa pustaka kriptografi pihak ketiga, menyajikan inspeksi edukatif langkah-demi-langkah per ronde, serta membandingkan keamanan berbagai mode operasi (*Block Cipher Modes of Operation*).

---

### 2. Rumusan Masalah
1. Bagaimana mengonstruksi operasi aritmatika medan berhingga $GF(2^8)$ serta pembangkitan S-Box dan invers S-Box melalui transformasi afin?
2. Bagaimana mengimplementasikan empat transformasi inti AES (SubBytes, ShiftRows, MixColumns, AddRoundKey) serta algoritma *Key Schedule* (penjadwalan kunci) 128-bit secara mandiri?
3. Bagaimana mekanisme penanganan data panjang sembarang menggunakan *padding* PKCS#7 dan mode operasi (ECB, CBC, dan CTR)?
4. Bagaimana membuktikan keabsahan implementasi mandiri terhadap vektor uji resmi standar NIST FIPS-197 dan mengukur *Avalanche Effect*?

---

### 3. Landasan Teori & Konsep Matematis

#### 3.1 Representasi Matriks State
Data blok input berukuran 128 bit (16 byte) dipetakan ke dalam matriks state dua dimensi $4 \times 4$ dengan urutan *column-major order*:

$$
\begin{bmatrix}
s_{0,0} & s_{0,1} & s_{0,2} & s_{0,3} \\
s_{1,0} & s_{1,1} & s_{1,2} & s_{1,3} \\
s_{2,0} & s_{2,1} & s_{2,2} & s_{2,3} \\
s_{3,0} & s_{3,1} & s_{3,2} & s_{3,3}
\end{bmatrix}
$$

di mana byte ke-$k$ ($0 \le k \le 15$) menempati baris $r = k \pmod 4$ dan kolom $c = \lfloor k / 4 \rfloor$.

#### 3.2 Aritmatika Medan Berhingga $GF(2^8)$
Elemen dalam medan berhingga biner berorde $2^8$ direpresentasikan sebagai polinomial berderajat paling tinggi 7 dengan koefisien biner $\{0, 1\}$.
* **Penjumlahan & Pengurangan**: Dilakukan dengan operasi biner XOR ($\oplus$).
* **Perkalian Polinomial**: Dihitung modulo polinomial biner tak tereduksi (*irreducible polynomial*):
  $$P(x) = x^8 + x^4 + x^3 + x + 1 \quad (\text{ekivalen dengan } \mathtt{0x11B})$$
* **Fungsi `xtime()`**: Perkalian suatu elemen dengan $x$ (biner $\mathtt{0x02}$). Dilakukan dengan pergeseran kiri 1 bit (`b << 1`), dan jika terjadi *overflow* pada bit ke-8, dilakukan XOR dengan $\mathtt{0x1B}$.

#### 3.3 Transformasi Ronde AES-128
Setiap ronde (dari total 10 ronde untuk kunci 128 bit) terdiri dari 4 tahapan operasi:
1. **`SubBytes` (Substitusi Byte)**:
   Transformasi non-linear yang memetakan setiap byte state $s_{r,c}$ menggunakan kotak-S (S-Box). S-Box diperoleh dari pencarian invers perkalian di $GF(2^8)$ dilanjutkan dengan transformasi afin matriks biner untuk merusak struktur aljabar.
2. **`ShiftRows` (Pergeseran Baris)**:
   Mekanisme difusi di mana baris ke-0 tidak bergeser, baris ke-1 digeser melingkar ke kiri 1 byte, baris ke-2 digeser ke kiri 2 byte, dan baris ke-3 digeser ke kiri 3 byte.
3. **`MixColumns` (Pencampuran Kolom)**:
   Setiap kolom matriks state dikalikan dengan matriks koefisien konstan di atas $GF(2^8)$:
   $$
   \begin{bmatrix} s'_{0,c} \\ s'_{1,c} \\ s'_{2,c} \\ s'_{3,c} \end{bmatrix} =
   \begin{bmatrix}
   02 & 03 & 01 & 01 \\
   01 & 02 & 03 & 01 \\
   01 & 01 & 02 & 03 \\
   03 & 01 & 01 & 02
   \end{bmatrix}
   \begin{bmatrix} s_{0,c} \\ s_{1,c} \\ s_{2,c} \\ s_{3,c} \end{bmatrix}
   $$
   *(Catatan: Tahap MixColumns ditiadakan pada ronde ke-10 / ronde terakhir).*
4. **`AddRoundKey` (Penambahan Kunci Ronde)**:
   Matriks state dioperasikan XOR secara langsung dengan matriks subkunci ronde yang dihasilkan dari proses *Key Expansion*.

#### 3.4 Key Schedule (Ekspansi Kunci)
Kunci rahasia 128-bit (4 word 32-bit: $W[0], W[1], W[2], W[3]$) diekspansi menjadi 44 word untuk membentuk 11 subkunci ronde ($11 \times 16 \text{ byte} = 176 \text{ byte}$).
Untuk indeks kelipatan 4 ($i \pmod 4 = 0$), diterapkan fungsi transformasi `RotWord` (rotasi siklis 1 byte ke kiri), `SubWord` (substitusi S-Box), dan penambahan konstanta ronde `Rcon[i/4]`.

---

### 4. Mode Operasi & Penanganan Pesan
Karena AES hanya beroperasi pada blok tetap 16 byte, diimplementasikan mode operasi dan padding:
1. **PKCS#7 Padding**: Memastikan panjang pesan kelipatan 16 byte dengan menambahkan $N$ byte bernilai $N$.
2. **Mode ECB (*Electronic Codebook*)**: Setiap blok dienkripsi secara independen. Mode ini rentan terhadap kebocoran pola data (*pattern leakage*).
3. **Mode CBC (*Cipher Block Chaining*)**: Setiap blok *plaintext* di-XOR dengan blok *ciphertext* sebelumnya sebelum dienkripsi. Menggunakan vektor inisialisasi acak (*IV - Initialization Vector*) 128-bit untuk mencegah replikasi pola.
4. **Mode CTR (*Counter Mode*)**: Mengubah algoritma blok menjadi *stream cipher* dengan mengenkripsi kombinasi Nonce dan nilai pencacah (*counter*).

---

### 5. Arsitektur Program & Pengujian
Program dikembangkan dalam file [`aes_cipher.py`](file:///Users/izazfalih/COLLAGE/Semester%205/Materi/Kriptografi/Project_AES/aes_cipher.py) dengan fitur:
1. **Pengujian Vektor Resmi NIST FIPS-197**:
   * Plaintext: `00112233445566778899aabbccddeeff`
   * Key: `000102030405060708090a0b0c0d0e0f`
   * Expected Ciphertext: `69c4e0d86a7b0430d8cdb78070b4c55a`
   * Hasil Pengujian: **Valid 100% (Bit-exact match)**.
2. **Visualizer Edukatif Step-by-Step**: Menampilkan isi matriks state $4 \times 4$ mulai dari ronde 0 hingga ronde 10 untuk keperluan demonstrasi di hadapan dosen.
3. **Uji Avalanche Effect**: Membuktikan bahwa pembalikan 1 bit pada plaintext menghasilkan perubahan >50% bit pada ciphertext (memenuhi kriteria difusi Shannon).
4. **Enkripsi File Riil**: Mendukung proteksi file biner, dokumen, dan gambar dengan penyimpanan IV otomatis.
