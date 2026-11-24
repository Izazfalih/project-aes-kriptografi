# Project Kriptografi: Implementasi AES-128 From Scratch

Proyek tugas mandiri Kriptografi (Semester 5) mengimplementasikan algoritma **AES-128 (Advanced Encryption Standard)** secara mandiri (*pure standard library*, tanpa pustaka kriptografi eksternal pihak ketiga).

## Struktur Berkas
* [`aes_cipher.py`](file:///Users/izazfalih/COLLAGE/Semester%205/Materi/Kriptografi/Project_AES/aes_cipher.py): Skrip program utama (CLI, engine AES, mode ECB/CBC/CTR, inspeksi state per ronde, dan pengujian).
* [`Konsep_Proyek_AES.docx`](file:///Users/izazfalih/COLLAGE/Semester%205/Materi/Kriptografi/Project_AES/Konsep_Proyek_AES.docx): Dokumen konsep & proposal akademik siap cetak / serah ke dosen.
* [`Konsep_Proyek_AES.md`](file:///Users/izazfalih/COLLAGE/Semester%205/Materi/Kriptografi/Project_AES/Konsep_Proyek_AES.md): Versi teks Markdown dari dokumen konsep.
* [`generate_docx.py`](file:///Users/izazfalih/COLLAGE/Semester%205/Materi/Kriptografi/Project_AES/generate_docx.py): Skrip generator Word Document.

## Cara Menjalankan Program

### 1. Mode Interaktif (Menu Utama)
```bash
python3 aes_cipher.py
```
Menu interaktif menyediakan opsi:
1. Enkripsi Teks (Pilihan Mode: ECB / CBC / CTR)
2. Dekripsi Teks (Pilihan Mode: ECB / CBC / CTR)
3. Inspeksi Edukatif: Step-by-Step Ronde AES (State Matriks 4x4)
4. Enkripsi & Dekripsi File Dokumen/Gambar
5. Jalankan Vektor Uji Resmi NIST FIPS-197
6. Demonstrasi Pengujian Avalanche Effect

### 2. Pengujian Cepat Vektor Standar NIST FIPS-197
```bash
python3 aes_cipher.py --test
```
Hasil uji membuktikan presisi matematis 100% terhadap dokumen spesifikasi FIPS-197 Appendix B.
