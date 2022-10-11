import streamlit as st
from cryptography.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SHA384())
st.write("""
# Fungsi Hash
""")

input = st.text_input('Masukkan Teks', 'Universitas Respati Yogyakarta')

algoritma = st.selectbox('Fungsi Hash',('SHA256','SHA384', 'SHA512', 'MD5', 'SHA1', 'SHA512_224', 'SHA512_256',
	'SHA224', 'SHA3_224', 'SHA3_256', 'SHA3_384', 'SHA3_512', 'SHAKE128', 'SHAKE256', 'BLAKE2b', 'BLAKE2s', 'SM3'))
if(algoritma == 'SHA256') :
    digest = hashes.Hash(hashes.SHA256()) 
elif(algoritma == 'SHA384') :
    digest = hashes.Hash(hashes.SHA384())
elif(algoritma == 'SHA512') :
    digest = hashes.Hash(hashes.SHA512())
elif(algoritma == 'MD5') :
    digest = hashes.Hash(hashes.MD5())
elif(algoritma == 'SHA1') :
    digest = hashes.Hash(hashes.SHA1())
elif(algoritma == 'SHA512_224') :
    digest = hashes.Hash(hashes.SHA512_224())
elif(algoritma == 'SHA512_256') :
    digest = hashes.Hash(hashes.SHA512_256())
elif(algoritma == 'SHA224') :
    digest = hashes.Hash(hashes.SHA224())
elif(algoritma == 'SHA3_224') :
    digest = hashes.Hash(hashes.SHA3_224())
elif(algoritma == 'SHA3_256') :
    digest = hashes.Hash(hashes.SHA3_256())
elif(algoritma == 'SHA3_384') :
    digest = hashes.Hash(hashes.SHA3_384())
elif(algoritma == 'SHA3_512') :
    digest = hashes.Hash(hashes.SHA3_512())
elif(algoritma == 'SHAKE128') :
    digest = hashes.Hash(hashes.SHAKE128())
elif(algoritma == 'SHAKE256') :
    digest = hashes.Hash(hashes.SHAKE256())
elif(algoritma == 'BLAKE2b') :
    digest = hashes.Hash(hashes.BLAKE2b())
elif(algoritma == 'BLAKE2s') :
    digest = hashes.Hash(hashes.BLAKE2s())
else :
    digest = hashes.Hash(hashes.SM3())

digest.update(input.encode())
hash = digest.finalize()
st.write('Hash :', hash.hex())
