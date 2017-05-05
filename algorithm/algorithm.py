import  random
import  hashlib
import os

DIM_CHUNK = 8 * 8

# funzione prende una successione di bytes e una chiave ka intera
# ritorna una sequenza di bytes della stessa dimensione di input
def tex_function_for_a(ka, a) :
    # conversione da bytes in int e in int bin string
    ba = (bin(int.from_bytes(a, byteorder='big'))[2:]).zfill(DIM_CHUNK)
    ba = ba[-DIM_CHUNK:]
    ka = ka % DIM_CHUNK
    ba = ba[-ka:] + ba[:-ka]
    # riconversione da string bin in int a bytes
    return  int(ba, 2).to_bytes(len(ba) // 8, byteorder='big')

# funzione prende una successione di bytes e una chiave ka intera
# ritorna una sequenza di bytes della stessa dimensione di input
def reverse_tex_funtion_for_a(ka, a):
    # conversione da bytes in int e in int bin string
    ba = (bin(int.from_bytes(a, byteorder='big'))[2:]).zfill(DIM_CHUNK)
    ba = ba[-DIM_CHUNK:]
    ka = ka % DIM_CHUNK
    ba = ba[ka:] + ba[:ka]
    # riconversione da string bin in int a bytes
    return int(ba, 2).to_bytes(len(ba) // 8, byteorder='big')

# funzione prende un intero e una chiave kb
# trasforma l'intero in binario e fa r_shift per kb pos
# kb deve essere intero viene fatto il modulo per portarlo a max 63
def tex_funtion_for_b (kb, b):
    # conversione da bytes in int e in int bin string
    bb = (bin(int.from_bytes(b, byteorder='big'))[2:]).zfill(DIM_CHUNK)
    bb = bb[-DIM_CHUNK:]
    kb = kb % DIM_CHUNK
    bb = bb[kb:] + bb[:kb]
    # riconversione da string bin in int a bytes
    return int(bb, 2).to_bytes(len(bb) // 8, byteorder='big')

# stessa cosa per function b
def reverse_tex_funtion_for_b (kb, b):
    # conversione da bytes in int e in int bin string
    bb = (bin(int.from_bytes(b, byteorder='big'))[2:]).zfill(DIM_CHUNK)
    ba = bb[-DIM_CHUNK:]
    kb = kb % DIM_CHUNK
    bb = bb[-kb:] + bb[:-kb]
    # riconversione da string bin in int a bytes
    return int(bb, 2).to_bytes(len(bb) // 8, byteorder='big')

def get_md5(path):
    md5 = hashlib.md5()
    tot_size = os.stat(path).st_size
    tot_read = 0
    with open(path,'rb') as f:
        while tot_read < tot_size:
            data = f.read(1024)
            md5.update(data)
            tot_read += len(data)
    return md5.hexdigest()


# questa funzione genera un array di chiavi
# da utilizzare per criptare tutti i chunk
def generate_keys(num_keys):
    keys = []
    for i in range(num_keys):
        keys.append(random.randrange(0, 2**(DIM_CHUNK // 8)))
    return keys

# main di prova vario
if __name__ == '__main__':

    ka = 8
    kb = 13
    # kb_xor = kb ** kb ** kb
    # kb_xor = (bin(kb_xor)[2:]).zfill(DIM_CHUNK)
    # kb_xor = kb_xor[-DIM_CHUNK:]
    # print(kb_xor, ' key generated per xor b')

    c = b'\xff\xd8\xff\xe0\x00\x10JF'
    print(c, ' chunk orig')

    ma = tex_function_for_a(ka, c)
    print(ma, ' chunk con func a e ka')

    mb = tex_funtion_for_b(kb, ma)
    print(mb, ' chunck con func b e kb')

    ma1 = reverse_tex_funtion_for_a(ka, mb)
    print(ma1 , ' reverse func a e ka')

    orig = reverse_tex_funtion_for_b(kb, ma1)
    print(orig, ' original reverse func b e kb')


    # mb = int(ma,2) ^ int(kb_xor,2)
    # print(bin(mb)[2:].zfill(DIM_CHUNK), ' chunk con le due chiavi xor e shift')

    #ma1 = mb ^ int(ka_xor,2)
    # mb_temp = ((bin(mb)[2:]).zfill(DIM_CHUNK))[-DIM_CHUNK:]
    # ma1 = mb_temp[ka:] + mb_temp[:ka]
    # print(ma1, ' ma1 senza shift con xor chiave b')
    #
    # orig = int(ma1, 2) ^ int(kb_xor, 2)
    # print(bin(orig)[2:].zfill(DIM_CHUNK), ' originale')





