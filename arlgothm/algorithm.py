
DIM_CHUNK = 8 * 8

# funzione prende un intero e una chiave ka
# trasforma l'intero in binario e fa r_shift per ka pos
# ka deve essere intero da 0 a 63 (utilizzare modulo per generarlo)
def tex_function_for_a(ka, a) :
    ba = (bin(a)[2:]).zfill(DIM_CHUNK)
    ba = ba[-DIM_CHUNK:]
    return  ba[-ka:] + ba[:-ka]

def reverse_tex_funtion_for_a(ka, a):
    ba = (bin(a)[2:]).zfill(DIM_CHUNK)
    ba = ba[-DIM_CHUNK:]
    return ba[ka:] + ba[:ka]

# funzione prende un intero e una chiave ka
# trasforma l'intero in binario e fa r_shift per ka pos
# ka deve essere intero da 0 a 63 (utilizzare modulo per generarlo)
def tex_funtion_for_b (kb, b):
    ba = (bin(b)[2:]).zfill(DIM_CHUNK)
    ba = ba[-DIM_CHUNK:]
    return ba[ka:] + ba[:ka]

def reverse_tex_funtion_for_b (kb, b):
    ba = (bin(b)[2:]).zfill(DIM_CHUNK)
    ba = ba[-DIM_CHUNK:]
    return ba[-ka:] + ba[:-ka]


if __name__ == '__main__':

    ka = 8
    kb = 13
    # kb_xor = kb ** kb ** kb
    # kb_xor = (bin(kb_xor)[2:]).zfill(DIM_CHUNK)
    # kb_xor = kb_xor[-DIM_CHUNK:]
    # print(kb_xor, ' key generated per xor b')

    c = 0x123456789abcdef1
    print(((bin(c)[2:]).zfill(DIM_CHUNK))[-DIM_CHUNK:], ' chunk orig')

    ma = tex_function_for_a(ka, c)
    print(ma, ' chunk con func a e ka')

    ma = int(ma,2)  # conversione in intero
    mb = tex_funtion_for_b(kb, ma)
    print(mb, ' chunck con func b e kb')

    mb = int(mb,2)  # conversione in intero
    ma1 = reverse_tex_funtion_for_a(ka, mb)
    print(ma1 , ' reverse func a e ka')

    ma1 = int(ma1,2)    # conversione in intero
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





