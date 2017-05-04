

if __name__ == '__main__':

    # TODO: trovare una funzione da sostituire per genreare ma invertibile

    DIM_CHUNK = 8*8

    ka = 8
    c = 0x123456789abcdef1

    bc = (bin(c)[2:]).zfill(DIM_CHUNK)
    bc = bc[-DIM_CHUNK:]
    print(bc, ' chunk orig')

    ka_xor = ka ** ka ** ka
    ka_xor = (bin(ka_xor)[2:]).zfill(DIM_CHUNK)
    ka_xor = ka_xor[-DIM_CHUNK:]
    print(ka_xor, ' key generated per xor a ')

    ma = int(bc, 2) ^ int(ka_xor, 2)
    # ma = bc[-ka:] + bc[:-ka]
    print(bin(ma)[2:].zfill(DIM_CHUNK), ' chunk shift ma')

    kb = 3
    kb_xor = kb**kb**kb
    kb_xor = (bin(kb_xor)[2:]).zfill(DIM_CHUNK)
    kb_xor = kb_xor[-DIM_CHUNK:]
    print(kb_xor, ' key generated per xor b')

    mb = ma ^ int(kb_xor,2)
    print (bin(mb)[2:].zfill(DIM_CHUNK), ' chunk con le due chiavi xor e shift')

    ma1 = mb ^ int(ka_xor,2)
    # mb_temp = ((bin(mb)[2:]).zfill(DIM_CHUNK))[-DIM_CHUNK:]
    # ma1 = mb_temp[ka:] + mb_temp[:ka]
    print(bin(ma1)[2:].zfill(DIM_CHUNK), ' ma1 senza shift con xor chiave b')

    orig = ma1 ^ int(kb_xor, 2)
    print(bin(orig)[2:].zfill(DIM_CHUNK), ' originale')





