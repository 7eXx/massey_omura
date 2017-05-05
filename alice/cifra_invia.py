from algorithm import algorithm
import os
import socket


ORIG_FILE = 'f22_raptor.jpg'
CRIPT_FILE_A = 'cripted_f22_a.jpg'
CRIPT_FILE_AB = 'crypted_f22_ab.jpg'
CRIPT_FILE_B = 'crypted_f22_b.jpg'

## cifra il file sui due percorsi
## ritorna il padding calcolato se aggiunto
def cypher_file_a(orig_file, dest_file, keys_a):
    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        for ka in keys_a:
            chunk = file_in.read(algorithm.DIM_CHUNK // 8)

            ## verifica vengono letti meno di 8 byte aggiunge il pagging
            if len(chunk) < 8:
                padding = 8 - len(chunk)
                chunk += bytes(8 - len(chunk))

            new_chunk = algorithm.tex_function_for_a(ka, chunk)
            file_out.write(new_chunk)
            read_bytes += len(new_chunk)

            ########### stampa elaborazione avanzamento
            print('Cifraggio file ...  ', read_bytes, ' / ', os.stat(orig_file).st_size)

    print('------ Encryption completed! ------')
    print('original file dimension:  ', dim_file, 'bytes')
    cripted_size = os.stat(dest_file).st_size
    print('encrypted file dimension: ', cripted_size, 'bytes')
    padding = cripted_size - dim_file
    print('necessary padding: ', padding, 'bytes')

    return padding


def decypher_file_a(orig_file, dest_file, padding, keys_a):

    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        for i in range(0, len(keys_a)):
            chunk = file_in.read(algorithm.DIM_CHUNK // 8)

            new_chunk = algorithm.reverse_tex_funtion_for_a(keys_a[i], chunk)

            if i == (len(keys_a) - 1):
                file_out.write(new_chunk[:-padding])
            else:
                file_out.write(new_chunk)

            read_bytes += len(new_chunk)

            ########### stampa elaborazione avanzamento
            print('Togliendo la chiave A ...  ', read_bytes, ' / ', os.stat(orig_file).st_size)

    print('------ Decriptazione con A ------')
    print('dimensione file iniziale: ', dim_file, 'bytes')
    cripted_size = os.stat(dest_file).st_size
    print('dimensione file finale: ', cripted_size, 'bytes')


if __name__ == '__main__' :

    md5_orig = algorithm.get_md5(ORIG_FILE)

    sock = socket.socket

    # generazione delle chiavi per a size / 8 byte
    num_keys_a = os.stat(ORIG_FILE).st_size // (algorithm.DIM_CHUNK // 8)
    # controllo se c'e' resto allora si ha una chiave in piu'
    if os.stat(ORIG_FILE).st_size % algorithm.DIM_CHUNK != 0:
        num_keys_a += 1

    ## genero le chiavi di A utilizzate uno per ogni chunk
    keys_a = algorithm.generate_keys(num_keys_a)
    ## cifratura del file, salvataggio su file output e ritorno del padding calcolato
    padd = cypher_file_a(ORIG_FILE, CRIPT_FILE_A, keys_a)

    ## decifratura da file in a out secondo un padding dato e chiavi calcolate
    decypher_file_a(CRIPT_FILE_A, CRIPT_FILE_B, padd, keys_a)

    md5_new = algorithm.get_md5(CRIPT_FILE_B)

    print('md5 originale = ' + md5_orig)
    print('md5 vecchio = ' + md5_new)

    #TODO il file e' pronto per essere inviato.
