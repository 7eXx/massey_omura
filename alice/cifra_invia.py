from algorithm import algorithm
import os


SEND_PATH = 'f22_raptor.jpg'
CRIPT_FILE = 'cripted_f22.jpg'
padding = 0
size_encrypt = 0

def cypher_file_a(path, keys_a):

    dim_file = os.stat(path).st_size
    read_bytes = 0

    with open(path,'rb') as file_in, open(CRIPT_FILE, 'wb') as file_out:

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
            print('Cifraggio file ...  ', read_bytes, ' / ', os.stat(path).st_size)

    print('------ Encryption completed! ------')
    print('original file dimension:  ', dim_file, 'bytes')
    cripted_size = os.stat(CRIPT_FILE).st_size
    print('encrypted file dimension: ', cripted_size, 'bytes')
    padding = cripted_size - dim_file
    print('necessary padding: ', padding, 'bytes')


if __name__ == '__main__' :

    md5_orig = algorithm.get_md5(SEND_PATH)

    # generazione delle chiavi per a size / 8 byte
    num_keys_a = os.stat(SEND_PATH).st_size // (algorithm.DIM_CHUNK // 8)
    # controllo se c'e' resto allora si ha una chiave in piu'
    if os.stat(SEND_PATH).st_size % algorithm.DIM_CHUNK != 0:
        num_keys_a += 1

    keys_a = algorithm.generate_keys(num_keys_a)

    cypher_file_a(SEND_PATH, keys_a)

    md5_new = algorithm.get_md5(CRIPT_FILE)

    print('md5 originale = ' + md5_orig)
    print('md5 vecchio = ' + md5_new)

    #TODO il file e' pronto per essere inviato.
