from algorithm import algorithm
import os
import socket


IP_DEST = "192.168.0.144"
DEST_PORT = 12345

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
            print('Cifraggio file con chiave A ...  ', read_bytes, ' / ', os.stat(orig_file).st_size)

    print('------ Criptaggio con chiave A completo ! ------')
    print('original file dimension:  ', dim_file, 'bytes')
    print('encrypted file dimension: ', read_bytes, 'bytes')
    padding = read_bytes - dim_file
    print('necessary padding: ', padding, 'bytes')

    return padding


def decypher_file_a(orig_file, dest_file, padding, keys_a):

    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        for i in range(0, len(keys_a)):
            chunk = file_in.read(algorithm.DIM_CHUNK // 8)
            new_chunk = algorithm.reverse_tex_function_for_a(keys_a[i], chunk)

            file_out.write(new_chunk)
            read_bytes += len(new_chunk)

            ########### stampa elaborazione avanzamento
            print('Togliendo la chiave A ...  ', read_bytes, ' / ', os.stat(orig_file).st_size)

    print('------ Decriptazione con A ------')
    print('dimensione file iniziale: ', dim_file, 'bytes')
    print('dimensione file finale: ', read_bytes, 'bytes')

## questa variante sfrutta solamente una chiave alla volta
## infatti se invio un chunk alla volta non c'e' bisogno di ricordarsi
## ogni volta tutte le chiavi. viene cifrato e decifrato un byte alla volta
## secondo lo schema riportato sugli appunti
if __name__ == '__main__' :

    md5_orig = algorithm.get_md5(ORIG_FILE)
    padding = 0
    size_tot = 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_DEST, DEST_PORT))

    ## calcolo del totale dei chunk da inviare
    num_chunk = os.stat(ORIG_FILE).st_size // (algorithm.DIM_CHUNK // 8)
    # verifico se e' necessario aggiunger e un padding
    if os.stat(ORIG_FILE).st_size % (algorithm.DIM_CHUNK // 8) != 0:
        num_chunk = num_chunk + 1
        size_tot = num_chunk * ((algorithm.DIM_CHUNK // 8))
        padding =  size_tot - os.stat(ORIG_FILE).st_size

    # invio md5 originale, padd, e dimensione originale
    sock.send(md5_orig.encode())
    sock.send(str(padding).encode())
    sock.send(str(num_chunk).zfill(10).encode())
    print('md5 ', md5_orig, ', padd ', padding, ', size_tot ', size_tot, ', num_chunk ', num_chunk)

    # ciclo che cifra con A, invia un chunk, decifra con A e reinvia
    orig_file = open(ORIG_FILE, 'rb')
    for i in range(num_chunk):

        chunk = orig_file.read(algorithm.DIM_CHUNK // 8)        ## leggo gli 8 bytes
        ## verifica se necessario aggiungere il padding al file
        if len(chunk) < (algorithm.DIM_CHUNK // 8):
            chunk += bytes(padding)

        ka = algorithm.generate_key()                           ## genera la chiave valida per il chunk letto
        chunk_a = algorithm.tex_function_for_a(ka, chunk)       ## cifratura del chunk

        ## invio del chunk cifrato con chiave a
        sock.send(chunk_a)
        ## ricevo il chunk cifrato con a_b
        chunk_ab = sock.recv(algorithm.DIM_CHUNK // 8)
        ## decifra il chunk
        chunk_b = algorithm.reverse_tex_function_for_a(ka, chunk_ab)
        ## reinvio del chunk senza la chiave ma solo con quella di b
        sock.send(chunk_b)

    ## chiusura del file e del socket
    orig_file.close()
    sock.close()





