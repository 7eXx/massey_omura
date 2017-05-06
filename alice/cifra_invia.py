from algorithm import algorithm
import os
import socket


IP_DEST = "192.168.0.144"
DEST_PORT = 12345

ORIG_FILE = 'f22_raptor.jpg'
CRIPT_FILE_A = 'cripted_f22_a.jpg'
CRIPT_FILE_AB = 'crypted_f22_ab.jpg'
CRIPT_FILE_B = 'crypted_f22_b.jpg'

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
    sock.send(str(padding).zfill(algorithm.DIM_PADD).encode())
    sock.send(str(num_chunk).zfill(algorithm.DIM_SIZE).encode())
    print('md5 ', md5_orig, ', padd ', padding, ', size_tot ', size_tot, ', num_chunk ', num_chunk)

    # ciclo che cifra con A, invia un chunk, decifra con A e reinvia
    orig_file = open(ORIG_FILE, 'rb')
    for i in range(0, num_chunk):

        chunk = orig_file.read(algorithm.DIM_CHUNK // 8)        ## leggo gli 8 bytes
        ## verifica se necessario aggiungere il padding al file
        if len(chunk) < (algorithm.DIM_CHUNK // 8):
            chunk += bytes(padding)

        ka = algorithm.generate_key()                           ## genera la chiave valida per il chunk letto
        chunk_a = algorithm.tex_function_for_a(ka, chunk)       ## cifratura del chunk
        print('cifraggio con chiave A ', ka)
        ## invio del chunk cifrato con chiave a
        sock.send(chunk_a)
        print('invio del chunk_a ', i)
        ## ricevo il chunk cifrato con a_b
        chunk_ab = sock.recv(algorithm.DIM_CHUNK // 8)
        print('ricevuto il chunk_ab ', i)
        ## decifra il chunk
        chunk_b = algorithm.reverse_tex_function_for_a(ka, chunk_ab)
        ## reinvio del chunk senza la chiave ma solo con quella di b
        sock.send(chunk_b)
        print('invio del chunk_b ', i)

    ## chiusura del file e del socket
    orig_file.close()
    sock.close()