from algorithm import  algorithm
import os
import socket

IP_SERVER = "192.168.0.140"
PORT_SERVER = 12345

CRIPT_FILE_A = 'cripted_f22_a.jpg'
CRIPT_FILE_AB = 'crypted_f22_ab.jpg'
CRIPT_FILE_B = 'crypted_f22_b.jpg'
FINAL_FILE = 'f22_raptor.jpg'

def cypher_file_b(orig_file, dest_file, keys_b):
    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        for kb in keys_b:
            chunk = file_in.read(algorithm.DIM_CHUNK // 8)

            new_chunk = algorithm.tex_function_for_b(kb, chunk)
            file_out.write(new_chunk)
            read_bytes += len(new_chunk)

            ########### stampa elaborazione avanzamento
            print('Cifraggio file con chiave B ...  ', read_bytes, ' / ', os.stat(orig_file).st_size)

    print('------ Criptaggio con chiave A completo! ------')
    print('original file dimension:  ', dim_file, 'bytes')
    print('encrypted file dimension: ', read_bytes, 'bytes')
    padding = read_bytes - dim_file
    print('necessary padding: ', padding, 'bytes')

    return padding

def decypher_file_b(orig_file, dest_file, padding, keys_b):

    dim_file = os.stat(orig_file).st_size
    read_bytes = 0

    with open(orig_file, 'rb') as file_in, open(dest_file, 'wb') as file_out:

        for i in range(0, len(keys_b)):
            chunk = file_in.read(algorithm.DIM_CHUNK // 8)
            new_chunk = algorithm.reverse_tex_function_for_b(keys_b[i], chunk)

            if i == (len(keys_b) - 1):
                file_out.write(new_chunk[:-padding])
            else:
                file_out.write(new_chunk)

            read_bytes += len(new_chunk)

            ########### stampa elaborazione avanzamento
            print('Togliendo la chiave B ...  ', read_bytes, ' / ', os.stat(orig_file).st_size)

    print('------ Decriptazione con B ------')
    print('dimensione file iniziale: ', dim_file, 'bytes')
    print('dimensione file finale: ', read_bytes, 'bytes')

if __name__ == '__main__':

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((IP_SERVER, PORT_SERVER))
    serversocket.listen(1)
    print('sto ascoltando')

    (client_sock, address) = serversocket.accept()

    ## ricevo md5 orig, padd eventuale e size totale
    md5_orig = client_sock.recv(32).decode()
    padd = int(client_sock.recv(1).decode())
    size_tot = int(client_sock.recv(20).decode())
    print('md5 ', md5_orig, ', padd ', padd , ', size_tot ', size_tot)


    ## ricevo il file cifrato da A
    algorithm.recv_file(client_sock, CRIPT_FILE_A, size_tot)

    ## creo le chiavi per b
    num_keys_b = os.stat(CRIPT_FILE_A).st_size // (algorithm.DIM_CHUNK // 8)
    keys_b = algorithm.generate_keys(num_keys_b)

    ## applico il vettore di chiavi di B e invia il nuovo file
    cypher_file_b(CRIPT_FILE_A, CRIPT_FILE_AB, keys_b)
    algorithm.send_file(client_sock, CRIPT_FILE_AB)

    ## riceve il file solo con criptaggio della chiave B
    algorithm.recv_file(client_sock, CRIPT_FILE_B, size_tot)

    ## applicazione decifraggio con chiavi di B
    decypher_file_b(CRIPT_FILE_B, FINAL_FILE, padd, keys_b)


    client_sock.close()

    md5_new = algorithm.get_md5(FINAL_FILE)

    print('md5 originale = ' + md5_orig)
    print('md5 vecchio = ' + md5_new)







