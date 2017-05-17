from algorithm import  algorithm
import os
import socket

IP_SERVER = "192.168.0.192"
PORT_SERVER = 12345

CRIPT_FILE_A = 'cripted_f22_a.jpg'
CRIPT_FILE_AB = 'crypted_f22_ab.jpg'
CRIPT_FILE_B = 'crypted_f22_b.jpg'
FINAL_FILE = 'f22_raptor.jpg'

## questa variante sfrutta solamente una chiave alla volta
## infatti se invio un chunk alla volta non c'e' bisogno di ricordarsi
## ogni volta tutte le chiavi. viene cifrato e decifrato un byte alla volta
## secondo lo schema riportato sugli appunti
if __name__ == '__main__':

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((IP_SERVER, PORT_SERVER))
    serversocket.listen(1)
    print('sto ascoltando')

    (client_sock, address) = serversocket.accept()

    ## ricevo md5 orig, padd eventuale e size totale
    md5_orig = client_sock.recv(algorithm.DIM_MD5).decode()
    padding = int(client_sock.recv(algorithm.DIM_PADD).decode())
    num_chunk = int(client_sock.recv(algorithm.DIM_SIZE).decode())
    size_tot = num_chunk * (algorithm.DIM_CHUNK_BYTE)
    print('md5 ', md5_orig, ', padd ', padding, ', size_tot ', size_tot, ', num_chunk ', num_chunk)
    client_sock.close()

    ## ciclo per ricevere ed elaborare tutti i chunk
    f_out = open(FINAL_FILE, 'wb')
    for i in range(0, num_chunk):
        (client_sock, address) = serversocket.accept()

        kb = algorithm.generate_key()       ## generazione della chiave di B per tutta l'elaborazione

        ## ricezione del chunk da A
        chunk_a = client_sock.recv(algorithm.DIM_CHUNK_BYTE)
        print('ricevuto il chunk_a ', i)
        ## cifratura del chunk con chiave di B
        chunk_ab = algorithm.tex_function_for_b(kb, chunk_a)
        print('cifraggio con chiave B ', kb)
        ## reinvio del chunk con chiave A e B
        client_sock.sendall(chunk_ab)
        print('invio del chunk_ab ', i)
        ## ricezione del chunk senza chiave A
        chunk_b = client_sock.recv(algorithm.DIM_CHUNK_BYTE)
        print('ricevuto il chunk_b ',i)
        ## decifratura del chunk con chiave B
        new_chunk = algorithm.reverse_tex_function_for_b(kb, chunk_b)

        ## verifica se ultimo chunk necessita del padding
        if i+1 == num_chunk:
            f_out.write(new_chunk[:-padding])
        else:
            f_out.write(new_chunk)

        client_sock.close()

    f_out.close()
    serversocket.close()

    md5_new = algorithm.get_md5(FINAL_FILE)

    print('md5 originale = ' + md5_orig)
    print('md5 vecchio = ' + md5_new)