#! /usr/bin/env python

import socket
import pickle
import sys
import time
import threading
import select
import traceback
from cryptography.fernet import Fernet
from hashlib import sha512
import hashlib
import rsa
import os.path

#Codigo para gerar chaves publicas('n' e 'e') e privadas('d' e 'n')
# O valor de 'n' é dado pela multiplicação de dois numeros primos grandes
# O valor de 'e' é valor do expoente comum da chave
# O valor de da chave privada
(publicKey2, privateKey2) = rsa.newkeys(1024)
nPublic_2client = publicKey2.n
ePublic_2client = publicKey2.e
dPrivate_2client = privateKey2.d
nPrivate_2client = privateKey2.n
publicKey1 = None


class Server(threading.Thread):

    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        read, write, err = select.select(lis, [], [])
        global publicKey1

# É criado um loop  que recebe e armazena o 'n' da chave publica do cliente 01 na 
# variável nPublic_client1
        for item in read:
            try:
                s = item.recv(1024)
                if s != '':
                    nPublic_client1 = int(s)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break

# É criado um loop  que recebe e armazena o 'e' da chave publica do  cliente 01 na
# variável ePublic_client1. Após isso gera  a chave publica do cliente 01 apartir da 
# variavel 'n' e 'e'
        for item in read:
            try:
                s = item.recv(1024)
                if s != '':
                    ePublic_client1 = int(s)
                    publicKey1 = rsa.key.PublicKey(
                        nPublic_client1, ePublic_client1)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break

# É criado um loop  que recebe a chave simétrica do cliente 01  criptografada
# e utilizadno a chave publica do cliente 02   é descriptografada.
        for item in read:
            try:
                s = item.recv(1024)
                if s != '':
                    keySimetricaCriptografada = s
                    keySimetrica = rsa.decrypt(
                        keySimetricaCriptografada, privateKey2)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break

#É criado um loop  que  tem com como função receber e conferir a assinatura da chave simétrica
        for item in read:
            try:
                s = item.recv(1024)
                if s != '':
                    # Se recebe a assinatura do cliente 01
                    assi = s
                    # Ocorre a vericação se a assinatura corresponde a chave simétrica recebida 
                    # atraves da chave assimetrica publica do cliente 01
                    if (rsa.verify(keySimetrica, assi, publicKey1)):
                        # Se verificado a recepção da chave simetrica do cliente 01
                        print('>> A chave simétrica foi recebida com sucesso << ')
                        # Salva em um arquivo.key a chave simetrica
                        sk = open('keySimetrica2.key', 'wb')
                        sk.write(keySimetrica)
                        sk.close()
                        f = Fernet(keySimetrica)
                        #Envia um "confirmado" para finalizazação do Handshake
                        confirmado = "confirmado"
                        self.receive.send(bytes(confirmado, encoding='utf8'))
                        #Caso ocorra erro será imprimido um mensagem na tela
                    else:
                        print('>>Atenção! Chave simétrica não foi recebida com sucesso! <<')
                        exit()
            except:
                traceback.print_exc(file=sys.stdout)

                break

# É criado um loop para recepção das mensagens  e da assinatura do cliente 01
        while 1:
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        #Recebe a mensagem criptografada
                        msgcriptografada = s
                         #Utiliza a chave simétrica do cliente 01 recebida para descriptografar a mensagem
                        msg = f.decrypt(msgcriptografada).decode()
                    else:
                        break
                except:
                    traceback.print_exc(file=sys.stdout)
                    break



# É criado um loop  para recepção da mensagem e calculo atraves de funções para saber se a mensagem 
# foi recebida de forma integra
            for item in read:
                try:
                    #Recebe a assinatura da mensagem
                    s = item.recv(1024)
                    if s != '':
                        assinaturaClient01 = s
                        msgh = msg.encode()
                        #Realiza-se a função digest da assinatura recebida e armazena na variavel 
                        #'hash_assinaturaClient01'
                        # (A função digest tem como  arepresentação numérica de tamanho fixo do conteúdo de 
                        # uma mensagemque é calculada por uma função hash) 
                        hash_assinaturaClient01 = int.from_bytes(hashlib.sha1(msgh).digest(), byteorder='big')
                        #Realiza-se a verificação da validade da assinatura através do:
                        #Calculo da função(assinatura^e) % n 
                        assinaturaNewClient01 = pow(int(assinaturaClient01), ePublic_client1, nPublic_client1)
                        #e da comparação Hash novo com a assinatura nova para validar a assinatura
                        if(hash_assinaturaClient01 == assinaturaNewClient01):
                            #Se a comparação  for valida, imprime a mensagem
                            print(msg + '\n>> ')
                        else:
                            print(
                                #Se a comparação for inválida, imprime um aviso
                                '>>Atenção! Mensagem não foi recebida de forma íntegra!<<')
                            exit()
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):

    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):
        sent = self.sock.send(msg)

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            host = input("Digite o IP do servidor:\n>> ")
            port = int(input("Digite a porta de destino do Servidor:\n>> "))
        except EOFError:
            print("Error")
            return 1
        print(">> Conectando... <<\n")
        s = ''
        self.connect(host, port)
        print(">> Conectado << \n")
        #Recebera o nome do usuario referente a cliente 02
        user_name = input("Entre com o nome de usuario que será usado:\n")
        #Irá adiar o segmento de chmada que tiver em execução em segundos
        time.sleep(1)
        srv = Server()
        srv.initialise(self.sock)
        srv.daemon = True
        print(">> Iniciando serviço... << ")
        srv.start()

# Quando se inicia o cliente 02 é  enviado o valor de chave publica  'n'  do cliente 02  
# para o cliente 01
        self.client(host, port, bytes(str(nPublic_2client), encoding='utf8'))
        #Irá adiar o segmento de chmada que tiver em execução em segundos
        time.sleep(3)

# Ocorre envio da chave publica do cliente 02 o valor de 'e', onde se aguarda a recepção da 
# chave publica do cliente 01
        self.client(host, port, bytes(str(ePublic_2client), encoding='utf8'))
        #Irá adiar o segmento de chmada que tiver em execução em segundos
        time.sleep(5)

#É criado um loop para  verificação do Handshake(Aperto de mão) 
        while 1:  # Verifica-se se já recebeu a chave simétrica
            #Verifica-se há o arquivo 'keySimetrica2.key' 
            if (os.path.isfile('keySimetrica2.key')):
                #Verifica-se este arquivo tem conteudo salvo nele
                if (os.path.getsize('keySimetrica2.key') > 0):
                #Se existir e conter, quebra o loop e vai para proxima tarefa     
                    break
                #Se não existir, continua aguardando o fim do Handshake onde se atribui um intervalo com um intervalo
                else:
                    print("Aguardando Fim do Handshake...")
                    #Irá adiar o segmento de chmada que tiver em execução em segundos
                    time.sleep(10)
            #Se não existir, continua aguardando o fim do Handshake onde se atribui um intervalo com um intervalo
            else:
                print("Aguardando Fim do Handshake...")
                #Irá adiar o segmento de chmada que tiver em execução em segundos
                time.sleep(10)

#É criado um loop para envio de mensagem definida até 150 caracteres
        while 1:
            msg = input('>>')
            #Verifica se a mensagem possui mais de 150 caracteres
            if(len(msg) > 151): #150 pois começa em 0
                print("Atenção! Não é permitido enviar mensagem com mais de 150 caracteres!")
                break
            if msg == 'exit':
                break
            if msg == '':
                continue
            # Se concatena o valor do input de msg com o user_name definido e realiza o encode da msg
            msg = user_name + ":" + msg
            msgh = msg.encode()

            #Seleciona  e abre do arquivo que contem a chave simétrica,faz a leitura do conteudo deste arquivo que 
            # e a chave simétrica f e atribui ao Fernet
            simk = open('keySimetrica2.key', 'rb')
            keySimetrica = simk.read()
            f = Fernet(keySimetrica)

            #Realiza a criptografia a partir da chave simétrica da mensagem utlizando fernet e **envia para o client 01**
            msgcriptografada = f.encrypt(msg.encode())
            self.client(host, port, msgcriptografada)
            #Irá adiar o segmento de chmada que tiver em execução em segundos
            time.sleep(2)
            
            # É gerado a hash da mensagem atraves o algoritmo SHA-1
            hash1 = int.from_bytes(hashlib.sha1(msgh).digest(), byteorder='big')

            #É gerado  a assinatura a partir desta hash e dos valores de 'd' e 'n' do cliente 02   
            # e **envia para o client 01 realiza o calculo (hash^d) % n
            assinatura1 = pow(hash1, dPrivate_2client, nPrivate_2client)
            self.client(host, port, bytes(str(assinatura1), encoding='utf8'))
            #Irá adiar o segmento de chmada que tiver em execução em segundos
            time.sleep(5)
        return (1)


if __name__ == '__main__':
    print(">> Starting client <<")
    cli = Client()
    cli.start()
