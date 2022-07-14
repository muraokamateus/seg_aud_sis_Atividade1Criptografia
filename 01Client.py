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


#Codigo para gerar chaves publicas('n' e 'e') e privadas('d' e 'n'):
# O valor de 'n' é dado pela multiplicação de dois numeros primos grandes
# O valor de 'e' é valor do expoente comum da chave
# O valor de da chave privada
(publicKey1,privateKey1) = rsa.newkeys(1024)
nPublic_1client = publicKey1.n
ePublic_1client = publicKey1.e
dPrivate_1client = privateKey1.d
nPrivate_1client = privateKey1.n
publicKey2 = None

SOCKET_LIST = []

class Server(threading.Thread):
    
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        read, write, err = select.select(lis, [], [])
        global publicKey2
        
# É criado um loop  que recebe e armazena o 'n' da chave publica do cliente 02 na 
# variável nPublic_client1
        for item in read: 
            try:
                s = item.recv(1024)
                if s != '':
                    nPublic_client2 = int(s)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break
        
# É criado um loop  que recebe e armazena o 'e' da chave publica do  cliente 02 na
# variável ePublic_client2. Após isso gera  a chave publica do cliente 02 apartir da 
# variavel 'n' e 'e'
        for item in read: 
            try:
                s = item.recv(1024)
                if s != '':
                    ePublic_client2 = int(s)
                    publicKey2 = rsa.key.PublicKey(nPublic_client2,ePublic_client2)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break
        
# Quando a chave publica do cliente 02 recebe os valores de 'n' e 'e' é criado um loop  que
# recebe um 'confirmado' do cliente 02 e será gravado no 'Handshake.txt', para que possa ser 
# finalizado o Handshake entre os clientes conectados
        for item in read:
            try:
                s = item.recv(1024)
                if s != '':
                    # Ocorre a leitura o valor 'confirmado', 
                    confirmado = s
                    # onde se cria um 'Handshake.txt'e
                    k = open('Handshake.txt','wb')
                    # grava no arquivo informação 'confirmado' 
                    k.write(confirmado)
                    #fecha o arquivo
                    k.close()
                else:
                    #Caso ocorra o loop é finalizado.
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break

# É criado um loop para recepção das mensagens  e da assinatura do cliente 02
        while 1:
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        #Recebe a mensagem criptografada
                        msgcriptografada = s
                        #Abre e faza  a leitura  o arquivo de onde a chave simetrica do cliente 
                        #foi gravada e armazena na variavel chaveSimetricaClient01
                        arqChaveSimetrica = open('keySimetrica.key','rb')
                        chaveSimetricaClient01 = arqChaveSimetrica.read()
                        f = Fernet(chaveSimetricaClient01)
                        #Utiliza a chave simétrica para descriptografar a mensagem
                        msg = f.decrypt(msgcriptografada).decode()    
                    else:
                        #Caso ocorra o loop é finalizado.
                        break
                except:
                    traceback.print_exc(file=sys.stdout)
                    break
            
# É criado um loop  para recepção da mensagem e calculo atraves de funções para saber se a mensagem 
# foi recebida de forma integra
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        assinaturaClient02 = s
                        msgh = msg.encode()
                        #Realiza-se a função digest da assinatura recebida e armazena na variavel 
                        #'hash_assinaturaClient02'
                        # (A função digest tem como  arepresentação numérica de tamanho fixo do conteúdo de 
                        # uma mensagemque é calculada por uma função hash) 
                        hash_assinaturaClient02 = int.from_bytes(hashlib.sha1(msgh).digest(), byteorder='big')
                        #Realiza-se a verificação da validade da assinatura através do:
                        #Calculo da função(assinatura^e) % n 
                        assinaturaNewClient02 = pow(int(assinaturaClient02),ePublic_client2,nPublic_client2)
                        #e da comparação Hash novo com a assinatura nova para validar a assinatura
                        if(hash_assinaturaClient02 == assinaturaNewClient02):
                            #Se a comparação  for valida, imprime a mensagem
                            print(msg + '\n>> ')
                        else:
                            #Se a comparação  for valida, imprime a mensagem
                            print('>>Atenção! Mensagem não foi recebida de forma íntegra!<<')
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
        user_name = input("Entre com o nome de usuario que será usado:\n>> ")
        #Irá adiar o segmento de chmada que tiver em execução em segundos
        time.sleep(1)
        srv = Server()
        srv.initialise(self.sock)
        srv.daemon = True
        print(">> Iniciando serviço... << ")
        srv.start()
        SOCKET_LIST.append(self.sock)


# Quando se inicia o cliente 02 é  enviado o valor de chave publica  'n'  do cliente 01  
# para o cliente 02
        self.client(host,port,bytes(str(nPublic_1client), encoding='utf8'))
        #Irá adiar o segmento de chmada que tiver em execução em segundos
        time.sleep(2)

# Ocorre envio da chave publica do cliente 01 o valor de 'e', onde se aguarda a recepção da 
# chave publica do cliente 02
        self.client(host,port,bytes(str(ePublic_1client), encoding='utf8'))
        #Irá adiar o segmento de chmada que tiver em execução em segundos
        time.sleep(4)
        
 
        
        # É gerado uma chave simétrica
        keySimetrica = Fernet.generate_key()
        f = Fernet(keySimetrica)
        #armazena-se no arquivo 'keySimetrica.key'  
        sk = open('keySimetrica.key','wb') 
        sk.write(keySimetrica)                                                                                                      
        sk.close()
        #É realizado o envio desta chave simétrica , criptografando-a  a partir da chave publica do cliente 02
        simkeycripto = rsa.encrypt(keySimetrica,publicKey2)
        self.client(host,port,simkeycripto)
        #Irá adiar o segmento de chmada que tiver em execução em segundos
        time.sleep(4)

        
        # Cria o hash utilizando a chave simetrica com o algoritimo de SHA-1
        hash1 = rsa.compute_hash(keySimetrica, 'SHA-1') 
        #Criando a assinatura do cliente
        assinatura = rsa.sign_hash(hash1, privateKey1, 'SHA-1')
        #Realiza o envio par o cliente 2
        self.client(host,port,assinatura)
        #Irá adiar o segmento de chmada que tiver em execução em segundos
        time.sleep(5)

#É criado um loop para  verificação de verificação do Handshake
        while 1: # Verifica-se se Handshake foi finalizado
            #Verifica-se há o arquivo 'Handshake.txt'
            if (os.path.isfile('Handshake.txt')): 
                #Verifica-se este arquivo tem conteudo salvo nele
                if (os.path.getsize('Handshake.txt') > 0):
                    #Se existir e conter, quebra o loop e vai para proxima tarefa
                    break
                #Se não existir, continua aguardando o fim do Handshake onde se atribui um intervalo com um intervalo
                else:
                    print(">> Aguardando Fim do Handshake... <<")
                    #Irá adiar o segmento de chmada que tiver em execução em segundos
                    time.sleep(10)
            #Se não existir, continua aguardando o fim do Handshake onde se atribui um intervalo com um intervalo        
            else:
                print(">> Aguardando Fim do Handshake... <<")
                #Irá adiar o segmento de chmada que tiver em execução em segundos
                time.sleep(10)
        
 #É criado um loop para envio de mensagem definida até 150 caracteres
        while 1:
            msg = input('>>')
            #Verifica se a mensagem possui mais de 150 caracteres
            if(len(msg)>151):#151 pois começa em 0
                print("Atenção! Não é permitido enviar mensagem com mais de 150 caracteres!")
                break
            if msg == 'exit':
                break
            if msg == '':
                continue
            # Se concatena o valor do input de msg com o user_name definido e realiza o encode da msg
            msg = user_name + ":" + msg
            msgh = msg.encode()

            #Realiza a criptografia a partir da chave simétrica da mensagem utlizando fernet e *envia para o client 02*
            msgcriptografada = f.encrypt(msg.encode())
            self.client(host, port, msgcriptografada)
            #Irá adiar o segmento de chmada que tiver em execução em segundos
            time.sleep(2)

            # É gerado a hash da mensagem atraves o algoritmo SHA-1
            hash2= int.from_bytes(hashlib.sha1(msgh).digest(), byteorder='big') 
            
            #É gerado  a assinatura a partir desta hash e dos valores de 'd' e 'n' do cliente 01
            # e envia para o client 01 realiza o calculo (hash^d) % n
            assinatura2 = pow(hash2,dPrivate_1client,nPrivate_1client)
            self.client(host,port,bytes(str(assinatura2), encoding='utf8'))
            #Irá adiar o segmento de chmada que tiver em execução em segundos
            time.sleep(5)
        return (1)

if __name__ == '__main__':
    print(">> Starting client <<")
    cli = Client()
    cli.start()