<p align="center">
  <h3 align="center">faDom</h3>
  <p align="center">Ache subdominios em wordlists com ajuda da bliblioteca dns.resolver</p>

  <p align="center">
    <a href="https://t.me/whoisgvb">
      <img src="https://img.shields.io/badge/Telegram-@whoisgvb-blue.svg">
    </a>
  </p>
</p>
<hr>

### Recursos
```
+ Resultados salvos em três arquivos diferentes com o nome do alvo
	subdominios + ip
	somente subdominios
	somente ip

+ Wordlists para subdominios

+ Wordlists para subsubdominios

+ Scan automatizado após trazer os resultados

```
### Requisitos de instalação
```
pip3 install --user -r requirements.txt
```

###  Uso completo

```
Usage: fadom.py [OPTIONS]

  -h, --help            show this help message and exit
  -f FILE               Arquivo de dicionário, padrão: subnames.txt.
  --full                Para executar o bruteforce completo, full_subnames.txt
                        será usado como arquivo de dicionário
  -t THREADS, --threads=THREADS
                        Número de threads de verificação, 100 por padrão
  -p RANGE_PORTS, --port=RANGE_PORTS
                        Range de portas a ser escaneado
  -n OUTPUT_NAME, --nmap=OUTPUT_NAME
                        Executar um scan após toda varredura

```

### Exemplos

```
python3 fadom.py google.com.br -t 300
python3 fadom.py google.com.br -t 500 --full -n nmapoutput -p 20-1024


[ ! ] Para melhores resultados você pode adicionar mais  servidores DNS ao arquivo "dir/serversDNS.txt"
      e/ou customizar as Wordlists =)
```

### Contato

```
[+]Email     gvbsec@protonmail.com
[+]Telegram  t.me/whoisgvb
```
