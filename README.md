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

```
### Requisitos de instalação
```
pip3 install --user -r requirements.txt
```

###  Uso completo

```
Usage: fadom.py [OPTIONS]

  -h, --help            show this help message and exit.
  -f FILE               Arquivo de dicionário, padrão: subnames.txt.
  --full                Para executar o bruteforce completo, full_subnames.txt
                        será usado como arquivo de dicionário.
  -t THREADS, --threads=THREADS
                        Número de threads de verificação, 100 por padrão.

```

### Exemplos

```
python3 fadom.py google.com.br -t 500 --full

[ ! ] Para melhores resultados você pode adicionar mais  servidores DNS ao arquivo "dir/serversDNS.txt"
```

### Contato

```
[+]Email     gvbsec@protonmail.com
[+]Telegram  t.me/whoisgvb
```