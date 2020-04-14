#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
    FindAllDomains!
"""
from _banner import Banner

import sys
import time
import optparse
import warnings
warnings.simplefilter("ignore", category=UserWarning)
import os
from multiprocessing import cpu_count
import dns.resolver
import gevent
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
from gevent.queue import PriorityQueue
import nmap

class faDom:
  
    """
        Recebe os argumentos de alvo(target)
    """
    def __init__(self, target, options):
        self.start_time = time.time()
        self.target = target.strip()
        self.options = options
        self.scan_count = self.found_count = 0
        self.console_width = os.get_terminal_size()[0] - 2

        # separa as tarefas de pool de dns e define o timeout pra 10
        self.resolvers = [dns.resolver.Resolver(configure=False) for _ in range(options.threads)]
        for resolver in self.resolvers:
            resolver.lifetime = resolver.timeout = 10.0

        self.print_count = 0
        self.STOP_ME = False

        # carrega os servidores DNS e verifica 
        self._load_dns_servers()

        # puxa os subdominios
        self.subs = []                          # subdominios para arquivo
        self.goodsubs = []                      # checaram se estão ok
        self._load_subname('dir/subnames.txt', self.subs)

        # carrega os subsubdominios
        self.subsubs = []
        self._load_subname('dir/subNext.txt', self.subsubs)
        self._print_msg('[+] Lista carregada :)')

        # salvos resultados no $target.txt
        
        global path
        
        path = os.path.join("results", target)
        if not os.path.exists(path):
            os.makedirs(path)
        
        self.outfile = open('%s/%s.txt' % (path, target), 'w')

        self.ip_dict = set()                            
        self.found_sub = set()

        # fila de tarefas
        self.queue = PriorityQueue()
        for sub in self.subs:
            self.queue.put(sub)

    
        # carrega os DNS salvos(os do arquivo serversDNS.txt)
    
    def _load_dns_servers(self):
        Banner()
        print('[*] Validando servidores DNS ...')
        self.dns_servers = []

        # crie um pool paralelo de processos para verificar os servidores DNS
        processors = cpu_count() * 2
        pool = Pool(processors)

        # le os ips de DNS e separa linha a linha
        for server in open('dir/ServersDNS.txt').readlines():
            server = server.strip()
            if server:
                pool.apply_async(self._test_server, (server, ))

        pool.join()                                     # esperando pelo processo finalizar
        self.dns_count = len(self.dns_servers)

        sys.stdout.write('\n')
        dns_info = '[+] Achados {} servidores DNS disponíveis no total'.format(self.dns_count)
        print(dns_info)

        if self.dns_count == 0:
            print('[ERROR] Nenhum servidor DNS disponível.')
            sys.exit(-1)

    def _test_server(self, server):

        # create a dns resolver and set timeout
        resolver = dns.resolver.Resolver()
        resolver.lifetime = resolver.timeout = 10.0

        try:
            resolver.nameservers = [server]


#177.43.56.139
#trufer139.static.host.gvt.net.br

            answers = resolver.query('public-dns-a.baidu.com')
            if answers[0].address != '180.76.76.76':
                raise Exception('resposta DNS incorreta')
            self.dns_servers.append(server)
        except:
            self._print_msg('[-] Verificação do DNS Server %s <Falhou> Encontrados: %s' % (server.ljust(16), len(self.dns_servers)))

        self._print_msg('[+] Verificação do DNS Server %s < OK > Encontrados: %s' % (server.ljust(16), len(self.dns_servers)))
        # self._print_msg(f'[+] Verificação do DNS Server {server.ljust(16)} < OK > Achados {len(self.dns_servers)}')




    def _load_subname(self, file, subname_list):
        # self._print_msg('[*] Carregando sub nomes ...')

        with open(file) as f:
            for line in f:
                sub = line.strip()
                if sub and sub not in subname_list:
                    tmp_set = {sub}

# no caso dos subnomes que contêm a seguinte expressão {alphnum}, {alpha}, {num} faço a substituição por caracteres e numeros
                
                    while len(tmp_set) > 0:
                        item = tmp_set.pop()
                        if item.find('{alphnum}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                                tmp_set.add(item.replace('{alphnum}', _letter, 1))
                        elif item.find('{alpha}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz':
                                tmp_set.add(item.replace('{alpha}', _letter, 1))
                        elif item.find('{num}') >= 0:
                            for _letter in '0123456789':
                                tmp_set.add(item.replace('{num}', _letter, 1))
                        elif item not in subname_list:
                            subname_list.append(item)

        

         # Pra melhorar a apresentação no finalzinho :P
   
    def _print_msg(self, _msg=None, _found_msg=False):
        if _msg is None:
            self.print_count += 1
            if self.print_count < 100:
                return
            self.print_count = 0
            msg = '%s Encontrados | %s Grupos | %s escaneados em %.1f segundos' % (
                self.found_count, self.queue.qsize(), self.scan_count, time.time() - self.start_time)
            sys.stdout.write('\r' + ' ' * (self.console_width - len(msg)) + msg)
        elif _msg.startswith('[+] Verificando DNS Server'):
            sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)))
        else:
            sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)) + '\n')
            if _found_msg:
                msg = '%s Found| %s Groups| %s scanned in %.1f seconds' % (
                    self.found_count, self.queue.qsize(), self.scan_count, time.time() - self.start_time)
                sys.stdout.write('\r' + ' ' * (self.console_width - len(msg)) + msg)
        sys.stdout.flush()

    def _print_domain(self, msg):
        console_width = os.get_terminal_size()[0]
        msg = '\r' + msg + ' ' * (console_width - len(msg))
        # msg = '\033[0;31;47m%s{}\033[0m'.format(msg)
        sys.stdout.write(msg)


    def _print_progress(self):
    
            # firulinha
        
        msg = '\033[0;31;47m%s\033[0m encontrados | %s restantes | %s escaneados em %.2f segundos' % \
              (self.found_count, self.queue.qsize(), self.scan_count, time.time()- self.start_time)

        console_width = os.get_terminal_size()[0]
        out = '\r' + ' ' * int((console_width - len(msg)) / 2) + msg
        sys.stdout.write(out)


        # atribuindo tarefas aos DNS
    
    def _scan(self, j):
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]]
        while not self.queue.empty():
            sub = self.queue.get(timeout=1.0)
            self.scan_count += 1

            try:
                cur_sub_domain = sub + '.' + self.target
                answers = self.resolvers[j].query(cur_sub_domain)
            except:
                continue

            if answers:
                ips = ', '.join(sorted([answer.address for answer in answers]))

                # excluindo intranet e afins
                if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                    continue
                if faDom.is_intranet(answers[0].address):
                    continue

                self.found_sub.add(cur_sub_domain)
                for answer in answers:
                    self.ip_dict.add(answer.address)

                if sub not in self.goodsubs:
                    self.goodsubs.append(sub)

                self.found_count += 1
                ip_info = '{} \t {}'.format(cur_sub_domain, ips)
                # print(ip_info)
                self.outfile.write(cur_sub_domain + '\t' + ips + '\n')
                self._print_domain(ip_info)
                sys.stdout.flush()
                self._print_progress()
                sys.stdout.flush()

    @staticmethod
    def is_intranet(ip):
        ret = ip.split('.')
        if len(ret) != 4:
            return True
        if ret[0] == '10':
            return True
        if ret[0] == '172' and 16 <= int(ret[1]) <= 32:
            return True
        if ret[0] == '192' and ret[1] == '168':
            return True
        return False

        # Atribuindo tarefa aos threads
    
    def run(self):
        threads = [gevent.spawn(self._scan, i) for i in range(self.options.threads)]

        print('[*] Inicializando %d threads' % self.options.threads)

        try:
            gevent.joinall(threads)
        except KeyboardInterrupt as e:
            msg = '[WARNING] User aborted.'
            sys.stdout.write('\r' + msg + ' ' * (self.console_width - len(msg)) + '\n\r')
            sys.stdout.flush()


def wildcard_test(dns_servers, domain, level=1):
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = dns_servers
        answers = r.query('lijiejie-not-existed-test.%s' % domain)
        ips = ', '.join(sorted([answer.address for answer in answers]))
        if level == 1:
            print('any-sub.%s\t%s' % (domain.ljust(30), ips))
            wildcard_test(dns_servers, 'any-sub.%s' % domain, 2)
        elif level == 2:
            exit(0)
    except Exception as e:
        return domain

def _nmap():
    try:
        ips = []
        f = open(os.path.join(path, ipFileName), 'r')
        for lines in f:
            ips.append(lines.strip())
            f.close
        print('[ + ] ARQUIVO IMPORTADO PARA O NMAP COM SUCESSO!')

    except:
        print('[ - ] FALHA AO ABRIR ARQUIVO!')
    
    return ips


if __name__ == '__main__':
    parser = optparse.OptionParser(version=1.3)
    parser.add_option('-f', dest='file', default='subnames.txt',
                      help='Arquivo de dicionário, padrão: subnames.txt.')
    parser.add_option('--full', dest='full_scan', default=False, action='store_true',
                      help='Para executar o bruteforce completo, full_subnames.txt será usado como arquivo de dicionário')
    parser.add_option('-t', '--threads', dest='threads', default=100, type=int,
                      help='Número de threads de verificação, 100 por padrão')
    parser.add_option('-p', '--port', dest='range_ports', type=str, help='Range de portas a ser escaneado, separados por - ')

    parser.add_option('-n', '--nmap', dest='output_name',
                      help='Executar um scan após toda varredura')

    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit(0)

    # inicialização sem precisar do -d ...
    d = faDom(target=args[0], options=options)
    wildcard_test(d.dns_servers, args[0])

    print('[*] Exploração de subdomínios de nível um ', args[0])
    print('[+] Há %d subdominios na fila...' % len(d.queue))
    print('\n')
    d.run()
    print('\n')
    print('%d subdominios encontrados' % len(d.found_sub))
    print('[*] Programa rodou por %.1f segundos ' % (time.time() - d.start_time))

    print('Exploração de subdomínios de nível dois ... ')
    time.sleep(1)

    d.queue = PriorityQueue()
    for subsub in d.subsubs:
        for sub in d.goodsubs:
            subname = subsub + '.' + sub
            d.queue.put(subname)

    print('Há %d subdominios na fila ...' % len(d.queue))
    d.run()
    print()
    sys.stdout.flush()
    print('%d subdonimios encontrados no total' % len(d.found_sub))
    print('[*] Os resultados são salvos em três arquivos, começando com %s' % args)

    # Salvando arquivos com somente IP, somente sub dominios e os dois juntos

    
    ipFileName = args[0] + '-ip.txt'
    subDomainsFileName = args[0] + '-subdominios.txt'
    csvFile = options.output_name    
    
    with open(os.path.join(path, ipFileName), 'w') as f:
        for ip in d.ip_dict:
            f.write(ip + '\n')

    with open(os.path.join(path, subDomainsFileName), 'w') as f:
        for domain in d.found_sub:
            f.write(domain + '\n')


    with open(os.path.join(path,csvFile + '.csv'), 'w') as y:
        nm = nmap.PortScanner()
        print('[ + ] Iniciando NMAP ')
        for x in _nmap():
            nm.scan(x, options.range_ports )
            

            for host in nm.all_hosts():
                
                if nm[host].state() != 'up':
                    print(f'Host : {host} {nm[host].hostname()} não disponivel')

                else:
                    
                    print(nm.command_line())
                    print('------------------------------------')
                    print(f'Host : {host} {nm[host].hostname()}')
                    print(f'Is : {nm[host].state()}')
                    for proto in nm[host].all_protocols():
                        print('-------')
                        print(f'Protocolo : {proto}')
                
                        lport = nm[host][proto].keys()
                        for port in lport:
                            print (f"port : {port}\tstate : {nm[host][proto][port]['state']}")
                    
                    print('\n')

                y.write(nm.csv() + '\n')


    
    print('[*] Programa rodou por %.1f segundos ' % (time.time() - d.start_time))
    y.close
    d.outfile.flush()
    d.outfile.close()
    
