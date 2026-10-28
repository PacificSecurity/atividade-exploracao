# Atividade 2 — Exploração e comando e controle

Este laboratório de treinamento tem dois contêineres. A **borda** publica serviços apenas em `127.0.0.1` da sua máquina; o **node-1** está em uma rede interna do Docker e não publica portas no host. O desafio é encontrar uma vulnerabilidade na borda, estabelecer uma sessão de comando e controle (C2) por esse acesso, investigar o serviço interno através da sessão ou de um encaminhamento criado por ela e encontrar o arquivo `flag.txt` no segundo contêiner.

Você pode usar Metasploit/Meterpreter ou outra ferramenta de C2. O laboratório foi feito para praticar reconhecimento, validação de hipóteses, exploração e pivô de rede. Não é preciso fazer força bruta, negação de serviço, persistência nem elevação de privilégio. Um banner que menciona uma versão vulnerável é apenas uma pista: confirme o comportamento do serviço antes de concluir que a falha existe.

## Baixar e iniciar

Baixe o pacote [atividade2-v1.tar.gz](https://atividade-preselec-pacsec.s3.us-east-1.amazonaws.com/exp/atividade2-v1.tar.gz) (aproximadamente 85 MB). Requisitos: Docker com Compose v2, espaço para extrair cerca de 239 MB de imagens e espaço adicional para carregá-las no Docker. No Mac com processador ARM, o Docker Desktop executa a borda x86-64 por emulação.

Confira o SHA-256 do arquivo baixado antes de extrair:

```text
170e8ebe2d10e0ca278945d0c820b4ab1ab14bbde7fb3d8d31e90cc8fc6c3d25
```

No Linux, use `sha256sum atividade2-v1.tar.gz`; no macOS, `shasum -a 256 atividade2-v1.tar.gz`. Depois execute:

```sh
tar -xzf atividade2-v1.tar.gz
cd atividade2
docker load -i images.tar
docker compose up -d
docker compose ps
```

O laboratório publica apenas as portas `127.0.0.1:18080` a `127.0.0.1:18084`. Se uma delas estiver ocupada, libere a porta antes de iniciar. Para usar a imagem interna nativa em Mac ARM, inicie com `LAB_ARCH=arm64 docker compose up -d` no lugar do comando padrão. Ao terminar, execute `docker compose down` na pasta `atividade2`.

## Seu objetivo

1. Enumere os serviços da borda e justifique qual deles investigar. Registre também uma hipótese descartada e a evidência que a descartou.
2. Explore a falha da borda, identifique o usuário obtido e estabeleça uma sessão de C2 por esse acesso. Mostre pelo menos uma tarefa e sua resposta no canal.
3. A partir da sessão ou do encaminhamento criado por ela, descubra o endereço de `node-1`, investigue seus serviços e explore a falha interna até encontrar `flag.txt`.
4. Explique as condições das falhas, suas fontes ou a lógica dos exploits utilizados.

Use comandos de administração do Docker para preparar e encerrar o laboratório. A exploração do segundo contêiner deve passar pelo acesso conquistado na borda. Restrinja os testes aos dois contêineres deste pacote e às portas locais do laboratório.

## Solução comentada

⚠️ **O [writeup](writeup.md) contém spoilers, inclusive a flag.** Tente resolver o desafio antes de abri-lo. Se já fez a atividade e travou em alguma etapa, use o texto para comparar seu raciocínio e revisar o caminho técnico.
