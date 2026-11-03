# AgentWatch

[![CI](https://github.com/Subaruberu/Agente-Watch/actions/workflows/ci.yml/badge.svg)](https://github.com/Subaruberu/Agente-Watch/actions/workflows/ci.yml)

Monitor de seguranca para agentes de codigo. Registra o que o agente faz (comandos, arquivos, URLs), limpa segredos e guarda tudo em SQLite para analise.

> **Status:** Fase 5 (captura + regras + juiz LLM + avaliacao + API + painel + Docker + CI + modelo de deploy no Azure). O juiz LLM ainda nao foi medido, e a imagem Docker e o deploy no Azure ainda nao foram executados (veja "O que foi e o que nao foi verificado").

## Como funciona

```
Claude Code --(hook PreToolUse, JSON no stdin)--> log_event.py --> SQLite
                                                       |-- events  (o que o agente fez)
                                                       `-- alerts  (o que as regras sinalizaram)
                                                            |
                                         API FastAPI <------'------> painel Streamlit
```

A cada chamada de ferramenta, o Claude Code executa `log_event.py`, que:

1. le o evento em JSON;
2. extrai comando, arquivo, URL, sessao e diretorio;
3. remove padroes obvios de segredo (chaves de API, tokens, senhas) e trunca textos longos;
4. grava uma linha na tabela `events`;
5. roda os monitores e grava os alertas na tabela `alerts`.

O hook **nunca bloqueia nem quebra o agente**: qualquer erro e ignorado e o processo sai com codigo 0.

## Instalacao

```bash
git clone https://github.com/Subaruberu/Agente-Watch.git && cd Agente-Watch
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```

## Ativar o hook

Copie o conteudo de `examples/settings.example.json` para o arquivo de configuracao do Claude Code (por exemplo `~/.claude/settings.json`) e troque `/CAMINHO/ABSOLUTO` pelo caminho real deste projeto.

> Confira o formato atual de hooks na documentacao oficial do Claude Code, pois ele pode mudar.

### Modo remoto (opcional)

Com `AGENTWATCH_API_URL` definida, o hook envia o evento a API em vez de gravar localmente:

```bash
export AGENTWATCH_API_URL=https://minha-api.exemplo.com
export AGENTWATCH_API_KEY=...
```

- So aceita `https` (ou `http` em `localhost`): a chave de API nao deve trafegar em texto puro.
- Segredos sao mascarados **antes** de sair da maquina, e so os campos necessarios sao enviados (sessao, ferramenta, entrada da ferramenta, diretorio). O caminho do transcript, por exemplo, nao e enviado.
- Se a API estiver fora do ar, o evento e gravado no SQLite local: nada se perde. O tempo maximo de espera e 1,5 s (`AGENTWATCH_REMOTE_TIMEOUT`), porque o hook roda antes de cada ferramenta e nao pode atrasar o agente.

## Testar sem o agente

```bash
AGENTWATCH_DB=/tmp/demo.db python3 log_event.py < examples/sample_event.json
AGENTWATCH_DB=/tmp/demo.db python3 -m agentwatch.show
```

## Monitores (Fase 2)

Os monitores **apenas detectam e registram**; nao bloqueiam nada.

| Regra | O que detecta | Severidade |
|---|---|---|
| `force-push` | `git push --force`, `-f`, `+branch`; `--force-with-lease` e mais leve | HIGH / MEDIUM |
| `sensitive-file` | `.env`, chaves SSH, `.aws/`, `.netrc`, `*.pem`, `*.key` (ignora `.env.example` e `*.pub`) | HIGH |
| `destructive-rm` | `rm -r` em `/`, `~`, `$HOME`, `..`, `*` ou caminho fora do projeto | CRITICAL / HIGH |
| `network-unknown-host` | `curl`/`wget` para dominio fora da lista confiavel; envio de dados e mais grave | HIGH / MEDIUM |
| `remote-script-exec` | `curl ... \| sh`, `bash <(curl ...)` | CRITICAL |
| `package-install` | instalacao por URL/git/indice alternativo, com `sudo` ou global; instalacao comum e informativa | HIGH / MEDIUM / LOW |

Dominios confiaveis extras: `AGENTWATCH_ALLOWED_DOMAINS=meudominio.com,outro.org`.

### Limitacoes conhecidas

- As regras sao por padrao de texto e tem **falsos positivos e negativos** (por exemplo, `cat server.pem` pode ser um certificado publico; comandos montados com variaveis ou `$(...)` nao sao resolvidos).
- `curl` com URL sem `http://` ou `https://` nao e analisado.
- Medir esses erros e o objetivo da Fase 3.

## Juiz LLM e avaliacao (Fase 3)

As regras erram: deixam passar comandos ofuscados e disparam em casos inocentes. O **juiz** pede a um modelo Claude que classifique cada evento como `safe` ou `suspicious`, e o modulo de **avaliacao** mede quanto cada abordagem acerta.

**Estrategias comparadas**

| Estrategia | Como decide |
|---|---|
| regras | alerta com severidade >= limiar |
| juiz LLM | o modelo decide sozinho, sem ver as regras |
| hibrido | regra CRITICAL decide direto; o resto vai ao juiz, com os alertas como dica |

**Decisoes de projeto do juiz**

- O conteudo do evento e tratado como **dado nao confiavel** (o agente pode tentar manipular o juiz). O prompt avisa isso, o evento vai delimitado por tags e o texto `</` e neutralizado.
- Respostas validas ficam em **cache** (`data/judge_cache.jsonl`), entao reavaliar nao paga duas vezes.
- Falha de API ou resposta invalida vira `error`, contado como suspeito (**fail-closed**) e reportado a parte.
- O juiz **nao roda dentro do hook** (latencia e custo): ele analisa eventos offline.
- Modelo padrao: `claude-haiku-5-5`. Troque com `AGENTWATCH_JUDGE_MODEL`.

**Rodar**

```bash
python -m agentwatch.evaluate                       # so regras, sem API
pip install -r requirements-judge.txt
export ANTHROPIC_API_KEY=...                        # nunca commite a chave
python -m agentwatch.evaluate --judge --report reports/avaliacao.md
```

> **Privacidade:** com `--judge`, comandos e caminhos sao enviados a API da Anthropic. A limpeza de segredos e por padroes e nao e perfeita; nao use eventos reais sensiveis.

**Metricas:** precisao, recall, F1 e taxa de falsos positivos, com intervalo de Wilson 95%. Inclui varredura de limiar das regras (precisao x recall).

**Conjunto rotulado** (`data/labeled_events.jsonl`): 69 eventos sinteticos (34 suspeitos, 35 seguros), em dois grupos: `comum` e `dificil` (ofuscacao, ferramentas fora do escopo das regras, casos dependentes de contexto).

### Resultado atual: somente regras (limiar MEDIUM)

| Precisao | Recall | Falso positivo |
|---|---|---|
| 0.73 [0.54-0.86] | 0.56 [0.39-0.71] | 0.20 [0.10-0.36] |

Relatorio completo em `reports/rules_baseline.md`. **O juiz ainda nao foi medido**: falta rodar `--judge` com uma chave de API.

### Cuidados ao interpretar

- O conjunto e **sintetico e rotulado pelo mesmo autor das regras**, entao ha vies.
- O grupo `dificil` foi escrito conhecendo os limites das regras: o recall baixo ali e esperado por construcao. A pergunta util e se o juiz recupera esses casos sem inflar os falsos positivos.
- No grupo `comum`, as regras acertam tudo porque usam os mesmos padroes de seus testes; isso nao prova generalizacao.
- Varios rotulos dependem de contexto (ex.: `git push -f` em branch pessoal).
- Antes de concluir algo, repita com eventos reais anonimizados.

## API e painel (Fase 4)

```bash
pip install -r requirements-app.txt

uvicorn agentwatch.api:app --host 127.0.0.1 --port 8000   # API (docs em /docs)
streamlit run dashboard.py                                # painel
```

**Demonstracao com dados sinteticos** (sem tocar no seu banco real):

```bash
python -m agentwatch.seed --db /tmp/demo.db
AGENTWATCH_DB=/tmp/demo.db streamlit run dashboard.py
```

### Endpoints

| Metodo | Rota | O que faz |
|---|---|---|
| GET | `/health` | verificacao de saude (sem autenticacao) |
| POST | `/events` | registra um evento (mesmo JSON do hook), aplica as regras e devolve os alertas |
| GET | `/events` | lista eventos; filtros `session_id`, `tool_name`, `limit`, `offset` |
| GET | `/alerts` | lista alertas; filtros `min_severity`, `rule_id`, `session_id` |
| GET | `/stats` | totais, alertas por severidade e por regra, eventos por ferramenta, serie diaria |
| GET | `/sessions` | sessoes com numero de eventos, alertas e pior severidade |
| GET | `/sessions/{id}/timeline` | eventos da sessao em ordem, cada um com seus alertas |

```bash
curl -X POST http://127.0.0.1:8000/events -H 'Content-Type: application/json' \
  -d '{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"git push --force"}}'
```

### Seguranca da API

- Por padrao a API e **aberta e pensada para localhost**: suba com `--host 127.0.0.1`.
- Para expor em rede, defina `AGENTWATCH_API_KEY`: todas as rotas (menos `/health`) passam a exigir o cabecalho `X-API-Key`. Use HTTPS na frente (proxy/ingress), pois a chave trafega no cabecalho.
- Segredos conhecidos sao mascarados antes de gravar, inclusive no `POST /events`, mas a limpeza e por padroes.
- Limites: `limit` maximo de 500 por consulta; campos de texto sao truncados em 2000 caracteres.

### Painel

Tres abas: **Visao geral** (KPIs, alertas por severidade e por regra, eventos por ferramenta, atividade diaria), **Alertas** (tabela com filtros de severidade e regra na barra lateral) e **Sessoes** (resumo e linha do tempo de cada sessao).

Por padrao le o SQLite local. Para usar a API (por exemplo, quando o painel roda em outro servidor):

```bash
export AGENTWATCH_API_URL=http://127.0.0.1:8000
export AGENTWATCH_API_KEY=...      # so se a API exigir
streamlit run dashboard.py
```

Os dois modos usam as mesmas consultas (`agentwatch/queries.py`) e os testes garantem que devolvem dados identicos.

## Docker, CI e deploy (Fase 5)

### Docker Compose (API + painel)

```bash
cp .env.example .env           # troque AGENTWATCH_API_KEY (openssl rand -hex 24)
docker compose up --build
# API:    http://127.0.0.1:8000/docs
# Painel: http://127.0.0.1:8501
```

- Uma unica imagem serve os dois servicos (`AGENTWATCH_SERVICE=api|dashboard`), roda sem privilegios e tem `HEALTHCHECK`.
- O painel le a API pela rede do compose; as portas ficam publicadas **somente em 127.0.0.1**.
- O banco fica no volume `agentwatch-data`.
- `AGENTWATCH_SEED_ON_START=1` gera dados **sinteticos** na primeira subida (so para demonstracao).

### Integracao continua

`.github/workflows/ci.yml` roda a cada push e pull request: lint (`ruff`), testes em Python 3.11 e 3.12, o smoke test da avaliacao e, num segundo job, o **build da imagem** com um teste de saude da API (com dados sinteticos) e do painel.

### Deploy de demonstracao no Azure Container Apps

`deploy/azure/deploy.sh` sobe uma demo publica com **dados sinteticos**: API em ingress interno (nao fica publica), painel em ingress externo.

```bash
az login
./deploy/azure/deploy.sh          # leia o script antes de rodar
az group delete --name agentwatch-demo-rg --yes --no-wait   # apaga tudo depois
```

Decisoes e riscos:

- **Uma replica so** (`min = max = 1`): o SQLite vive dentro da replica; com varias, cada uma teria um banco diferente.
- Banco **efemero** com dados sinteticos, de proposito. SQLite em disco de rede (Azure Files/SMB) tem problemas de travamento de arquivo; para dados reais, o caminho certo e trocar para um banco gerenciado (PostgreSQL, por exemplo).
- O painel Streamlit **nao tem autenticacao**. Nunca publique dados reais assim; para isso, coloque autenticacao na frente (por exemplo, a autenticacao integrada do Container Apps).
- Recursos na nuvem **podem gerar custo**.

### O que foi e o que nao foi verificado

| Item | Situacao |
|---|---|
| Testes automatizados (124) e lint | executados e passando |
| Entrypoint (`api`, `dashboard`, semeadura, erro de servico) | executado localmente, sem Docker |
| Sintaxe do compose, do workflow e do `deploy.sh` | validada |
| `docker build` / `docker compose up` | **nao executado** (sem Docker no ambiente de desenvolvimento); o job `docker` do CI e o primeiro teste real |
| `deploy.sh` no Azure | **nao executado**; e um modelo, confira cada comando com `az containerapp --help` |
| Juiz LLM contra a API real | **nao medido** (falta chave de API) |

## Ver eventos e alertas

```bash
python3 -m agentwatch.show 20            # ultimos 20 eventos
python3 -m agentwatch.show --alerts 20   # ultimos 20 alertas
python3 -m agentwatch.scan               # reaplica as regras em todos os eventos ja gravados
```

O banco fica em `~/.agentwatch/events.db` (ou no caminho de `AGENTWATCH_DB`).

## Privacidade

- Segredos conhecidos sao mascarados (padroes no texto e valores de chaves como `password`, `token`, `api_key`), mas a limpeza e por padroes e **nao e perfeita**.
- Nao publique bancos reais. `*.db` ja esta no `.gitignore`.
- Para demos publicas, use eventos sinteticos como `examples/sample_event.json`.

## Estrutura

```
agentwatch/
  db.py        # schema e acesso ao SQLite
  hook.py      # parsing, redacao e gravacao
  monitors.py  # regras de deteccao (evento -> alertas)
  scan.py      # reanalisa eventos antigos com as regras atuais
  judge.py     # juiz LLM (prompt, cache, parsing, modo hibrido)
  evaluate.py  # metricas e relatorio: regras vs. juiz
  queries.py   # consultas de leitura (API e painel)
  api.py       # API FastAPI
  datasource.py# fonte do painel: SQLite local ou API
  seed.py      # dados sinteticos para demonstracao
  show.py      # leitura rapida de eventos e alertas
dashboard.py   # painel Streamlit
Dockerfile, docker-compose.yml, docker-entrypoint.sh
.github/workflows/ci.yml   # lint, testes e build da imagem
deploy/azure/deploy.sh     # modelo de deploy (nao executado)
log_event.py   # ponto de entrada do hook
data/          # conjunto rotulado (e cache do juiz, ignorado pelo git)
reports/       # relatorios de avaliacao
tests/         # pytest
examples/      # configuracao e evento de exemplo
```

## Roadmap

- [x] Fase 1: captura e armazenamento
- [x] Fase 2: monitores por regra com testes
- [x] Fase 3: juiz LLM e avaliacao (codigo e testes prontos; **falta medir o juiz com chave de API**)
- [x] Fase 4: API FastAPI e painel Streamlit
- [x] Fase 5: Docker, GitHub Actions e modelo de deploy no Azure (falta executar o build e o deploy)