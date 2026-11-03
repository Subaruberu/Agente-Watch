# AgentWatch

Monitor de seguranca para agentes de codigo. Registra o que o agente faz (comandos, arquivos, URLs), limpa segredos e guarda tudo em SQLite para analise.

> **Status:** Fase 3 (captura + regras + juiz LLM + avaliacao). Proximas fases: API + painel, deploy no Azure.

## Como funciona

```
Claude Code --(hook PreToolUse, JSON no stdin)--> log_event.py --> SQLite
                                                       |-- events  (o que o agente fez)
                                                       `-- alerts  (o que as regras sinalizaram)
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
git clone <seu-repo> agentwatch && cd agentwatch
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```

## Ativar o hook

Copie o conteudo de `examples/settings.example.json` para o arquivo de configuracao do Claude Code (por exemplo `~/.claude/settings.json`) e troque `/CAMINHO/ABSOLUTO` pelo caminho real deste projeto.

> Confira o formato atual de hooks na documentacao oficial do Claude Code, pois ele pode mudar.

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

## Ver eventos e alertas

```bash
python3 -m agentwatch.show 20            # ultimos 20 eventos
python3 -m agentwatch.show --alerts 20   # ultimos 20 alertas
python3 -m agentwatch.scan               # reaplica as regras em todos os eventos ja gravados
```

O banco fica em `~/.agentwatch/events.db` (ou no caminho de `AGENTWATCH_DB`).

## Privacidade

- Segredos conhecidos sao mascarados, mas a limpeza e por padroes e **nao e perfeita**.
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
  show.py      # leitura rapida de eventos e alertas
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
- [ ] Fase 4: API FastAPI e painel Streamlit
- [ ] Fase 5: Docker, GitHub Actions e deploy no Azure
