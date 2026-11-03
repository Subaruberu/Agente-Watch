# AgentWatch

Monitor de seguranca para agentes de codigo. Registra o que o agente faz (comandos, arquivos, URLs), limpa segredos e guarda tudo em SQLite para analise.

> **Status:** Fase 2 (captura + regras de deteccao). Proximas fases: avaliacao com LLM, API + painel, deploy no Azure.

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
  show.py      # leitura rapida de eventos e alertas
log_event.py   # ponto de entrada do hook
tests/         # pytest
examples/      # configuracao e evento de exemplo
```

## Roadmap

- [x] Fase 1: captura e armazenamento
- [x] Fase 2: monitores por regra com testes
- [ ] Fase 3: LLM-as-judge e avaliacao (precisao e recall)
- [ ] Fase 4: API FastAPI e painel Streamlit
- [ ] Fase 5: Docker, GitHub Actions e deploy no Azure
