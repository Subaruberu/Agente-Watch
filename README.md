# AgentWatch

Monitor de seguranca para agentes de codigo. Registra o que o agente faz (comandos, arquivos, URLs), limpa segredos e guarda tudo em SQLite para analise.

> **Status:** Fase 1 (captura). Proximas fases: regras de deteccao, avaliacao com LLM, API + painel, deploy no Azure.

## Como funciona

```
Claude Code --(hook PreToolUse, JSON no stdin)--> log_event.py --> SQLite
```

A cada chamada de ferramenta, o Claude Code executa `log_event.py`, que:

1. le o evento em JSON;
2. extrai comando, arquivo, URL, sessao e diretorio;
3. remove padroes obvios de segredo (chaves de API, tokens, senhas) e trunca textos longos;
4. grava uma linha na tabela `events`.

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

## Ver os eventos

```bash
python3 -m agentwatch.show 20   # ultimos 20 eventos
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
  show.py      # leitura rapida dos eventos
log_event.py   # ponto de entrada do hook
tests/         # pytest
examples/      # configuracao e evento de exemplo
```

## Roadmap

- [x] Fase 1: captura e armazenamento
- [ ] Fase 2: monitores por regra (`git push --force`, leitura de `.env`, `rm -rf`...)
- [ ] Fase 3: LLM-as-judge e avaliacao (precisao e recall)
- [ ] Fase 4: API FastAPI e painel Streamlit
- [ ] Fase 5: Docker, GitHub Actions e deploy no Azure
