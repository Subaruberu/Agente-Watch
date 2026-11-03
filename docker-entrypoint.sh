#!/bin/sh
# Escolhe o servico pela variavel AGENTWATCH_SERVICE (api | dashboard).
set -eu

# Demo: gera dados SINTETICOS na primeira subida, se o banco ainda nao existe.
# Use apenas em demonstracoes; nunca com dados reais.
if [ "${AGENTWATCH_SEED_ON_START:-0}" = "1" ] && [ ! -s "${AGENTWATCH_DB}" ]; then
    python -m agentwatch.seed --db "${AGENTWATCH_DB}"
fi

case "${AGENTWATCH_SERVICE:-api}" in
    api)
        exec uvicorn agentwatch.api:app --host 0.0.0.0 --port 8000
        ;;
    dashboard)
        exec streamlit run dashboard.py \
            --server.address 0.0.0.0 --server.port 8501 \
            --server.headless true --browser.gatherUsageStats false
        ;;
    *)
        echo "AGENTWATCH_SERVICE invalido: '${AGENTWATCH_SERVICE}' (use api ou dashboard)" >&2
        exit 2
        ;;
esac
