#!/usr/bin/env bash
# Demo publica do AgentWatch no Azure Container Apps (dados SINTETICOS).
#
# ATENCAO: este script e um MODELO. Ele NAO foi executado por quem o escreveu.
# Leia cada comando e confira com `az containerapp --help` antes de rodar.
# Cria recursos que PODEM GERAR CUSTO. Para apagar tudo: az group delete -n "$RG" --yes
#
# Desenho:
#   - API em ingress INTERNO (nao fica publica), com chave em segredo, 1 replica
#     (SQLite e por replica: mais de uma replica daria dados inconsistentes);
#   - painel com ingress externo, lendo a API pela rede interna;
#   - banco efemero com dados sinteticos (AGENTWATCH_SEED_ON_START=1): sem dados reais.
#   - O painel Streamlit nao tem autenticacao: NUNCA publique dados reais assim.
set -euo pipefail

RG="${RG:-agentwatch-demo-rg}"
LOCATION="${LOCATION:-brazilsouth}"
ENV_NAME="${ENV_NAME:-agentwatch-env}"
API_APP="${API_APP:-agentwatch-api}"
DASH_APP="${DASH_APP:-agentwatch-dashboard}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

command -v az >/dev/null || { echo "Instale o Azure CLI e rode 'az login'." >&2; exit 1; }
az extension add --name containerapp --upgrade --only-show-errors

API_KEY="$(openssl rand -hex 24)"

echo "==> Grupo de recursos e ambiente"
az group create --name "$RG" --location "$LOCATION" --output none
az containerapp env create --name "$ENV_NAME" --resource-group "$RG" --location "$LOCATION" --output none

echo "==> API (ingress interno, 1 replica, dados sinteticos)"
az containerapp up \
  --name "$API_APP" --resource-group "$RG" --environment "$ENV_NAME" \
  --source "$ROOT" --ingress internal --target-port 8000 \
  --env-vars AGENTWATCH_SERVICE=api AGENTWATCH_SEED_ON_START=1

az containerapp secret set --name "$API_APP" --resource-group "$RG" --secrets "apikey=$API_KEY" --output none
az containerapp update --name "$API_APP" --resource-group "$RG" \
  --set-env-vars AGENTWATCH_API_KEY=secretref:apikey \
  --min-replicas 1 --max-replicas 1 --output none

API_FQDN="$(az containerapp show --name "$API_APP" --resource-group "$RG" \
  --query properties.configuration.ingress.fqdn --output tsv)"

echo "==> Painel (ingress externo)"
az containerapp up \
  --name "$DASH_APP" --resource-group "$RG" --environment "$ENV_NAME" \
  --source "$ROOT" --ingress external --target-port 8501 \
  --env-vars AGENTWATCH_SERVICE=dashboard "AGENTWATCH_API_URL=https://$API_FQDN"

az containerapp secret set --name "$DASH_APP" --resource-group "$RG" --secrets "apikey=$API_KEY" --output none
az containerapp update --name "$DASH_APP" --resource-group "$RG" \
  --set-env-vars AGENTWATCH_API_KEY=secretref:apikey --output none

DASH_FQDN="$(az containerapp show --name "$DASH_APP" --resource-group "$RG" \
  --query properties.configuration.ingress.fqdn --output tsv)"

echo
echo "Painel: https://$DASH_FQDN"
echo "Para apagar tudo: az group delete --name $RG --yes --no-wait"
