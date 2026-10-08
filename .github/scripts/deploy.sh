#!/usr/bin/env bash
# Steps used by .github/workflows/deploy.yml and teardown.yml. Inputs come from the environment:
#   TENANT        brightwater | orchidvalley | pinecrest (one subscription per customer)
#   DEPLOY_TOOL   terraform | bicep
#   ARM_* / AZURE_*  set by azure/login (OIDC) and the workflow env
#
#   deploy.sh assign    create or update the policy definitions, initiative and subscription assignment
#   deploy.sh smoke     check the assignment exists with the configured effect and regions
#   deploy.sh destroy   remove the assignment, initiative and definitions (teardown workflow only)
#
# Never run from this repository so far: DEPLOY_ENABLED is not set.
set -euo pipefail

TENANT="${TENANT:?TENANT is required}"
TOOL="${DEPLOY_TOOL:-terraform}"
STACK="infra/terraform"
NAME="soc-residency-${TENANT}"

tf_init() {
  : "${TFSTATE_RESOURCE_GROUP:?set repo/environment variable TFSTATE_RESOURCE_GROUP}"
  : "${TFSTATE_STORAGE_ACCOUNT:?set repo/environment variable TFSTATE_STORAGE_ACCOUNT}"
  terraform -chdir="$STACK" init -input=false \
    -backend-config="envs/${TENANT}.backend.hcl" \
    -backend-config="resource_group_name=${TFSTATE_RESOURCE_GROUP}" \
    -backend-config="storage_account_name=${TFSTATE_STORAGE_ACCOUNT}" \
    -backend-config="container_name=${TFSTATE_CONTAINER:-tfstate}"
}

assign() {
  if [[ "$TOOL" == "terraform" ]]; then
    tf_init
    terraform -chdir="$STACK" apply -auto-approve -input=false -var-file="envs/${TENANT}.tfvars"
  else
    az deployment sub create --name "${NAME}-${GITHUB_RUN_ID:-local}" --location "$(jq -r '.parameters.allowedLocations.value[0]' "infra/bicep/params/${TENANT}.parameters.json")" \
      --template-file infra/bicep/main.bicep --parameters "@infra/bicep/params/${TENANT}.parameters.json" -o none
  fi
}

smoke() {
  effect=$(az policy assignment show --name "$NAME" --query "parameters.effect.value" -o tsv)
  regions=$(az policy assignment show --name "$NAME" --query "parameters.allowedLocations.value" -o tsv | tr '\n' ' ')
  [[ -n "$effect" ]] || { echo "::error::assignment $NAME not found"; exit 1; }
  echo "assignment $NAME: effect $effect, regions $regions"
}

destroy() {
  if [[ "$TOOL" == "terraform" ]]; then
    tf_init
    terraform -chdir="$STACK" destroy -auto-approve -input=false -var-file="envs/${TENANT}.tfvars"
  else
    az policy assignment delete --name "$NAME"
    az policy set-definition delete --name "$NAME"
    for r in locations ai-accounts model-deployment-types log-analytics; do az policy definition delete --name "${NAME}-${r}"; done
  fi
}

"$@"
