#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Create, run, watch and destroy the training instance.
#
# A script you can read rather than a Terraform module, deliberately. It creates exactly
# one VM, and the two things most worth being able to check by eye are that it is the VM
# you expected and that it gets deleted.
set -euo pipefail

PROJECT="${FLOWX_PROJECT:-prj-ai-flowx-dev}"
# europe-west1 rather than us-central1: this is an EU-language project and keeping the
# training data in the EU is the smaller surprise. Quota checked 2026-08-11, 16 L4 in
# both, none in use.
ZONE="${FLOWX_ZONE:-europe-west1-b}"
NAME="${FLOWX_INSTANCE:-border-moderation-train}"
MACHINE="${FLOWX_MACHINE:-g2-standard-8}"   # 1x L4, 8 vCPU, 32 GB
DISK_GB="${FLOWX_DISK:-200}"
REMOTE="/opt/training"

# Deep Learning VM with PyTorch and CUDA preinstalled. Building a CUDA stack by hand on
# a fresh Ubuntu is an hour of the GPU's billed time spent not training. The image
# already carries torch, which is why requirements.txt does not pin it: reinstalling a
# different torch over the one built against this image's driver is how a run gets an
# hour in and then cannot see the GPU.
IMAGE_FAMILY="pytorch-2-9-cu129-ubuntu-2204-nvidia-580"
IMAGE_PROJECT="deeplearning-platform-release"
# The image ships torch in the system interpreter. Checked on the running instance
# rather than assumed: an earlier version guessed /opt/conda and the path did not exist.
PY_BIN="/usr/bin/python3"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() { sed -n '3,12p' "$0"; echo; echo "usage: $0 {create|push|run|logs|status|fetch|delete}"; }

case "${1:-}" in
create)
  echo "creating ${NAME} in ${ZONE} (${MACHINE}, 1x L4)"
  gcloud compute instances create "$NAME" \
    --project="$PROJECT" --zone="$ZONE" \
    --machine-type="$MACHINE" \
    --accelerator="type=nvidia-l4,count=1" \
    --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="${DISK_GB}GB" --boot-disk-type=pd-balanced \
    --maintenance-policy=TERMINATE \
    --metadata="install-nvidia-driver=True" \
    --scopes=cloud-platform \
    --labels="purpose=border-moderation-training,owner=flowx-border"
  echo "waiting for ssh"
  until gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" \
        --command="nvidia-smi -L" --quiet 2>/dev/null; do sleep 15; done
  "$0" push
  gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet --command="
    set -e
    sudo mkdir -p ${REMOTE} && sudo chown -R \$USER ${REMOTE}
    ${PY_BIN} -m pip install -q -r ${REMOTE}/requirements.txt
    ${PY_BIN} -c 'import torch; print(\"torch\", torch.__version__, \"cuda\", torch.cuda.is_available())'
  "
  ;;
push)
  echo "copying training/ to ${NAME}:${REMOTE}"
  gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet \
    --command="sudo mkdir -p ${REMOTE} && sudo chown -R \$USER ${REMOTE}"
  gcloud compute scp --recurse --project="$PROJECT" --zone="$ZONE" --quiet \
    "$here"/*.py "$here"/*.yaml "$here"/requirements.txt "$NAME:${REMOTE}/"
  ;;
run)
  # nohup, because the run outlives any ssh session and a dropped connection must not
  # kill eight hours of GPU time.
  gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet --command="
    cd ${REMOTE}
    nohup bash -c '
      set -e
      ${PY_BIN} prepare_data.py --config config.yaml
      ${PY_BIN} train.py --config config.yaml
      ${PY_BIN} evaluate.py --config config.yaml | tee eval.txt
      ${PY_BIN} export_onnx.py --config config.yaml
      echo DONE > ${REMOTE}/STATUS
    ' > ${REMOTE}/train.log 2>&1 &
    echo started
  "
  echo "started. watch with: $0 logs"
  ;;
logs) gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet \
        --command="tail -f ${REMOTE}/train.log" ;;
status) gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet \
        --command="cat ${REMOTE}/STATUS 2>/dev/null || echo RUNNING; tail -5 ${REMOTE}/train.log" ;;
fetch)
  mkdir -p "$here/artifacts"
  gcloud compute scp --recurse --project="$PROJECT" --zone="$ZONE" --quiet \
    "$NAME:${REMOTE}/artifacts/*" "$here/artifacts/" || true
  gcloud compute scp --project="$PROJECT" --zone="$ZONE" --quiet \
    "$NAME:${REMOTE}/eval.txt" "$here/" || true
  echo "fetched into $here/artifacts"
  ;;
delete)
  # The instance bills whether or not it is training. Deleting it is the step people
  # forget, which is why it is a subcommand rather than a note in a README.
  gcloud compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet
  ;;
*) usage; exit 1 ;;
esac
