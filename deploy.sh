#!/usr/bin/env bash
set -euo pipefail

CLUSTER=pwno-cluster
REGION=us-central1
PROJECT=pwno-io
IMAGE=us-central1-docker.pkg.dev/pwno-io/pwno-vm-images/research-container
DEPLOY=research-container
SERVICE=research-container-lb

echo "Fetching credentials for $CLUSTER"
gcloud container clusters get-credentials "$CLUSTER" \
    --region "$REGION" \
    --project "$PROJECT"

if kubectl get deployment "$DEPLOY" &>/dev/null; then
  echo "Updating $DEPLOY → $IMAGE"
  kubectl set image deployment/"$DEPLOY" "$DEPLOY"="$IMAGE" --record
else
  echo "Creating deployment $DEPLOY"
  kubectl create deployment "$DEPLOY" --image="$IMAGE"
fi

# ← add this
kubectl set resources deployment/"$DEPLOY" \
  --containers="$DEPLOY" \
  --requests=cpu=500m,memory=512Mi \
  --limits=cpu=500m,memory=512Mi

kubectl patch deployment "$DEPLOY" --type='strategic' -p "
spec:
  template:
    spec:
      containers:
      - name: $DEPLOY
        ports:
        - containerPort: 5500
        readinessProbe:
          httpGet:
            path: /mcp
            port: 5500
          initialDelaySeconds: 5
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /mcp
            port: 5500
          initialDelaySeconds: 10
          periodSeconds: 20
"

if kubectl get svc "$SERVICE" &>/dev/null; then
  echo "Service $SERVICE already exists"
else
  echo "Exposing $DEPLOY as LoadBalancer → $SERVICE"
  kubectl expose deployment "$DEPLOY" \
    --type=LoadBalancer \
    --name="$SERVICE" \
    --port=5500 \
    --target-port=5500
fi

echo -n "Waiting for EXTERNAL-IP"
while :; do
  IP=$(kubectl get svc "$SERVICE" \
       -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
  if [[ -n "$IP" ]]; then
    echo -e "\nlive at http://$IP:5500/mcp"
    break
  fi
  echo -n "."
  sleep 2
done
