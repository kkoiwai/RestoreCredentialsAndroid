#!/usr/bin/env bash
set -e

SERVICE_NAME="${SERVICE_NAME:-restore-credentials-poc}"
REGION="${GCP_REGION:-asia-northeast1}"
CLIENT_ID="${CLIENT_ID:-android-poc-client}"
REDIRECT_URI="${REDIRECT_URI:-restoreapp://auth-callback}"

echo "============================================================"
echo "Deploying ${SERVICE_NAME} to Google Cloud Run"
echo "Min instances: 0 | Max instances: 1"
echo "Region: ${REGION}"
echo "============================================================"

gcloud run deploy "${SERVICE_NAME}" \
  --source . \
  --region "${REGION}" \
  --platform managed \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 1 \
  --memory 512Mi \
  --timeout 300s \
  --quiet

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --platform managed --region "${REGION}" --format 'value(status.url)')
RP_HOST="${SERVICE_URL#https://}"

echo "============================================================"
echo "Configuring RP_ID=${RP_HOST}, ISSUER=${SERVICE_URL}, CLIENT_ID=${CLIENT_ID}..."
gcloud run services update "${SERVICE_NAME}" \
  --region "${REGION}" \
  --set-env-vars "RP_ID=${RP_HOST},ISSUER=${SERVICE_URL},CLIENT_ID=${CLIENT_ID},REDIRECT_URI=${REDIRECT_URI}" \
  --quiet

echo "============================================================"
echo "Deployment successful!"
echo "Service URL: ${SERVICE_URL}"
echo "RP_ID:       ${RP_HOST}"
echo "AuthTab URL: ${SERVICE_URL}/login.html"
echo "============================================================"
