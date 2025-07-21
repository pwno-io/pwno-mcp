INSTANCE=research-container
ZONE=asia-southeast1-a
IMAGE=us-central1-docker.pkg.dev/pwno-io/pwno-vm-images/research-container

# 2. Create a preemptible VM that runs your container once, then stops it
gcloud compute instances create-with-container $INSTANCE \
    --zone=$ZONE \
    --machine-type=e2-micro \
    --preemptible \
    --container-image=$IMAGE \
    --container-restart-policy=never

gcloud compute instances describe $INSTANCE \
    --zone=$ZONE \
    --format="get(networkInterfaces[0].accessConfigs[0].natIP)"

#gcloud compute instances delete $INSTANCE --zone=$ZONE --quiet
