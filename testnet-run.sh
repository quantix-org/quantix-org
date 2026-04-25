rm -rf data/validator-*
mkdir -p data/validator-{0,1,2,3}
chmod -R 777 data/validator-*
docker-compose -f docker-compose-testnet.yml build --no-cache
docker images | grep quantix
docker-compose -f docker-compose-testnet.yml up -d
docker-compose -f docker-compose-testnet.yml logs -f