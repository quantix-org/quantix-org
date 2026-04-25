mkdir -p data/validator-{0,1,2,3}
chmod -R 777 data/validator-*
docker-compose -f docker-compose-testnet.yml up --build -d
