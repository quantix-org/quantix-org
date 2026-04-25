sudo docker-compose -f docker-compose-testnet.yml down -v --remove-orphans 2>/dev/null || true
sudo rm -rf data/validator-*
echo "WIPED"
