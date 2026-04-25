docker system prune -af --volumes
sudo docker-compose -f docker-compose-testnet.yml down -v 
sudo rm -rf data/validator-*
echo "WIPED"
