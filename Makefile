build-compose:
	swagger generate spec -o .\spec\swagger.yaml
	docker-compose build