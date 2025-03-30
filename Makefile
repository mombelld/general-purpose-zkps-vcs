build-docker-image:
	# just for debugging the build process
	# docker builder prune --force --all

	docker build \
		--progress plain \
		-t vc-demo \
		.

run-docker-image:
	# Turn off seccomp to void potentially slower runtime inside docker
	docker run \
		--security-opt seccomp=unconfined \
		-ti \
		--rm \
		--name spartan-bench \
		--net=host \
		--privileged=true \
		-v /var/run/docker.sock:/var/run/docker.sock \
		vc-demo