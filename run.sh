		docker run \
			--privileged \
			--net=host \
			--pid=host \
			-v /cgroup:/cgroup:ro \
                        -v /var/lib/docker:/var/lib/docker:ro \
			-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
			-v /var/run/docker.sock:/var/run/docker.sock \
			-it bcc_crawler --crawlmode INVM --frequency 10 --feature profile --format profile

