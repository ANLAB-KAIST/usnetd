upload:
	./deploy

tests:
	# The TCP goodput experiments are fully scripted
	/bin/ls | grep tcp | xargs -n 1 -d '\n' ./gather

generategraphs:
	cd graphs && ./render

manualtestmpps:
	# Please observe the output of netmap pkt-gen manually
	# First evaluate direct netmap without using usnetd:
	# prepare server:
	echo sudo netmap/build-apps/pkt-gen/pkt-gen -i enp6s0f0 -f rx
	# run client:
	# direct netmap without using usnetd, vary the packet size argument -l SIZE to fill entries in direct_pps_server:SIZE/last:
	echo sudo netmap/build-apps/pkt-gen/pkt-gen -i enp4s0f0 -f tx -4 -d 169.254.137.191:3333 -D 00:1b:21:4b:50:8c -l 64
	#
	# Now evaluate using usnetd
	# prepare server:
	echo sudo RUST_LOG=info taskset -c 6 ./usnetd enp6s0f0config
	echo sudo netmap/build-apps/pkt-gen/pkt-gen -i enp6s0f0{4094 -f rx
	# prepare client:
	echo sudo RUST_LOG=info taskset -c 6 ./usnetd enp4s0f0config
	# run client:
	# using usnetd, vary the packet size argument -l SIZE to fill entries in switch_pps_server:SIZE/last:
	echo sudo netmap/build-apps/pkt-gen/pkt-gen -i enp4s0f0{4094 -f tx -4 -d 169.254.137.191:3333 -D 00:1b:21:4b:50:8c -l 64

manualtesthttp:
	# Please extract the average value of the /usr/bin/ab manually
	# Run the HTTP server with usnet_sockets:
	echo BG_THREAD_PIN_CPU_ID=2 RUST_LOG=usnet_sockets=info USNET_SOCKETS='{"UsnetConfig":{"Interface":{"interface":{"Interface":"enp6s0f0"},"ipc":"NetmapPipe","mac":"Passthru","ipv4":"Passthru"}}}' ./smolbench -b 500000 httpd -q 8000
	# run client and fill entries in httpd_server:usnet/last:
	echo ab -n 5000 -c 32 http://169.254.137.191:8000/
	# The following example entry shows the needed format:
	# ,Network Stack,GHz,Reqs
	# 0,usnet,2.6,862
	#
	# The Linux host stack can also be evaluated as server:
	echo ./smolbenchhost -b 500000 httpd -q 8000
	# run the same client again as above and fill entries in httpd_server:linux/last:
	echo ab -n 5000 -c 32 http://169.254.137.191:8000/
	# The format stays the same:
	# ,Network Stack,GHz,Reqs
	# 0,Linux,2.6,20096
