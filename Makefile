layer:
	mkdir -p python deployment
	rm -rf deployment/*.zip
	pip3 install -r requirements.txt --target python
	zip -r deployment/layer.zip python/

master_package:
	cd master && zip -r ../deployment/master.zip .

child_package: 
	cd child && zip -r ../deployment/child.zip .

package: layer master_package child_package
