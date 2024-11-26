
# This is for compiling the hadoop repo
## cd into your /USER
git clone https://github.com/mitthu/hadoop-nimble.git

## Go into nix-shell using following command 
nix-shell -p jdk8 maven

## Change the nodejs version in the pom.xml
open this xml file: hadoop-nimble/hadoop-project/pom.xml
go to this line: <nodejs.version>v12.22.1</nodejs.version> and change it to this: 
<nodejs.version>v14.21.3</nodejs.version>
## compile hadoop-nimble
cd hadoop-nimble

mvn package -Pdist -DskipTests -Dtar -Dmaven.javadoc.skip=true 


# This is for installing hadoop

If youre not in a nix-shell still -> go there
nix-shell -p jdk8 maven

mkdir opt

sudo tar -xvf hadoop-3.3.3.tar.gz -C /home/USER/opt

sudo mv /home/USER/opt/hadoop-3.3.3 /home/USER/opt/hadoop-nimble

sudo chown -R `whoami` /home/kilian/opt/hadoop-nimble

exit (exit the nix-shell)

echo 'export PATH=$PATH:/opt/hadoop-nimble/bin' | tee -a ~/.bashrc 

nix-shell

mkdir mnt

cd mnt

mkdir store 

cd ..

sudo chown -R `whoami` mnt/store

## change the configs

echo "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<?xml-stylesheet type=\"text/xsl\" href=\"configuration.xsl\"?>
<configuration>
	<property>
		<name>dfs.name.dir</name>
		<value>/home/USER/mnt/store/namenode</value>
	</property>
	<property>
		<name>dfs.data.dir</name>
		<value>/home/USER/mnt/store/datanode</value>
	</property>
</configuration>
" | sudo tee opt/hadoop-nimble/etc/hadoop/hdfs-site.xml


## Here replace namenodeip and nimbleip with the ip-addresses, i chose 127.0.0.1 for localhost but maybe for your ssh TEE things you might need the VMs ip
echo "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<?xml-stylesheet type=\"text/xsl\" href=\"configuration.xsl\"?>
<configuration>
	<property>
		<name>fs.defaultFS</name>
		<value>hdfs://<namenodeip>:9000</value>
	</property>
	<property>
		<name>fs.nimbleURI</name>
		<value>http://<nimbleip>:8082/</value>
	</property>
	<property>
		<name>fs.nimble.batchSize</name>
		<value>100</value>
	</property>
</configuration>
" | sudo tee opt/hadoop-nimble/etc/hadoop/core-site.xml


# Getting it to run

cd Nimble/experiments

python3 start_nimble_memory.py 
or
python3 start_nimble_table.py

cd ..
cd ..

## Format namenode (needed once)
hdfs namenode -format

## Start Namenode
hdfs --daemon start namenode

## Start Datanode
hdfs --daemon start datanode

# Getting the normal Hadoop

## in your /home/USER folder
curl -o hadoop-upstream.tar.gz https://archive.apache.org/dist/hadoop/common/hadoop-3.3.3/hadoop-3.3.3.tar.gz

nix-shell -p jdk8

sudo tar -xvf hadoop-upstream.tar.gz -C /home/USER/opt

sudo mv opt/hadoop-3.3.3 opt/hadoop-upstream

sudo chown -R `whoami` opt/hadoop-upstream


# Hadoop NNThroughputBenchmarking

nix-shell -p jdk8

## start up nimble and hadoop like above 

## run the benchmark script

sh runNNTBenchmark.sh

## Results are in the bash.terminal / no log files are created


# Installing HiBench

export NIXPKGS_ALLOW_INSECURE=1

nix-shell -p maven python2 --impure

cd ~ // to your highest folder

git clone https://github.com/Intel-bigdata/HiBench.git

cd HiBench

git checkout 00aa105

mvn -Phadoopbench -Dhadoop=3.2 -DskipTests package (TWICE if it fails first try)


 ## replace user and ip with the ip
echo -n '# Configure
hibench.hadoop.home           /home/kilian/opt/hadoop-nimble
hibench.hadoop.executable     ${hibench.hadoop.home}/bin/hadoop
hibench.hadoop.configure.dir  ${hibench.hadoop.home}/etc/hadoop
hibench.hdfs.master           hdfs://127.0.0.1:9000
hibench.hadoop.release        apache
' >conf/hadoop.conf

## this with replace ip 127.0.0.1 for localhost
echo "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<?xml-stylesheet type=\"text/xsl\" href=\"configuration.xsl\"?>
<configuration>
	<property>
		<name>yarn.resourcemanager.hostname</name>
		<value><namenodeip></value>
	</property>
</configuration>
" | sudo tee /home/kilian/opt/hadoop-nimble/etc/hadoop/yarn-site.xml

## cd into Nimble experiments folder
python3 start_nimble_memory.py

## cd back to HiBench folder
### start these two
yarn --daemon start resourcemanager

yarn --daemon start nodemanager

## create new runHiBench.sh with following text
#!/bin/bash

size=large
sed -ie "s/hibench.scale.profile .*/hibench.scale.profile $size/g" conf/hibench.conf

function bench {
        kind=$1
        name=$2
        bin/workloads/$kind/$name/prepare/prepare.sh
        bin/workloads/$kind/$name/hadoop/run.sh
}

bench micro     wordcount
bench micro     sort
bench micro     terasort
bench micro     dfsioe
bench websearch pagerank

### Run that script in the HiBench folder, output in report/hibench.report


# Switch between hadoop-nimble and hadoop-upstream

## create two new scripts in your home folder, add the text and replace USER with your name
touch nnreset.sh 
touch dnreset.sh 

both take the argument [ nimble / upstream ]

nnreset is following:
	#!/bin/bash
	# name: nnreset.sh
	# usage: ./nnreset.sh [ nimble / upstream ]

	UPSTREAM=/home/USER/opt/hadoop-upstream
	NIMBLE=/home/USER/opt/hadoop-nimble
	STORAGE=/home/USER/mnt/store

	# Switch to?
	if   [ "$1" = "nimble"   ]; then
			BASE=$NIMBLE
	elif [ "$1" = "upstream" ]; then
			BASE=$UPSTREAM
	else
			echo "usage: $0 [ nimble / upstream ]"
			exit 1
	fi

	echo "Switching to $BASE"

	# Stop existing services
	$UPSTREAM/bin/hdfs --daemon stop namenode
	$UPSTREAM/bin/yarn --daemon stop resourcemanager
	$NIMBLE/bin/hdfs   --daemon stop namenode
	$NIMBLE/bin/yarn   --daemon stop resourcemanager

	# Remove storage
	rm -rf $STORAGE/*

	# Initialize
	mkdir -p $STORAGE
	$BASE/bin/hdfs namenode -format
	$BASE/bin/hdfs --daemon start namenode
	$BASE/bin/yarn --daemon start resourcemanager

dnreset is following:
	#!/bin/bash
	# name: dnreset.sh
	# usage: ./dnreset.sh [ nimble / upstream ]

	UPSTREAM=/home/USER/opt/hadoop-upstream
	NIMBLE=/home/USER/opt/hadoop-nimble
	STORAGE=/home/USER/mnt/store

	# Switch to?
	if   [ "$1" = "nimble"   ]; then
			BASE=$NIMBLE
	elif [ "$1" = "upstream" ]; then
			BASE=$UPSTREAM
	else
			echo "usage: $0 [ nimble / upstream ]"
			exit 1
	fi

	echo "Switching to $BASE"

	# Stop existing services
	$UPSTREAM/bin/hdfs --daemon stop datanode
	$UPSTREAM/bin/yarn --daemon stop nodemanager
	$NIMBLE/bin/hdfs   --daemon stop datanode
	$NIMBLE/bin/yarn   --daemon stop nodemanager

	# Remove storage
	rm -rf $STORAGE/*

	# Initialize
	mkdir -p $STORAGE
	$BASE/bin/hdfs namenode -format
	$BASE/bin/hdfs --daemon start datanode
	$BASE/bin/yarn --daemon start nodemanager

# If anything doesnt work --> https://github.com/mitthu/hadoop-nimble?tab=readme-ov-file#deploy 
# I followed those steps, adjusted everything and got rid of any errors by them, but maybe i missed sth