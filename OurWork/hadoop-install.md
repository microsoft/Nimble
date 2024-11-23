
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





