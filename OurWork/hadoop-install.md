
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




