# Deploying `NimbleLedger`

## DevOps for Administrators

### Provisioning the Azure Container Registry Instance

The Azure Container Registry is a private container registry which stores the images
from Github CI build actions of Nimble Ledger. The first step in the process is to setup the
private Azure Container Registry (ACR) instance in Azure which can be done as follows:

1. Create a private registry with Premium SKU using the [Azure Container Registry](https://azure.microsoft.com/en-us/services/container-registry/#overview). 
2. Once generated, Enable the `Admin user` setting from `Access Keys` settings.
3. This will generate the `Username` and regeneratable `password`, `password2` fields.
4. The `login_server` information is provided in the `Overview` section

We use the `Azure Container Registry Login` Github Action from the official Marketplace releases by Azure and add
the following information to the Github actions:

```yaml
- uses: azure/docker-login@v1
  with:
    login-server: ${{ secrets.ACR_LOGIN_SERVER }}  # eg. testnimbleregistry.azurecr.io
    username: ${{ secrets.ACR_USERNAME }}
    password: ${{ secrets.ACR_PASSWORD }}
```

Using Github Actions, Configure the variables `ACR_LOGIN_SERVER`, 'ACR_USERNAME', 'ACR_PASSWORD' in the `Secrets` (Repository Settings > Secrets).

Once configured, the push will result in an image build being pushed to the repository.

### Fetching a CI built image

The `NimbleLedger` images are uploaded to the Azure Container Registry in the format:

```log
registry_name.azurecr.io/nimbleledger:(COMMIT_HASH[:8])
```

To use the images locally, first authenticate to the ACR Login Server and enter the authentication
username and password necessary.

```shell
$ docker login {{ ACR_LOGIN_SERVER }}
```

The `nimbleledger` image can be obtained by doing:

```shell
$ docker pull {{ACR_LOGIN_SERVER}}.azurecr.io/nimbleledger:{{HASH[:8]}}
```

### Finding available images

It is possible to find available images in ACR by using the `az` CLI. This is done however in two steps because of CLI limitations:

```bash
export ACR_LOGIN_SERVER="example_login_server"  # eg. example_login_server.azurecr.io
REPOSITORIES=$(az acr repository list -n $ACR_LOGIN_SERVER -o tsv)  # To list repositories
for REPOSITORY in ${REPOSITORIES[@]}
do
  IMAGE_HASHES=$(az acr repository show-tags --n $ACR_LOGIN_SERVER --repository $REPOSITORY -o tsv)
  for HASH in ${IMAGE_HASHES[@]}
  do
    echo ${REPOSITORY}:${HASH}
  done
done
```

### Using the CI Built Image

The `image` downloaded, can be used as a replacement to the `build : .` step in the `docker-compose.yml` file
to set up the test cluster, this can be done by replacing the `build` with the corresponding `image:tag` information.

Here's an example:

```shell
endorser-1:
    image: {{ACR_LOGIN_SERVER}}.azurecr.io/nimbleledger:{{TAG_VALUE}}
    command: ./endorser -- 9090 0.0.0.0
    volumes:
    - .:/Nimble/Nimble
    ports:
    - "9090:9090"
    container_name: endorser-1
    networks:
      - basic
```
