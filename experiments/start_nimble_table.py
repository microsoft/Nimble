from config import *
from setup_nodes import *

if os.environ.get('STORAGE_MASTER_KEY', '') == "" or os.environ.get('STORAGE_ACCOUNT_NAME', '') == "":
    print("Make sure to set the STORAGE_MASTER_KEY and STORAGE_ACCOUNT_NAME environment variables")
    exit(-1)

store = " -s table -n nimble" + str(random.randint(1,100000000)) + " -a \"" + os.environ['STORAGE_ACCOUNT_NAME'] + "\""
store += " -k \"" + os.environ['STORAGE_MASTER_KEY'] + "\""

teardown()
setup(store, False)
