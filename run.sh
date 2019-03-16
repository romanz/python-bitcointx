export PYTHONPATH=.
export LD_LIBRARY_PATH=$PWD/../secp256k1-zkp/.libs/
py.test bitcointx/tests/test_elements_sidechain_transactions.py -v -k blind_un -s
