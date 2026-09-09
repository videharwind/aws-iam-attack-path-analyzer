import pytest
import boto3

@pytest.mark.aws
def test_connection():
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    assert 'Account' in identity