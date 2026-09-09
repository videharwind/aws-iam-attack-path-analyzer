def test_dependencies():
    import boto3
    import networkx
    
    assert boto3 is not None
    assert networkx is not None