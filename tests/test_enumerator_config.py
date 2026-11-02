import boto3
import IAM_Enumerator


def test_enumerator_config_and_caching(monkeypatch):
    calls = []

    class FakeClient:
        pass

    fake_client_instance = FakeClient()

    class FakeSession:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def client(self, service_name):
            assert service_name == "iam"
            return fake_client_instance

    monkeypatch.setattr(boto3, "Session", FakeSession)

    # 1. Assert lazy creation (configure_client does not instantiate session)
    IAM_Enumerator.configure_client(profile="test-profile", region="eu-west-1")
    assert len(calls) == 0

    # 2. First get_client call creates Session and passes profile and region
    client1 = IAM_Enumerator.get_client()
    assert client1 is fake_client_instance
    assert len(calls) == 1
    assert calls[0] == {"profile_name": "test-profile", "region_name": "eu-west-1"}

    # 3. Caching: second get_client call does not instantiate Session again
    client2 = IAM_Enumerator.get_client()
    assert client2 is fake_client_instance
    assert len(calls) == 1

    # 4. configure_client resets cache and defaults pass None
    IAM_Enumerator.configure_client()
    assert len(calls) == 1
    client3 = IAM_Enumerator.get_client()
    assert len(calls) == 2
    assert calls[1] == {"profile_name": None, "region_name": None}

    # Reset back to defaults for clean test state
    IAM_Enumerator.configure_client()

