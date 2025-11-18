def test_create_organization(client, test_user):
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "password123"
        }
    )
    token = login_response.json()["access_token"]

    response = client.post(
        "/api/v1/orgs",
        json={
            "name": "New Org",
            "slug": "new-org",
            "description": "Test organization"
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "New Org"
    assert data["slug"] == "new-org"


def test_list_organizations(client, test_user, test_org):
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "password123"
        }
    )
    token = login_response.json()["access_token"]

    response = client.get(
        "/api/v1/orgs",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0