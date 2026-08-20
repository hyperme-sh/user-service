from user_service.app import create_app


def test_openapi_includes_group_and_org_list_get():
    app = create_app(test_event_sink=[])
    spec = app.openapi()
    paths = spec["paths"]
    assert "get" in paths["/api/v1/groups"]
    assert "get" in paths["/api/v1/groups/{group_id}"]
    assert "get" in paths["/api/v1/organizations"]
    assert "get" in paths["/api/v1/organizations/{organization_id}"]
    schemas = spec["components"]["schemas"]
    assert "GroupListPage" in schemas
    assert "OrganizationListPage" in schemas
    group_list = paths["/api/v1/groups"]["get"]
    param_names = {p["name"] for p in group_list.get("parameters", [])}
    assert {"limit", "offset", "q"} <= param_names
