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


def test_openapi_includes_user_role_assign_remove():
    app = create_app(test_event_sink=[])
    spec = app.openapi()
    paths = spec["paths"]
    assert "patch" in paths["/api/v1/users/{user_id}/assign_role"]
    assert "patch" in paths["/api/v1/users/{user_id}/remove_role"]
    schemas = spec["components"]["schemas"]
    assert "UserRoleUpdateBody" in schemas
    assert "role_id" in schemas["UserResponse"]["properties"]


def test_openapi_includes_portal_org_group_controls():
    app = create_app(test_event_sink=[])
    spec = app.openapi()
    paths = spec["paths"]
    assert "get" in paths["/api/v1/me/portal-controls"]
    assert "get" in paths["/api/v1/groups/{group_id}/members"]
    assert "get" in paths["/api/v1/users/{user_id}/groups"]
    assert "delete" in paths["/api/v1/users/{user_id}/groups/{group_id}"]
    schemas = spec["components"]["schemas"]
    assert "PortalControlsResponse" in schemas
    assert "GroupMemberListPage" in schemas
    assert "can_mint_keys" in schemas["PortalControlsResponse"]["properties"]
    assert "can_checkout" in schemas["PortalControlsResponse"]["properties"]
    assert "can_see_host_status" in schemas["PortalControlsResponse"]["properties"]
    assert schemas["PortalControlsResponse"]["properties"]["can_use_ir_door"]
