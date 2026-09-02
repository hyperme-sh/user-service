from api.common.portal_controls import evaluate_portal_controls, normalize_group_name


def test_normalize_keycloak_group_paths():
    assert normalize_group_name("/host") == "host"
    assert normalize_group_name("/org/renter") == "renter"
    assert normalize_group_name("Billing Group") == "billing"
    assert normalize_group_name("workspace") is None
    assert normalize_group_name("team") is None


def test_org_admin_gets_slice2_controls_and_ir_door():
    c = evaluate_portal_controls(["admin"], [])
    assert c.org_admin is True
    assert c.can_invite_members is True
    assert c.can_assign_group is True
    assert c.can_mint_keys is True
    assert c.can_checkout is True
    assert c.can_see_host_status is True
    assert c.can_see_leases is True
    assert c.can_use_ir_door is True
    assert c.can_export_ir_receipts is True


def test_renter_group_can_checkout_mint_and_see_leases():
    c = evaluate_portal_controls(["user"], ["renter"])
    assert c.org_admin is False
    assert c.can_invite_members is False
    assert c.can_assign_group is False
    assert c.can_mint_keys is True
    assert c.can_checkout is True
    assert c.can_see_leases is True
    assert c.can_see_host_status is False
    assert c.can_use_ir_door is False
    assert c.can_export_ir_receipts is False


def test_billing_group_can_mint_keys_only():
    c = evaluate_portal_controls([], ["/billing"])
    assert c.can_mint_keys is True
    assert c.can_checkout is False
    assert c.can_see_host_status is False
    assert c.can_see_leases is False
    assert c.can_use_ir_door is False
    assert c.can_export_ir_receipts is False


def test_host_group_sees_path_b_status():
    c = evaluate_portal_controls(["host"], [])
    assert c.can_see_host_status is True
    assert c.can_mint_keys is False
    assert c.can_checkout is False
    assert c.can_use_ir_door is False
    assert c.can_export_ir_receipts is False
    assert "host" in c.groups


def test_guest_has_no_portal_controls():
    c = evaluate_portal_controls(["guest"], [])
    assert c.as_dict()["can_mint_keys"] is False
    assert c.can_invite_members is False
    assert c.can_use_ir_door is False
    assert c.can_export_ir_receipts is False
