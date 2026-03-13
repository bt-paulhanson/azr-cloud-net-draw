"""
Unit tests for NSG/UDR tooltip rendering in MLD diagrams.

Covers:
- _format_nsg_tooltip() helper function
- _format_udr_tooltip() helper function
- _add_vnet_with_optional_subnets() XML output for NSG/UDR icons:
    label accuracy (count, singular/plural, zero-rules, no-name fallback)
    tooltip accuracy
    object->mxCell XML structure
"""
from lxml import etree
from unittest.mock import Mock

from cloudnetdraw.diagram_generator import (
    _format_nsg_tooltip,
    _format_udr_tooltip,
    _add_vnet_with_optional_subnets,
)


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

def _make_rule(name="AllowHTTPS", priority=100, direction="Inbound",
               access="Allow", protocol="TCP",
               source="*", source_port="*",
               destination="*", destination_port="443"):
    return {
        "name": name,
        "priority": priority,
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "source": source,
        "source_port": source_port,
        "destination": destination,
        "destination_port": destination_port,
    }


def _make_route(name="default", address_prefix="0.0.0.0/0",
                next_hop_type="VirtualAppliance", next_hop_ip="10.0.0.4"):
    return {
        "name": name,
        "address_prefix": address_prefix,
        "next_hop_type": next_hop_type,
        "next_hop_ip": next_hop_ip,
    }


def _make_config():
    """Return a minimal mock config suitable for MLD rendering."""
    cfg = Mock()
    cfg.get_vnet_style_string.return_value = "shape=rectangle;"
    cfg.get_subnet_style_string.return_value = "shape=rectangle;"
    cfg.get_icon_path.return_value = "img/icon.svg"
    cfg.get_icon_size.return_value = (16, 16)
    cfg.get_hub_spoke_edge_style.return_value = ""
    cfg.layout = {
        "hub": {"height": 50, "width": 400},
        "subnet": {
            "padding_x": 25,
            "padding_y": 55,
            "spacing_y": 30,
            "width": 350,
            "height": 20,
        },
    }
    cfg.icon_positioning = {
        "vnet_icons": {"y_offset": 3, "right_margin": 6, "icon_gap": 5},
        "virtual_hub_icon": {"offset_x": -10, "offset_y": -15},
        "subnet_icons": {"icon_gap": 3, "icon_y_offset": 2, "subnet_icon_y_offset": 3},
    }
    cfg.drawio = {"group": {"extra_height": 20, "connectable": "0"}}
    cfg.canvas_padding = 20
    cfg.vnet_width = 400
    cfg.zone_spacing = 500
    cfg.vnet_spacing_x = 450
    return cfg


def _make_xml_root():
    """Return a fresh lxml root element in draw.io flat-structure style."""
    mxGraphModel = etree.Element("mxGraphModel")
    root = etree.SubElement(mxGraphModel, "root")
    etree.SubElement(root, "mxCell", id="0")
    etree.SubElement(root, "mxCell", id="1", parent="0")
    return root


def _make_vnet(subnets):
    """Return a minimal VNet data dict with the supplied subnets list."""
    return {
        "name": "test-vnet",
        "address_space": "10.0.0.0/16",
        "subscription_name": "sub",
        "subscription_id": "sid",
        "tenant_id": "tid",
        "resourcegroup_id": "rgid",
        "resourcegroup_name": "rg",
        "resource_id": (
            "/subscriptions/sid/resourceGroups/rg"
            "/providers/Microsoft.Network/virtualNetworks/test-vnet"
        ),
        "azure_console_url": "",
        "type": "vnet",
        "subnets": subnets,
        "expressroute": "No",
        "vpn_gateway": "No",
        "firewall": "No",
    }


def _make_subnet(nsg="No", udr="No", nsg_name="", nsg_rules=None,
                 udr_name="", routes=None):
    """Return a subnet data dict with NSG/UDR fields."""
    return {
        "name": "snet",
        "address": "10.0.0.0/24",
        "nsg": nsg,
        "udr": udr,
        "nsg_name": nsg_name,
        "nsg_rules": nsg_rules if nsg_rules is not None else [],
        "udr_name": udr_name,
        "routes": routes if routes is not None else [],
    }


def _render_vnet(subnets):
    """Call _add_vnet_with_optional_subnets in MLD mode; return the root."""
    root = _make_xml_root()
    _add_vnet_with_optional_subnets(
        _make_vnet(subnets), 0, 0, root, _make_config(), show_subnets=True
    )
    return root


def _find_icon_objects(root, icon_type):
    """Find all <object> elements whose id contains the icon type suffix."""
    return [el for el in root.iter("object") if f"{icon_type}_" in el.get("id", "")]


# ---------------------------------------------------------------------------
# _format_nsg_tooltip()
# ---------------------------------------------------------------------------

class TestFormatNsgTooltip:
    """Tests for the _format_nsg_tooltip() helper."""

    def test_header_includes_nsg_name(self):
        subnet = {"nsg_name": "my-nsg", "nsg_rules": [_make_rule()]}
        result = _format_nsg_tooltip(subnet)
        assert result.startswith("NSG: my-nsg")

    def test_header_without_name_is_generic(self):
        subnet = {"nsg_name": "", "nsg_rules": []}
        result = _format_nsg_tooltip(subnet)
        assert result.startswith("NSG")
        assert "NSG: " not in result  # no colon when name is empty

    def test_rule_line_contains_key_fields(self):
        rule = _make_rule(
            name="AllowHTTPS", priority=100, direction="Inbound",
            access="Allow", protocol="TCP",
            source="VirtualNetwork", source_port="*",
            destination="*", destination_port="443",
        )
        subnet = {"nsg_name": "nsg", "nsg_rules": [rule]}
        result = _format_nsg_tooltip(subnet)
        assert "[Inbound]" in result
        assert "100" in result
        assert "AllowHTTPS" in result
        assert "TCP" in result
        assert "443" in result
        assert "Allow" in result

    def test_arrow_unicode_present_in_rule_lines(self):
        subnet = {"nsg_name": "nsg", "nsg_rules": [_make_rule()]}
        result = _format_nsg_tooltip(subnet)
        assert "\u2192" in result

    def test_empty_rules_with_name_shows_no_rules(self):
        subnet = {"nsg_name": "empty-nsg", "nsg_rules": []}
        result = _format_nsg_tooltip(subnet)
        assert "(no rules)" in result
        assert "fetched" not in result

    def test_empty_rules_without_name_shows_no_rules(self):
        subnet = {"nsg_name": "", "nsg_rules": []}
        result = _format_nsg_tooltip(subnet)
        assert "(no rules)" in result

    def test_multiple_rules_each_on_own_line(self):
        rules = [_make_rule(name="R1"), _make_rule(name="R2")]
        subnet = {"nsg_name": "nsg", "nsg_rules": rules}
        result = _format_nsg_tooltip(subnet)
        assert "R1" in result
        assert "R2" in result
        lines = result.split("\n")
        assert len(lines) == 3  # header + 2 rule lines


# ---------------------------------------------------------------------------
# _format_udr_tooltip()
# ---------------------------------------------------------------------------

class TestFormatUdrTooltip:
    """Tests for the _format_udr_tooltip() helper."""

    def test_header_includes_udr_name(self):
        subnet = {"udr_name": "my-rt", "routes": [_make_route()]}
        result = _format_udr_tooltip(subnet)
        assert result.startswith("UDR: my-rt")

    def test_route_line_contains_key_fields(self):
        route = _make_route(
            name="default-route", address_prefix="0.0.0.0/0",
            next_hop_type="VirtualAppliance", next_hop_ip="10.0.0.4",
        )
        subnet = {"udr_name": "rt", "routes": [route]}
        result = _format_udr_tooltip(subnet)
        assert "default-route" in result
        assert "0.0.0.0/0" in result
        assert "VirtualAppliance (10.0.0.4)" in result

    def test_next_hop_ip_omitted_when_none(self):
        route = _make_route(next_hop_type="VnetLocal", next_hop_ip=None)
        subnet = {"udr_name": "rt", "routes": [route]}
        result = _format_udr_tooltip(subnet)
        assert "VnetLocal" in result
        assert "(None)" not in result

    def test_empty_routes_with_name_shows_no_routes(self):
        subnet = {"udr_name": "empty-rt", "routes": []}
        result = _format_udr_tooltip(subnet)
        assert "(no routes)" in result
        assert "fetched" not in result

    def test_empty_routes_without_name_shows_no_routes(self):
        subnet = {"udr_name": "", "routes": []}
        result = _format_udr_tooltip(subnet)
        assert "(no routes)" in result

    def test_multiple_routes_each_on_own_line(self):
        routes = [_make_route(name="r1"), _make_route(name="r2")]
        subnet = {"udr_name": "rt", "routes": routes}
        result = _format_udr_tooltip(subnet)
        lines = result.split("\n")
        assert len(lines) == 3  # header + 2 route lines


# ---------------------------------------------------------------------------
# XML output — NSG icon label & structure
# ---------------------------------------------------------------------------

class TestNsgIconXmlOutput:
    """Test that the NSG icon <object> element has correct label and tooltip."""

    def test_nsg_with_rules_produces_object_with_count_label(self):
        subnet = _make_subnet(
            nsg="Yes", nsg_name="my-nsg",
            nsg_rules=[_make_rule("R1"), _make_rule("R2")],
        )
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "nsg")
        assert len(objs) == 1
        assert objs[0].get("label") == "NSG (2 rules)"

    def test_nsg_tooltip_contains_rule_details(self):
        subnet = _make_subnet(
            nsg="Yes", nsg_name="my-nsg",
            nsg_rules=[_make_rule("AllowHTTPS", destination_port="443")],
        )
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "nsg")
        tooltip = objs[0].get("tooltip")
        assert "NSG: my-nsg" in tooltip
        assert "AllowHTTPS" in tooltip
        assert "443" in tooltip

    def test_nsg_with_zero_rules_but_name_shows_zero_count(self):
        """An NSG whose rules fetch succeeded but returned 0 rules shows '(0 rules)'."""
        subnet = _make_subnet(nsg="Yes", nsg_name="empty-nsg", nsg_rules=[])
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "nsg")
        assert objs[0].get("label") == "NSG (0 rules)"

    def test_nsg_without_name_falls_back_to_plain_label(self):
        """NSG with no nsg_name (fetch failed) shows plain 'NSG'."""
        subnet = _make_subnet(nsg="Yes", nsg_name="", nsg_rules=[])
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "nsg")
        assert objs[0].get("label") == "NSG"

    def test_nsg_singular_one_rule(self):
        subnet = _make_subnet(
            nsg="Yes", nsg_name="nsg", nsg_rules=[_make_rule()],
        )
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "nsg")
        assert objs[0].get("label") == "NSG (1 rule)"

    def test_nsg_plural_two_rules(self):
        subnet = _make_subnet(
            nsg="Yes", nsg_name="nsg",
            nsg_rules=[_make_rule("R1"), _make_rule("R2")],
        )
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "nsg")
        assert objs[0].get("label") == "NSG (2 rules)"

    def test_nsg_object_wraps_mxcell_with_image_style(self):
        """NSG icon must use object->mxCell; the mxCell must have shape=image."""
        subnet = _make_subnet(nsg="Yes", nsg_name="nsg", nsg_rules=[_make_rule()])
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "nsg")
        cell = objs[0].find("mxCell")
        assert cell is not None, "mxCell child not found inside NSG object"
        assert "shape=image" in cell.get("style", "")


# ---------------------------------------------------------------------------
# XML output — UDR icon label & structure
# ---------------------------------------------------------------------------

class TestUdrIconXmlOutput:
    """Test that the UDR icon <object> element has correct label and tooltip."""

    def test_udr_with_routes_produces_object_with_count_label(self):
        subnet = _make_subnet(
            udr="Yes", udr_name="my-rt",
            routes=[_make_route("r1"), _make_route("r2")],
        )
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "udr")
        assert len(objs) == 1
        assert objs[0].get("label") == "UDR (2 routes)"

    def test_udr_tooltip_contains_route_details(self):
        subnet = _make_subnet(
            udr="Yes", udr_name="my-rt",
            routes=[_make_route("default", "0.0.0.0/0", "VirtualAppliance", "10.0.0.4")],
        )
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "udr")
        tooltip = objs[0].get("tooltip")
        assert "UDR: my-rt" in tooltip
        assert "0.0.0.0/0" in tooltip
        assert "VirtualAppliance (10.0.0.4)" in tooltip

    def test_udr_with_zero_routes_but_name_shows_zero_count(self):
        """A route table with 0 routes but a name shows '(0 routes)'."""
        subnet = _make_subnet(udr="Yes", udr_name="empty-rt", routes=[])
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "udr")
        assert objs[0].get("label") == "UDR (0 routes)"

    def test_udr_without_name_falls_back_to_plain_label(self):
        subnet = _make_subnet(udr="Yes", udr_name="", routes=[])
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "udr")
        assert objs[0].get("label") == "UDR"

    def test_udr_singular_one_route(self):
        subnet = _make_subnet(
            udr="Yes", udr_name="rt", routes=[_make_route()],
        )
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "udr")
        assert objs[0].get("label") == "UDR (1 route)"

    def test_udr_plural_two_routes(self):
        subnet = _make_subnet(
            udr="Yes", udr_name="rt",
            routes=[_make_route("r1"), _make_route("r2")],
        )
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "udr")
        assert objs[0].get("label") == "UDR (2 routes)"

    def test_udr_object_wraps_mxcell_with_image_style(self):
        subnet = _make_subnet(udr="Yes", udr_name="rt", routes=[_make_route()])
        root = _render_vnet([subnet])
        objs = _find_icon_objects(root, "udr")
        cell = objs[0].find("mxCell")
        assert cell is not None, "mxCell child not found inside UDR object"
        assert "shape=image" in cell.get("style", "")
