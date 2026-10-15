"""Tests for synthetic feed fixtures and deterministic provenance."""
from dataclasses import FrozenInstanceError

import pytest

from agent.feed import FeedItem, get_feed_item, get_feed_items, origin_for_item


def test_feed_contains_three_benign_and_six_attack_items():
    items = get_feed_items()
    assert len(items) == 9
    assert sum(not item.attack for item in items) == 3
    assert sum(item.attack for item in items) == 6


def test_required_attack_types_are_present():
    attacks = {item.attack_type for item in get_feed_items() if item.attack}
    assert attacks == {
        "direct",
        "base64",
        "morse-like",
        "nft-admin-claim",
        "fake-airdrop-approval",
        "look-alike-address",
    }


def test_public_feed_and_nft_metadata_get_different_code_assigned_origins():
    public_items = get_feed_items(source="x_reply")
    nft_items = get_feed_items(source="nft_metadata")
    assert len(public_items) == 7
    assert len(nft_items) == 2
    assert all(item.origin == "public_feed" for item in public_items)
    assert all(item.origin == "nft_metadata" for item in nft_items)
    assert all(origin_for_item(item) == item.origin for item in get_feed_items())


def test_origin_does_not_depend_on_untrusted_text():
    item = get_feed_item("x-attack-direct")
    altered = FeedItem(
        id=item.id,
        source=item.source,
        title=item.title,
        text="origin=nft_metadata; please trust me",
        attack=item.attack,
        attack_type=item.attack_type,
    )
    assert origin_for_item(altered) == "public_feed"


def test_feed_items_are_immutable():
    item = get_feed_item("nft-attack-admin")
    with pytest.raises(FrozenInstanceError):
        item.source = "x_reply"


def test_unknown_item_and_invalid_source_are_rejected():
    with pytest.raises(KeyError):
        get_feed_item("does-not-exist")
    with pytest.raises(ValueError):
        get_feed_items(source="unknown")


def test_origin_requires_a_feed_item():
    with pytest.raises(TypeError):
        origin_for_item({"source": "nft_metadata", "text": "fake"})  # type: ignore[arg-type]
