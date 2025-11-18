import re
from typing import Optional


def generate_slug(text: str) -> str:
    """Generate a URL-friendly slug from text"""
    slug = text.lower()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    return slug


def validate_slug(slug: str) -> bool:
    """Validate that a slug only contains allowed characters"""
    return bool(re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', slug))