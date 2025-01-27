from ..celeryconf import app
from ..core.utils import create_thumbnails
from .models import Category, Collection, ProductMedia, Store


@app.task
def create_product_thumbnails(image_id: str):
    """Take a ProductMedia model and create thumbnails for it."""
    create_thumbnails(pk=image_id, model=ProductMedia, size_set="products")


@app.task
def create_category_background_image_thumbnails(category_id: str):
    """Take a Product model and create the background image thumbnails for it."""
    create_thumbnails(
        pk=category_id,
        model=Category,
        size_set="background_images",
        image_attr="background_image",
    )


@app.task
def create_collection_background_image_thumbnails(collection_id: str):
    """Take a Collection model and create the background image thumbnails for it."""
    create_thumbnails(
        pk=collection_id,
        model=Collection,
        size_set="background_images",
        image_attr="background_image",
    )

@app.task
def create_store_background_image_thumbnails(store_id: str):
    """Take a Product model and create the background image thumbnails for it."""
    create_thumbnails(
        pk=store_id,
        model=Store,
        size_set="background_images",
        image_attr="background_image",
    )