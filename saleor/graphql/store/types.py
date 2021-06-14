import graphene

from ...store import models
from ..core.connection import CountableDjangoObjectType
from ..meta.types import ObjectWithMetadata
from ..core.types import Image

class StoreType(CountableDjangoObjectType):
    name = graphene.String(
        description="The store name.",
        required=True,
    )
    description = graphene.String(
        description="The store description.",
        required=True,
    )

    class Meta:
        description = (
            "Represents a type of page. It defines what attributes are available to "
            "pages of this type."
        )
        interfaces = [graphene.relay.Node, ObjectWithMetadata]
        model = models.StoreType
        only_fields = ["id", "name"]


class Store(CountableDjangoObjectType):
    name = graphene.String(
        description="The store name.",
        required=True,
    )
    description = graphene.String(
        description="The store description.",
    )
    phone = graphene.String(
        description="The store phone.",
    )
    acreage = graphene.Float(
        description="The store acreage.",
    )
    latlong = graphene.String(
        description="The store latlong.",
    )
    url = graphene.String(
        description="The store's URL.",
    )
    store_type = graphene.Field(
        StoreType,
        id=graphene.Argument(graphene.ID, description="ID of the store type."),
        description="Look up a store type by ID",
    )
    logo = graphene.Field(Image, size=graphene.Int(description="Size of the avatar."))
    background_image = graphene.Field(Image, size=graphene.Int(description="Size of the avatar."))
    user_name = graphene.String(
        description="Owner of store",
    )

    class Meta:
        description = (
            "A static page that can be manually added by a shop operator through the "
            "dashboard."
        )
        only_fields = [
            "name",
            "description",
            "store_type",
            "date_joined",
            "latlong",
            "acreage",
            "url",
            "phone",
            "city",
            "city_area",
            "company_name",
            "country",
            "country_area",
            "id",
            "postal_code",
            "street_address_1",
            "street_address_2",
        ]
        interfaces = [graphene.relay.Node, ObjectWithMetadata]
        model = models.Store
    
    @staticmethod
    def resolve_logo(root: models.Store, info, size=None, **_kwargs):
        if root.logo:
            return Image.get_adjusted(
                image=root.logo,
                alt=None,
                size=size,
                rendition_key_set="store_logo",
                info=info,
            )
    
    @staticmethod
    def resolve_background_image(root: models.Store, info, size=None, **_kwargs):
        if root.background_image:
            return Image.get_adjusted(
                image=root.logo,
                alt=None,
                size=size,
                rendition_key_set="store_background_image",
                info=info,
            )