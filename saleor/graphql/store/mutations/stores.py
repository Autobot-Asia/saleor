from collections import defaultdict
from datetime import date

import graphene
from django.core.exceptions import ValidationError
from django.db import transaction

from ....attribute import AttributeType
from ....store import models
from ...attribute.utils import AttributeAssignmentMixin
from ...core.mutations import ModelDeleteMutation, ModelMutation
from ...core.types.common import PageError, SeoInput
from ...core.utils import clean_seo_fields, validate_slug_and_generate_if_needed
from ...core.types import SeoInput, Upload
from ...utils.validators import check_for_duplicates
from ....store.error_codes import StoreErrorCode
from ....core.permissions import StorePermissions
from ....store.models import StoreType
from ....core.exceptions import PermissionDenied
from ....store.utils import delete_stores

from ....product.thumbnails import (
    create_store_background_image_thumbnails,
)

from ...core.utils import (
    clean_seo_fields,
    from_global_id_strict_type,
    get_duplicated_values,
    validate_image_file,    
)


class StoreInput(graphene.InputObjectType):
    name = graphene.String(description="Store name.")
    description = graphene.String(description="Store full description.")
    phone = graphene.String(description="Phone number.")
    acreage = graphene.Float( description="Store acreage")
    latlong = graphene.String( description="latlong has format lat,long")

    seo = SeoInput(description="Search engine optimization fields.")
    background_image = Upload(description="Background image file.")
    background_image_alt = graphene.String(description="Alt text for a stores media.")


class StoreCreate(ModelMutation):
    class Arguments:
        input = StoreInput(
            required=True, description="Fields required to create a store."
        )
        store_type_id = graphene.ID(
            description=(
                    "ID of the store type. Default is FARM type"
            ),
            name="store_type",
        )

    class Meta:
        description = "Creates a new store."
        model = models.Store
        permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreErrorCode
        error_type_field = "store_errors"

    @classmethod
    def clean_input(cls, info, instance, data):
        cleaned_input = super().clean_input(info, instance, data)        
        store_type_id = data["store_type_id"]
        if store_type_id:
            store_type = cls.get_node_or_error(
                info, store_type_id, field="store_type", only_type=StoreType
            )
            cleaned_input["store_type"] = store_type
        if data.get("background_image"):
            image_data = info.context.FILES.get(data["background_image"])
            validate_image_file(image_data, "background_image")
        clean_seo_fields(cleaned_input)
        return cleaned_input

    @classmethod
    def perform_mutation(cls, root, info, **data):
        store_type_id = data.pop("store_type_id", None)
        data["input"]["store_type_id"] = store_type_id
        return super().perform_mutation(root, info, **data)

    @classmethod
    def save(cls, info, instance, cleaned_input):
        instance.save()
        if cleaned_input.get("background_image"):
            create_store_background_image_thumbnails.delay(instance.pk)


class StoreUpdate(StoreCreate):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a store to update.")
        input = StoreInput(
            required=True, description="Fields required to update a store."
        )

    class Meta:
        description = "Updates a store."
        model = models.Store
        permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreErrorCode
        error_type_field = "store_errors"


class StoreDelete(ModelDeleteMutation):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a store to delete.")

    class Meta:
        description = "Deletes a store."
        model = models.Store
        permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreErrorCode
        error_type_field = "store_errors"

    @classmethod
    def perform_mutation(cls, _root, info, **data):
        if not cls.check_permissions(info.context):
            raise PermissionDenied()
        node_id = data.get("id")
        instance = cls.get_node_or_error(info, node_id, only_type=models.Store)

        db_id = instance.id
        delete_stores([db_id])
        instance.id = db_id
        return cls.success_response(instance)
