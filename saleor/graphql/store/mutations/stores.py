from collections import defaultdict
from datetime import date

from pkg_resources import require
from saleor.checkout import AddressType
from saleor.account.models import Address, User

import graphene
from django.core.exceptions import ValidationError
from django.db import transaction
from django.conf import settings
from ....attribute import AttributeType
from ....store import models, error_codes
from ...attribute.utils import AttributeAssignmentMixin
from ...core.mutations import ModelDeleteMutation, ModelMutation
from ...core.types.common import StoreError
from ...core.utils import clean_seo_fields, validate_slug_and_generate_if_needed
from ...core.types import SeoInput, Upload
from ...utils.validators import check_for_duplicates
from ....core.permissions import StorePermissions
from ....core.exceptions import PermissionDenied
from ....store.utils import delete_stores, delete_stores_types
from ..types import Store, StoreType
from ...account.enums import CountryCodeEnum
from ....core.utils.url import validate_storefront_url
from ....product.thumbnails import (
    create_store_background_image_thumbnails,
)
from ....account.error_codes import AccountErrorCode
from ...core.utils import (
    clean_seo_fields,
    from_global_id_strict_type,
    get_duplicated_values,
    validate_image_file,
)
from django.contrib.auth import password_validation
from ....plugins.manager import get_plugins_manager
from ....account.utils import store_user_address
from ....core.permissions import get_permissions_default
from django.contrib.auth.models import Group

class StoreInput(graphene.InputObjectType):
    name = graphene.String(description="Store name.", required=True)
    first_name = graphene.String(description="Given name.", required=True)
    last_name = graphene.String(description="Family name.", required=True)
    email = graphene.String(description="The email address of the user.", required=True)
    password = graphene.String(description="Password.", required=True)
    description = graphene.JSONString(description="Store full description (JSON).")
    phone = graphene.String(description="Phone number.")
    acreage = graphene.Float( description="Store acreage")
    latlong = graphene.String( description="latlong has format lat,long")
    seo = SeoInput(description="Search engine optimization fields.")
    background_image = Upload(description="Background image file.")
    background_image_alt = graphene.String(description="Alt text for a stores media.")
    company_name = graphene.String(description="Company or organization.")
    street_address_1 = graphene.String(description="Address.")
    street_address_2 = graphene.String(description="Address.")
    city = graphene.String(description="City.")
    city_area = graphene.String(description="District.")
    postal_code = graphene.String(description="Postal code.")
    country = CountryCodeEnum(description="Country.")
    country_area = graphene.String(description="State or province.")

class StoreCreateInput(StoreInput):
    store_type = graphene.ID(
        description="ID of the store type that store belongs to.", required=True
    )


class StoreCreate(ModelMutation):
    class Arguments:
        input = StoreCreateInput(
            required=True, description="Fields required to create a store."
        )

    class Meta:
        description = "Creates a new store."
        model = models.Store
        #permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreError
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

        # Validate store name
        store_name = cleaned_input["name"]
        find_store = models.Store.objects.filter(name=store_name).first()
        if find_store:
            raise ValidationError({
                "name": ValidationError(
                    "Store Name already exists", code=error_codes.StoreErrorCode.ALREADY_EXISTS
                )
            })

        # Validate for create user
        if not settings.ENABLE_ACCOUNT_CONFIRMATION_BY_EMAIL:
            return cleaned_input
        elif not data.get("redirect_url"):
            raise ValidationError(
                {
                    "redirect_url": ValidationError(
                        "This field is required.", code=AccountErrorCode.REQUIRED
                    )
                }
            )

        try:
            validate_storefront_url(data["redirect_url"])
        except ValidationError as error:
            raise ValidationError(
                {
                    "redirect_url": ValidationError(
                        error.message, code=AccountErrorCode.INVALID
                    )
                }
            )

        password = data["password"]
        try:
            password_validation.validate_password(password, instance)
        except ValidationError as error:
            raise ValidationError({"password": error})
        
        return cleaned_input

    def create_group_data(name, permissions, users):
        group, _ = Group.objects.get_or_create(name=name)
        group.permissions.add(*permissions)
        group.user_set.add(*users)
        return group

    @classmethod
    def perform_mutation(cls, root, info, **data):
        store_type_id = data.pop("store_type_id", None)
        data["input"]["store_type_id"] = store_type_id
        retval = super().perform_mutation(root, info, **data)
        # user = info.context.user
        # if not user.is_superuser:
        #     user.store_id = retval.store.id
        # if user.is_authenticated:
        #     user.save()
        user = User()
        user.is_supplier = True
        user.store_id = retval.store.id
        user.email = data["input"]["email"]
        user.first_name = data["input"]["first_name"]
        user.last_name = data["input"]["last_name"]
        password = data["input"]["password"]
        user.set_password(password)
        user.save()

        permissions = get_permissions_default()
        for permission in permissions:
            base_name = permission.codename.split("_")[1:]
            group_name = " ".join(base_name)
            group_name += " management"
            group_name = group_name.capitalize()
            cls.create_group_data(group_name, [permission], [user])

        address = Address(
            first_name = data["input"]["first_name"],
            last_name = data["input"]["last_name"],
        )
        address.save()
        manager = get_plugins_manager()
        store_user_address(user, address, AddressType.BILLING, manager)
        store_user_address(user, address, AddressType.SHIPPING, manager)
            
        return retval

    @classmethod
    def save(cls, info, instance, cleaned_input):
        instance.save()
        if cleaned_input.get("background_image"):
            create_store_background_image_thumbnails.delay(instance.pk)

class StoreUpdateInput(graphene.InputObjectType):
    store_type = graphene.ID(
        description="ID of the store type that store belongs to.", required=True
    )
    name = graphene.String(description="Store name.", required=True)
    user_id = graphene.ID(
        description="ID of the store type that store belongs to."
    )
    first_name = graphene.String(description="Given name.")
    last_name = graphene.String(description="Family name.")
    description = graphene.JSONString(description="Store full description (JSON).")
    phone = graphene.String(description="Phone number.")
    acreage = graphene.Float( description="Store acreage")
    latlong = graphene.String( description="latlong has format lat,long")
    seo = SeoInput(description="Search engine optimization fields.")
    background_image = Upload(description="Background image file.")
    background_image_alt = graphene.String(description="Alt text for a stores media.")
    company_name = graphene.String(description="Company or organization.")
    street_address_1 = graphene.String(description="Address.")
    street_address_2 = graphene.String(description="Address.")
    city = graphene.String(description="City.")
    city_area = graphene.String(description="District.")
    postal_code = graphene.String(description="Postal code.")
    country = CountryCodeEnum(description="Country.")
    country_area = graphene.String(description="State or province.")
class StoreUpdate(ModelMutation):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a store to update.")
        input = StoreUpdateInput(
            required=True, description="Fields required to update a store."
        )

    class Meta:
        description = "Updates a store."
        model = models.Store
        permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreError
        error_type_field = "store_errors"

    @classmethod
    def clean_input(cls, info, instance, data):
        cleaned_input = super().clean_input(info, instance, data)

        # Validate store name
        store_name = cleaned_input["name"]
        find_store = models.Store.objects.filter(name=store_name).first()
        if find_store:
            raise ValidationError({
                "name": ValidationError(
                    "Store Name already exists", code=error_codes.StoreErrorCode.ALREADY_EXISTS
                )
            })

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
        retval = super().perform_mutation(root, info, **data)

        if("user_id" in data["input"] and "first_name" in data["input"] and "last_name" in data["input"]):
            pk = from_global_id_strict_type(data["input"]["user_id"], only_type="User")
            user = User.objects.get(pk=pk)
            user.first_name = data["input"]["first_name"]
            user.last_name = data["input"]["last_name"]
            user.save()
        return retval

    @classmethod
    def save(cls, info, instance, cleaned_input):
        instance.save()
        if cleaned_input.get("background_image"):
            create_store_background_image_thumbnails.delay(instance.pk)


class StoreDelete(ModelDeleteMutation):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a store to delete.")

    class Meta:
        description = "Deletes a store."
        model = models.Store
        permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreError
        error_type_field = "store_errors"

    @classmethod
    def perform_mutation(cls, _root, info, **data):
        if not cls.check_permissions(info.context):
            raise PermissionDenied()
        node_id = data.get("id")
        instance = cls.get_node_or_error(info, node_id, only_type=Store)

        db_id = instance.id
        delete_stores([db_id])
        instance.id = db_id
        return cls.success_response(instance)


class StoreTypeInput(graphene.InputObjectType):
    name = graphene.String(description="Store type name.")
    description = graphene.JSONString(description="Store type full description (JSON).")
    #seo = SeoInput(description="Search engine optimization fields.")

class StoreTypeCreate(ModelMutation):
    class Arguments:
        input = StoreTypeInput(
            required=True, description="Fields required to create a store type."
        )

    class Meta:
        description = "Creates a new store type."
        model = models.StoreType
        permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreError
        error_type_field = "store_errors"

    @classmethod
    def clean_input(cls, info, instance, data):
        cleaned_input = super().clean_input(info, instance, data)
        #store_type_id = data["store_type_id"]
        
        return cleaned_input

    @classmethod
    def perform_mutation(cls, root, info, **data):
        #parent_id = data.pop("parent_id", None)
        #data["input"]["parent_id"] = parent_id
        return super().perform_mutation(root, info, **data)

    @classmethod
    def save(cls, info, instance, cleaned_input):
        instance.save()

class StoreTypeUpdate(StoreTypeCreate):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a store to update.")
        input = StoreTypeInput(
            required=True, description="Fields required to update a store type."
        )

    class Meta:
        description = "Updates a store type."
        model = models.StoreType
        permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreError
        error_type_field = "store_errors"


class StoreTypeDelete(ModelDeleteMutation):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a store to delete.")

    class Meta:
        description = "Deletes a store type."
        model = models.StoreType
        permissions = (StorePermissions.MANAGE_STORES,)
        error_type_class = StoreError
        error_type_field = "store_errors"

    @classmethod
    def perform_mutation(cls, _root, info, **data):
        if not cls.check_permissions(info.context):
            raise PermissionDenied()
        node_id = data.get("id")
        instance = cls.get_node_or_error(info, node_id, only_type=Store)

        db_id = instance.id
        delete_stores_types([db_id])
        instance.id = db_id
        return cls.success_response(instance)

class StoreMediaInput(graphene.InputObjectType):
    logo = Upload(description="Background image file.")
    logo_alt = graphene.String(description="Alt text for a stores media.")
    background_image = Upload(description="Background image file.")
    background_image_alt = graphene.String(description="Alt text for a stores media.")

class StoreMediaUpdate(ModelMutation):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a store to update.")
        input = StoreMediaInput(
            required=True, description="Fields required to update a store type."
        )

    class Meta:
        description = "Updates a store type."
        model = models.Store
        error_type_class = StoreError
        error_type_field = "store_errors"
