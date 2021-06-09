import graphene

from ....core.permissions import PostPermissions
from ....post import models
from ...core.mutations import ModelBulkDeleteMutation
from ...core.types.common import PostError

class PostMediaBulkDelete(ModelBulkDeleteMutation):
    class Arguments:
        ids = graphene.List(
            graphene.ID, required=True, description="List of postMedia IDs to delete."
        )

    class Meta:
        description = "Deletes post media."
        model = models.PostMedia
        permissions = (PostPermissions.MANAGE_POSTS,)
        error_type_class = PostError
        error_type_field = "menu_errors"
