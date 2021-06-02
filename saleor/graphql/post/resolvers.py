import graphene

from ...post import models
from ..core.validators import validate_one_of_args_is_in_query
from .types import Post


def resolve_post(info, global_page_id=None, slug=None):
    validate_one_of_args_is_in_query("id", global_page_id, "slug", slug)
    user = info.context.user
    _type, post_pk = graphene.Node.from_global_id(global_page_id)
    post = models.Post.objects.get(pk=post_pk)
    return post


def resolve_posts(info, **_kwargs):
    return models.Post.objects.all()
