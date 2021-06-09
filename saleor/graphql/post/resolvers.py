import graphene

from ...post import models
from ...social import models as social_models
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

def resolve_posts_by_follows(info, **_kwargs):
    user = info.context.user
    posts = []
    if user and hasattr(user, 'id') and user.id:
        user_id = user.id
        stores = social_models.Social.objects.filter(user_id=user_id).values('store_id')
        store_ids = []
        for store in stores:
            store_ids.append(store['store_id'])
        posts = models.Post.objects.filter(store_id__in=store_ids)
    else:
        posts = models.Post.objects.all()

    return posts

def resolve_posts_by_store(info, store_id=None, **_kwargs):
    _type, store_pk = graphene.Node.from_global_id(store_id)
    posts = []
    if store_pk:
        posts = models.Post.objects.filter(store_id=store_pk)
    else:
        posts = models.Post.objects.all()

    return posts
