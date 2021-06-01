from templated_email import send_templated_mail
from ..celeryconf import app
from ..core.emails import get_email_context
from ..plugins.manager import get_plugins_manager


def collect_data_for_send_message(data, product, template):
    """Collect the required data for sending emails."""
    send_kwargs, email_context = get_email_context()
    print('send_kwargs', send_kwargs)

    email_context["requestor"] = data["requestor"]
    email_context["name"] = product.name
    email_context["quantity"] = data["quantity"]
    email_context["message"] = data["message"]
    return {
        "recipient_list": [data["recipent"]],
        "template_name": template,
        "context": email_context,
        **send_kwargs,
    }


@app.task
def product_send_message(data, product):
    email_data = collect_data_for_send_message(data, product, "product/product_send_message")
    send_templated_mail(**email_data)
