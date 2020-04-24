from validate_email import validate_email


def if_valid_add(email):
    is_valid = validate_email(email, verify=True)
    if is_valid is True:
        return 'OK'
    else:
        return 'NO'
