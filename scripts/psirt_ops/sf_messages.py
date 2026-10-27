"""Pure EmailMessage coverage rules, independent of Case index success."""


def email_items(source):
    """Keep observable identified rows with their original evidence offsets."""
    messages = source.get('emails')
    if not isinstance(messages, list):
        return []
    return [(index, row) for index, row in enumerate(messages)
            if isinstance(row, dict) and isinstance(row.get('Id'), str) and row['Id'].strip()]


def email_coverage(source):
    messages = source.get('emails')
    items = email_items(source)
    if 'emails' not in source:
        reason = 'EMAILS_NOT_PROVIDED'
    elif not isinstance(messages, list):
        reason = 'INVALID_EMAILS_COLLECTION'
    elif len(items) != len(messages):
        reason = 'INVALID_EMAIL_ROW'
    elif len({row['Id'] for _, row in items}) != len(items):
        reason = 'DUPLICATE_EMAIL_ID'
    elif source.get('status') != 'SUCCESS' or source.get('complete') is not True:
        reason = 'SOURCE_INCOMPLETE'
    else:
        reason = None
    complete = reason is None
    coverage = ('COMPLETE_IN_CONFIGURED_WINDOW' if complete else
                'PARTIAL' if source.get('status') == 'PARTIAL' or
                reason in ('INVALID_EMAIL_ROW', 'DUPLICATE_EMAIL_ID') else 'UNKNOWN')
    return {'complete': complete, 'coverage': coverage, 'reason': reason,
            'observed_count': len(items), 'count': len(items) if complete else None}
