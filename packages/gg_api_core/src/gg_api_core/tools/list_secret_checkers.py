"""DEFERRED — list of detectors whose validity can be checked.

# TODO(HIL): Implement alongside ``check_secret_validity`` (see neighbouring
# stub).
#
# Plan reference: docs/HIL_PLAN.md §A.3.
#
# This tool is described as a thin filter over ``list_detectors`` keeping only
# those with a checker. The current ``list_detectors`` response is opaque on
# checker support — there is no documented ``checker_supported`` field on the
# ``/v1/secret_detectors`` payload that we surface today. Without that field
# (or a dedicated endpoint), the filtering rule is undefined.
#
# When implementing:
#   * Confirm the field name returned by ``/v1/secret_detectors`` that flags
#     checker support (or the dedicated endpoint, if any).
#   * Build on top of the existing ``list_detectors`` tool / client method
#     rather than duplicating pagination.
#   * Required scope: ``["scan"]``.
#
# Not registered on any server until the above is done.
"""
