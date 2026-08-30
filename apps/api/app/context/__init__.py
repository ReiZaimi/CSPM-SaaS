"""Asset context: what an asset is worth, and who says so.

Severity is a property of a finding. Context is a property of the *asset* --
how critical it is to the business, how sensitive the data it holds, which
environment it belongs to -- and the risk engine multiplies the two. The same
open management port is a different risk on a dev box than on a production
jump host, and everything that makes that sentence true lives here.

It used to live in the Azure normalizer, three helper functions deep inside the
module that turns ARM JSON into resources. Two problems with that, and only the
second is about tidiness:

* **A second provider would have written its own copy.** Tag vocabularies, the
  production/development word lists, the rule that a database holds data by
  definition -- none of it is Azure-specific, and all of it would have been
  reimplemented slightly differently under `connectors/aws/`.
* **The customer could not overrule it.** Inference from tags is a guess, and
  the customer knows the answer. There was nowhere to put the answer, because
  normalization is a pure function of a capture and a declaration is not in the
  capture.

So inference and declaration are separated. :func:`infer` is pure and stays in
the normalizer's path; :func:`resolve` applies what the customer has declared,
in the pipeline, where the database is. Every value carries the
:class:`~app.core.enums.ContextSource` it came from, which is what makes "why is
this HIGH" answerable at all.
"""

from app.context.engine import (
    AssetContext,
    ContextDeclaration,
    infer,
    resolve,
    resolve_resource,
)

__all__ = [
    "AssetContext",
    "ContextDeclaration",
    "infer",
    "resolve",
    "resolve_resource",
]
