"""Allow ``python -m ccs_pydantic_ai`` to invoke the CLI."""
import sys

from .cli import main

sys.exit(main())
