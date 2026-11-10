"""Allow ``python -m check_secrets`` after installation."""

from .scanner import main

raise SystemExit(main())
