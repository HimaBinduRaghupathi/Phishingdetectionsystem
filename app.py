# Vercel deployment entrypoint
from backend.app import app

# Export the Flask WSGI app directly.
# Vercel Python builder will use the `app` variable as the entrypoint.
