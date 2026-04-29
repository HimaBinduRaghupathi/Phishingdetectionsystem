# Vercel deployment entrypoint
from backend.app import app as backend_app

# Expose the Flask app as 'app' for Vercel
app = backend_app

# Vercel requires a handler for serverless functions
def handler(request):
    return backend_app(request)
