import os
import sys
import threading
import socket
import time
import uvicorn

# Ensure project root and src/ are in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src/cyberstartup"))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Cyber Startup Static Test Server")
app.mount("/", StaticFiles(directory=os.path.join(PROJECT_ROOT, "docs"), html=True), name="static")

class BackgroundServer:
    """
    Wraps the FastAPI uvicorn production server to run in a background thread for tests,
    specifically patched to serve the docs/ directory statically for E2E tests.
    """
    def __init__(self, port=0):
        # Resolve dynamic/free port if port=0
        if port == 0:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('localhost', 0))
            self.port = s.getsockname()[1]
            s.close()
        else:
            self.port = port

        # Configure uvicorn runner for the FastAPI app
        config = uvicorn.Config(
            app=app,
            host="localhost",
            port=self.port,
            log_level="warning",
            loop="asyncio"
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self._run_server)
        self.thread.daemon = True

    def _run_server(self):
        try:
            self.server.run()
        except Exception as e:
            import traceback
            traceback.print_exc(file=sys.stderr)
            raise e

    def start(self):
        """Starts the background uvicorn server thread and blocks until it is online."""
        self.thread.start()
        # Wait for the uvicorn server to start serving requests
        timeout = 90.0
        start_time = time.time()
        while not self.server.started:
            if not self.thread.is_alive():
                raise RuntimeError("Uvicorn server thread died before starting.")
            if time.time() - start_time > timeout:
                raise RuntimeError("Uvicorn test server failed to start within timeout.")
            time.sleep(0.05)

    def stop(self):
        """Shuts down the background server and terminates the thread."""
        self.server.should_exit = True
        self.thread.join(timeout=3.0)
