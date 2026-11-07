import subprocess
import sys
from pathlib import Path


def test_history_survives_loader_and_is_removed_at_exit():
    fixture = Path(__file__).resolve().parents[1] / 'core/user-service/tests/historical_db_fixture.py'
    probe = """
import gc, importlib.util, runpy, sys, types
from pathlib import Path

package = types.ModuleType('controlplane_db')
package.__path__ = []
sys.modules[package.__name__] = package
runpy.run_path(sys.argv[1])
gc.collect()
assert importlib.util.find_spec('controlplane_db.migrations') is not None
print(Path(package.__path__[-1]).parents[1])
"""
    directory = subprocess.check_output([sys.executable, '-c', probe, str(fixture)], text=True)
    assert not Path(directory.strip()).exists()
