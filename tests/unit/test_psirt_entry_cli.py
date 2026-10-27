"""Safe, actionable CLI errors without disclosing arbitrary exception strings."""
import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
spec = importlib.util.spec_from_file_location('entry_cli', ROOT/'scripts/run_psirt_casework.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class EntryCLITests(unittest.TestCase):
    def invoke(self, error):
        output = io.StringIO()
        with patch.object(sys,'argv',['run_psirt_casework.py','start']), \
                patch.object(cli,'start',side_effect=error), contextlib.redirect_stdout(output):
            code = cli.main()
        return code, json.loads(output.getvalue())

    def test_stale_service_has_specific_non_secret_recovery_message(self):
        code, result = self.invoke(cli.ServiceVersionMismatch())
        self.assertEqual(code,2)
        self.assertEqual(result['error_code'],'ServiceVersionMismatch')
        self.assertIn('停止舊工作台服務',result['message'])
        self.assertFalse(result['completed'])

    def test_unexpected_exception_details_are_not_disclosed(self):
        code, result = self.invoke(ValueError('private exception marker'))
        self.assertEqual(code,2)
        self.assertEqual(result['error_type'],'ValueError')
        self.assertNotIn('private exception marker',json.dumps(result))
        self.assertNotIn('message',result)


if __name__ == '__main__':
    unittest.main()
