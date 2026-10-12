import ast
import unittest
import tempfile
import types
from pathlib import Path


SOURCE = Path(__file__).with_name("agent.py")


class CursorRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_main_preserves_previous_cursor(self):
        self.assertIn(
            "newest_seq = max(int(previous_seq), newest_seq)",
            self.source,
        )

    def test_watch_preserves_previous_cursor(self):
        self.assertIn(
            "newest_seq = max(int(last_seq), newest_seq)",
            self.source,
        )

    def test_watch_rejects_messages_without_sequence(self):
        self.assertIn(
            "Messages reçus sans séquence exploitable",
            self.source,
        )

    def test_watch_restores_state_when_save_fails(self):
        self.assertIn(
            "state[room] = previous_room_state",
            self.source,
        )
        self.assertIn(
            "save_state(state)",
            self.source,
        )

    def test_source_is_valid_python(self):
        self.assertIsInstance(self.tree, ast.Module)

    def test_failed_save_restores_previous_state(self):
        def update_with_save(state, room, new_seq, save):
            previous = state.get(room)
            previous = previous.copy() if previous is not None else None

            state[room] = {"last_seq": new_seq}

            try:
                save(state)
            except Exception:
                if previous is None:
                    state.pop(room, None)
                else:
                    state[room] = previous
                raise

        state = {"room-a": {"last_seq": 100}}

        def failing_save(_state):
            raise OSError("Erreur de sauvegarde simulée")

        with self.assertRaisesRegex(OSError, "simulée"):
            update_with_save(state, "room-a", 120, failing_save)

        self.assertEqual(state["room-a"], {"last_seq": 100})

    def test_failed_save_removes_new_room(self):
        def update_with_save(state, room, new_seq, save):
            previous = state.get(room)
            previous = previous.copy() if previous is not None else None

            state[room] = {"last_seq": new_seq}

            try:
                save(state)
            except Exception:
                if previous is None:
                    state.pop(room, None)
                else:
                    state[room] = previous
                raise

        state = {}

        def failing_save(_state):
            raise OSError("Erreur de sauvegarde simulée")

        with self.assertRaises(OSError):
            update_with_save(state, "room-new", 10, failing_save)

        self.assertNotIn("room-new", state)
    def test_real_save_state_writes_json_to_temp_file(self):
        save_node = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "save_state"
        )

        module = ast.Module(body=[save_node], type_ignores=[])
        ast.fix_missing_locations(module)

        namespace = {
            "Path": Path,
            "json": __import__("json"),
        }
        exec(compile(module, str(SOURCE), "exec"), namespace)

        with tempfile.TemporaryDirectory() as temp_dir:
            state_file = Path(temp_dir) / "state.json"
            namespace["STATE_FILE"] = state_file

            expected = {"room-a": {"last_seq": 120}}
            namespace["save_state"](expected)

            self.assertTrue(state_file.exists())
            self.assertEqual(
                __import__("json").loads(
                    state_file.read_text(encoding="utf-8")
                ),
                expected,
            )
            self.assertFalse(
                state_file.with_name("state.json.tmp").exists()
            )

    def test_real_save_state_preserves_old_file_if_replace_fails(self):
        save_node = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "save_state"
        )

        module = ast.Module(body=[save_node], type_ignores=[])
        ast.fix_missing_locations(module)

        namespace = {
            "Path": Path,
            "json": __import__("json"),
        }
        exec(compile(module, str(SOURCE), "exec"), namespace)

        with tempfile.TemporaryDirectory() as temp_dir:
            state_file = Path(temp_dir) / "state.json"
            state_file.write_text(
                '{"room-a": {"last_seq": 100}}',
                encoding="utf-8",
            )
            namespace["STATE_FILE"] = state_file

            original_replace = Path.replace

            def failing_replace(path, target):
                raise OSError("Échec de remplacement simulé")

            Path.replace = failing_replace
            try:
                with self.assertRaisesRegex(OSError, "simulé"):
                    namespace["save_state"](
                        {"room-a": {"last_seq": 120}}
                    )
            finally:
                Path.replace = original_replace

            self.assertEqual(
                __import__("json").loads(
                    state_file.read_text(encoding="utf-8")
                ),
                {"room-a": {"last_seq": 100}},
            )
if __name__ == "__main__":
    unittest.main(verbosity=2)