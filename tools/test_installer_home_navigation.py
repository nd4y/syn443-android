import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import installer_cancel_ui as ui


class InstallerHomeNavigationTest(unittest.TestCase):
    def test_resumed_below_the_update_entry_returns_to_top_then_searches_down(self):
        pages = ["Secure Your Network", "Обновление приложения", "Чат с администратором", "Маршруты"]
        position = 3
        directions = []
        def visible():
            root = ET.Element("hierarchy")
            row = ET.SubElement(root, "node", package=ui.PACKAGE, scrollable="true", bounds="[0,20][400,620]")
            # The target may be absent while the previous frame is recycled.
            label = pages[position]
            if label == pages[1] and all(d > 0 for d in directions):
                label = "Вход"
            ET.SubElement(row, "node", package=ui.PACKAGE, enabled="true", text=label, bounds="[0,20][100,60]")
            return root
        def swipe(*args):
            nonlocal position
            direction = int(args[6]) - int(args[4])
            directions.append(direction)
            position = max(0, min(3, position - (1 if direction > 0 else -1)))
        with patch.object(ui, "tree", side_effect=visible), patch.object(ui, "adb", side_effect=swipe), patch.object(ui.time, "sleep"):
            self.assertEqual(ui.home_update_control().get("text"), pages[1])
        self.assertEqual(len(directions), 4)
        self.assertGreater(directions[0], 0)
        self.assertLess(directions[-1], 0)
