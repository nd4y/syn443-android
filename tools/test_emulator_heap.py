import os
import unittest
from unittest.mock import patch
from check_emulator_heap import check, megabytes


class EmulatorHeapTest(unittest.TestCase):
    def test_units_bounds_and_malformed_properties(self):
        for raw, expected in [(b'256m\r\n', 256), (b'128M', 128), (b'65536k', 64), (b'1G', 1024)]:
            self.assertEqual(expected, megabytes(raw))
        for raw in (b'', b'16', b'0m', b'-1m', b'1.5G', b'256m extra', b'9999999999m', b'\xff'):
            with self.assertRaises((AssertionError, UnicodeDecodeError)): megabytes(raw)

    def exercise(self, maximum=b'256m', growth=b'128m', serial=b'emulator-5554', hardware=b'ranchu'):
        values = {('get-serialno',): serial, ('shell', 'getprop', 'ro.hardware'): hardware,
                  ('shell', 'getprop', 'dalvik.vm.heapsize'): maximum, ('shell', 'getprop', 'dalvik.vm.heapgrowthlimit'): growth}
        with patch.dict(os.environ, {'SYN443_CI_AVD': 'syn443-ci'}): check(lambda *args: values[args])

    def test_representative_heap_and_absent_optional_growth(self):
        self.exercise()
        self.exercise(growth=b'')
        self.exercise(maximum=b'128m', growth=b'64m')

    def test_tiny_heap_inconsistent_growth_and_physical_device_are_rejected(self):
        for args in [dict(maximum=b'16m'), dict(growth=b'16m'), dict(growth=b'512m'), dict(maximum=b'4g'),
                     dict(serial=b'physical-device'), dict(hardware=b'qcom')]:
            with self.assertRaises(AssertionError): self.exercise(**args)
        with patch.dict(os.environ, {'SYN443_CI_AVD': 'other'}):
            with self.assertRaises(AssertionError): check(lambda *args: b'')


if __name__ == '__main__': unittest.main()
