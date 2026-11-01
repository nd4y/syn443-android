import unittest
from unittest.mock import patch

import run_vpn_process_faults as driver


class ControlPollTest(unittest.TestCase):
    def test_temporary_provider_death_is_polled_without_replaying_commands(self):
        with patch.object(driver, 'adb', side_effect=[b'No result found.', b'Result: Bundle[{ok=true, json={"desiredOn":true}}]']) as adb, patch.object(driver.time, 'sleep'):
            driver.await_condition(lambda: driver.call('status')['desiredOn'], timeout=1)
        self.assertEqual(adb.call_count, 2)
        self.assertTrue(all('status' in call.args for call in adb.call_args_list))

    def test_explicit_command_rejection_is_never_hidden(self):
        with patch.object(driver, 'adb', return_value=b'Result: Bundle[{ok=false, error=command_rejected}]'):
            with self.assertRaises(AssertionError):
                driver.await_condition(lambda: driver.call('status'), timeout=1)

    def test_provider_outage_cannot_satisfy_deadline(self):
        with patch.object(driver, 'adb', return_value=b'No result found.'), patch.object(driver.time, 'sleep'):
            with self.assertRaisesRegex(AssertionError, 'deadline'):
                driver.await_condition(lambda: driver.call('status'), timeout=0.01)
