import unittest
from password import PasswordManager

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.manager = PasswordManager(":memory:")

    def tearDown(self):
        self.manager.conn.close()

    def test_store_and_verify_password(self):
        password = "TestPassword123"
        self.manager.store_password(password)
        self.assertTrue(self.manager.verify_password(password))

    def test_verify_incorrect_password(self):
        correct_password = "CorrectPassword123"
        incorrect_password = "IncorrectPassword456"
        self.manager.store_password(correct_password)
        self.assertFalse(self.manager.verify_password(incorrect_password))

if __name__ == "__main__":
    unittest.main()
